# YubiKey-Backed Zero-Knowledge Authentication Protocol

## 1. System Requirements
* **Hardware Token:** Standard off-the-shelf YubiKey utilizing the PIV applet.
* **Server Resistance to Offline Compromise:** The server must not store the Data Encryption Key (DEK) in plaintext or hold any static key capable of decrypting the stored DEK.
* **Ephemeral Client Trust:** The client laptop is permitted to hold secrets (the DEK and derived keys) temporarily in volatile memory (RAM), but must not store them on disk.
* **No Plaintext Transmission:** The DEK must never be transmitted over the network in plaintext.
* **Hardware-Only Client Asymmetry:** The client software must not possess or manage its own asymmetric keypair. It strictly relies on the YubiKey's ECC pairs for all asymmetric operations.
* **Anti-Replay & Hardware Proof:** All unlock requests must be bound to a fresh server challenge (Nonce) and mathematically prove the physical presence of the YubiKey during the exact session.

---

## 2. Cryptographic State & Initialization

### 2.1 Entity Key Material
* **Server:** * Static ECC Keypair: $(K_{S\_priv}, K_{S\_pub})$
  * Knows YubiKey Public Keys: $K_{yk\_ecdh\_pub}$ (Slot 9D), $K_{yk\_sign\_pub}$ (Slot 9C)
* **Client:** * Knows Server Public Key: $K_{S\_pub}$
* **YubiKey (PIV Applet):**
  * Slot 9D (Key Management): ECC Keypair $(K_{yk\_ecdh\_priv}, K_{yk\_ecdh\_pub})$ configured for ECDH.
  * Slot 9C (Digital Signature): ECC Keypair $(K_{yk\_sign\_priv}, K_{yk\_sign\_pub})$ configured for ECDSA.

### 2.2 Phase A: Server-Side Offline Protection (Setup / Key Rotation)
*Objective: Encrypt the DEK such that only the physical YubiKey can participate in its decryption, utilizing ECIES to strip the server of decryption privileges.*

1. Server generates the Data Encryption Key ($DEK$).
2. Server generates a one-time ephemeral ECC keypair: $(K_{E\_priv}, K_{E\_pub})$.
3. Server computes the offline shared secret: 
   $$SharedSecret_{offline} = \text{ECDH}(K_{E\_priv}, K_{yk\_ecdh\_pub})$$
4. Server derives the wrapping key via HKDF: 
   $$K_{offline} = \text{HKDF}(SharedSecret_{offline})$$
5. Server encrypts the DEK using AES-GCM: 
   $$C_{YK}, Tag_{offline} = \text{AES-GCM-Encrypt}(K_{offline}, DEK)$$
6. Server **permanently destroys** $K_{E\_priv}$ and the plaintext $DEK$. 
7. Server stores $C_{YK}$, $Tag_{offline}$, and $K_{E\_pub}$.

---

## 3. The Execution Flow (Unlock Algorithm)

### 3.1 Phase B: Client Hardware Unwrapping
*Objective: The client securely retrieves the DEK into volatile memory.*

1. **Challenge:** Server generates a cryptographically secure Nonce $N$.
2. **Delivery:** Server transmits $N$, $C_{YK}$, $Tag_{offline}$, $K_{E\_pub}$, and $K_{S\_pub}$ to the Client.
3. **Hardware ECDH:** Client passes $K_{E\_pub}$ to YubiKey Slot `9D`.
4. **Token Response:** YubiKey computes $SharedSecret_{offline} = \text{ECDH}(K_{yk\_ecdh\_priv}, K_{E\_pub})$ and returns it to the Client.
5. **Decryption:** Client derives $K_{offline} = \text{HKDF}(SharedSecret_{offline})$ and decrypts $C_{YK}$ to hold the raw $DEK$ in RAM.

### 3.2 Phase C: Hardware-Backed Transport Wrapping
*Objective: The client establishes a mutually authenticated tunnel to the server and proves physical token presence.*

1. **Tunnel ECDH:** Client passes Server's static key $K_{S\_pub}$ to YubiKey Slot `9D`.
2. **Token Response:** YubiKey computes $SharedSecret_{transport} = \text{ECDH}(K_{yk\_ecdh\_priv}, K_{S\_pub})$ and returns it to the Client.
3. **Hardware Signature:** Client passes Nonce $N$ to YubiKey Slot `9C`.
4. **Token Response:** YubiKey returns the signature $S_{YK} = \text{Sign}(K_{yk\_sign\_priv}, N)$.
5. **Key Derivation:** Client uses HKDF with the Nonce as salt to bind the session key: 
   $$K_{transport} = \text{HKDF}(SharedSecret_{transport}, \text{salt=}N)$$
6. **Payload Wrapping:** Client encrypts the $DEK$ and the Signature together, using the Nonce $N$ as Associated Data (AAD) to prevent ciphertext detachment:
   $$Ciphertext, Tag_{transport} = \text{AES-GCM-Encrypt}(K_{transport}, \text{Payload: } [DEK, S_{YK}], \text{AAD: } N)$$
7. **Cleanup:** Client wipes $DEK$, Shared Secrets, and Keys from RAM.
8. **Transmission:** Client transmits $Ciphertext$ and $Tag_{transport}$ to the Server.

### 3.3 Phase D: Server Verification and Unlock
*Objective: The server validates the session, the hardware presence, and mounts the keystore.*

1. **Tunnel ECDH:** Server computes the mirror shared secret:
   $$SharedSecret_{transport} = \text{ECDH}(K_{S\_priv}, K_{yk\_ecdh\_pub})$$
2. **Key Derivation:** Server derives $K_{transport} = \text{HKDF}(SharedSecret_{transport}, \text{salt=}N)$.
3. **Decryption & Session Validation:** Server attempts AES-GCM decryption using $N$ as the expected AAD. 
   * *Failure condition: If the Tag is invalid or AAD does not match, the payload was tampered with or replayed.*
4. **Extraction:** Server extracts the plaintext $DEK$ and $S_{YK}$.
5. **Hardware Validation:** Server verifies $S_{YK}$ against Nonce $N$ using the pre-shared $K_{yk\_sign\_pub}$.
   * *Failure condition: If the signature is invalid, the operation was executed by a compromised client caching the shared secret without the physical token present.*
6. **Unlock:** If all validations pass, the Server uses the $DEK$ to mount the target keystore into memory.