# DeviceEncryptionYubiKey (DEYK)

A hardware-backed, zero-knowledge authentication protocol that leverages YubiKey PIV applets (ECC) to protect a Data Encryption Key (DEK).

## Overview

The protocol ensures that the server never holds a static key capable of decrypting the DEK without the physical presence and participation of a specific YubiKey.

- **deyk-client**: Rust client that communicates with the YubiKey via PIV to perform ECDH and signing.
- **deyk-server**: Rust server that manages the encrypted DEK and coordinates the challenge-response protocol.

## Project Structure

- `deyk-client/`: The client-side application logic.
- `deyk-server/`: The server-side application logic.
- `DESIGN.md`: Detailed cryptographic specification of the 4-phase protocol.

## Setup

### 1. Initialize YubiKey (PIV)

You need to generate two ECC P-256 keypairs on your YubiKey in slots `9D` (Key Management) and `9C` (Digital Signature).

**Generate ECDH Key (Slot 9D) with Touch Requirement:**
```bash
ykman piv keys generate --algorithm ECCP256 --touch-policy ALWAYS 9d ecdh_pub.pem
```

*Note: The `--touch-policy ALWAYS` flag ensures that the physical button must be pressed for every cryptographic operation.*

### 2. Convert PEM to Hex

The server configuration requires the public keys in raw hex format (uncompressed, 65 bytes / 130 characters).

**Extract Hex from PEM:**
```bash
# For ECDH Public Key
openssl ec -pubin -in ecdh_pub.pem -outform DER | tail -c 65 | xxd -p -c 65
```

## Quick Start

1. **Server Setup**:
   ```bash
   cd deyk-server
   cargo run -- setup --set-yubikey-ecdh-pub <HEX_FROM_9D> --set-yubikey-sign_pub <HEX_FROM_9C>
   ```

2. **Client Unlock**:
   ```bash
   cd deyk-client
   cargo run -- unlock --server-url <URL>
   ```

## End-to-End Testing

To test the entire protocol flow (Phases A through D) manually using the CLI tools:

### Phase A: Server Setup
Initialize the server configuration with your YubiKey public keys. This generates the DEK and encrypts it for your hardware.
```bash
# In deyk-server/
cargo run -- setup \
  --set-yubikey-ecdh-pub <HEX_9D> \
  --set-yubikey-sign-pub <HEX_9C>
```
*Note the `plaintext_dek` (for verification), `c_yk`, `k_e_pub`, and `server_pub_key` from the output.*

### Phase B: Client Unwrap
The client uses the YubiKey to decrypt the `c_yk` using the ephemeral public key `k_e_pub`.
```bash
# In deyk-client/
cargo run -- --pin <YOUR_PIN> unwrap \
  --c-yk <C_YK_HEX> \
  --k-e-pub <K_E_PUB_HEX>
```
*Verify that the resulting hex matches the `plaintext_dek` from Phase A.*

### Phase C: Client Wrap
Get a fresh challenge (nonce) from the server and wrap the DEK for secure transport.
```bash
# 1. Get Nonce (Server)
# In deyk-server/
cargo run -- get-nonce

# 2. Wrap for Transport (Client)
# In deyk-client/
cargo run -- --pin <YOUR_PIN> wrap \
  --dek <DEK_HEX> \
  --nonce <SERVER_NONCE_HEX> \
  --k-s-pub <SERVER_PUB_KEY_HEX>
```
*This will output the `Payload Hex` and `Client Nonce Hex` to be sent back to the server.*

### Phase D: Server Unlock
The server unwraps the DEK using both nonces.
```bash
# In deyk-server/
cargo run -- unlock \
  --payload <PAYLOAD_HEX> \
  --client-nonce <CLIENT_NONCE_HEX>
```
*The server should output the same `dek` hex, proving the loop is complete and secure.*
