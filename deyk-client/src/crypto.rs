use anyhow::Result;
use p256::PublicKey;
use hkdf::Hkdf;
use sha2::Sha256;
use aes_siv::{aead::{Aead, KeyInit, Payload}, Aes256SivAead};
use crate::yubikey::YubiKeyToken;
use rand::{RngCore};

pub fn unwrap_dek(
    token: &mut dyn YubiKeyToken,
    c_yk: &[u8],
    k_e_pub: &PublicKey,
) -> Result<[u8; 32]> {
    // 1. Hardware ECDH
    let shared_secret = token.compute_ecdh(k_e_pub)?;

    // 2. Derive wrapping key via HKDF
    let hk = Hkdf::<Sha256>::new(None, &shared_secret);
    let mut k_offline = [0u8; 64]; // Aes256SivAead needs 64 bytes
    hk.expand(b"offline-wrapping-key", &mut k_offline)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;

    // 3. Decrypt C_YK
    let cipher = Aes256SivAead::new_from_slice(&k_offline)
        .map_err(|_| anyhow::anyhow!("Failed to initialize AES-SIV"))?;
    
    let nonce = [0u8; 16]; // Static nonce for Phase A offline protection
    let dek_bytes = cipher.decrypt(nonce.as_slice().into(), c_yk)
        .map_err(|_| anyhow::anyhow!("DEK decryption failed. Incorrect YubiKey or tampered payload?"))?;

    if dek_bytes.len() != 32 {
        anyhow::bail!("Decrypted DEK has invalid length: {} (expected 32)", dek_bytes.len());
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_bytes);
    Ok(dek)
}

pub fn wrap_transport(
    token: &mut dyn YubiKeyToken,
    dek: &[u8; 32],
    k_s_pub: &PublicKey,
    server_nonce: &[u8],
) -> Result<(Vec<u8>, String)> {
    if server_nonce.len() != 16 {
        anyhow::bail!("Invalid server nonce length: {} (expected 16)", server_nonce.len());
    }

    // 1. Compute transport shared secret
    let shared_secret = token.compute_ecdh(k_s_pub)?;

    // Generate a secure 16-byte nonce
    let mut client_nonce_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut client_nonce_bytes);
    let client_nonce_hex = hex::encode(client_nonce_bytes);

    // 2. Derive transport wrapping key via HKDF
    let hk = Hkdf::<Sha256>::new(Some(client_nonce_bytes.as_slice()), &shared_secret);
    let mut k_transport = [0u8; 64];
    hk.expand(b"transport-wrapping-key", &mut k_transport)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;

    let unwrapped_payload = Payload {
        msg: dek,
        aad: server_nonce,
    };

    // 5. Encrypt using AES-SIV
    let cipher = Aes256SivAead::new_from_slice(&k_transport)
        .map_err(|_| anyhow::anyhow!("Failed to initialize AES-SIV"))?;
    
    // AES-SIV with Nonce as AAD
    let payload_enc = cipher.encrypt(&client_nonce_bytes.into(), unwrapped_payload)
        .map_err(|_| anyhow::anyhow!("Transport wrapping failed"))?;

    Ok((payload_enc, client_nonce_hex))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yubikey::MockToken;
    use p256::SecretKey;
    use rand::rngs::OsRng;
    use rand::RngCore;

    #[test]
    fn test_unwrap_dek_success() {
        // --- Setup ---
        let yk_ecdh_priv = SecretKey::random(&mut OsRng);
        let yk_ecdh_pub = yk_ecdh_priv.public_key();
        let yk_sign_priv = SecretKey::random(&mut OsRng); // Not used here but needed for MockToken
        
        let mut mock_token = MockToken::new(yk_ecdh_priv, yk_sign_priv);
        
        // Generate a random DEK and encrypt it (simulating Phase A)
        let mut expected_dek = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut expected_dek);

        let e_priv = p256::ecdh::EphemeralSecret::random(&mut OsRng);
        let k_e_pub = e_priv.public_key();
        
        let shared_secret = e_priv.diffie_hellman(&yk_ecdh_pub);
        let mut k_offline = [0u8; 64];
        Hkdf::<Sha256>::new(None, &shared_secret.raw_secret_bytes())
            .expand(b"offline-wrapping-key", &mut k_offline).unwrap();
        
        let cipher = Aes256SivAead::new_from_slice(&k_offline).unwrap();
        let nonce = [0u8; 16];
        let c_yk = cipher.encrypt(nonce.as_slice().into(), expected_dek.as_slice()).unwrap();

        // --- Execute Phase B ---
        let unwrapped_dek = unwrap_dek(&mut mock_token, &c_yk, &k_e_pub).expect("Unwrap should succeed");

        // --- Verify ---
        assert_eq!(unwrapped_dek, expected_dek);
    }

    #[test]
    fn test_wrap_transport_success() {
        // --- Setup ---
        let yk_ecdh_priv = SecretKey::random(&mut OsRng);
        let yk_sign_priv = SecretKey::random(&mut OsRng);
        let mut mock_token = MockToken::new(yk_ecdh_priv.clone(), yk_sign_priv.clone());

        let s_priv = SecretKey::random(&mut OsRng);
        let k_s_pub = s_priv.public_key();

        let dek = [7u8; 32];
        let server_nonce = [42u8; 16];

        // --- Execute Phase C ---
        let (payload_enc, client_nonce_hex) = wrap_transport(&mut mock_token, &dek, &k_s_pub, &server_nonce).expect("Wrap should succeed");
        let client_nonce_bytes = hex::decode(client_nonce_hex).unwrap();

        // --- Verify (Simulating Server-Side Phase D) ---
        let shared_secret_transport = p256::ecdh::diffie_hellman(s_priv.to_nonzero_scalar(), mock_token.ecdh_priv.public_key().as_affine());
        let mut k_transport = [0u8; 64];
        Hkdf::<Sha256>::new(Some(&client_nonce_bytes), &shared_secret_transport.raw_secret_bytes())
            .expand(b"transport-wrapping-key", &mut k_transport).unwrap();
        
        let cipher = Aes256SivAead::new_from_slice(&k_transport).unwrap();
        let unwrapped_payload = aes_siv::aead::Payload {
            msg: payload_enc.as_slice(),
            aad: &server_nonce,
        };
        let decrypted = cipher.decrypt(client_nonce_bytes.as_slice().into(), unwrapped_payload).unwrap();

        assert_eq!(&decrypted[..32], &dek);
    }

    #[test]
    fn test_unwrap_dek_tampered_c_yk() {
        let yk_ecdh_priv = SecretKey::random(&mut OsRng);
        let mut mock_token = MockToken::new(yk_ecdh_priv.clone(), SecretKey::random(&mut OsRng));
        let e_priv = p256::ecdh::EphemeralSecret::random(&mut OsRng);
        
        let shared_secret = e_priv.diffie_hellman(&yk_ecdh_priv.public_key());
        let mut k_offline = [0u8; 64];
        Hkdf::<Sha256>::new(None, &shared_secret.raw_secret_bytes())
            .expand(b"offline-wrapping-key", &mut k_offline).unwrap();
        
        let cipher = Aes256SivAead::new_from_slice(&k_offline).unwrap();
        let mut c_yk = cipher.encrypt(&[0u8; 16].into(), [7u8; 32].as_slice()).unwrap();

        // Tamper
        c_yk[0] ^= 0xFF;

        let result = unwrap_dek(&mut mock_token, &c_yk, &e_priv.public_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_unwrap_dek_wrong_k_e_pub() {
        let yk_ecdh_priv = SecretKey::random(&mut OsRng);
        let mut mock_token = MockToken::new(yk_ecdh_priv.clone(), SecretKey::random(&mut OsRng));
        let e_correct = p256::ecdh::EphemeralSecret::random(&mut OsRng);
        let e_wrong = p256::ecdh::EphemeralSecret::random(&mut OsRng);
        
        let shared_secret = e_correct.diffie_hellman(&yk_ecdh_priv.public_key());
        let mut k_offline = [0u8; 64];
        Hkdf::<Sha256>::new(None, &shared_secret.raw_secret_bytes())
            .expand(b"offline-wrapping-key", &mut k_offline).unwrap();
        
        let cipher = Aes256SivAead::new_from_slice(&k_offline).unwrap();
        let c_yk = cipher.encrypt(&[0u8; 16].into(), [7u8; 32].as_slice()).unwrap();

        let result = unwrap_dek(&mut mock_token, &c_yk, &e_wrong.public_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_unwrap_dek_invalid_cyk_length() {
        let mut mock_token = MockToken::new(SecretKey::random(&mut OsRng), SecretKey::random(&mut OsRng));
        let k_e_pub = SecretKey::random(&mut OsRng).public_key();
        
        // c_yk too short for AES-SIV
        let result = unwrap_dek(&mut mock_token, &[0u8; 15], &k_e_pub);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_transport_invalid_nonce_length() {
        let mut mock_token = MockToken::new(SecretKey::random(&mut OsRng), SecretKey::random(&mut OsRng));
        let k_s_pub = SecretKey::random(&mut OsRng).public_key();
        
        let result = wrap_transport(&mut mock_token, &[0u8; 32], &k_s_pub, &[0u8; 15]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid server nonce length"));
    }
}
