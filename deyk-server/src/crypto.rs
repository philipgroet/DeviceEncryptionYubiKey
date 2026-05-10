use p256::ecdh::EphemeralSecret;
use p256::{EncodedPoint, PublicKey, SecretKey};
use hkdf::Hkdf;
use sha2::Sha256;
use anyhow::{Result, Context};
use rand::{RngCore, thread_rng};
use aes_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256SivAead
};

pub struct PhaseAOutput {
    pub c_yk: Vec<u8>,
    pub k_e_pub: EncodedPoint,
    pub dek: [u8; 32],
}

pub fn generate_c_yk(k_yk_ecdh_pub: &PublicKey) -> Result<PhaseAOutput> {
    // Step 1: Generate a random 256-bit DEK
    let mut dek: [u8; 32] = [0; 32];
    thread_rng().fill_bytes(&mut dek);

    // Step 3: Generate ephemeral ECC P-256 keypair and compute shared secret
    let e_priv = EphemeralSecret::random(&mut rand::thread_rng());
    let k_e_pub = EncodedPoint::from(&e_priv.public_key());

    let shared_secret = e_priv.diffie_hellman(k_yk_ecdh_pub);
    let shared_secret_bytes = shared_secret.raw_secret_bytes();

    // Step 4: Derive wrapping key via HKDF-SHA256
    // AES-SIV-256 (Aes256SivAead) requires a 64-byte key.
    let hk = Hkdf::<Sha256>::new(None, &shared_secret_bytes);
    let mut k_offline = [0u8; 64];
    hk.expand(b"offline-wrapping-key", &mut k_offline)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;

    // Step 5: Encrypt DEK using AES-SIV
    let cipher = Aes256SivAead::new_from_slice(&k_offline)
        .map_err(|_| anyhow::anyhow!("Failed to initialize AES-SIV"))?;
    
    // AES-SIV is deterministic, but the AEAD trait expects a nonce.
    // For ECIES where the key is one-time ephemeral, a static zero nonce is fine.
    let nonce = [0u8; 16]; // AES-SIV typically uses 128-bit S2V (nonce/AD)
    let c_yk = cipher.encrypt(nonce.as_slice().into(), dek.as_slice())
        .map_err(|_| anyhow::anyhow!("Failed to encrypt DEK"))?;

    Ok(PhaseAOutput {
        c_yk,
        k_e_pub,
        dek,
    })
}

pub fn run_phase_d(
    k_s_priv: &SecretKey,
    k_yk_ecdh_pub: &PublicKey,
    server_nonce: &[u8],
    client_nonce: &[u8],
    payload_hex: &str,
) -> Result<[u8; 32]> {
    // 0. Validate nonce lengths
    if server_nonce.len() != 16 {
        anyhow::bail!("Invalid server nonce length: {} (expected 16)", server_nonce.len());
    }
    if client_nonce.len() != 16 {
        anyhow::bail!("Invalid client nonce length: {} (expected 16)", client_nonce.len());
    }

    // 1. Compute transport shared secret
    let shared_secret = p256::ecdh::diffie_hellman(k_s_priv.to_nonzero_scalar(), k_yk_ecdh_pub.as_affine());
    let shared_secret_bytes = shared_secret.raw_secret_bytes();

    // 2. Derive transport key via HKDF
    let hk = Hkdf::<Sha256>::new(Some(client_nonce), &shared_secret_bytes);
    let mut k_transport = [0u8; 64];
    hk.expand(b"transport-wrapping-key", &mut k_transport)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;

    // 3. Decrypt payload
    let cipher = Aes256SivAead::new_from_slice(&k_transport)
        .map_err(|_| anyhow::anyhow!("Failed to initialize AES-SIV"))?;
    
    let wrapped_payload = hex::decode(payload_hex).context("Invalid payload hex")?;
    let cipher_payload = Payload {
        msg: &wrapped_payload,
        aad: server_nonce,
    };
    let dek = cipher.decrypt(client_nonce.into(), cipher_payload)
        .map_err(|_| anyhow::anyhow!("Decryption failed - possibly invalid nonce or tampered payload"))?;

    if dek.len() != 32 {
        anyhow::bail!("Decrypted DEK has invalid length: {} (expected 32)", dek.len());
    }

    let mut dek_array = [0u8; 32];
    dek_array.copy_from_slice(dek.as_slice());    
    Ok(dek_array)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use rand::rngs::OsRng;
    use p256::ecdsa::SigningKey;

    #[test]
    fn test_phase_a_and_d_success() {
        // --- Setup ---
        let yk_ecdh_priv = SecretKey::random(&mut OsRng);
        let yk_ecdh_pub = yk_ecdh_priv.public_key();
        let yk_sign_priv = SigningKey::random(&mut OsRng);
        let yk_sign_pub = PublicKey::from(yk_sign_priv.verifying_key());

        println!("--- MOCK YUBIKEY KEYS ---");
        println!("ECDH PRIV: {}", hex::encode(yk_ecdh_priv.to_bytes()));
        println!("ECDH PUB:  {}", hex::encode(yk_ecdh_pub.to_encoded_point(false).as_bytes()));
        println!("SIGN PRIV: {}", hex::encode(yk_sign_priv.to_bytes()));
        println!("SIGN PUB:  {}", hex::encode(yk_sign_pub.to_encoded_point(false).as_bytes()));
        println!("-------------------------");

        let s_priv = SecretKey::random(&mut OsRng);

        // Phase A
        let setup_output = generate_c_yk(&yk_ecdh_pub).expect("Setup failed");

        // --- Client Side (Phase B & C) ---
        // 1. Unwrap DEK (Phase B)
        let k_e_pub = PublicKey::from_encoded_point(&setup_output.k_e_pub).into_option().unwrap();
        let shared_secret_offline = p256::ecdh::diffie_hellman(yk_ecdh_priv.to_nonzero_scalar(), k_e_pub.as_affine());
        let mut k_offline = [0u8; 64];
        Hkdf::<Sha256>::new(None, &shared_secret_offline.raw_secret_bytes())
            .expand(b"offline-wrapping-key", &mut k_offline).unwrap();
        let cipher_offline = Aes256SivAead::new_from_slice(&k_offline).unwrap();
        let dek = cipher_offline.decrypt(&[0u8; 16].into(), setup_output.c_yk.as_slice()).unwrap();

        // 2. Transport Wrap (Phase C)
        let server_nonce = [42u8; 16];
        let mut client_nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut client_nonce);
        
        let shared_secret_transport = p256::ecdh::diffie_hellman(yk_ecdh_priv.to_nonzero_scalar(), s_priv.public_key().as_affine());
        let mut k_transport = [0u8; 64];
        Hkdf::<Sha256>::new(Some(&client_nonce), &shared_secret_transport.raw_secret_bytes())
            .expand(b"transport-wrapping-key", &mut k_transport).unwrap();
        
        let payload_plain = dek.clone();
        
        let cipher_transport = Aes256SivAead::new_from_slice(&k_transport).unwrap();
        let cipher_payload = aes_siv::aead::Payload {
            msg: payload_plain.as_slice(),
            aad: &server_nonce,
        };
        let payload_enc = cipher_transport.encrypt((&client_nonce).into(), cipher_payload).unwrap();

        // --- Server Side (Phase D) ---
        let recovered_dek = run_phase_d(
            &s_priv,
            &yk_ecdh_pub,
            &server_nonce,
            &client_nonce,
            &hex::encode(payload_enc)
        ).expect("Phase D failed");

        assert_eq!(recovered_dek, setup_output.dek);
    }

    #[test]
    fn test_phase_d_wrong_server_nonce() {
        let yk_ecdh_priv = SecretKey::random(&mut OsRng);
        let s_priv = SecretKey::random(&mut OsRng);
        let server_nonce_correct = [1u8; 16];
        let server_nonce_wrong = [2u8; 16];
        let client_nonce = [0u8; 16];

        // Wrap with correct server nonce
        let shared_secret_transport = p256::ecdh::diffie_hellman(yk_ecdh_priv.to_nonzero_scalar(), s_priv.public_key().as_affine());
        let mut k_transport = [0u8; 64];
        Hkdf::<Sha256>::new(Some(&client_nonce), &shared_secret_transport.raw_secret_bytes())
            .expand(b"transport-wrapping-key", &mut k_transport).unwrap();
        let cipher = Aes256SivAead::new_from_slice(&k_transport).unwrap();
        let payload_enc = cipher.encrypt((&client_nonce).into(), Payload { msg: &[7u8; 32], aad: &server_nonce_correct }).unwrap();

        // Attempt D with wrong server nonce
        let result = run_phase_d(&s_priv, &yk_ecdh_priv.public_key(), &server_nonce_wrong, &client_nonce, &hex::encode(payload_enc));
        assert!(result.is_err());
    }

    #[test]
    fn test_phase_d_wrong_client_nonce() {
        let yk_ecdh_priv = SecretKey::random(&mut OsRng);
        let s_priv = SecretKey::random(&mut OsRng);
        let server_nonce = [1u8; 16];
        let client_nonce_correct = [10u8; 16];
        let client_nonce_wrong = [20u8; 16];

        // Wrap with correct client nonce
        let shared_secret_transport = p256::ecdh::diffie_hellman(yk_ecdh_priv.to_nonzero_scalar(), s_priv.public_key().as_affine());
        let mut k_transport = [0u8; 64];
        Hkdf::<Sha256>::new(Some(&client_nonce_correct), &shared_secret_transport.raw_secret_bytes())
            .expand(b"transport-wrapping-key", &mut k_transport).unwrap();
        let cipher = Aes256SivAead::new_from_slice(&k_transport).unwrap();
        let payload_enc = cipher.encrypt((&client_nonce_correct).into(), Payload { msg: &[7u8; 32], aad: &server_nonce }).unwrap();

        // Attempt D with wrong client nonce
        let result = run_phase_d(&s_priv, &yk_ecdh_priv.public_key(), &server_nonce, &client_nonce_wrong, &hex::encode(payload_enc));
        assert!(result.is_err());
    }

    #[test]
    fn test_phase_d_tampered_payload() {
        let yk_ecdh_priv = SecretKey::random(&mut OsRng);
        let s_priv = SecretKey::random(&mut OsRng);
        let server_nonce = [1u8; 16];
        let client_nonce = [0u8; 16];

        let shared_secret_transport = p256::ecdh::diffie_hellman(yk_ecdh_priv.to_nonzero_scalar(), s_priv.public_key().as_affine());
        let mut k_transport = [0u8; 64];
        Hkdf::<Sha256>::new(Some(&client_nonce), &shared_secret_transport.raw_secret_bytes())
            .expand(b"transport-wrapping-key", &mut k_transport).unwrap();
        let cipher = Aes256SivAead::new_from_slice(&k_transport).unwrap();
        let mut payload_enc = cipher.encrypt((&client_nonce).into(), Payload { msg: &[7u8; 32], aad: &server_nonce }).unwrap();

        // Tamper
        payload_enc[0] ^= 0xFF;

        let result = run_phase_d(&s_priv, &yk_ecdh_priv.public_key(), &server_nonce, &client_nonce, &hex::encode(payload_enc));
        assert!(result.is_err());
    }

    #[test]
    fn test_phase_d_wrong_server_key() {
        let yk_ecdh_priv = SecretKey::random(&mut OsRng);
        let s_priv_correct = SecretKey::random(&mut OsRng);
        let s_priv_wrong = SecretKey::random(&mut OsRng);
        let server_nonce = [1u8; 16];
        let client_nonce = [0u8; 16];

        let shared_secret_transport = p256::ecdh::diffie_hellman(yk_ecdh_priv.to_nonzero_scalar(), s_priv_correct.public_key().as_affine());
        let mut k_transport = [0u8; 64];
        Hkdf::<Sha256>::new(Some(&client_nonce), &shared_secret_transport.raw_secret_bytes())
            .expand(b"transport-wrapping-key", &mut k_transport).unwrap();
        let cipher = Aes256SivAead::new_from_slice(&k_transport).unwrap();
        let payload_enc = cipher.encrypt((&client_nonce).into(), Payload { msg: &[7u8; 32], aad: &server_nonce }).unwrap();

        let result = run_phase_d(&s_priv_wrong, &yk_ecdh_priv.public_key(), &server_nonce, &client_nonce, &hex::encode(payload_enc));
        assert!(result.is_err());
    }

    #[test]
    fn test_phase_d_invalid_nonce_length() {
        let yk_ecdh_priv = SecretKey::random(&mut OsRng);
        let s_priv = SecretKey::random(&mut OsRng);
        let short_nonce = [1u8; 15];
        let long_nonce = [1u8; 17];
        let normal_nonce = [1u8; 16];

        let result = run_phase_d(&s_priv, &yk_ecdh_priv.public_key(), &short_nonce, &normal_nonce, "deadbeef");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid server nonce length"));

        let result = run_phase_d(&s_priv, &yk_ecdh_priv.public_key(), &normal_nonce, &long_nonce, "deadbeef");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid client nonce length"));
    }

    #[test]
    fn test_phase_d_invalid_payload_length() {
        let yk_ecdh_priv = SecretKey::random(&mut OsRng);
        let s_priv = SecretKey::random(&mut OsRng);
        let nonce = [1u8; 16];

        // Payload too short for AES-SIV (must be at least 16 bytes for S2V tag)
        let result = run_phase_d(&s_priv, &yk_ecdh_priv.public_key(), &nonce, &nonce, "aabbcc");
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "Hardware signature verification is not yet implemented"]
    fn test_phase_d_invalid_signature() {
        // This is a placeholder for when Phase C/D includes a hardware signature
        // as described in DESIGN.md.
        assert!(false, "Signature verification not implemented");
    }
}
