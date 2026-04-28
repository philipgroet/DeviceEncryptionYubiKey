use p256::ecdh::EphemeralSecret;
use p256::{EncodedPoint, PublicKey, SecretKey};
use hkdf::Hkdf;
use sha2::Sha256;
use anyhow::{Result, Context};
use rand::{RngCore, thread_rng};
use aes_siv::{
    aead::{Aead, KeyInit},
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
    k_yk_sign_pub: &PublicKey,
    nonce: &[u8],
    payload_hex: &str,
) -> Result<[u8; 32]> {
    // 1. Compute transport shared secret
    let shared_secret = p256::ecdh::diffie_hellman(k_s_priv.to_nonzero_scalar(), k_yk_ecdh_pub.as_affine());
    let shared_secret_bytes = shared_secret.raw_secret_bytes();

    // 2. Derive transport key via HKDF
    let hk = Hkdf::<Sha256>::new(Some(nonce), &shared_secret_bytes);
    let mut k_transport = [0u8; 64];
    hk.expand(b"transport-wrapping-key", &mut k_transport)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;

    // 3. Decrypt payload
    let cipher = Aes256SivAead::new_from_slice(&k_transport)
        .map_err(|_| anyhow::anyhow!("Failed to initialize AES-SIV"))?;
    
    let payload = hex::decode(payload_hex).context("Invalid payload hex")?;
    // AES-SIV with Nonce as AAD
    let decrypted = cipher.decrypt(nonce.into(), payload.as_slice())
        .map_err(|_| anyhow::anyhow!("Decryption failed - possibly invalid nonce or tampered payload"))?;

    // 4. Extract DEK and Signature
    if decrypted.len() < 32 {
        anyhow::bail!("Decrypted payload too short");
    }
    let (dek_bytes, sig_bytes) = decrypted.split_at(32);
    let mut dek = [0u8; 32];
    dek.copy_from_slice(dek_bytes);

    // 5. Verify Signature
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let sig = Signature::from_der(sig_bytes).map_err(|_| anyhow::anyhow!("Invalid signature format"))?;
    let verify_key = VerifyingKey::from(k_yk_sign_pub);
    verify_key.verify(nonce, &sig).map_err(|_| anyhow::anyhow!("Hardware signature verification failed"))?;

    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use rand::rngs::OsRng;
    use p256::ecdsa::{SigningKey, signature::Signer};

    #[test]
    fn test_phase_a_and_d_success() {
        // --- Setup ---
        let yk_ecdh_priv = SecretKey::random(&mut OsRng);
        let yk_ecdh_pub = yk_ecdh_priv.public_key();
        let yk_sign_priv = SigningKey::random(&mut OsRng);
        let yk_sign_pub = PublicKey::from(yk_sign_priv.verifying_key());

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
        let nonce = [42u8; 16];
        let shared_secret_transport = p256::ecdh::diffie_hellman(yk_ecdh_priv.to_nonzero_scalar(), s_priv.public_key().as_affine());
        let mut k_transport = [0u8; 64];
        Hkdf::<Sha256>::new(Some(&nonce), &shared_secret_transport.raw_secret_bytes())
            .expand(b"transport-wrapping-key", &mut k_transport).unwrap();
        
        let sig: p256::ecdsa::Signature = yk_sign_priv.sign(&nonce);
        let mut payload_plain = dek.clone();
        payload_plain.extend_from_slice(sig.to_der().as_bytes());

        let cipher_transport = Aes256SivAead::new_from_slice(&k_transport).unwrap();
        let payload_enc = cipher_transport.encrypt((&nonce).into(), payload_plain.as_slice()).unwrap();

        // --- Server Side (Phase D) ---
        let recovered_dek = run_phase_d(
            &s_priv,
            &yk_ecdh_pub,
            &yk_sign_pub,
            &nonce,
            &hex::encode(payload_enc)
        ).expect("Phase D failed");

        assert_eq!(recovered_dek, setup_output.dek);
    }
}
