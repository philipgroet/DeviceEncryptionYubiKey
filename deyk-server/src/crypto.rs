use p256::ecdh::EphemeralSecret;
use p256::{EncodedPoint, PublicKey};
use hkdf::Hkdf;
use sha2::Sha256;
use anyhow::Result;
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

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{SecretKey, elliptic_curve::{group::GroupEncoding, sec1::FromEncodedPoint}, pkcs8::EncodePublicKey};
    use rand::rngs::OsRng;

    #[test]
    fn test_phase_a_success() {
        let k_yk_ecdh_priv = SecretKey::random(&mut OsRng);
        let k_yk_ecdh_pub = k_yk_ecdh_priv.public_key();

        println!("Secret Key: {:?}", hex::encode(&k_yk_ecdh_priv.to_bytes()));
        println!("Public Key: {:?}", hex::encode(&k_yk_ecdh_pub.as_affine().to_bytes()));

        let result = generate_c_yk(&k_yk_ecdh_pub).expect("Phase A should succeed");

        // --- Mock Phase B (Decryption) ---
        // 1. Decode Ephemeral Public Key from Phase A
        let k_e_pub = PublicKey::from_encoded_point(&result.k_e_pub).into_option().unwrap();

        // 2. Compute Shared Secret using YubiKey's Private Key (Mocked)
        let shared_secret = p256::ecdh::diffie_hellman(k_yk_ecdh_priv.to_nonzero_scalar(), k_e_pub.as_affine());
        let shared_secret_bytes = shared_secret.raw_secret_bytes();

        // 3. Derive wrapping key via HKDF
        let hk = Hkdf::<Sha256>::new(None, &shared_secret_bytes);
        let mut k_offline = [0u8; 64];
        hk.expand(b"offline-wrapping-key", &mut k_offline).unwrap();

        // 4. Decrypt C_YK
        let cipher = Aes256SivAead::new_from_slice(&k_offline).unwrap();
        let nonce = [0u8; 16];
        let decrypted_dek = cipher.decrypt(nonce.as_slice().into(), result.c_yk.as_slice()).expect("Decryption failed");

        // 5. Verify DEK matches
        assert_eq!(decrypted_dek, result.dek);
    }
}
