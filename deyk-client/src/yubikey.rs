use anyhow::{Result, Context};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use yubikey::piv::{SlotId, AlgorithmId};
use yubikey::YubiKey;

pub trait YubiKeyToken {
    /// Perform ECDH in Slot 9D
    fn compute_ecdh(&mut self, remote_pub: &PublicKey) -> Result<Vec<u8>>;
    
    /// Sign data in Slot 9C
    fn sign(&mut self, data: &[u8], pin: String) -> Result<Vec<u8>>;
}

pub struct HardwareToken {
    yk: YubiKey,
}

impl HardwareToken {
    pub fn connect(pin: String) -> Result<Self> {
        let mut yk = YubiKey::open().context("Failed to open YubiKey. Is it plugged in?")?;
        yk.verify_pin(pin.as_bytes()).context("Incorrect YubiKey PIN")?;
        Ok(Self { yk })
    }
}

impl YubiKeyToken for HardwareToken {
    fn compute_ecdh(&mut self, remote_pub: &PublicKey) -> Result<Vec<u8>> {
        let point = remote_pub.to_encoded_point(false);
        // Slot 9D usually has "PIN Once" policy, so the connect() verification is enough.
        let secret = yubikey::piv::decrypt_data(&mut self.yk, point.as_bytes(), AlgorithmId::EccP256, SlotId::KeyManagement)
            .context("YubiKey ECDH operation (decipher) failed")?;
        Ok(secret.to_vec())
    }

    fn sign(&mut self, data: &[u8], pin: String) -> Result<Vec<u8>> {
        // Slot 9C often has "PIN Always" policy. Re-verify PIN before signing.
        self.yk.verify_pin(pin.as_bytes()).context("Failed to re-verify PIN for signing operation")?;
        
        let sig = yubikey::piv::sign_data(&mut self.yk, data, AlgorithmId::EccP256, SlotId::Signature)
            .context("YubiKey signing operation failed")?;
        Ok(sig.to_vec())
    }
}

pub struct MockToken {
    pub ecdh_priv: SecretKey,
    pub sign_priv: SecretKey,
}

impl MockToken {
    pub fn new(ecdh_priv: SecretKey, sign_priv: SecretKey) -> Self {
        Self { ecdh_priv, sign_priv }
    }
}

impl YubiKeyToken for MockToken {
    fn compute_ecdh(&mut self, remote_pub: &PublicKey) -> Result<Vec<u8>> {
        let shared = p256::ecdh::diffie_hellman(self.ecdh_priv.to_nonzero_scalar(), remote_pub.as_affine());
        Ok(shared.raw_secret_bytes().to_vec())
    }

    fn sign(&mut self, data: &[u8], _pin: String) -> Result<Vec<u8>> {
        use p256::ecdsa::{SigningKey, signature::Signer};
        let signing_key = SigningKey::from(&self.sign_priv);
        let sig: p256::ecdsa::Signature = signing_key.sign(data);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}
