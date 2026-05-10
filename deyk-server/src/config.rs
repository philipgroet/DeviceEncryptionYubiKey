use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use anyhow::{Result, Context};
use p256::{EncodedPoint, SecretKey, PublicKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ServerStateJson {
    pub k_yk_ecdh_pub: Option<String>,
    pub k_yk_sign_pub: Option<String>,
    pub c_yk: Option<String>,
    pub k_e_pub: Option<String>,
    pub k_s_priv: Option<String>,
    pub k_s_pub: Option<String>,
    pub server_nonce: Option<String>,
}

impl ServerStateJson {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        if !path.as_ref().exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        let state = serde_json::from_str(&content)?;
        Ok(state)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// Verifies that the server nonce can be successfully cleared from memory
    /// using the `Option::take()` method, ensuring it's no longer available for re-use.
    #[test]
    fn test_nonce_clearing() {
        let mut state = ServerStateJson::default();
        state.server_nonce = Some("test-nonce".to_string());
        
        // Take the nonce
        let taken = state.server_nonce.take();
        assert_eq!(taken, Some("test-nonce".to_string()));
        assert!(state.server_nonce.is_none());
    }

    /// Verifies that clearing the nonce in the server state and saving it to disk
    /// correctly persists the "cleared" state (nonce should be None upon reload).
    #[test]
    fn test_persistence_clears_nonce() -> Result<()> {
        let file = NamedTempFile::new()?;
        let path = file.path().to_path_buf();

        let mut state = ServerStateJson::default();
        state.server_nonce = Some("secret-nonce".to_string());
        state.save(&path)?;

        // Load and check it's there
        let mut loaded = ServerStateJson::load(&path)?;
        assert_eq!(loaded.server_nonce, Some("secret-nonce".to_string()));

        // Clear it
        loaded.server_nonce.take();
        loaded.save(&path)?;

        // Reload and check it's gone
        let reloaded = ServerStateJson::load(&path)?;
        assert!(reloaded.server_nonce.is_none());

        Ok(())
    }
}

pub struct ServerState {
    pub k_yk_ecdh_pub: PublicKey,
    pub k_s_priv: SecretKey,
}

impl ServerState {
    // pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
    //     let json = ServerStateJson::load(path)?;
    //     Self::parse(json)
    // }

    pub fn parse(json: ServerStateJson) -> Result<Self> {
        let k_yk_ecdh_pub_hex = json.k_yk_ecdh_pub.context("Missing k_yk_ecdh_pub")?;
        let yk_pub_bytes = hex::decode(k_yk_ecdh_pub_hex)?;
        let yk_pub_point = EncodedPoint::from_bytes(&yk_pub_bytes).map_err(|_| anyhow::anyhow!("Invalid YubiKey ECDH public key"))?;
        let k_yk_ecdh_pub = PublicKey::from_encoded_point(&yk_pub_point).into_option().context("Invalid YubiKey ECDH public key point")?;

        let k_s_priv_hex = json.k_s_priv.context("Missing k_s_priv")?;
        let k_s_priv_bytes = hex::decode(k_s_priv_hex)?;
        let k_s_priv = SecretKey::from_slice(&k_s_priv_bytes).map_err(|_| anyhow::anyhow!("Invalid server private key"))?;

        Ok(Self {
            k_yk_ecdh_pub,
            k_s_priv,
        })
    }
}
