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
