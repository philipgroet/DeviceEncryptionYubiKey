use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use anyhow::{Result, Context};
use p256::{EncodedPoint, SecretKey, PublicKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ServerStateJson {
    pub k_yk_ecdh_pub: Option<String>,
    pub yubikey_sign_pub: Option<String>,
    pub c_yk: Option<String>,
    pub k_e_pub: Option<String>,
    pub k_s_priv: Option<String>,
    pub k_s_pub: Option<String>,
    pub nonce: Option<String>,
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
    pub c_yk: Vec<u8>,
    pub k_e_pub: EncodedPoint,
    pub k_yk_ecdh_pub: PublicKey,
    pub k_yk_sign_pub: PublicKey,
    pub k_s_priv: SecretKey,
    pub k_s_pub: PublicKey,
    pub nonce: Option<Vec<u8>>,
}

impl ServerState {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let json = ServerStateJson::load(path)?;
        Self::parse(json)
    }

    pub fn parse(json: ServerStateJson) -> Result<Self> {
        let k_yk_ecdh_pub_hex = json.k_yk_ecdh_pub.context("Missing k_yk_ecdh_pub")?;
        let yk_pub_bytes = hex::decode(k_yk_ecdh_pub_hex)?;
        let yk_pub_point = EncodedPoint::from_bytes(&yk_pub_bytes).map_err(|_| anyhow::anyhow!("Invalid YubiKey ECDH public key"))?;
        let k_yk_ecdh_pub = PublicKey::from_encoded_point(&yk_pub_point).into_option().context("Invalid YubiKey ECDH public key point")?;

        let yubikey_sign_pub_hex = json.yubikey_sign_pub.context("Missing yubikey_sign_pub")?;
        let yk_sign_bytes = hex::decode(yubikey_sign_pub_hex)?;
        let yk_sign_point = EncodedPoint::from_bytes(&yk_sign_bytes).map_err(|_| anyhow::anyhow!("Invalid YubiKey sign public key"))?;
        let k_yk_sign_pub = PublicKey::from_encoded_point(&yk_sign_point).into_option().context("Invalid YubiKey sign public key point")?;

        let c_yk_hex = json.c_yk.context("Missing c_yk")?;
        let c_yk = hex::decode(c_yk_hex)?;

        let k_e_pub_hex = json.k_e_pub.context("Missing k_e_pub")?;
        let k_e_pub_bytes = hex::decode(k_e_pub_hex)?;
        let k_e_pub = EncodedPoint::from_bytes(&k_e_pub_bytes).map_err(|_| anyhow::anyhow!("Invalid k_e_pub"))?;

        let k_s_priv_hex = json.k_s_priv.context("Missing k_s_priv")?;
        let k_s_priv_bytes = hex::decode(k_s_priv_hex)?;
        let k_s_priv = SecretKey::from_slice(&k_s_priv_bytes).map_err(|_| anyhow::anyhow!("Invalid server private key"))?;

        let k_s_pub_hex = json.k_s_pub.context("Missing k_s_pub")?;
        let k_s_pub_bytes = hex::decode(k_s_pub_hex)?;
        let k_s_pub_point = EncodedPoint::from_bytes(&k_s_pub_bytes).map_err(|_| anyhow::anyhow!("Invalid server public key"))?;
        let k_s_pub = PublicKey::from_encoded_point(&k_s_pub_point).into_option().context("Invalid server public key point")?;

        let nonce = if let Some(nonce_hex) = json.nonce {
            Some(hex::decode(nonce_hex)?)
        } else {
            None
        };

        Ok(Self {
            c_yk,
            k_e_pub,
            k_yk_ecdh_pub,
            k_yk_sign_pub,
            k_s_priv,
            k_s_pub,
            nonce,
        })
    }
}
