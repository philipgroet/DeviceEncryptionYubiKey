mod yubikey;
mod crypto;

use anyhow::{Result, Context};
use clap::{Parser, Subcommand};
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey, SecretKey};
use yubikey::YubiKeyToken;
use ct_codecs::{Hex, Decoder, Encoder};

#[derive(Parser)]
#[command(name = "deyk-client")]
#[command(about = "Device Encryption YubiKey Client", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// YubiKey PIN (required for hardware token)
    #[arg(long, global = true)]
    pin: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Phase B: Unwrap the DEK using YubiKey
    Unwrap {
        /// The encrypted DEK (c_yk) from the server (Hex)
        #[arg(long)]
        c_yk: String,

        /// The ephemeral public key (k_e_pub) from the server (Hex)
        #[arg(long)]
        k_e_pub: String,

        /// Set the server's transport public key (Hex) and save to config
        #[arg(long)]
        set_k_s_pub: Option<String>,

        /// Path to the client configuration file
        #[arg(long, default_value = "deyk_client_config.json")]
        config: String,
    },
    /// Phase C: Wrap the DEK for transport to the server
    Wrap {
        /// The unwrapped Data Encryption Key (Hex)
        #[arg(long)]
        dek: String,

        /// The server's transport public key (Hex)
        #[arg(long)]
        k_s_pub: Option<String>,

        /// The nonce from the server (Hex)
        #[arg(long)]
        nonce: String,

        /// Path to the client configuration file
        #[arg(long, default_value = "deyk_config.json")]
        config: String,
    },
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ClientConfig {
    pub k_s_pub: Option<String>,
}

impl ClientConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        if !path.as_ref().exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        let config = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}

fn get_token(pin: Option<String>) -> Result<Box<dyn YubiKeyToken>> {
    // Check for mock environment variables
    if let (Ok(ecdh_hex), Ok(sign_hex)) = (std::env::var("DEYK_MOCK_ECDH_PRIV"), std::env::var("DEYK_MOCK_SIGN_PRIV")) {
        println!("Using Mock YubiKey...");
        let ecdh_bytes = Hex::decode_to_vec(ecdh_hex, None).map_err(|_| anyhow::anyhow!("Invalid DEYK_MOCK_ECDH_PRIV hex"))?;
        let sign_bytes = Hex::decode_to_vec(sign_hex, None).map_err(|_| anyhow::anyhow!("Invalid DEYK_MOCK_SIGN_PRIV hex"))?;
        
        let ecdh_priv = SecretKey::from_slice(&ecdh_bytes).map_err(|_| anyhow::anyhow!("Invalid mock ECDH private key"))?;
        let sign_priv = SecretKey::from_slice(&sign_bytes).map_err(|_| anyhow::anyhow!("Invalid mock sign private key"))?;
        
        Ok(Box::new(yubikey::MockToken::new(ecdh_priv, sign_priv)))
    } else {
        println!("Connecting to Hardware YubiKey...");
        let pin = pin.context("Hardware YubiKey requires --pin <PIN>")?;
        Ok(Box::new(yubikey::HardwareToken::connect(pin)?))
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let pin = cli.pin.clone();

    match cli.command {
        Commands::Unwrap { c_yk, k_e_pub, set_k_s_pub, config } => {
            let mut client_config = ClientConfig::load(&config)?;
            
            if let Some(pub_key) = set_k_s_pub {
                client_config.k_s_pub = Some(pub_key);
                client_config.save(&config).context("Failed to save client configuration")?;
            }

            let c_yk_bytes = Hex::decode_to_vec(c_yk, None).map_err(|_| anyhow::anyhow!("Invalid c_yk hex"))?;
            let k_e_pub_bytes = Hex::decode_to_vec(k_e_pub, None).map_err(|_| anyhow::anyhow!("Invalid k_e_pub hex"))?;
            let k_e_pub_point = EncodedPoint::from_bytes(&k_e_pub_bytes).map_err(|_| anyhow::anyhow!("Invalid k_e_pub encoded point"))?;
            let k_e_pub = PublicKey::from_encoded_point(&k_e_pub_point).into_option().context("Invalid k_e_pub point")?;

            let mut token = get_token(pin)?;
            let dek = crypto::unwrap_dek(token.as_mut(), &c_yk_bytes, &k_e_pub)?;

            println!("DEK unwrapped successfully!");
            println!("{}", Hex::encode_to_string(dek).unwrap());
        }
        Commands::Wrap { dek, k_s_pub, nonce, config } => {
            let mut client_config = ClientConfig::load(&config)?;
            
            // Use k_s_pub from CLI if provided, otherwise use from config
            if let Some(pub_key) = k_s_pub {
                client_config.k_s_pub = Some(pub_key);
                client_config.save(&config).context("Failed to save client configuration")?;
            }

            let k_s_pub_hex = client_config.k_s_pub.as_ref()
                .context("Server public key (k_s_pub) not set. Please provide it using --k-s-pub <HEX>")?;
            
            let dek_bytes = Hex::decode_to_vec(dek, None).map_err(|_| anyhow::anyhow!("Invalid DEK hex"))?;
            if dek_bytes.len() != 32 {
                anyhow::bail!("Invalid DEK length: {} (expected 64 hex characters / 32 bytes)", dek_bytes.len() * 2);
            }
            let mut dek_array = [0u8; 32];
            dek_array.copy_from_slice(&dek_bytes);

            let k_s_pub_bytes = Hex::decode_to_vec(k_s_pub_hex, None).map_err(|_| anyhow::anyhow!("Invalid k_s_pub hex"))?;
            let k_s_pub_point = EncodedPoint::from_bytes(&k_s_pub_bytes).map_err(|_| anyhow::anyhow!("Invalid k_s_pub encoded point"))?;
            let k_s_pub = PublicKey::from_encoded_point(&k_s_pub_point).into_option().context("Invalid k_s_pub point")?;

            let nonce_bytes = Hex::decode_to_vec(nonce, None).map_err(|_| anyhow::anyhow!("Invalid nonce hex"))?;

            let mut token = get_token(pin)?;
            let (payload_enc, client_nonce) = crypto::wrap_transport(token.as_mut(), &dek_array, &k_s_pub, &nonce_bytes)?;

            println!("Transport wrap successful!");
            println!("Payload Hex: {}", Hex::encode_to_string(payload_enc).unwrap());
            println!("Client Nonce Hex: {}", client_nonce);
        }
    }

    Ok(())
}
