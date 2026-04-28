mod config;
mod crypto;

use clap::{Parser, Subcommand};
use config::{ServerStateJson, ServerState};
use anyhow::{Result, Context};
use serde_json::json;
use p256::SecretKey;
use rand::{rngs::OsRng, RngCore};
use p256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};

#[derive(Parser)]
#[command(name = "deyk-server")]
#[command(about = "Device Encryption YubiKey Server", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Setup Phase A: Generate and encrypt DEK for a YubiKey
    Setup {
        /// Path to the JSON configuration file
        #[arg(long, default_value = "deyk_config.json")]
        config: String,

        /// Set or update the YubiKey ECDH public key (Hex)
        #[arg(long)]
        set_yubikey_ecdh_pub: Option<String>,

        /// Set or update the YubiKey Sign public key (Hex)
        #[arg(long)]
        set_yubikey_sign_pub: Option<String>,
    },
    /// Phase D: Server Verification and Unlock
    Unlock {
        /// Path to the JSON configuration file
        #[arg(long, default_value = "deyk_config.json")]
        config: String,

        /// The encrypted payload from the client (Hex)
        #[arg(long)]
        payload: String,
    },
    /// Get a fresh nonce from the server
    GetNonce {
        /// Path to the JSON configuration file
        #[arg(long, default_value = "deyk_config.json")]
        config: String,
    },
}

fn validate_yubikey_pub_length(hex_str: &str, name: &str) -> Result<()> {
    // Uncompressed P-256 is 65 bytes (130 hex chars), compressed is 33 bytes (66 hex chars)
    let len = hex_str.len();
    if len == 130 || len == 66 {
        Ok(())
    } else {
        anyhow::bail!("Invalid {} length: {} (expected 66 or 130 hex characters)", name, len)
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup { config, set_yubikey_ecdh_pub, set_yubikey_sign_pub } => {
            let mut json_state = ServerStateJson::load(&config)?;

            if let Some(pub_key) = set_yubikey_ecdh_pub {
                validate_yubikey_pub_length(&pub_key, "YubiKey ECDH public key")?;
                json_state.k_yk_ecdh_pub = Some(pub_key);
            }

            if let Some(sign_key) = set_yubikey_sign_pub {
                validate_yubikey_pub_length(&sign_key, "YubiKey sign public key")?;
                json_state.yubikey_sign_pub = Some(sign_key);
            }

            // Ensure YubiKey pubs are available
            let yk_pub_hex = json_state.k_yk_ecdh_pub.as_ref()
                .context("YubiKey ECDH public key not set. Please provide it using --set-yubikey-ecdh-pub <HEX>")?;
            let _yk_sign_hex = json_state.yubikey_sign_pub.as_ref()
                .context("YubiKey sign public key not set. Please provide it using --set-yubikey-sign-pub <HEX>")?;

            // Ensure server keypair exists
            if json_state.k_s_priv.is_none() {
                let sk = SecretKey::random(&mut OsRng);
                let pk = sk.public_key();
                json_state.k_s_priv = Some(hex::encode(sk.to_bytes()));
                json_state.k_s_pub = Some(hex::encode(pk.to_encoded_point(true).as_bytes()));
            }

            // Confirmation if overwriting existing DEK/c_yk
            if json_state.c_yk.is_some() {
                use dialoguer::Confirm;
                let confirmed = Confirm::new()
                    .with_prompt("A DEK and ciphertext (c_yk) already exist in the configuration. Overwriting will generate a NEW DEK and invalidate the old one. Do you want to continue?")
                    .default(false)
                    .interact()?;
                
                if !confirmed {
                    println!("Operation cancelled.");
                    return Ok(());
                }
            }

            // Load for crypto logic
            let yk_pub_bytes = hex::decode(yk_pub_hex)?;
            let yk_pub_point = p256::EncodedPoint::from_bytes(&yk_pub_bytes).map_err(|_| anyhow::anyhow!("Invalid YubiKey public key"))?;
            let k_yk_ecdh_pub = p256::PublicKey::from_encoded_point(&yk_pub_point).into_option().context("Invalid YubiKey public key point")?;

            // Generate c_yk and DEK
            let output = crypto::generate_c_yk(&k_yk_ecdh_pub)?;

            // Update JSON state for persistence
            json_state.c_yk = Some(hex::encode(&output.c_yk));
            json_state.k_e_pub = Some(hex::encode(output.k_e_pub.as_bytes()));
            
            // Save final state
            json_state.save(&config).context("Failed to save configuration")?;

            let result = json!({
                "status": "success",
                "plaintext_dek": hex::encode(output.dek),
                "config_file": config,
                "server_pub_key": json_state.k_s_pub
            });

            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Unlock { config, payload } => {
            let mut json_state = ServerStateJson::load(&config)?;
            
            // Extract nonce and clear it immediately in the persistent state
            let nonce_hex = json_state.nonce.take().context("No active nonce found. Please run 'get-nonce' command first.")?;
            json_state.save(&config).context("Failed to clear nonce in configuration")?;

            // Now parse the full state for logic
            let state = ServerState::parse(json_state)?;
            let nonce_bytes = hex::decode(nonce_hex)?;

            let dek = crypto::run_phase_d(
                &state.k_s_priv,
                &state.k_yk_ecdh_pub,
                &state.k_yk_sign_pub,
                &nonce_bytes,
                &payload
            )?;

            let result = json!({
                "status": "success",
                "dek": hex::encode(dek)
            });

            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::GetNonce { config } => {
            let mut json_state = ServerStateJson::load(&config)?;
            
            // Generate a secure 16-byte nonce
            let mut nonce_bytes = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce_hex = hex::encode(nonce_bytes);

            // Update and save
            json_state.nonce = Some(nonce_hex.clone());
            json_state.save(&config).context("Failed to save configuration with nonce")?;

            let result = json!({
                "status": "success",
                "nonce": nonce_hex
            });

            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }

    Ok(())
}
