//! SoftEther VPN Client CLI Application

use anyhow::{Context, Result};
use base64::Engine as _;
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use vpnclient::{shared_config, VpnClient, DEFAULT_CONFIG_FILE};

#[derive(Parser)]
#[command(name = "vpnclient")]
#[command(about = "SoftEther VPN Client (Rust)")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = DEFAULT_CONFIG_FILE)]
    config: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Generate password hash (usage: --gen-hash <username> <password>)
    #[arg(long)]
    gen_hash: bool,

    /// Username for hash generation
    #[arg(long, requires = "gen_hash")]
    username: Option<String>,

    /// Password for hash generation
    #[arg(long, requires = "gen_hash")]
    password: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing with env overrides
    // Priority: RUST_LOG (standard), then RUST_LOG_LEVEL (custom, e.g., "debug"), then --verbose flag
    let fallback = if cli.verbose { "debug" } else { "info" };
    let default_level = std::env::var("RUST_LOG_LEVEL").unwrap_or_else(|_| fallback.to_string());
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_level.clone()))
        .unwrap_or_else(|_| EnvFilter::new(fallback));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_target(true).without_time())
        .try_init()
        .ok();
    // Third-party style log gating can be enabled via RUST_LOG

    // Handle hash generation mode
    if cli.gen_hash {
        let username = cli.username.context("Username required for --gen-hash")?;
        let password = cli.password.context("Password required for --gen-hash")?;
        
        // Generate password hash using SoftEther method (SHA-0 of password + uppercase username)
        let hash = cedar::ClientAuth::hash_password_with_username(&password, &username);
        
        // Encode to base64 for storage
        let encoded_hash = base64::prelude::BASE64_STANDARD.encode(&hash);
        
        println!("✓ Password hash generated successfully");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Username: {}", username);
        println!("Password Hash (base64):");
        println!("{}", encoded_hash);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        println!("Add this to your config.json:");
        println!("  \"username\": \"{}\",", username);
        println!("  \"hashed_password\": \"{}\"\n", encoded_hash);
        println!("Example config:");
        println!("{{");
        println!("  \"host\": \"vpn.example.com\",");
        println!("  \"port\": 443,");
        println!("  \"hub_name\": \"VPN\",");
        println!("  \"username\": \"{}\",", username);
        println!("  \"auth\": {{");
        println!("    \"Password\": {{");
        println!("      \"hashed_password\": \"{}\"", encoded_hash);
        println!("    }}");
        println!("  }}");
        println!("}}");
        return Ok(());
    }

    // Single entrypoint: connect using the provided config
    connect(&cli.config).await
}

/// Connect to VPN server
async fn connect(config_path: &str) -> Result<()> {
    info!("Loading configuration from: {}", config_path);

    // Parse shared ClientConfig (skip_tls_verify is controlled by config file)
    let cc: shared_config::ClientConfig = shared_config::io::load_json(config_path)
        .with_context(|| format!("Failed to load configuration from: {config_path}"))?;
    
    // Show TLS verification status from config
    if cc.skip_tls_verify {
        info!("⚠️  TLS certificate verification is DISABLED (skip_tls_verify=true in config)");
    } else {
        info!("🔒 TLS certificate verification is ENABLED");
    }
    
    let mut vpn_client = VpnClient::from_shared_config(cc)?;
    // Run like the classic vpnclient: connect and keep running until interrupted
    match vpn_client.run_until_interrupted().await {
        Ok(()) => {
            info!("VPN session ended");
            if std::env::var("RUST_FORCE_EXIT_ON_CTRL_C").ok().as_deref() == Some("1") {
                // Give log a moment to flush then exit the process to avoid lingering background tasks
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                std::process::exit(0);
            }
            Ok(())
        }
        Err(e) => {
            error!("❌ VPN session error: {}", e);
            Err(e)
        }
    }
}
