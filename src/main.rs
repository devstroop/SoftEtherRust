//! SoftEther VPN Client CLI Application

use anyhow::{Context, Result};
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

    /// Disable TLS certificate verification (insecure). Overrides config for this run.
    /// Guarded by feature flag or env (SOFTETHER_VPNCLIENT_ALLOW_INSECURE=1).
    #[arg(long, default_value_t = false)]
    insecure: bool,
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

    // Single entrypoint: connect using the provided config
    connect(&cli.config, cli.insecure).await
}

/// Connect to VPN server
async fn connect(config_path: &str, insecure_flag: bool) -> Result<()> {
    info!("Loading configuration from: {}", config_path);

    // Parse shared ClientConfig only (legacy format no longer supported here)
    let cc: shared_config::ClientConfig = shared_config::io::load_json(config_path)
        .with_context(|| format!("Failed to load configuration from: {config_path}"))?;
    let mut cc = cc;
    // Optional override: --insecure only effective when allowed via feature or env
    let allow_insecure = cfg!(feature = "allow-insecure")
        || std::env::var("SOFTETHER_VPNCLIENT_ALLOW_INSECURE")
            .ok()
            .as_deref()
            == Some("1");
    if insecure_flag {
        if allow_insecure {
            info!("--insecure enabled for this run (overrides config)");
            cc.skip_tls_verify = true;
        } else {
            info!("--insecure ignored: enable feature 'allow-insecure' or set env SOFTETHER_VPNCLIENT_ALLOW_INSECURE=1");
        }
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
