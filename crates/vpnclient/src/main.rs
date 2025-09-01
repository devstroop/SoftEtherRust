//! SoftEther VPN Client CLI Application

use anyhow::{Context, Result};
use clap::Parser;
use vpnclient::shared_config as shared_config;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use vpnclient::{VpnClient, DEFAULT_CONFIG_FILE};
use tokio::sync::mpsc;
use vpnclient::types::{ClientEvent, EventLevel, ClientState};

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
    /// Guarded by env var: set SOFTETHER_ALLOW_INSECURE=1 to enable this flag.
    #[arg(long, default_value_t = false)]
    insecure: bool,

    /// Redact interface snapshot (mask IP/DNS)
    #[arg(long, default_value_t = false)]
    redact_interface: bool,

    /// Verbose interface snapshot (more DNS entries, verbose=true flag)
    #[arg(long, default_value_t = false)]
    verbose_interface: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing - use standard RUST_LOG or fallback to CLI verbose flag
    let fallback = if cli.verbose { "debug" } else { "info" };
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(fallback));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_target(true).without_time())
        .try_init()
        .ok();
    // Third-party style log gating can be enabled via RUST_LOG

    // Single entrypoint: connect using the provided config
    connect(&cli).await
}

/// Connect to VPN server
async fn connect(cli: &Cli) -> Result<()> {
    let config_path = &cli.config;
    info!("Loading configuration from: {}", config_path);

    // Parse shared ClientConfig only (legacy format no longer supported here)
    let (cc_loaded, unknown) = shared_config::io::load_client_config_with_unknowns(config_path)
        .with_context(|| format!("Failed to load configuration from: {config_path}"))?;
    if !unknown.is_empty() {
        // Lightweight single-line warning (issue #010)
        tracing::warn!("Unknown config keys: {} (ignored)", unknown.join(","));
    }
    let mut cc = cc_loaded;
    // Optional override: --insecure only effective when allowed via env var
    let allow_insecure = std::env::var("SOFTETHER_ALLOW_INSECURE")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);
    if cli.insecure {
        if allow_insecure {
            info!("--insecure enabled for this run (overrides config)");
            cc.skip_tls_verify = true;
        } else {
            info!("--insecure ignored: set env SOFTETHER_ALLOW_INSECURE=1 to enable");
        }
    }
    // Snapshot redact/verbose config fields removed; CLI flags now ignored (future: runtime-only effects if reintroduced)
    let mut vpn_client = VpnClient::from_shared_config(cc)?;
    // Wire up event channel so interface_snapshot and metrics events are surfaced
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<ClientEvent>();
    vpn_client.set_event_channel(event_tx);
    tokio::spawn(async move {
        while let Some(ev) = event_rx.recv().await {
            match ev.level {
                EventLevel::Info => info!(code=ev.code, "{}", ev.message),
                EventLevel::Warn => tracing::warn!(code=ev.code, "{}", ev.message),
                EventLevel::Error => tracing::error!(code=ev.code, "{}", ev.message),
            }
        }
    });
    // Optional: state channel for external visibility (logs here too)
    let (state_tx, mut state_rx) = mpsc::unbounded_channel::<ClientState>();
    vpn_client.set_state_channel(state_tx);
    tokio::spawn(async move {
        while let Some(st) = state_rx.recv().await { info!(code=9999, "state_change {:?}", st); }
    });
    // Run like the classic vpnclient: connect and keep running until interrupted
    match vpn_client.run_until_interrupted().await {
        Ok(()) => {
            info!("VPN session ended");
            // Give a moment for logs to flush, then exit immediately
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            std::process::exit(0);
        }
        Err(e) => {
            error!("❌ VPN session error: {}", e);
            // Exit immediately on error too
            std::process::exit(1);
        }
    }
}
