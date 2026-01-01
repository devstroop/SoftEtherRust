//! SoftEther VPN Client - Command Line Interface
//!
//! A high-performance SoftEther VPN client written in Rust.

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use tracing::{error, info, warn, Level};
use tracing_subscriber::fmt::format::FmtSpan;

use softether_rust::{crypto, VpnClient, VpnConfig};

#[derive(Parser)]
#[command(name = "softether-rust")]
#[command(author = "SoftEther Rust Team")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "A high-performance SoftEther VPN client", long_about = None)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Enable debug output
    #[arg(short, long)]
    debug: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to a VPN server
    Connect {
        /// Server hostname or IP address
        #[arg(short, long)]
        server: Option<String>,

        /// Server port
        #[arg(short, long, default_value = "443")]
        port: Option<u16>,

        /// Hub name
        #[arg(short = 'H', long)]
        hub: Option<String>,

        /// Username
        #[arg(short, long)]
        username: Option<String>,

        /// Password hash (hex-encoded, generate with 'hash' command)
        #[arg(long)]
        password_hash: Option<String>,

        /// Disable TLS (for testing only, not recommended)
        #[arg(long)]
        no_tls: bool,

        /// Verify TLS certificate (default: skip verification)
        #[arg(long)]
        verify_tls: bool,
    },

    /// Generate password hash for authentication
    Hash {
        /// Username (required for hash computation)
        #[arg(short, long)]
        username: String,

        /// Password (will prompt securely if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Disconnect from the VPN
    Disconnect,

    /// Show connection status
    Status,

    /// Generate a sample configuration file
    GenConfig {
        /// Output file path
        #[arg(short, long, default_value = "config.json")]
        output: PathBuf,
    },
}

fn init_logging(verbose: bool, debug: bool) {
    let level = if debug {
        Level::DEBUG
    } else if verbose {
        Level::INFO
    } else {
        Level::WARN
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .init();
}

fn load_config(path: Option<&PathBuf>) -> Result<Option<VpnConfig>, Box<dyn std::error::Error>> {
    if let Some(path) = path {
        let content = std::fs::read_to_string(path)?;
        let config: VpnConfig = serde_json::from_str(&content)?;
        Ok(Some(config))
    } else {
        Ok(None)
    }
}

fn prompt_password() -> String {
    rpassword::prompt_password("Password: ").unwrap_or_default()
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_logging(cli.verbose, cli.debug);

    if let Err(e) = run(cli).await {
        error!("Error: {}", e);
        process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Load config file if provided
    let file_config = load_config(cli.config.as_ref())?;

    match cli.command {
        Commands::Hash { username, password } => {
            // Get password (prompt if not provided)
            let password = password.unwrap_or_else(prompt_password);
            
            if password.is_empty() {
                return Err("Password cannot be empty".into());
            }

            // Compute hash
            let hash = crypto::hash_password(&password, &username);
            let hash_hex = hex::encode(hash);

            println!("Password hash for user '{}':", username);
            println!("{}", hash_hex);
            println!();
            println!("Add this to your config.json:");
            println!("  \"password_hash\": \"{}\"", hash_hex);
        }

        Commands::Connect {
            server,
            port,
            hub,
            username,
            password_hash,
            no_tls,
            verify_tls,
        } => {
            // Build config from file and/or command line args
            let config = if let Some(mut config) = file_config {
                // Override with command line args
                if let Some(s) = server {
                    config.server = s;
                }
                if let Some(p) = port {
                    config.port = p;
                }
                if let Some(h) = hub {
                    config.hub = h;
                }
                if let Some(u) = username {
                    config.username = u;
                }
                if let Some(h) = password_hash {
                    // Validate it's valid hex
                    let bytes = hex::decode(&h).map_err(|e| format!("Invalid password hash (must be 40 hex chars): {}", e))?;
                    if bytes.len() != 20 {
                        return Err(format!("Password hash must be 20 bytes (40 hex chars), got {} bytes", bytes.len()).into());
                    }
                    config.password_hash = h;
                }
                if verify_tls {
                    config.skip_tls_verify = false;
                }
                config
            } else {
                // Require server, hub, username, and password_hash from command line
                let server = server.ok_or("Server address is required (use -s or config file)")?;
                let hub = hub.ok_or("Hub name is required (use -H or config file)")?;
                let username = username.ok_or("Username is required (use -u or config file)")?;
                let password_hash_str = password_hash.ok_or(
                    "Password hash is required (use --password-hash or config file). Generate with: vpnclient hash -u <username>"
                )?;
                // Validate it's valid hex
                let password_hash_bytes = hex::decode(&password_hash_str)
                    .map_err(|e| format!("Invalid password hash (must be 40 hex chars): {}", e))?;
                if password_hash_bytes.len() != 20 {
                    return Err(format!("Password hash must be 20 bytes (40 hex chars), got {} bytes", password_hash_bytes.len()).into());
                }

                VpnConfig {
                    server,
                    port: port.unwrap_or(443),
                    hub,
                    username,
                    password_hash: password_hash_str,
                    skip_tls_verify: !verify_tls,
                    ..Default::default()
                }
            };

            // Warn if --no-tls is used (SoftEther requires TLS)
            if no_tls {
                warn!("--no-tls flag is ignored. SoftEther protocol requires TLS/HTTPS.");
            }

            // Validate config
            config.validate()?;

            info!("Connecting to {}:{}", config.server, config.port);
            info!("Hub: {}, Username: {}", config.hub, config.username);

            let mut client = VpnClient::new(config);
            
            match client.connect().await {
                Ok(()) => {
                    info!("Disconnected");
                }
                Err(e) => {
                    error!("Connection failed: {}", e);
                    return Err(e.into());
                }
            }
        }

        Commands::Disconnect => {
            info!("Disconnect command - not implemented yet (requires daemon mode)");
        }

        Commands::Status => {
            info!("Status command - not implemented yet (requires daemon mode)");
        }

        Commands::GenConfig { output } => {
            let sample_config = VpnConfig {
                server: "vpn.example.com".to_string(),
                port: 443,
                hub: "VPN".to_string(),
                username: "your_username".to_string(),
                password_hash: "0000000000000000000000000000000000000000".to_string(), // Generate with: vpnclient hash -u your_username
                ..Default::default()
            };

            let json = serde_json::to_string_pretty(&sample_config)?;
            std::fs::write(&output, json)?;
            println!("Sample configuration written to {:?}", output);
            println!();
            println!("To generate your password hash, run:");
            println!("  vpnclient hash -u your_username -p your_password");
        }
    }

    Ok(())
}
