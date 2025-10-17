//! SoftEther VPN Client Library

pub mod adapter_bridge;
mod adapter_bridge_packets;
mod auth;
pub mod config;
pub mod connection;
pub mod dhcp;
pub mod io;
pub mod links;
pub mod network;
pub mod network_config;
pub mod policy;
pub mod tunnel;
pub mod types;
pub mod vpnclient;

// Re-export main types
pub use config::VpnConfig;
pub use vpnclient::VpnClient;

// Client version constants - MUST match Zig to get proper server policies!
// Server applies different policies based on client identification
pub const CLIENT_VERSION: u32 = 444;
pub const CLIENT_BUILD: u32 = 9807;
pub const CLIENT_STRING: &str = "SoftEther VPN Client";

// Default configuration constants
pub const DEFAULT_CONFIG_FILE: &str = "config.json";
pub const DEFAULT_PORT: u16 = 443;
pub const DEFAULT_HUB: &str = "DEFAULT";
pub const DEFAULT_MAX_CONNECTIONS: u32 = 1;
pub const DEFAULT_TIMEOUT: u32 = 10000;

// Configuration error type
#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Json(String),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "IO error: {}", e),
            ConfigError::Json(e) => write!(f, "JSON error: {}", e),
            ConfigError::Invalid(msg) => write!(f, "Invalid configuration: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        ConfigError::Json(e.to_string())
    }
}

// Result type alias
pub type Result<T> = std::result::Result<T, ConfigError>;

// Shared config format (simple JSON format for CLI)
pub mod shared_config {
    use serde::{Deserialize, Serialize};

    /// Simple client configuration format (JSON)
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClientConfig {
        pub server: String,
        #[serde(default = "default_port")]
        pub port: u16,
        pub hub: String,
        pub username: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub password_hash: Option<String>,
        #[serde(default = "default_true")]
        pub use_compress: bool,
        #[serde(default = "default_true")]
        pub use_encrypt: bool,
        #[serde(default = "default_max_connections")]
        pub max_connections: u32,
        #[serde(default)]
        pub skip_tls_verify: bool,
        /// SecureNAT mode: when false (default), uses LocalBridge with L2 Ethernet frames.
        /// When true, uses SecureNAT with L3 IP packets (NAT traversal).
        #[serde(default)]
        pub secure_nat: bool,
        #[serde(default)]
        pub udp_acceleration: bool,
    }

    fn default_port() -> u16 {
        443
    }
    fn default_true() -> bool {
        true
    }
    fn default_max_connections() -> u32 {
        1
    }

    pub mod io {
        use super::*;
        use anyhow::Result;
        use std::path::Path;

        pub fn load_json<P: AsRef<Path>>(path: P) -> Result<ClientConfig> {
            let data = std::fs::read_to_string(path)?;
            let config: ClientConfig = serde_json::from_str(&data)?;
            Ok(config)
        }
    }
}
