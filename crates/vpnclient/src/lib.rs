//! SoftEther VPN Client
//!
//! A complete VPN client implementation in Rust that connects to SoftEther VPN servers
//! and establishes secure tunnels using virtual network adapters.

// Use external adapter crate to align with module separation
pub use adapter;
mod config;
pub mod dhcp;
pub mod network;
pub mod tunnel;
pub mod vpnclient; // internal-only legacy config used by vpnclient implementation
                   // Re-export legacy config type for CLI fallback parsing
pub use config::VpnConfig as LegacyVpnConfig;

pub use network::*;
pub use tunnel::*;
pub use vpnclient::*;

use mayaqua::Result;

/// Re-export commonly used types
pub use cedar::{
    AuthType, ClientAuth, ClientOption, Connection, Session, SessionConfig, SOFTETHER_BUILD,
    SOFTETHER_VER,
};

/// Client version information
pub const CLIENT_VERSION: u32 = 1000;
pub const CLIENT_BUILD: u32 = 1000;
pub const CLIENT_STRING: &str = "SoftEther VPN Client (Rust)";

/// Default configuration values
pub const DEFAULT_CONFIG_FILE: &str = "config.json";
pub const DEFAULT_PORT: u16 = 443;
pub const DEFAULT_HUB: &str = "DEFAULT";
pub const DEFAULT_MAX_CONNECTIONS: u32 = 2;
pub const DEFAULT_TIMEOUT: u32 = 30;

/// Client result type
pub type ClientResult<T> = Result<T>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(CLIENT_VERSION, 1000);
        assert_eq!(CLIENT_BUILD, 1000);
        assert!(!CLIENT_STRING.is_empty());
        assert_eq!(DEFAULT_PORT, 443);
        assert_eq!(DEFAULT_HUB, "DEFAULT");
    }
}
