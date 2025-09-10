// Modules - Clean architecture inspired by Go implementation
// This organizes the VPN client into focused, single-responsibility modules

pub mod auth;
pub mod dhcp;
pub mod network;
pub mod bridge;
pub mod session;
pub mod client;    // Modern VPN client implementation
pub mod legacy;    // Legacy compatibility wrapper

// Re-export key types for easier access
pub use dhcp::{DhcpClient, DhcpOptions, types::{Lease, LeaseV6, DhcpState, DhcpMetrics}};
pub use session::{SessionWithDhcp, SessionManager, SessionState, SessionEvent, SessionConfig};
pub use client::ModernVpnClient;
pub use legacy::VpnClient;

/// Module-level error type
#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    #[error("DHCP error: {0}")]
    Dhcp(String),
    
    #[error("Session error: {0}")]
    Session(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Authentication error: {0}")]
    Auth(String),
    
    #[error("Bridge error: {0}")]
    Bridge(String),
    
    #[error("Client error: {0}")]
    Client(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Parse error: {0}")]
    Parse(String),
    
    #[error("Timeout error: {0}")]
    Timeout(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Result type for module operations
pub type ModuleResult<T> = Result<T, ModuleError>;

/// Module initialization and configuration
pub struct ModuleConfig {
    pub enable_dhcp: bool,
    pub enable_dhcpv6: bool,
    pub adapter_is_l2: bool,
    pub hostname: String,
    pub mac_address: [u8; 6],
}

impl Default for ModuleConfig {
    fn default() -> Self {
        Self {
            enable_dhcp: true,
            enable_dhcpv6: false,
            adapter_is_l2: false, // Wintun is L3 by default
            hostname: "SoftEtherRust".to_string(),
            mac_address: [0x00, 0xac, 0xde, 0x12, 0x34, 0x56],
        }
    }
}