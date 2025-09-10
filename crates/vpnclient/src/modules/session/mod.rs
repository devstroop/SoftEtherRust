// Session management module - inspired by Go's session handling
// This consolidates session-related functionality

pub mod dhcp_session;
pub mod manager;

pub use dhcp_session::SessionWithDhcp;
pub use manager::SessionManager;

use crate::modules::dhcp::DhcpOptions;
use std::net::Ipv4Addr;

/// Session state tracking
#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Idle,
    Connecting,
    Authenticating,
    Established,
    DhcpRequesting,
    NetworkConfiguring,
    Active,
    Disconnecting,
    Error(String),
}

/// Session events for external monitoring
#[derive(Debug, Clone)]
pub enum SessionEvent {
    StateChanged(SessionState),
    DhcpCompleted(DhcpOptions),
    NetworkConfigured,
    Error(String),
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub hostname: String,
    pub mac_address: [u8; 6],
    pub auto_dhcp: bool,
    pub static_ip: Option<(Ipv4Addr, Ipv4Addr, Option<Ipv4Addr>)>, // IP, mask, gateway
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            hostname: "SoftEtherRust".to_string(),
            mac_address: [0x00, 0xac, 0xde, 0x12, 0x34, 0x56],
            auto_dhcp: true,
            static_ip: None,
        }
    }
}