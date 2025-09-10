//! Network mode detection for SoftEther VPN servers
//! 
//! Determines whether the server uses SecureNAT (SoftEther DHCP) or LocalBridge (external DHCP)
//! mode and adapts the client accordingly.

// Currently unused but will be used when the module is expanded

/// Network mode of the VPN server
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// SoftEther provides virtual DHCP/NAT server
    SecureNAT,
    /// External DHCP/NAT through physical network bridge
    LocalBridge,
    /// Mode could not be determined
    Unknown,
}

/// Simple wrapper for DHCP analysis results
#[derive(Debug, Clone)]
pub struct NetworkModeInfo {
    pub mode: NetworkMode,
    pub confidence: f32,
    pub details: String,
}

impl NetworkModeInfo {
    pub fn new(mode: NetworkMode, confidence: f32, details: String) -> Self {
        Self {
            mode,
            confidence,
            details,
        }
    }
}