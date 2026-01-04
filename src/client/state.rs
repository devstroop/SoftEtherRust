//! VPN connection state machine.

/// VPN connection states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnState {
    /// Not connected.
    Disconnected,
    /// Connecting to server.
    Connecting,
    /// Performing HTTP handshake.
    Handshaking,
    /// Authenticating with server.
    Authenticating,
    /// Establishing tunnel.
    EstablishingTunnel,
    /// Performing DHCP.
    ConfiguringNetwork,
    /// Fully connected.
    Connected,
    /// Reconnecting after disconnect.
    Reconnecting,
    /// Connection error.
    Error(String),
}

impl VpnState {
    /// Check if currently connected.
    pub fn is_connected(&self) -> bool {
        matches!(self, VpnState::Connected)
    }

    /// Check if in an error state.
    pub fn is_error(&self) -> bool {
        matches!(self, VpnState::Error(_))
    }

    /// Check if transitioning (not idle).
    pub fn is_transitioning(&self) -> bool {
        matches!(
            self,
            VpnState::Connecting
                | VpnState::Handshaking
                | VpnState::Authenticating
                | VpnState::EstablishingTunnel
                | VpnState::ConfiguringNetwork
                | VpnState::Reconnecting
        )
    }
}

impl std::fmt::Display for VpnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VpnState::Disconnected => write!(f, "Disconnected"),
            VpnState::Connecting => write!(f, "Connecting"),
            VpnState::Handshaking => write!(f, "Handshaking"),
            VpnState::Authenticating => write!(f, "Authenticating"),
            VpnState::EstablishingTunnel => write!(f, "Establishing Tunnel"),
            VpnState::ConfiguringNetwork => write!(f, "Configuring Network"),
            VpnState::Connected => write!(f, "Connected"),
            VpnState::Reconnecting => write!(f, "Reconnecting"),
            VpnState::Error(e) => write!(f, "Error: {e}"),
        }
    }
}
