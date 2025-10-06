//! Protocol constants and definitions matching C implementation

use mayaqua::error::Error;

/// HTTP MIME types for protocol negotiation
pub const MIME_OCTET_STREAM: &str = "application/octet-stream";
pub const MIME_TEXT_PLAIN: &str = "text/plain";
pub const MIME_SOFTETHER_VPN: &str = "application/x-softethervpn";

/// Cedar protocol signature (from Cedar.h)
pub const CEDAR_SIGNATURE_STR: &str = "SE-VPN4-PROTOCOL";

// Connection and retry timing (aligned with Protocol.h / C defaults)
pub const CONNECTING_TIMEOUT_MS: u32 = 15_000; // CONNECTING_TIMEOUT
pub const CONNECTING_TIMEOUT_AZURE_MS: u32 = 8_000; // CONNECTING_TIMEOUT_AZURE
pub const CONNECTING_POOLING_SPAN_MS: u32 = 3_000; // CONNECTING_POOLING_SPAN
pub const MIN_RETRY_INTERVAL_MS: u32 = 5_000; // MIN_RETRY_INTERVAL
pub const MAX_RETRY_INTERVAL_MS: u32 = 300_000; // MAX_RETRY_INTERVAL
pub const MAX_ADDITIONAL_CONNECTION_FAILED_COUNTER: u32 = 16;
pub const ADDITIONAL_CONNECTION_FAILED_COUNTER_RESET_MS: u32 = 60_000;

/// UDP Acceleration and NAT-T related constants (from UdpAccel.h)
pub const UDP_ACCELERATION_WINDOW_SIZE_MSEC: u32 = 30_000; // UDP_ACCELERATION_WINDOW_SIZE_MSEC
pub const UDP_ACCELERATION_KEEPALIVE_TIMEOUT: u32 = 9_000; // UDP_ACCELERATION_KEEPALIVE_TIMEOUT
pub const UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN: u32 = 1_000; // UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN
pub const UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX: u32 = 3_000; // UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX
pub const UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN_FAST: u32 = 500; // UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN_FAST
pub const UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX_FAST: u32 = 1_000; // UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX_FAST
pub const UDP_ACCELERATION_KEEPALIVE_TIMEOUT_FAST: u32 = 2_100; // UDP_ACCELERATION_KEEPALIVE_TIMEOUT_FAST
pub const UDP_ACCELERATION_COMMON_KEY_SIZE_V1: usize = 20; // UDP_ACCELERATION_COMMON_KEY_SIZE_V1
pub const UDP_ACCELERATION_COMMON_KEY_SIZE_V2: usize = 128; // UDP_ACCELERATION_COMMON_KEY_SIZE_V2
pub const UDP_ACCELERATION_MAX_PAYLOAD_SIZE: usize = 1600; // UDP_ACCELERATION_SUPPORTED_MAX_PAYLOAD_SIZE
pub const UDP_NAT_T_PORT_SIGNATURE_IN_KEEP_ALIVE: &str = "NATT_MY_PORT"; // UDP_NAT_T_PORT_SIGNATURE_IN_KEEP_ALIVE

/// Authentication types matching C implementation
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthType {
    Anonymous = 0,     // CLIENT_AUTHTYPE_ANONYMOUS
    Password = 1,      // CLIENT_AUTHTYPE_PASSWORD
    PlainPassword = 2, // CLIENT_AUTHTYPE_PLAIN_PASSWORD
    Certificate = 3,   // CLIENT_AUTHTYPE_CERT (user certificate)
    SecureDevice = 4,  // CLIENT_AUTHTYPE_SECURE_DEVICE
    Ticket = 99,       // Cluster ticket based redirection (non-standard client extension)
}

impl AuthType {
    pub fn from_u32(value: u32) -> Result<Self, Error> {
        match value {
            0 => Ok(AuthType::Anonymous),
            1 => Ok(AuthType::Password),
            2 => Ok(AuthType::PlainPassword),
            3 => Ok(AuthType::Certificate),
            4 => Ok(AuthType::SecureDevice),
            99 => Ok(AuthType::Ticket),
            _ => Err(Error::InvalidParameter),
        }
    }
}

/// Connection status values matching C implementation
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionStatus {
    Negotiation = 0, // CONNECTION_STATUS_NEGOTIATION
    UserAuth = 1,    // CONNECTION_STATUS_USERAUTH
    Established = 2, // CONNECTION_STATUS_ESTABLISHED
}

impl ConnectionStatus {
    pub fn from_u32(value: u32) -> Result<Self, Error> {
        match value {
            0 => Ok(ConnectionStatus::Negotiation),
            1 => Ok(ConnectionStatus::UserAuth),
            2 => Ok(ConnectionStatus::Established),
            _ => Err(Error::InvalidParameter),
        }
    }
}

/// Protocol types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProtocolType {
    Tcp = 0,
    Udp = 1,
}

/// Proxy types for client connections
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyType {
    Direct = 0, // Direct connection (no proxy)
    Http = 1,   // HTTP proxy
    Socks4 = 2, // SOCKS4 proxy
    Socks5 = 3, // SOCKS5 proxy
}

impl ProxyType {
    pub fn from_u32(value: u32) -> Result<Self, Error> {
        match value {
            0 => Ok(ProxyType::Direct),
            1 => Ok(ProxyType::Http),
            2 => Ok(ProxyType::Socks4),
            3 => Ok(ProxyType::Socks5),
            _ => Err(Error::InvalidParameter),
        }
    }
}

/// Session type flags
#[derive(Debug, Clone, Default)]
pub struct SessionFlags {
    pub local_host_session: bool,
    pub server_mode: bool,
    pub normal_client: bool,
    pub link_mode_client: bool,
    pub link_mode_server: bool,
    pub secure_nat_mode: bool,
    pub bridge_mode: bool,
    pub bridge_is_eth_loopback_block: bool,
    pub virtual_host: bool,
    pub l3_switch_mode: bool,
    pub in_proc_mode: bool,
}

/// UDP acceleration settings
#[derive(Debug, Clone, Default)]
pub struct UdpAccelSettings {
    pub use_udp_acceleration: bool,
    pub udp_acceleration_version: u32,
    pub use_hmac_on_udp_acceleration: bool,
    pub is_using_udp_acceleration: bool,
    pub udp_accel_mss: u32,
    pub udp_accel_fast_disconnect_detect: bool,
}

/// R-UDP (Reliable UDP) settings
#[derive(Debug, Clone, Default)]
pub struct RudpSettings {
    pub is_rudp_session: bool,
    pub rudp_mss: u32,
    pub enable_bulk_on_rudp: bool,
    pub bulk_on_rudp_version: u32,
    pub enable_hmac_on_bulk_of_rudp: bool,
    pub enable_udp_recovery: bool,
}

/// Protocol option flags
#[derive(Debug, Clone, Default)]
pub struct ProtocolOptions {
    pub use_encrypt: bool,
    pub use_fast_rc4: bool,
    pub use_compress: bool,
    pub half_connection: bool,
    pub qos: bool,
    pub no_send_signature: bool,
    pub no_routing_tracking: bool,
    pub disable_qos: bool,
    pub no_tls1: bool,
    pub no_udp_acceleration: bool,
}

/// SoftEther protocol commands (for RPC)
pub const CMD_LOGIN: &str = "Login";
pub const CMD_GET_SERVER_INFO: &str = "GetServerInfo";
pub const CMD_GET_SERVER_STATUS: &str = "GetServerStatus";
pub const CMD_CREATE_HUB: &str = "CreateHub";
pub const CMD_ENUM_HUB: &str = "EnumHub";
pub const CMD_DELETE_HUB: &str = "DeleteHub";
pub const CMD_GET_HUB_STATUS: &str = "GetHubStatus";
pub const CMD_SET_HUB_STATUS: &str = "SetHubStatus";

/// Common pack element names used in SoftEther protocol
pub const PACK_ELEMENT_METHOD: &str = "method";
pub const PACK_ELEMENT_ERR: &str = "err";
pub const PACK_ELEMENT_RET: &str = "ret";
pub const PACK_ELEMENT_USERNAME: &str = "username";
pub const PACK_ELEMENT_PASSWORD: &str = "password";
pub const PACK_ELEMENT_HUBNAME: &str = "hubname";
pub const PACK_ELEMENT_VERSION: &str = "version";
pub const PACK_ELEMENT_BUILD: &str = "build";
pub const PACK_ELEMENT_CLIENT_STR: &str = "client_str";
pub const PACK_ELEMENT_SERVER_STR: &str = "server_str";
pub const PACK_ELEMENT_PROTOCOL: &str = "protocol";
pub const PACK_ELEMENT_COMPRESSED: &str = "compressed";
pub const PACK_ELEMENT_MAX_CONNECTION: &str = "max_connection";
pub const PACK_ELEMENT_USE_ENCRYPT: &str = "use_encrypt";
pub const PACK_ELEMENT_USE_COMPRESS: &str = "use_compress";
pub const PACK_ELEMENT_HALF_CONNECTION: &str = "half_connection";
pub const PACK_ELEMENT_TIMEOUT: &str = "timeout";
pub const PACK_ELEMENT_QOS: &str = "qos";
pub const PACK_ELEMENT_CLIENT_IP: &str = "client_ip";
pub const PACK_ELEMENT_CLIENT_PORT: &str = "client_port";
pub const PACK_ELEMENT_SERVER_IP: &str = "server_ip";
pub const PACK_ELEMENT_SERVER_PORT: &str = "server_port";
pub const PACK_ELEMENT_CLIENT_HOST: &str = "client_host";
pub const PACK_ELEMENT_TICKET: &str = "ticket";
pub const PACK_ELEMENT_POLICY: &str = "policy";
pub const PACK_ELEMENT_SESSION_KEY: &str = "session_key";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_types() {
        assert_eq!(AuthType::Anonymous as u32, 0);
        assert_eq!(AuthType::Password as u32, 1);
        assert_eq!(AuthType::Certificate as u32, 3);
        assert_eq!(AuthType::Ticket as u32, 99);

        assert_eq!(AuthType::from_u32(0).unwrap(), AuthType::Anonymous);
        assert_eq!(AuthType::from_u32(1).unwrap(), AuthType::Password);
        assert_eq!(AuthType::from_u32(99).unwrap(), AuthType::Ticket);
    }

    #[test]
    fn test_connection_status() {
        assert_eq!(ConnectionStatus::Negotiation as u32, 0);
        assert_eq!(ConnectionStatus::UserAuth as u32, 1);
        assert_eq!(ConnectionStatus::Established as u32, 2);
    }

    #[test]
    fn test_proxy_types() {
        assert_eq!(ProxyType::Direct as u32, 0);
        assert_eq!(ProxyType::Http as u32, 1);
        assert_eq!(ProxyType::Socks5 as u32, 3);
    }
}
