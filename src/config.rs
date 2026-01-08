//! Configuration types for the SoftEther VPN client.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

/// VPN client configuration.
///
/// The configuration is organized into logical sections:
/// - **Server**: Server address, port, hub, and TLS settings
/// - **Authentication**: Username and password hash
/// - **Connection**: Timeout, max connections, and half-duplex mode
/// - **Session**: Protocol features (encryption, compression, UDP accel)
/// - **Tunnel**: MTU, routing, and static IP configuration
/// - **Options**: QoS, monitor mode, and other optional features
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VpnConfig {
    // ─────────────────────────────────────────────────────────────────────────
    // Server
    // ─────────────────────────────────────────────────────────────────────────
    /// VPN server hostname or IP address.
    pub server: String,

    /// Server port (default: 443).
    pub port: u16,

    /// Virtual Hub name.
    pub hub: String,

    /// Skip TLS certificate verification (default: true).
    /// Set to false to require valid server certificates.
    /// Most SoftEther servers use self-signed certificates.
    pub skip_tls_verify: bool,

    /// Custom CA certificate in PEM format (optional).
    /// When set, this CA is used to verify the server certificate instead of system roots.
    #[serde(default)]
    pub custom_ca_pem: Option<String>,

    /// Server certificate SHA-256 fingerprint for pinning (optional).
    /// Format: hex-encoded 64 characters (e.g., "a1b2c3...").
    /// When set, the server certificate must match this fingerprint exactly.
    #[serde(default)]
    pub cert_fingerprint_sha256: Option<String>,

    // ─────────────────────────────────────────────────────────────────────────
    // Authentication
    // ─────────────────────────────────────────────────────────────────────────
    /// Username for authentication.
    pub username: String,

    /// Pre-computed password hash (40-char hex string of SHA-0 hash).
    /// Generate using: vpnclient hash -u <username> -p <password>
    pub password_hash: String,

    // ─────────────────────────────────────────────────────────────────────────
    // Connection
    // ─────────────────────────────────────────────────────────────────────────
    /// Connection timeout in seconds (default: 30).
    pub timeout_seconds: u64,

    /// Maximum number of TCP connections (1-32, default: 1).
    /// Higher values can improve throughput but use more resources.
    pub max_connections: u8,

    /// Enable half-connection (half-duplex) mode (default: false).
    /// When true, each TCP connection is used for one direction only:
    /// - Requires max_connections >= 2 to function properly
    /// - Connection 1: client → server (upload)
    /// - Connection 2: server → client (download)
    /// When false (full-duplex), each connection handles both directions.
    pub half_connection: bool,

    // ─────────────────────────────────────────────────────────────────────────
    // Session
    // ─────────────────────────────────────────────────────────────────────────
    /// Use NAT traversal mode (default: false = bridge/routing mode).
    /// - false: Bridge mode - request bridge/routing permissions (L2 setups)
    /// - true: NAT mode - no bridge routing requested
    pub nat_traversal: bool,

    /// Enable tunnel data encryption (RC4, default: true).
    /// Encrypts VPN packets inside the TLS tunnel (defense in depth).
    pub use_encrypt: bool,

    /// Enable compression (default: false).
    /// Reduces bandwidth but increases CPU usage.
    pub use_compress: bool,

    /// Enable UDP acceleration (default: false).
    /// Uses UDP for data when possible (faster but may be blocked).
    pub udp_accel: bool,

    // ─────────────────────────────────────────────────────────────────────────
    // Tunnel
    // ─────────────────────────────────────────────────────────────────────────
    /// MTU size for the TUN device (default: 1400).
    /// Used for packet handling, not sent to server.
    pub mtu: u16,

    /// Routing configuration for VPN traffic.
    pub routing: RoutingConfig,

    /// Static IP configuration. When set, DHCP is skipped.
    #[serde(default)]
    pub static_ip: Option<StaticIpConfig>,

    // ─────────────────────────────────────────────────────────────────────────
    // Options
    // ─────────────────────────────────────────────────────────────────────────
    /// Enable VoIP/QoS prioritization (default: true).
    /// When enabled, VoIP packets get higher priority.
    pub qos: bool,

    /// Request monitor mode for packet capture (default: false).
    /// Requires special server permissions.
    pub monitor_mode: bool,
}

/// Routing configuration for VPN traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RoutingConfig {
    /// Set default route through VPN (all traffic, default: false).
    /// When true, all internet traffic goes through the VPN.
    pub default_route: bool,

    /// Accept routes pushed by server via DHCP (default: true).
    pub accept_pushed_routes: bool,

    /// IPv4 networks to include (CIDR format, e.g., "10.0.0.0/8").
    /// Traffic to these networks will go through the VPN.
    #[serde(default)]
    pub ipv4_include: Vec<String>,

    /// IPv4 networks to exclude (CIDR format, e.g., "192.168.1.0/24").
    /// Traffic to these networks will NOT go through the VPN.
    #[serde(default)]
    pub ipv4_exclude: Vec<String>,

    /// IPv6 networks to include (CIDR format).
    #[serde(default)]
    pub ipv6_include: Vec<String>,

    /// IPv6 networks to exclude (CIDR format).
    #[serde(default)]
    pub ipv6_exclude: Vec<String>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            default_route: false,
            accept_pushed_routes: true,
            ipv4_include: Vec::new(),
            ipv4_exclude: Vec::new(),
            ipv6_include: Vec::new(),
            ipv6_exclude: Vec::new(),
        }
    }
}

/// Static IP configuration for when DHCP is not used.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct StaticIpConfig {
    // ─────────────────────────────────────────────────────────────────────────
    // IPv4 Static Configuration
    // ─────────────────────────────────────────────────────────────────────────
    /// Static IPv4 address (e.g., "10.0.0.100").
    #[serde(default)]
    pub ipv4_address: Option<String>,

    /// IPv4 subnet mask (e.g., "255.255.255.0").
    #[serde(default)]
    pub ipv4_netmask: Option<String>,

    /// IPv4 gateway address (e.g., "10.0.0.1").
    #[serde(default)]
    pub ipv4_gateway: Option<String>,

    /// Primary IPv4 DNS server.
    #[serde(default)]
    pub ipv4_dns1: Option<String>,

    /// Secondary IPv4 DNS server.
    #[serde(default)]
    pub ipv4_dns2: Option<String>,

    // ─────────────────────────────────────────────────────────────────────────
    // IPv6 Static Configuration
    // ─────────────────────────────────────────────────────────────────────────
    /// Static IPv6 address (e.g., "2001:db8::1").
    #[serde(default)]
    pub ipv6_address: Option<String>,

    /// IPv6 prefix length (e.g., 64).
    #[serde(default)]
    pub ipv6_prefix_len: Option<u8>,

    /// IPv6 gateway address.
    #[serde(default)]
    pub ipv6_gateway: Option<String>,

    /// Primary IPv6 DNS server.
    #[serde(default)]
    pub ipv6_dns1: Option<String>,

    /// Secondary IPv6 DNS server.
    #[serde(default)]
    pub ipv6_dns2: Option<String>,
}

impl StaticIpConfig {
    /// Check if IPv4 static configuration is complete.
    pub fn has_ipv4(&self) -> bool {
        self.ipv4_address.is_some() && self.ipv4_netmask.is_some()
    }

    /// Check if IPv6 static configuration is complete.
    pub fn has_ipv6(&self) -> bool {
        self.ipv6_address.is_some() && self.ipv6_prefix_len.is_some()
    }

    /// Parse IPv4 address.
    pub fn parse_ipv4_address(&self) -> Option<Ipv4Addr> {
        self.ipv4_address.as_ref()?.parse().ok()
    }

    /// Parse IPv4 netmask.
    pub fn parse_ipv4_netmask(&self) -> Option<Ipv4Addr> {
        self.ipv4_netmask.as_ref()?.parse().ok()
    }

    /// Parse IPv4 gateway.
    pub fn parse_ipv4_gateway(&self) -> Option<Ipv4Addr> {
        self.ipv4_gateway.as_ref()?.parse().ok()
    }

    /// Parse IPv4 DNS1.
    pub fn parse_ipv4_dns1(&self) -> Option<Ipv4Addr> {
        self.ipv4_dns1.as_ref()?.parse().ok()
    }

    /// Parse IPv4 DNS2.
    pub fn parse_ipv4_dns2(&self) -> Option<Ipv4Addr> {
        self.ipv4_dns2.as_ref()?.parse().ok()
    }

    /// Parse IPv6 address.
    pub fn parse_ipv6_address(&self) -> Option<std::net::Ipv6Addr> {
        self.ipv6_address.as_ref()?.parse().ok()
    }

    /// Parse IPv6 gateway.
    pub fn parse_ipv6_gateway(&self) -> Option<std::net::Ipv6Addr> {
        self.ipv6_gateway.as_ref()?.parse().ok()
    }

    /// Parse IPv6 DNS1.
    pub fn parse_ipv6_dns1(&self) -> Option<std::net::Ipv6Addr> {
        self.ipv6_dns1.as_ref()?.parse().ok()
    }

    /// Parse IPv6 DNS2.
    pub fn parse_ipv6_dns2(&self) -> Option<std::net::Ipv6Addr> {
        self.ipv6_dns2.as_ref()?.parse().ok()
    }
}

impl RoutingConfig {
    /// Parse IPv4 CIDR strings into (Ipv4Addr, prefix_len) tuples.
    pub fn parse_ipv4_cidrs(cidrs: &[String]) -> Vec<(Ipv4Addr, u8)> {
        cidrs
            .iter()
            .filter_map(|cidr| Self::parse_ipv4_cidr(cidr))
            .collect()
    }

    /// Parse a single IPv4 CIDR string.
    fn parse_ipv4_cidr(cidr: &str) -> Option<(Ipv4Addr, u8)> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return None;
        }
        let ip: Ipv4Addr = parts[0].parse().ok()?;
        let prefix: u8 = parts[1].parse().ok()?;
        if prefix > 32 {
            return None;
        }
        Some((ip, prefix))
    }
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            // Server
            server: String::new(),
            port: 443,
            hub: String::new(),
            skip_tls_verify: false,
            custom_ca_pem: None,
            cert_fingerprint_sha256: None,
            // Authentication
            username: String::new(),
            password_hash: String::new(),
            // Connection
            timeout_seconds: 30,
            max_connections: 1,
            half_connection: false,
            // Session
            nat_traversal: false, // Bridge mode by default (common for L2 setups)
            use_encrypt: true,
            use_compress: false,
            udp_accel: false,
            // Tunnel
            mtu: 1400,
            routing: RoutingConfig::default(),
            static_ip: None,
            // Options
            qos: false,
            monitor_mode: false,
        }
    }
}

impl VpnConfig {
    /// Create a new configuration with required fields.
    pub fn new(server: String, hub: String, username: String, password_hash: String) -> Self {
        Self {
            server,
            hub,
            username,
            password_hash,
            ..Default::default()
        }
    }

    /// Load configuration from a JSON file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::Error::Config(format!("Failed to read config file: {e}")))?;
        Self::from_json(&content)
    }

    /// Parse configuration from JSON string.
    pub fn from_json(json: &str) -> crate::Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| crate::Error::Config(format!("Failed to parse config JSON: {e}")))
    }

    /// Serialize configuration to JSON.
    pub fn to_json(&self) -> crate::Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| crate::Error::Config(format!("Failed to serialize config: {e}")))
    }

    /// Save configuration to a JSON file.
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> crate::Result<()> {
        let json = self.to_json()?;
        std::fs::write(path, json)
            .map_err(|e| crate::Error::Config(format!("Failed to write config file: {e}")))
    }

    /// Get the connection timeout as a Duration.
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> crate::Result<()> {
        if self.server.is_empty() {
            return Err(crate::Error::Config("Server address is required".into()));
        }
        if self.hub.is_empty() {
            return Err(crate::Error::Config("Hub name is required".into()));
        }
        if self.username.is_empty() {
            return Err(crate::Error::Config("Username is required".into()));
        }
        if self.password_hash.is_empty() {
            return Err(crate::Error::Config(
                "Password hash is required. Generate with: vpnclient hash -u <username> -p <password>".into(),
            ));
        }
        if self.port == 0 {
            return Err(crate::Error::Config("Invalid port number".into()));
        }
        // Warn if half_connection is enabled but max_connections < 2
        if self.half_connection && self.max_connections < 2 {
            return Err(crate::Error::Config(
                "half_connection requires max_connections >= 2 (one connection per direction)"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Merge with environment variables.
    ///
    /// Environment variables take precedence over existing values.
    /// Supported variables:
    /// - SOFTETHER_SERVER
    /// - SOFTETHER_PORT
    /// - SOFTETHER_HUB
    /// - SOFTETHER_USER
    /// - SOFTETHER_PASSWORD_HASH
    pub fn merge_env(&mut self) {
        if let Ok(val) = std::env::var("SOFTETHER_SERVER") {
            self.server = val;
        }
        if let Ok(val) = std::env::var("SOFTETHER_PORT") {
            if let Ok(port) = val.parse() {
                self.port = port;
            }
        }
        if let Ok(val) = std::env::var("SOFTETHER_HUB") {
            self.hub = val;
        }
        if let Ok(val) = std::env::var("SOFTETHER_USER") {
            self.username = val;
        }
        if let Ok(val) = std::env::var("SOFTETHER_PASSWORD_HASH") {
            self.password_hash = val;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = VpnConfig::default();
        assert_eq!(config.port, 443);
        assert!(config.skip_tls_verify); // Default: skip TLS verify (self-signed)
        assert_eq!(config.timeout_seconds, 30);
    }

    #[test]
    fn test_config_validation() {
        let config = VpnConfig::default();
        assert!(config.validate().is_err());

        let config = VpnConfig::new(
            "vpn.example.com".into(),
            "VPN".into(),
            "user".into(),
            "0000000000000000000000000000000000000001".into(),
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_json_roundtrip() {
        let config = VpnConfig::new(
            "vpn.example.com".into(),
            "VPN".into(),
            "user".into(),
            "0000000000000000000000000000000000000001".into(),
        );
        let json = config.to_json().unwrap();
        let parsed = VpnConfig::from_json(&json).unwrap();
        assert_eq!(config.server, parsed.server);
        assert_eq!(config.hub, parsed.hub);
    }

    #[test]
    fn test_routing_config_default() {
        let routing = RoutingConfig::default();
        assert!(!routing.default_route);
        assert!(routing.accept_pushed_routes);
        assert!(routing.ipv4_include.is_empty());
        assert!(routing.ipv4_exclude.is_empty());
    }

    #[test]
    fn test_parse_ipv4_cidrs() {
        let cidrs = vec![
            "10.0.0.0/8".to_string(),
            "192.168.1.0/24".to_string(),
            "172.16.0.0/12".to_string(),
        ];
        let parsed = RoutingConfig::parse_ipv4_cidrs(&cidrs);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], (Ipv4Addr::new(10, 0, 0, 0), 8));
        assert_eq!(parsed[1], (Ipv4Addr::new(192, 168, 1, 0), 24));
        assert_eq!(parsed[2], (Ipv4Addr::new(172, 16, 0, 0), 12));
    }

    #[test]
    fn test_parse_ipv4_cidrs_invalid() {
        let cidrs = vec![
            "invalid".to_string(),
            "10.0.0.0".to_string(),    // missing prefix
            "10.0.0.0/33".to_string(), // prefix too large
            "10.0.0.0/8".to_string(),  // valid
        ];
        let parsed = RoutingConfig::parse_ipv4_cidrs(&cidrs);
        assert_eq!(parsed.len(), 1); // Only valid one
        assert_eq!(parsed[0], (Ipv4Addr::new(10, 0, 0, 0), 8));
    }

    #[test]
    fn test_routing_config_json() {
        let json = r#"{
            "server": "vpn.example.com",
            "hub": "VPN",
            "username": "user",
            "password_hash": "0000000000000000000000000000000000000001",
            "routing": {
                "default_route": true,
                "accept_pushed_routes": false,
                "ipv4_include": ["10.0.0.0/8"],
                "ipv4_exclude": ["192.168.1.0/24"]
            }
        }"#;
        let config = VpnConfig::from_json(json).unwrap();
        assert!(config.routing.default_route);
        assert!(!config.routing.accept_pushed_routes);
        assert_eq!(config.routing.ipv4_include.len(), 1);
        assert_eq!(config.routing.ipv4_exclude.len(), 1);
    }

    #[test]
    fn test_half_connection_validation() {
        // half_connection=false with max_connections=1 should be OK
        let mut config = VpnConfig::new(
            "vpn.example.com".into(),
            "VPN".into(),
            "user".into(),
            "0000000000000000000000000000000000000001".into(),
        );
        config.max_connections = 1;
        config.half_connection = false;
        assert!(config.validate().is_ok());

        // half_connection=true with max_connections=1 should fail
        config.half_connection = true;
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("half_connection requires max_connections >= 2"));

        // half_connection=true with max_connections=2 should be OK
        config.max_connections = 2;
        assert!(config.validate().is_ok());
    }
}
