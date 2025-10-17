//! Configuration management for SoftEther VPN client

use crate::{DEFAULT_HUB, DEFAULT_MAX_CONNECTIONS, DEFAULT_PORT};
use anyhow::{Context, Result};
use base64::prelude::*;
use cedar::AuthType;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// VPN client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    /// Server hostname or IP address
    pub host: String,

    /// Server port (default: 443)
    #[serde(default = "default_port")]
    pub port: u16,

    /// Virtual hub name (default: "DEFAULT")
    #[serde(default = "default_hub")]
    pub hub_name: String,

    /// Username for authentication
    pub username: String,

    /// Authentication configuration
    #[serde(flatten)]
    pub auth: AuthConfig,

    /// Connection options
    #[serde(default)]
    pub connection: ConnectionConfig,

    /// Client options
    #[serde(default)]
    pub client: ClientConfig,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "auth_type", rename_all = "snake_case")]
pub enum AuthConfig {
    /// Anonymous authentication
    Anonymous,

    /// Password authentication
    Password {
        /// Base64-encoded SHA1 hashed password
        hashed_password: String,
    },

    /// Certificate authentication
    Certificate {
        /// Path to certificate file
        cert_file: String,
        /// Path to private key file
        key_file: String,
    },

    /// Secure device authentication
    SecureDevice {
        /// Certificate name on the device
        cert_name: String,
        /// Key name on the device
        key_name: String,
    },
}

/// Connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// Maximum number of connections
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u32,

    /// Enable compression
    #[serde(default = "default_true")]
    pub use_compression: bool,

    /// Enable encryption
    #[serde(default = "default_true")]
    pub use_encryption: bool,

    /// Enable UDP acceleration (uses UDP ports 67/68 when enabled)
    #[serde(default)]
    pub udp_acceleration: bool,

    /// Skip TLS certificate verification (insecure)
    #[serde(default)]
    pub skip_tls_verify: bool,

    /// HTTP proxy configuration
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,

    /// Apply DNS servers provided by server (requires privileges)
    #[serde(default)]
    pub apply_dns: bool,

    /// Use HalfConnection mode to split directions across TCP links
    /// When enabled, the client hints the server to split send/receive directions.
    /// Default: false
    #[serde(default)]
    pub half_connection: bool,

    /// Optional client_id for servers that require a specific client build id
    #[serde(default)]
    pub client_id: Option<u32>,

    /// SecureNAT mode: when false (default), uses LocalBridge mode with L2 Ethernet frames.
    /// When true, uses SecureNAT mode with L3 IP packets (NAT traversal).
    /// Default: false (LocalBridge mode for better compatibility)
    #[serde(default)]
    pub secure_nat: bool,
}

/// HTTP proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Proxy hostname
    pub host: String,

    /// Proxy port
    pub port: u16,

    /// Proxy username (optional)
    pub username: Option<String>,

    /// Proxy password (optional)
    pub password: Option<String>,
}

/// Client-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Local adapter MAC address (optional, will be generated if not provided)
    pub adapter_mac: Option<String>,

    /// Interface name for the virtual adapter
    #[serde(default = "default_interface_name")]
    pub interface_name: String,

    /// macOS only: Network Service name to apply DNS to (e.g., "Wi-Fi", "Ethernet").
    /// If not set, DNS is not auto-applied unless we can deduce the service.
    #[serde(default)]
    pub macos_dns_service_name: Option<String>,

    /// Enable detailed logging
    #[serde(default)]
    pub verbose: bool,

    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// DHCP: initial settle delay before first DISCOVER (ms)
    #[serde(default = "default_dhcp_settle_ms")]
    pub dhcp_settle_ms: u64,

    /// DHCP: initial retry interval (ms)
    #[serde(default = "default_dhcp_initial_ms")]
    pub dhcp_initial_ms: u64,

    /// DHCP: maximum retry interval cap (ms)
    #[serde(default = "default_dhcp_max_ms")]
    pub dhcp_max_ms: u64,

    /// DHCP: jitter fraction applied to retry intervals (0.0..0.5)
    #[serde(default = "default_dhcp_jitter_pct")]
    pub dhcp_jitter_pct: f64,

    /// macOS: start system DHCP kick after this delay (ms); if 0, start immediately in parallel
    #[serde(default = "default_dhcp_fallback_after_ms")]
    pub dhcp_fallback_after_ms: u64,

    /// macOS: total duration to keep kicking DHCP (ms)
    #[serde(default = "default_dhcp_kick_timeout_ms")]
    pub dhcp_kick_timeout_ms: u64,
}

// Default value functions
fn default_port() -> u16 {
    DEFAULT_PORT
}
fn default_hub() -> String {
    DEFAULT_HUB.to_string()
}
fn default_max_connections() -> u32 {
    DEFAULT_MAX_CONNECTIONS
}
fn default_timeout() -> u32 {
    10000
}
fn default_true() -> bool {
    true
}
fn default_interface_name() -> String {
    "vpn0".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_dhcp_settle_ms() -> u64 {
    200
}
fn default_dhcp_initial_ms() -> u64 {
    800
}
fn default_dhcp_max_ms() -> u64 {
    8000
}
fn default_dhcp_jitter_pct() -> f64 {
    0.15
}
fn default_dhcp_fallback_after_ms() -> u64 {
    6000
}
fn default_dhcp_kick_timeout_ms() -> u64 {
    20000
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            timeout: default_timeout(),
            use_compression: true,
            use_encryption: true,
            udp_acceleration: false,
            skip_tls_verify: false,
            proxy: None,
            apply_dns: false,
            half_connection: false,
            client_id: None,
            secure_nat: false,
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            adapter_mac: None,
            interface_name: default_interface_name(),
            macos_dns_service_name: None,
            verbose: false,
            log_level: default_log_level(),
            dhcp_settle_ms: default_dhcp_settle_ms(),
            dhcp_initial_ms: default_dhcp_initial_ms(),
            dhcp_max_ms: default_dhcp_max_ms(),
            dhcp_jitter_pct: default_dhcp_jitter_pct(),
            dhcp_fallback_after_ms: default_dhcp_fallback_after_ms(),
            dhcp_kick_timeout_ms: default_dhcp_kick_timeout_ms(),
        }
    }
}

impl VpnConfig {
    /// Load configuration from a JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;

        let config: VpnConfig = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.as_ref().display()))?;

        config.validate()?;
        Ok(config)
    }

    /// Save configuration to a JSON file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize configuration")?;

        fs::write(&path, content)
            .with_context(|| format!("Failed to write config file: {}", path.as_ref().display()))?;

        Ok(())
    }

    /// Create a new configuration with password authentication
    pub fn new_password(
        host: String,
        port: u16,
        hub_name: String,
        username: String,
        hashed_password: String,
    ) -> Self {
        Self {
            host,
            port,
            hub_name,
            username,
            auth: AuthConfig::Password { hashed_password },
            connection: ConnectionConfig::default(),
            client: ClientConfig::default(),
        }
    }

    /// Create a new configuration with certificate authentication
    pub fn new_certificate(
        host: String,
        port: u16,
        hub_name: String,
        username: String,
        cert_file: String,
        key_file: String,
    ) -> Self {
        Self {
            host,
            port,
            hub_name,
            username,
            auth: AuthConfig::Certificate {
                cert_file,
                key_file,
            },
            connection: ConnectionConfig::default(),
            client: ClientConfig::default(),
        }
    }

    /// Create a new configuration with anonymous authentication
    pub fn new_anonymous(host: String, port: u16, hub_name: String) -> Self {
        Self {
            host,
            port,
            hub_name,
            username: "anonymous".to_string(),
            auth: AuthConfig::Anonymous,
            connection: ConnectionConfig::default(),
            client: ClientConfig::default(),
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.host.is_empty() {
            anyhow::bail!("Host cannot be empty");
        }

        if self.port == 0 {
            anyhow::bail!("Port cannot be zero");
        }

        if self.hub_name.is_empty() {
            anyhow::bail!("Hub name cannot be empty");
        }

        if self.username.is_empty() && !matches!(self.auth, AuthConfig::Anonymous) {
            anyhow::bail!("Username cannot be empty for non-anonymous authentication");
        }

        // Validate authentication configuration
        match &self.auth {
            AuthConfig::Password { hashed_password } => {
                if hashed_password.is_empty() {
                    anyhow::bail!("Hashed password cannot be empty");
                }

                // Validate base64 encoding and length
                let decoded = base64::prelude::BASE64_STANDARD
                    .decode(hashed_password)
                    .context("Invalid base64 encoding in hashed password")?;

                if decoded.len() != 20 {
                    anyhow::bail!("Hashed password must be exactly 20 bytes (SHA1)");
                }
            }
            AuthConfig::Certificate {
                cert_file,
                key_file,
            } => {
                if cert_file.is_empty() {
                    anyhow::bail!("Certificate file path cannot be empty");
                }
                if key_file.is_empty() {
                    anyhow::bail!("Key file path cannot be empty");
                }
            }
            AuthConfig::SecureDevice {
                cert_name,
                key_name,
            } => {
                if cert_name.is_empty() {
                    anyhow::bail!("Certificate name cannot be empty");
                }
                if key_name.is_empty() {
                    anyhow::bail!("Key name cannot be empty");
                }
            }
            AuthConfig::Anonymous => {
                // No additional validation needed
            }
        }

        // Validate connection configuration
        if self.connection.max_connections == 0 {
            anyhow::bail!("Max connections cannot be zero");
        }

        if self.connection.timeout == 0 {
            anyhow::bail!("Timeout cannot be zero");
        }

        Ok(())
    }

    /// Get the authentication type
    pub fn auth_type(&self) -> AuthType {
        match &self.auth {
            AuthConfig::Anonymous => AuthType::Anonymous,
            AuthConfig::Password { .. } => AuthType::Password,
            AuthConfig::Certificate { .. } => AuthType::Certificate,
            AuthConfig::SecureDevice { .. } => AuthType::SecureDevice,
        }
    }

    /// Get the server address as a string
    pub fn server_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_config_creation() {
        let config = VpnConfig::new_password(
            "test.com".to_string(),
            443,
            "TEST".to_string(),
            "user".to_string(),
            base64::prelude::BASE64_STANDARD.encode(b"12345678901234567890"), // 20 bytes
        );

        assert_eq!(config.host, "test.com");
        assert_eq!(config.port, 443);
        assert_eq!(config.hub_name, "TEST");
        assert_eq!(config.username, "user");
        assert_eq!(config.auth_type(), AuthType::Password);
    }

    #[test]
    fn test_config_validation() {
        let mut config = VpnConfig::new_password(
            "test.com".to_string(),
            443,
            "TEST".to_string(),
            "user".to_string(),
            base64::prelude::BASE64_STANDARD.encode(b"12345678901234567890"),
        );

        assert!(config.validate().is_ok());

        // Test empty host
        config.host = String::new();
        assert!(config.validate().is_err());

        // Test zero port
        config.host = "test.com".to_string();
        config.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_serialization() -> Result<()> {
        let config = VpnConfig::new_password(
            "test.com".to_string(),
            443,
            "TEST".to_string(),
            "user".to_string(),
            base64::prelude::BASE64_STANDARD.encode(b"12345678901234567890"),
        );

        let json = serde_json::to_string(&config)?;
        let deserialized: VpnConfig = serde_json::from_str(&json)?;

        assert_eq!(config.host, deserialized.host);
        assert_eq!(config.port, deserialized.port);
        assert_eq!(config.username, deserialized.username);

        Ok(())
    }

    #[test]
    fn test_config_file_operations() -> Result<()> {
        let config = VpnConfig::new_password(
            "test.com".to_string(),
            443,
            "TEST".to_string(),
            "user".to_string(),
            base64::prelude::BASE64_STANDARD.encode(b"12345678901234567890"),
        );

        let temp_file = NamedTempFile::new()?;
        config.to_file(temp_file.path())?;

        let loaded_config = VpnConfig::from_file(temp_file.path())?;
        assert_eq!(config.host, loaded_config.host);
        assert_eq!(config.port, loaded_config.port);

        Ok(())
    }

    #[test]
    fn test_anonymous_config() {
        let config = VpnConfig::new_anonymous("test.com".to_string(), 443, "TEST".to_string());

        assert_eq!(config.auth_type(), AuthType::Anonymous);
        assert!(config.validate().is_ok());
    }
}
