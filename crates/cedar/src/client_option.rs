//! Client connection options matching C CLIENT_OPTION structure

use crate::constants::ProxyType;
use crate::{
    MAX_ACCOUNT_NAME_LEN, MAX_DEVICE_NAME_LEN, MAX_HOST_NAME_LEN, MAX_HUBNAME_LEN, SHA1_SIZE,
};
use mayaqua::{Error, Result};

/// Maximum lengths for proxy authentication
pub const MAX_PROXY_USERNAME_LEN: usize = 255;
pub const MAX_PROXY_PASSWORD_LEN: usize = 255;

/// Client connection options (matches CLIENT_OPTION structure)
#[derive(Debug, Clone)]
pub struct ClientOption {
    pub account_name: String,                // Connection setting name
    pub hostname: String,                    // Host name
    pub port: u16,                           // Port number
    pub port_udp: u16,                       // UDP port number (0: TCP only)
    pub proxy_type: ProxyType,               // Type of proxy
    pub proxy_name: String,                  // Proxy server name
    pub proxy_port: u16,                     // Port number of proxy server
    pub proxy_username: String,              // Proxy username
    pub proxy_password: String,              // Proxy password
    pub num_retry: u32,                      // Automatic retries
    pub retry_interval: u32,                 // Retry interval (seconds)
    pub hubname: String,                     // HUB name
    pub max_connection: u32,                 // Max concurrent TCP connections
    pub use_encrypt: bool,                   // Use encrypted communication
    pub use_compress: bool,                  // Use data compression
    pub half_connection: bool,               // Use half connection in TCP
    pub no_routing_tracking: bool,           // Disable routing tracking
    pub device_name: String,                 // VLAN device name
    pub additional_connection_interval: u32, // Additional connection interval
    pub connection_disconnect_span: u32,     // Disconnection interval
    pub hide_status_window: bool,            // Hide status window
    pub hide_nic_info_window: bool,          // Hide NIC info window
    pub require_monitor_mode: bool,          // Monitor port mode
    pub require_bridge_routing_mode: bool,   // Bridge or routing mode
    pub disable_qos: bool,                   // Disable VoIP/QoS function
    pub from_admin_pack: bool,               // For Administration Pack
    pub no_tls1: bool,                       // Do not use TLS 1.0
    pub no_udp_acceleration: bool,           // Do not use UDP acceleration
    pub host_unique_key: [u8; SHA1_SIZE],    // Host unique key
}

impl ClientOption {
    /// Create new client options with defaults
    pub fn new(hostname: &str, port: u16, hubname: &str) -> Result<Self> {
        if hostname.is_empty() || hostname.len() > MAX_HOST_NAME_LEN {
            return Err(Error::InvalidParameter);
        }
        if port == 0 {
            return Err(Error::InvalidParameter);
        }
        if hubname.is_empty() || hubname.len() > MAX_HUBNAME_LEN {
            return Err(Error::InvalidParameter);
        }

        Ok(Self {
            account_name: String::new(),
            hostname: hostname.to_string(),
            port,
            port_udp: 0, // TCP only by default
            proxy_type: ProxyType::Direct,
            proxy_name: String::new(),
            proxy_port: 8080,
            proxy_username: String::new(),
            proxy_password: String::new(),
            num_retry: 3,
            retry_interval: 15,
            hubname: hubname.to_string(),
            max_connection: 1,
            use_encrypt: true,
            use_compress: false,
            half_connection: false,
            no_routing_tracking: false,
            device_name: String::new(),
            additional_connection_interval: 1000,
            connection_disconnect_span: 12000,
            hide_status_window: false,
            hide_nic_info_window: false,
            require_monitor_mode: false,
            require_bridge_routing_mode: false,
            disable_qos: false,
            from_admin_pack: false,
            no_tls1: false,
            no_udp_acceleration: false,
            host_unique_key: [0u8; SHA1_SIZE],
        })
    }

    /// Set account name
    pub fn with_account_name(mut self, name: &str) -> Result<Self> {
        if name.len() > MAX_ACCOUNT_NAME_LEN {
            return Err(Error::InvalidParameter);
        }
        self.account_name = name.to_string();
        Ok(self)
    }

    /// Set device name for VLAN
    pub fn with_device_name(mut self, name: &str) -> Result<Self> {
        if name.len() > MAX_DEVICE_NAME_LEN {
            return Err(Error::InvalidParameter);
        }
        self.device_name = name.to_string();
        Ok(self)
    }

    /// Configure HTTP proxy
    pub fn with_http_proxy(
        mut self,
        proxy_host: &str,
        proxy_port: u16,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Self> {
        if proxy_host.len() > MAX_HOST_NAME_LEN {
            return Err(Error::InvalidParameter);
        }

        self.proxy_type = ProxyType::Http;
        self.proxy_name = proxy_host.to_string();
        self.proxy_port = proxy_port;

        if let Some(user) = username {
            if user.len() > MAX_PROXY_USERNAME_LEN {
                return Err(Error::InvalidParameter);
            }
            self.proxy_username = user.to_string();
        }

        if let Some(pass) = password {
            if pass.len() > MAX_PROXY_PASSWORD_LEN {
                return Err(Error::InvalidParameter);
            }
            self.proxy_password = pass.to_string();
        }

        Ok(self)
    }

    /// Configure SOCKS5 proxy
    pub fn with_socks5_proxy(
        mut self,
        proxy_host: &str,
        proxy_port: u16,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Self> {
        if proxy_host.len() > MAX_HOST_NAME_LEN {
            return Err(Error::InvalidParameter);
        }

        self.proxy_type = ProxyType::Socks5;
        self.proxy_name = proxy_host.to_string();
        self.proxy_port = proxy_port;

        if let Some(user) = username {
            if user.len() > MAX_PROXY_USERNAME_LEN {
                return Err(Error::InvalidParameter);
            }
            self.proxy_username = user.to_string();
        }

        if let Some(pass) = password {
            if pass.len() > MAX_PROXY_PASSWORD_LEN {
                return Err(Error::InvalidParameter);
            }
            self.proxy_password = pass.to_string();
        }

        Ok(self)
    }

    /// Enable UDP acceleration
    pub fn with_udp_acceleration(mut self, enable: bool) -> Self {
        self.no_udp_acceleration = !enable;
        if enable && self.port_udp == 0 {
            self.port_udp = self.port; // Use same port for UDP by default
        }
        self
    }

    /// Set compression
    pub fn with_compression(mut self, enable: bool) -> Self {
        self.use_compress = enable;
        self
    }

    /// Set encryption (always enabled by default for security)
    pub fn with_encryption(mut self, enable: bool) -> Self {
        self.use_encrypt = enable;
        self
    }

    /// Set maximum connections
    pub fn with_max_connections(mut self, max: u32) -> Self {
        self.max_connection = if max == 0 { 1 } else { max };
        self
    }

    /// Set retry configuration
    pub fn with_retry_config(mut self, num_retries: u32, interval_seconds: u32) -> Self {
        self.num_retry = num_retries;
        self.retry_interval = interval_seconds;
        self
    }

    /// Generate host unique key from hostname and other parameters
    pub fn generate_host_unique_key(&mut self) -> Result<()> {
        use sha1::{Digest, Sha1};

        let mut hasher = Sha1::new();
        hasher.update(self.hostname.as_bytes());
        hasher.update(&self.port.to_le_bytes());
        hasher.update(self.hubname.as_bytes());

        let result = hasher.finalize();
        self.host_unique_key.copy_from_slice(&result[..SHA1_SIZE]);

        Ok(())
    }

    /// Validate all parameters
    pub fn validate(&self) -> Result<()> {
        if self.hostname.is_empty() || self.hostname.len() > MAX_HOST_NAME_LEN {
            return Err(Error::InvalidParameter);
        }

        if self.port == 0 {
            return Err(Error::InvalidParameter);
        }

        if self.hubname.is_empty() || self.hubname.len() > MAX_HUBNAME_LEN {
            return Err(Error::InvalidParameter);
        }

        if self.account_name.len() > MAX_ACCOUNT_NAME_LEN {
            return Err(Error::InvalidParameter);
        }

        if self.device_name.len() > MAX_DEVICE_NAME_LEN {
            return Err(Error::InvalidParameter);
        }

        if self.max_connection == 0 {
            return Err(Error::InvalidParameter);
        }

        // Validate proxy settings
        if self.proxy_type != ProxyType::Direct {
            if self.proxy_name.is_empty() || self.proxy_name.len() > MAX_HOST_NAME_LEN {
                return Err(Error::InvalidParameter);
            }
            if self.proxy_port == 0 {
                return Err(Error::InvalidParameter);
            }
            if self.proxy_username.len() > MAX_PROXY_USERNAME_LEN {
                return Err(Error::InvalidParameter);
            }
            if self.proxy_password.len() > MAX_PROXY_PASSWORD_LEN {
                return Err(Error::InvalidParameter);
            }
        }

        Ok(())
    }

    /// Check if using proxy
    pub fn is_using_proxy(&self) -> bool {
        self.proxy_type != ProxyType::Direct
    }

    /// Check if UDP is enabled
    pub fn is_udp_enabled(&self) -> bool {
        self.port_udp != 0
    }

    /// Get effective port for UDP (falls back to TCP port)
    pub fn get_udp_port(&self) -> u16 {
        if self.port_udp != 0 {
            self.port_udp
        } else {
            self.port
        }
    }
}

impl Default for ClientOption {
    fn default() -> Self {
        // Create a default that will fail validation (forces explicit configuration)
        Self {
            account_name: String::new(),
            hostname: String::new(),
            port: 0,
            port_udp: 0,
            proxy_type: ProxyType::Direct,
            proxy_name: String::new(),
            proxy_port: 8080,
            proxy_username: String::new(),
            proxy_password: String::new(),
            num_retry: 3,
            retry_interval: 15,
            hubname: String::new(),
            max_connection: 1,
            use_encrypt: true,
            use_compress: false,
            half_connection: false,
            no_routing_tracking: false,
            device_name: String::new(),
            additional_connection_interval: 1000,
            connection_disconnect_span: 12000,
            hide_status_window: false,
            hide_nic_info_window: false,
            require_monitor_mode: false,
            require_bridge_routing_mode: false,
            disable_qos: false,
            from_admin_pack: false,
            no_tls1: false,
            no_udp_acceleration: false,
            host_unique_key: [0u8; SHA1_SIZE],
        }
    }
}
