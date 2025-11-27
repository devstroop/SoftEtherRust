//! C-compatible configuration structs for FFI
//!
//! These types provide a stable, version-safe interface for passing configuration
//! across the FFI boundary without JSON serialization overhead.

use std::ffi::CStr;
use std::os::raw::c_char;
use vpnclient::shared_config::{ClientConfig, ClientOptions};

/// C-compatible VPN configuration struct
/// 
/// All strings must be null-terminated UTF-8 C strings.
/// Use default values for optional fields (see constructor functions).
#[repr(C)]
pub struct SoftEtherConfig {
    /// Server hostname or IP (null-terminated C string)
    pub host: *const c_char,
    
    /// Server port (default: 443)
    pub port: u16,
    
    /// Virtual hub name (null-terminated C string)
    pub hub_name: *const c_char,
    
    /// Username (null-terminated C string)
    pub username: *const c_char,
    
    /// Pre-hashed password in base64 (null-terminated C string)
    /// Format: SHA-0 hash encoded as base64
    pub hashed_password: *const c_char,
    
    /// Connection configuration
    pub connection: SoftEtherConnectionConfig,
    
    /// Client configuration  
    pub client: SoftEtherClientConfig,
}

/// C-compatible connection configuration
#[repr(C)]
pub struct SoftEtherConnectionConfig {
    /// Maximum number of parallel TCP connections (default: 1)
    pub max_connections: u32,
    
    /// Connection timeout in milliseconds (default: 10000)
    pub timeout_ms: u32,
    
    /// Enable compression (default: false)
    pub use_compression: bool,
    
    /// Enable encryption (default: true) 
    pub use_encryption: bool,
    
    /// Enable UDP acceleration (default: false)
    pub udp_acceleration: bool,
    
    /// Skip TLS certificate verification (INSECURE, default: false)
    pub skip_tls_verify: bool,
    
    /// Apply DNS settings from server (default: false)
    pub apply_dns: bool,
    
    /// Use half-connection mode (default: false)
    pub half_connection: bool,
    
    /// Use SecureNAT mode instead of LocalBridge (default: false)
    pub secure_nat: bool,
}

/// C-compatible client configuration
#[repr(C)]
pub struct SoftEtherClientConfig {
    /// Enable verbose logging (default: false)
    pub verbose: bool,
    
    /// Log level: 0=error, 1=warn, 2=info, 3=debug, 4=trace (default: 2)
    pub log_level: u32,
}

impl SoftEtherConfig {
    /// Convert C struct to Rust ClientConfig (shared_config format)
    /// 
    /// # Safety
    /// All string pointers must point to valid null-terminated UTF-8 strings
    pub unsafe fn to_client_config(&self) -> Result<ClientConfig, String> {
        let server = if self.host.is_null() {
            return Err("host is null".to_string());
        } else {
            CStr::from_ptr(self.host)
                .to_str()
                .map_err(|e| format!("Invalid UTF-8 in host: {}", e))?
                .to_string()
        };
        
        let hub = if self.hub_name.is_null() {
            "DEFAULT".to_string()
        } else {
            CStr::from_ptr(self.hub_name)
                .to_str()
                .map_err(|e| format!("Invalid UTF-8 in hub_name: {}", e))?
                .to_string()
        };
        
        let username = if self.username.is_null() {
            return Err("username is null".to_string());
        } else {
            CStr::from_ptr(self.username)
                .to_str()
                .map_err(|e| format!("Invalid UTF-8 in username: {}", e))?
                .to_string()
        };
        
        let password_hash = if self.hashed_password.is_null() {
            return Err("hashed_password is null".to_string());
        } else {
            CStr::from_ptr(self.hashed_password)
                .to_str()
                .map_err(|e| format!("Invalid UTF-8 in hashed_password: {}", e))?
                .to_string()
        };
        
        Ok(ClientConfig {
            server,
            port: if self.port == 0 { 443 } else { self.port },
            hub,
            username,
            password: None,
            password_hash: Some(password_hash),
            use_compress: self.connection.use_compression,
            use_encrypt: self.connection.use_encryption,
            max_connections: if self.connection.max_connections == 0 { 1 } else { self.connection.max_connections },
            skip_tls_verify: self.connection.skip_tls_verify,
            secure_nat: self.connection.secure_nat,
            udp_acceleration: self.connection.udp_acceleration,
            client: ClientOptions {
                static_ipv4: None,
                static_ipv4_gateway: None,
                dhcp_timeout_secs: 20,
            },
        })
    }
}

/// Create default connection config
/// 
/// Call this from Swift to get sensible defaults, then override fields as needed.
#[no_mangle]
pub extern "C" fn softether_config_connection_default() -> SoftEtherConnectionConfig {
    SoftEtherConnectionConfig {
        max_connections: 1,
        timeout_ms: 10000,
        use_compression: false,
        use_encryption: true,
        udp_acceleration: false,
        skip_tls_verify: false,
        apply_dns: false,
        half_connection: false,
        secure_nat: false,
    }
}

/// Create default client config
#[no_mangle]
pub extern "C" fn softether_config_client_default() -> SoftEtherClientConfig {
    SoftEtherClientConfig {
        verbose: false,
        log_level: 2, // info
    }
}
