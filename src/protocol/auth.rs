//! Authentication protocol for SoftEther.

use super::constants::*;
use super::pack::Pack;
use crate::crypto::{self, Rc4KeyPair, RC4_KEY_SIZE, SHA0_DIGEST_LEN};
use crate::error::{Error, Result};
use crate::net::{
    UdpAccelAuthParams, UdpAccelServerResponse, UDP_ACCELERATION_COMMON_KEY_SIZE_V1,
    UDP_ACCELERATION_COMMON_KEY_SIZE_V2,
};
use bytes::Bytes;
use std::net::IpAddr;

/// Authentication types supported by SoftEther.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthType {
    Anonymous = 0,
    Password = 1,
    PlainPassword = 2,
    SecurePassword = 3,
    Certificate = 4,
    Ticket = 99,
}

/// Parsed Hello response from server.
#[derive(Debug, Clone)]
pub struct HelloResponse {
    /// Server random challenge (20 bytes).
    pub random: [u8; SHA0_DIGEST_LEN],
    /// Server version.
    pub server_version: u32,
    /// Server build number.
    pub server_build: u32,
    /// Server identification string.
    pub server_string: String,
    /// Whether server supports secure password.
    pub use_secure_password: bool,
    /// Whether server supports plain password.
    pub use_plain_password: bool,
}

impl HelloResponse {
    /// Parse a Hello response from a Pack.
    pub fn from_pack(pack: &Pack) -> Result<Self> {
        // Check for error
        if let Some(error) = pack.get_int("error") {
            if error != 0 {
                return Err(Error::server(error, format!("Server error: {error}")));
            }
        }

        // Get random challenge
        let random_data = pack
            .get_data("random")
            .ok_or_else(|| Error::invalid_response("Missing 'random' field in Hello response"))?;

        if random_data.len() != SHA0_DIGEST_LEN {
            return Err(Error::invalid_response(format!(
                "Invalid random length: expected {}, got {}",
                SHA0_DIGEST_LEN,
                random_data.len()
            )));
        }

        let mut random = [0u8; SHA0_DIGEST_LEN];
        random.copy_from_slice(random_data);

        Ok(Self {
            random,
            server_version: pack.get_int("version").unwrap_or(0),
            server_build: pack.get_int("build").unwrap_or(0),
            server_string: pack.get_str("hello").unwrap_or("").to_string(),
            use_secure_password: pack.get_int("use_secure_password").unwrap_or(0) != 0,
            use_plain_password: pack.get_int("use_plain_password").unwrap_or(1) != 0,
        })
    }
}

/// Authentication result from server.
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// Whether authentication succeeded.
    pub success: bool,
    /// Error code (0 = success).
    pub error: u32,
    /// Error message if any.
    pub error_message: Option<String>,
    /// Session key for established session.
    pub session_key: Bytes,
    /// Redirect information for cluster setup.
    pub redirect: Option<RedirectInfo>,
    /// Connection direction for half-connection mode (0=both, 1=c2s, 2=s2c).
    pub direction: u32,
    /// RC4 key pair for defense-in-depth encryption (if server provides keys).
    /// Note: TLS encryption is ALWAYS active regardless of this.
    pub rc4_key_pair: Option<Rc4KeyPair>,
    /// Legacy flag: true when RC4 keys not present.
    /// Note: TLS is ALWAYS used regardless of this flag.
    pub use_ssl_data_encryption: bool,
    /// UDP acceleration server response (if server supports it).
    pub udp_accel_response: Option<UdpAccelServerResponse>,
}

/// Redirect information for cluster server setup.
#[derive(Debug, Clone)]
pub struct RedirectInfo {
    /// Redirect server IP address (host byte order).
    pub ip: u32,
    /// Redirect server port.
    pub port: u16,
    /// Authentication ticket (20 bytes).
    pub ticket: [u8; SHA0_DIGEST_LEN],
}

impl RedirectInfo {
    /// Get the IP address as a dotted string.
    pub fn ip_string(&self) -> String {
        // IP is stored in little-endian format in Pack
        let bytes = self.ip.to_le_bytes();
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

impl AuthResult {
    /// Parse an authentication result from a Pack.
    pub fn from_pack(pack: &Pack) -> Result<Self> {
        Self::from_pack_with_remote(pack, None)
    }

    /// Parse an authentication result from a Pack with optional remote IP for UDP accel.
    pub fn from_pack_with_remote(pack: &Pack, remote_ip: Option<IpAddr>) -> Result<Self> {
        let error = pack.get_int("error").unwrap_or(0);

        if error != 0 {
            let error_message = pack.get_str("error_str").map(|s| s.to_string());
            return Ok(Self {
                success: false,
                error,
                error_message,
                session_key: Bytes::new(),
                redirect: None,
                direction: 0,
                rc4_key_pair: None,
                use_ssl_data_encryption: false,
                udp_accel_response: None,
            });
        }

        // Check for redirect (use lowercase keys since Pack stores them lowercase)
        let redirect_flag = pack.get_int("redirect").unwrap_or(0);
        if redirect_flag != 0 {
            let ip = pack.get_int("ip").unwrap_or(0);
            let port = pack.get_int("port").unwrap_or(443) as u16;

            let mut ticket = [0u8; SHA0_DIGEST_LEN];
            if let Some(ticket_data) = pack.get_data("ticket") {
                let copy_len = ticket_data.len().min(SHA0_DIGEST_LEN);
                ticket[..copy_len].copy_from_slice(&ticket_data[..copy_len]);
            }

            return Ok(Self {
                success: true,
                error: 0,
                error_message: None,
                session_key: Bytes::new(),
                redirect: Some(RedirectInfo { ip, port, ticket }),
                direction: 0,
                rc4_key_pair: None,
                use_ssl_data_encryption: false,
                udp_accel_response: None,
            });
        }

        // Parse direction for half-connection mode (0=both, 1=c2s, 2=s2c)
        let direction = pack.get_int("direction").unwrap_or(0);

        // Parse RC4 key pair for tunnel encryption (UseFastRC4 mode)
        // Server sends these in the Welcome packet if encryption is enabled
        let rc4_key_pair = Self::parse_rc4_keys(pack);

        // RC4 defense-in-depth mode:
        // - If RC4 keys present -> RC4 encryption applied inside TLS tunnel
        // - If no RC4 keys -> TLS-only (TLS encryption is ALWAYS active regardless)
        // Note: use_ssl_data_encryption is a legacy flag, TLS is always used.
        let use_ssl_data_encryption = rc4_key_pair.is_none();

        // Parse UDP acceleration response if server supports it
        let udp_accel_response = remote_ip.and_then(|ip| Self::parse_udp_accel_response(pack, ip));

        Ok(Self {
            success: true,
            error: 0,
            error_message: None,
            session_key: pack.get_data("session_key").cloned().unwrap_or_default(),
            redirect: None,
            direction,
            rc4_key_pair,
            use_ssl_data_encryption,
            udp_accel_response,
        })
    }

    /// Parse RC4 key pair from server response.
    ///
    /// Server sends `rc4_key_client_to_server` and `rc4_key_server_to_client` (16 bytes each)
    /// when UseFastRC4 mode is enabled.
    fn parse_rc4_keys(pack: &Pack) -> Option<Rc4KeyPair> {
        let c2s_key = pack.get_data("rc4_key_client_to_server")?;
        let s2c_key = pack.get_data("rc4_key_server_to_client")?;

        if c2s_key.len() != RC4_KEY_SIZE || s2c_key.len() != RC4_KEY_SIZE {
            tracing::warn!(
                "Invalid RC4 key sizes: c2s={}, s2c={} (expected {})",
                c2s_key.len(),
                s2c_key.len(),
                RC4_KEY_SIZE
            );
            return None;
        }

        let mut client_to_server = [0u8; RC4_KEY_SIZE];
        let mut server_to_client = [0u8; RC4_KEY_SIZE];
        client_to_server.copy_from_slice(c2s_key);
        server_to_client.copy_from_slice(s2c_key);

        tracing::debug!("Parsed RC4 key pair from server response (UseFastRC4 mode)");
        Some(Rc4KeyPair::new(client_to_server, server_to_client))
    }

    /// Parse UDP acceleration response from the server's auth result Pack.
    ///
    /// This should be called after successful authentication to extract UDP accel params.
    pub fn parse_udp_accel_response(
        pack: &Pack,
        remote_ip: IpAddr,
    ) -> Option<UdpAccelServerResponse> {
        // Check if server supports UDP acceleration
        if pack.get_int("use_udp_acceleration").unwrap_or(0) == 0 {
            return None;
        }

        let version = pack.get_int("udp_acceleration_version").unwrap_or(1);
        let fast_disconnect_detect = pack
            .get_int("udp_accel_fast_disconnect_detect")
            .unwrap_or(0)
            != 0;

        // Parse server IP
        let server_ip = Self::parse_ip(pack, "udp_acceleration_server_ip").unwrap_or(remote_ip); // Fall back to remote IP if not specified

        let server_port = pack.get_int("udp_acceleration_server_port").unwrap_or(0) as u16;

        if server_port == 0 {
            return None;
        }

        // Parse server key based on version
        let server_key = if version >= 2 {
            pack.get_data("udp_acceleration_server_key_v2")
                .map(|d| d.to_vec())
                .filter(|k| k.len() == UDP_ACCELERATION_COMMON_KEY_SIZE_V2)?
        } else {
            pack.get_data("udp_acceleration_server_key")
                .map(|d| d.to_vec())
                .filter(|k| k.len() == UDP_ACCELERATION_COMMON_KEY_SIZE_V1)?
        };

        let server_cookie = pack.get_int("udp_acceleration_server_cookie").unwrap_or(0);
        let client_cookie = pack.get_int("udp_acceleration_client_cookie").unwrap_or(0);

        if server_cookie == 0 || client_cookie == 0 {
            return None;
        }

        let use_encryption = pack.get_int("udp_acceleration_use_encryption").unwrap_or(1) != 0;
        let use_hmac = pack.get_int("use_hmac_on_udp_acceleration").unwrap_or(0) != 0;

        Some(UdpAccelServerResponse {
            enabled: true,
            version,
            server_ip,
            server_port,
            server_key,
            server_cookie,
            client_cookie,
            use_encryption,
            use_hmac,
            fast_disconnect_detect,
        })
    }

    /// Parse IP address from Pack (handles both IPv4 and IPv6).
    fn parse_ip(pack: &Pack, name: &str) -> Option<IpAddr> {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let is_ipv6 = pack.get_int(&format!("{name}@ipv6_bool")).unwrap_or(0) != 0;

        if is_ipv6 {
            let ipv6_data = pack.get_data(&format!("{name}@ipv6_array"))?;
            if ipv6_data.len() >= 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&ipv6_data[..16]);
                let ip = Ipv6Addr::from(octets);
                if ip.is_unspecified() {
                    return None;
                }
                return Some(IpAddr::V6(ip));
            }
        } else {
            let ip_u32 = pack.get_int(name)?;
            let bytes = ip_u32.to_le_bytes();
            let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            if ip.is_unspecified() {
                return None;
            }
            return Some(IpAddr::V4(ip));
        }

        None
    }
}

/// Connection options for authentication.
#[derive(Debug, Clone)]
pub struct ConnectionOptions {
    /// Maximum number of TCP connections (1-32).
    pub max_connections: u8,
    /// Enable half-connection mode (requires max_connections >= 2).
    pub half_connection: bool,
    /// Enable encryption for tunnel data (RC4).
    pub use_encrypt: bool,
    /// Enable compression.
    pub use_compress: bool,
    /// Enable UDP acceleration.
    pub udp_accel: bool,
    /// Request bridge/routing mode (for L2 bridging, requires server permission).
    pub bridge_mode: bool,
    /// Request monitor mode (for packet capture, requires server permission).
    pub monitor_mode: bool,
    /// Enable VoIP/QoS prioritization (default: true).
    pub qos: bool,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            max_connections: 1,
            half_connection: false,
            use_encrypt: true,
            use_compress: false,
            udp_accel: false,
            bridge_mode: false,
            monitor_mode: false,
            qos: true,
        }
    }
}

/// Builder for authentication Pack.
pub struct AuthPack {
    pack: Pack,
}

impl AuthPack {
    /// Create a new authentication Pack with pre-hashed password.
    ///
    /// The password hash should be computed using `crypto::hash_password(password, username)`.
    ///
    /// # Arguments
    /// * `hub` - Hub name to connect to
    /// * `username` - Username for authentication
    /// * `password_hash` - Pre-hashed password (SHA-0)
    /// * `auth_type` - Authentication type
    /// * `server_random` - Server's random challenge
    /// * `options` - Connection options
    /// * `udp_accel_params` - Optional UDP acceleration parameters (if UDP accel enabled and socket bound)
    pub fn new(
        hub: &str,
        username: &str,
        password_hash: &[u8; SHA0_DIGEST_LEN],
        auth_type: AuthType,
        server_random: &[u8; SHA0_DIGEST_LEN],
        options: &ConnectionOptions,
        udp_accel_params: Option<&UdpAccelAuthParams>,
    ) -> Self {
        let mut pack = Pack::new();

        // Authentication fields
        pack.add_str("method", "login");
        pack.add_str("hubname", hub);
        pack.add_str("username", username);
        pack.add_int("authtype", auth_type as u32);

        // Compute and add secure password
        let secure_password = crypto::compute_secure_password(password_hash, server_random);
        pack.add_data("secure_password", secure_password.to_vec());

        // Client version info
        pack.add_str("client_str", CLIENT_STRING);
        pack.add_int("client_ver", CLIENT_VERSION);
        pack.add_int("client_build", CLIENT_BUILD);

        // Protocol (0 = TCP)
        pack.add_int("protocol", 0);

        // Version fields
        pack.add_str("hello", CLIENT_STRING);
        pack.add_int("version", CLIENT_VERSION);
        pack.add_int("build", CLIENT_BUILD);
        pack.add_int("client_id", 0);

        // Connection options (wired from config)
        pack.add_int("max_connection", options.max_connections as u32);
        pack.add_bool("use_encrypt", options.use_encrypt);
        pack.add_bool("use_compress", options.use_compress);
        // half_connection: use config value (requires max_connections >= 2 if true)
        pack.add_bool("half_connection", options.half_connection);
        pack.add_bool("require_bridge_routing_mode", options.bridge_mode);
        pack.add_bool("require_monitor_mode", options.monitor_mode);
        pack.add_bool("qos", options.qos);

        // UDP acceleration R-UDP bulk support
        pack.add_bool("support_bulk_on_rudp", options.udp_accel);
        pack.add_bool("support_hmac_on_bulk_of_rudp", options.udp_accel);
        pack.add_bool("support_udp_recovery", options.udp_accel);

        // Unique ID
        let unique_id: [u8; 20] = crypto::random_bytes();
        pack.add_data("unique_id", unique_id.to_vec());
        pack.add_int(
            "rudp_bulk_max_version",
            if options.udp_accel { 2 } else { 0 },
        );

        // UDP acceleration using flag - send client UDP params if available
        // This follows the C code in Protocol.c ClientUploadAuth()
        if let Some(params) = udp_accel_params {
            pack.add_bool("use_udp_acceleration", true);
            pack.add_int("udp_acceleration_version", params.max_version);

            // Add client IP (using PackAddIp format)
            Self::add_ip(&mut pack, "udp_acceleration_client_ip", params.client_ip);
            pack.add_int("udp_acceleration_client_port", params.client_port as u32);

            // Add client keys
            pack.add_data("udp_acceleration_client_key", params.client_key.to_vec());
            pack.add_data(
                "udp_acceleration_client_key_v2",
                params.client_key_v2.to_vec(),
            );

            // HMAC and fast disconnect support
            pack.add_bool("support_hmac_on_udp_acceleration", true);
            pack.add_bool("support_udp_accel_fast_disconnect_detect", true);
            pack.add_int("udp_acceleration_max_version", params.max_version);
        }

        // Node info (OutRpcNodeInfo in C)
        let cedar_unique_id: [u8; 16] = crypto::random_bytes(); // Cedar unique ID is 16 bytes
        let hostname = Self::get_hostname();
        pack.add_str("ClientProductName", CLIENT_STRING);
        pack.add_str("ServerProductName", "");
        pack.add_str("ClientOsName", std::env::consts::OS);
        pack.add_str("ClientOsVer", "");
        pack.add_str("ClientOsProductId", "");
        pack.add_str("ClientHostname", &hostname);
        pack.add_str("ServerHostname", "");
        pack.add_str("ProxyHostname", "");
        pack.add_str("HubName", hub);
        pack.add_data("UniqueId", cedar_unique_id.to_vec());
        // Note: C uses LittleEndian32 for these fields
        pack.add_int("ClientProductVer", CLIENT_VERSION.to_le());
        pack.add_int("ClientProductBuild", CLIENT_BUILD.to_le());
        pack.add_int("ServerProductVer", 0);
        pack.add_int("ServerProductBuild", 0);

        // IP addresses (using PackAddIp32 format)
        Self::add_ip32(&mut pack, "ClientIpAddress", 0);
        pack.add_data("ClientIpAddress6", vec![0u8; 16]);
        pack.add_int("ClientPort", 0);
        Self::add_ip32(&mut pack, "ServerIpAddress", 0);
        pack.add_data("ServerIpAddress6", vec![0u8; 16]);
        pack.add_int("ServerPort2", 0);
        Self::add_ip32(&mut pack, "ProxyIpAddress", 0);
        pack.add_data("ProxyIpAddress6", vec![0u8; 16]);
        pack.add_int("ProxyPort", 0);

        // WinVer fields (OutRpcWinVer in C)
        pack.add_bool("V_IsWindows", false);
        pack.add_bool("V_IsNT", false);
        pack.add_bool("V_IsServer", false);
        pack.add_bool("V_IsBeta", false);
        pack.add_int("V_VerMajor", 0);
        pack.add_int("V_VerMinor", 0);
        pack.add_int("V_Build", 0);
        pack.add_int("V_ServicePack", 0);
        pack.add_str("V_Title", std::env::consts::OS);

        // Note: 'pencore' is NOT added by client - it's a server-side feature

        Self { pack }
    }

    /// Create a ticket authentication Pack (for cluster redirect).
    ///
    /// # Arguments
    /// * `hub` - Hub name to connect to
    /// * `username` - Username for authentication
    /// * `server_random` - Server's random challenge
    /// * `ticket` - Authentication ticket from redirect
    /// * `options` - Connection options
    /// * `udp_accel_params` - Optional UDP acceleration parameters
    pub fn new_ticket(
        hub: &str,
        username: &str,
        _server_random: &[u8; SHA0_DIGEST_LEN],
        ticket: &[u8; SHA0_DIGEST_LEN],
        options: &ConnectionOptions,
        udp_accel_params: Option<&UdpAccelAuthParams>,
    ) -> Self {
        let mut pack = Pack::new();

        // Authentication fields with ticket
        pack.add_str("method", "login");
        pack.add_str("hubname", hub);
        pack.add_str("username", username);
        pack.add_int("authtype", AuthType::Ticket as u32);
        pack.add_data("ticket", ticket.to_vec());

        // Client version info
        pack.add_str("client_str", CLIENT_STRING);
        pack.add_int("client_ver", CLIENT_VERSION);
        pack.add_int("client_build", CLIENT_BUILD);

        // Protocol
        pack.add_int("protocol", 0);

        // Version fields
        pack.add_str("hello", CLIENT_STRING);
        pack.add_int("version", CLIENT_VERSION);
        pack.add_int("build", CLIENT_BUILD);
        pack.add_int("client_id", 0);

        // Connection options (same as password auth, from config)
        pack.add_int("max_connection", options.max_connections as u32);
        pack.add_bool("use_encrypt", options.use_encrypt);
        pack.add_bool("use_compress", options.use_compress);
        // half_connection: use config value (requires max_connections >= 2 if true)
        pack.add_bool("half_connection", options.half_connection);
        pack.add_bool("require_bridge_routing_mode", options.bridge_mode);
        pack.add_bool("require_monitor_mode", options.monitor_mode);
        pack.add_bool("qos", options.qos);

        pack.add_bool("support_bulk_on_rudp", options.udp_accel);
        pack.add_bool("support_hmac_on_bulk_of_rudp", options.udp_accel);
        pack.add_bool("support_udp_recovery", options.udp_accel);

        let unique_id: [u8; 20] = crypto::random_bytes();
        pack.add_data("unique_id", unique_id.to_vec());
        pack.add_int(
            "rudp_bulk_max_version",
            if options.udp_accel { 2 } else { 0 },
        );

        // UDP acceleration using flag - send client UDP params if available
        if let Some(params) = udp_accel_params {
            pack.add_bool("use_udp_acceleration", true);
            pack.add_int("udp_acceleration_version", params.max_version);

            Self::add_ip(&mut pack, "udp_acceleration_client_ip", params.client_ip);
            pack.add_int("udp_acceleration_client_port", params.client_port as u32);

            pack.add_data("udp_acceleration_client_key", params.client_key.to_vec());
            pack.add_data(
                "udp_acceleration_client_key_v2",
                params.client_key_v2.to_vec(),
            );

            pack.add_bool("support_hmac_on_udp_acceleration", true);
            pack.add_bool("support_udp_accel_fast_disconnect_detect", true);
            pack.add_int("udp_acceleration_max_version", params.max_version);
        }

        // Node info (OutRpcNodeInfo in C)
        let cedar_unique_id: [u8; 16] = crypto::random_bytes(); // Cedar unique ID is 16 bytes
        let hostname = Self::get_hostname();
        pack.add_str("ClientProductName", CLIENT_STRING);
        pack.add_str("ServerProductName", "");
        pack.add_str("ClientOsName", std::env::consts::OS);
        pack.add_str("ClientOsVer", "");
        pack.add_str("ClientOsProductId", "");
        pack.add_str("ClientHostname", &hostname);
        pack.add_str("ServerHostname", "");
        pack.add_str("ProxyHostname", "");
        pack.add_str("HubName", hub);
        pack.add_data("UniqueId", cedar_unique_id.to_vec());
        // Note: C uses LittleEndian32 for these fields
        pack.add_int("ClientProductVer", CLIENT_VERSION.to_le());
        pack.add_int("ClientProductBuild", CLIENT_BUILD.to_le());
        pack.add_int("ServerProductVer", 0);
        pack.add_int("ServerProductBuild", 0);

        // IP addresses
        Self::add_ip32(&mut pack, "ClientIpAddress", 0);
        pack.add_data("ClientIpAddress6", vec![0u8; 16]);
        pack.add_int("ClientPort", 0);
        Self::add_ip32(&mut pack, "ServerIpAddress", 0);
        pack.add_data("ServerIpAddress6", vec![0u8; 16]);
        pack.add_int("ServerPort2", 0);
        Self::add_ip32(&mut pack, "ProxyIpAddress", 0);
        pack.add_data("ProxyIpAddress6", vec![0u8; 16]);
        pack.add_int("ProxyPort", 0);

        // WinVer fields (OutRpcWinVer in C)
        pack.add_bool("V_IsWindows", false);
        pack.add_bool("V_IsNT", false);
        pack.add_bool("V_IsServer", false);
        pack.add_bool("V_IsBeta", false);
        pack.add_int("V_VerMajor", 0);
        pack.add_int("V_VerMinor", 0);
        pack.add_int("V_Build", 0);
        pack.add_int("V_ServicePack", 0);
        pack.add_str("V_Title", std::env::consts::OS);

        // Note: 'pencore' is NOT added by client - it's a server-side feature

        Self { pack }
    }

    /// Add IP address in PackAddIp32 format.
    fn add_ip32(pack: &mut Pack, name: &str, ip: u32) {
        pack.add_bool(&format!("{name}@ipv6_bool"), false);
        pack.add_data(&format!("{name}@ipv6_array"), vec![0u8; 16]);
        pack.add_int(&format!("{name}@ipv6_scope_id"), 0);
        pack.add_int(name, ip);
    }

    /// Add IP address in PackAddIp format (handles both IPv4 and IPv6).
    fn add_ip(pack: &mut Pack, name: &str, ip: IpAddr) {
        match ip {
            IpAddr::V4(v4) => {
                pack.add_bool(&format!("{name}@ipv6_bool"), false);
                pack.add_data(&format!("{name}@ipv6_array"), vec![0u8; 16]);
                pack.add_int(&format!("{name}@ipv6_scope_id"), 0);
                // IPv4 address as u32 in network byte order stored as little-endian
                let octets = v4.octets();
                let ip_u32 = u32::from_le_bytes(octets);
                pack.add_int(name, ip_u32);
            }
            IpAddr::V6(v6) => {
                pack.add_bool(&format!("{name}@ipv6_bool"), true);
                pack.add_data(&format!("{name}@ipv6_array"), v6.octets().to_vec());
                pack.add_int(&format!("{name}@ipv6_scope_id"), 0);
                pack.add_int(name, 0);
            }
        }
    }

    /// Get the system hostname (like GetMachineName in C).
    fn get_hostname() -> String {
        #[cfg(unix)]
        {
            let mut buf = [0u8; 256];
            let result =
                unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
            if result == 0 {
                let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                String::from_utf8_lossy(&buf[..len]).into_owned()
            } else {
                "unknown".to_string()
            }
        }
        #[cfg(windows)]
        {
            use std::process::Command;
            // Use hostname command on Windows
            Command::new("hostname")
                .output()
                .ok()
                .and_then(|output| {
                    if output.status.success() {
                        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "unknown".to_string())
        }
        #[cfg(not(any(unix, windows)))]
        {
            "unknown".to_string()
        }
    }

    /// Get the underlying Pack.
    pub fn into_pack(self) -> Pack {
        self.pack
    }

    /// Get a reference to the underlying Pack.
    pub fn to_pack(&self) -> &Pack {
        &self.pack
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Bytes {
        self.pack.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_pack_creation() {
        let password_hash = crypto::hash_password("password", "user");
        let server_random = [0u8; 20];
        let options = ConnectionOptions::default();

        let auth_pack = AuthPack::new(
            "VPN",
            "user",
            &password_hash,
            AuthType::Password,
            &server_random,
            &options,
            None,
        );
        let bytes = auth_pack.to_bytes();

        // Should produce non-empty bytes
        assert!(!bytes.is_empty());

        // Should be parseable
        let parsed = Pack::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.get_str("method"), Some("login"));
        assert_eq!(parsed.get_str("hubname"), Some("VPN"));
        assert_eq!(parsed.get_str("username"), Some("user"));
    }

    #[test]
    fn test_hello_response_parse() {
        let mut pack = Pack::new();
        pack.add_data("random", vec![0u8; 20]);
        pack.add_int("version", 444);
        pack.add_int("build", 9807);
        pack.add_str("hello", "SoftEther VPN Server");

        let hello = HelloResponse::from_pack(&pack).unwrap();
        assert_eq!(hello.server_version, 444);
        assert_eq!(hello.server_build, 9807);
        assert_eq!(hello.server_string, "SoftEther VPN Server");
    }

    #[test]
    fn test_auth_result_success() {
        let mut pack = Pack::new();
        pack.add_int("error", 0);
        pack.add_data("session_key", vec![1, 2, 3, 4]);

        let result = AuthResult::from_pack(&pack).unwrap();
        assert!(result.success);
        assert!(!result.session_key.is_empty());
    }

    #[test]
    fn test_auth_result_error() {
        let mut pack = Pack::new();
        pack.add_int("error", 7); // ERR_AUTH_FAILED
        pack.add_str("error_str", "Authentication failed");

        let result = AuthResult::from_pack(&pack).unwrap();
        assert!(!result.success);
        assert_eq!(result.error, 7);
        assert_eq!(
            result.error_message,
            Some("Authentication failed".to_string())
        );
    }

    #[test]
    fn test_redirect_ip_string() {
        // IP is stored in little-endian in Pack format
        // 192.168.0.1 as little-endian u32: bytes [192, 168, 0, 1] = 0x0100A8C0
        let redirect = RedirectInfo {
            ip: 0x0100A8C0, // 192.168.0.1 in little-endian
            port: 443,
            ticket: [0u8; 20],
        };
        assert_eq!(redirect.ip_string(), "192.168.0.1");
    }

    #[test]
    fn test_udp_accel_response_parse() {
        use std::net::Ipv4Addr;

        let mut pack = Pack::new();
        pack.add_int("error", 0);
        pack.add_data("session_key", vec![1, 2, 3, 4]);

        // Add UDP acceleration fields
        pack.add_int("use_udp_acceleration", 1);
        pack.add_int("udp_acceleration_version", 2);

        // Server IP: 10.0.0.1 as little-endian u32
        pack.add_int(
            "udp_acceleration_server_ip",
            u32::from_le_bytes([10, 0, 0, 1]),
        );
        pack.add_bool("udp_acceleration_server_ip@ipv6_bool", false);
        pack.add_data("udp_acceleration_server_ip@ipv6_array", vec![0u8; 16]);
        pack.add_int("udp_acceleration_server_ip@ipv6_scope_id", 0);

        pack.add_int("udp_acceleration_server_port", 40000);
        pack.add_data("udp_acceleration_server_key_v2", vec![0u8; 128]);
        pack.add_int("udp_acceleration_server_cookie", 12345);
        pack.add_int("udp_acceleration_client_cookie", 67890);
        pack.add_int("udp_acceleration_use_encryption", 1);
        pack.add_int("use_hmac_on_udp_acceleration", 1);
        pack.add_int("udp_accel_fast_disconnect_detect", 1);

        let remote_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let response = AuthResult::parse_udp_accel_response(&pack, remote_ip);

        assert!(response.is_some());
        let resp = response.unwrap();
        assert!(resp.enabled);
        assert_eq!(resp.version, 2);
        assert_eq!(resp.server_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(resp.server_port, 40000);
        assert_eq!(resp.server_key.len(), 128);
        assert_eq!(resp.server_cookie, 12345);
        assert_eq!(resp.client_cookie, 67890);
        assert!(resp.use_encryption);
        assert!(resp.use_hmac);
        assert!(resp.fast_disconnect_detect);
    }

    #[test]
    fn test_udp_accel_not_enabled() {
        use std::net::Ipv4Addr;

        let mut pack = Pack::new();
        pack.add_int("error", 0);
        pack.add_data("session_key", vec![1, 2, 3, 4]);
        // use_udp_acceleration not set or 0

        let remote_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let response = AuthResult::parse_udp_accel_response(&pack, remote_ip);

        assert!(response.is_none());
    }
}
