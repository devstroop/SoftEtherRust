//! FFI types for C interoperability.
//!
//! These types are designed to be safe across the C ABI boundary.

use std::ffi::{c_char, c_int, c_void};
use std::os::raw::c_uint;

/// Result codes for FFI functions.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftEtherResult {
    /// Operation succeeded.
    Ok = 0,
    /// Invalid parameter (null pointer, etc.).
    InvalidParam = -1,
    /// Client not connected.
    NotConnected = -2,
    /// Connection failed.
    ConnectionFailed = -3,
    /// Authentication failed.
    AuthFailed = -4,
    /// DHCP failed.
    DhcpFailed = -5,
    /// Timeout.
    Timeout = -6,
    /// I/O error.
    IoError = -7,
    /// Already connected.
    AlreadyConnected = -8,
    /// Internal error.
    InternalError = -99,
}

/// Connection state for callbacks.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftEtherState {
    Disconnected = 0,
    Connecting = 1,
    Handshaking = 2,
    Authenticating = 3,
    EstablishingTunnel = 4,
    Connected = 5,
    Disconnecting = 6,
    Error = 7,
}

/// VPN configuration passed from mobile apps.
#[repr(C)]
pub struct SoftEtherConfig {
    /// Server hostname or IP (null-terminated UTF-8).
    pub server: *const c_char,
    /// Server port.
    pub port: c_uint,
    /// Virtual hub name (null-terminated UTF-8).
    pub hub: *const c_char,
    /// Username (null-terminated UTF-8).
    pub username: *const c_char,
    /// Password hash, hex or base64 encoded (null-terminated UTF-8).
    pub password_hash: *const c_char,

    // TLS Settings
    /// Skip TLS certificate verification (1 = true, 0 = false).
    pub skip_tls_verify: c_int,
    /// Custom CA certificate in PEM format (null-terminated UTF-8, can be null).
    /// When set, this CA is used to verify the server certificate.
    pub custom_ca_pem: *const c_char,
    /// Server certificate SHA-256 fingerprint for pinning (null-terminated UTF-8, can be null).
    /// Format: 64 hex characters (e.g., "a1b2c3d4...").
    pub cert_fingerprint_sha256: *const c_char,

    // Connection Settings
    /// Maximum TCP connections (1-32).
    pub max_connections: c_uint,
    /// Connection timeout in seconds.
    pub timeout_seconds: c_uint,
    /// MTU size (default 1400).
    pub mtu: c_uint,

    // Protocol Features
    /// Use RC4 packet encryption within TLS tunnel (1 = true, 0 = false).
    pub use_encrypt: c_int,
    /// Use zlib compression (1 = true, 0 = false).
    pub use_compress: c_int,
    /// Enable UDP acceleration (1 = true, 0 = false).
    pub udp_accel: c_int,
    /// Enable QoS/VoIP prioritization (1 = true, 0 = false).
    pub qos: c_int,

    // Session Mode
    /// NAT traversal mode (1 = NAT mode, 0 = Bridge mode).
    pub nat_traversal: c_int,
    /// Monitor/packet capture mode (1 = true, 0 = false).
    pub monitor_mode: c_int,

    // Routing
    /// Route all traffic through VPN (1 = true, 0 = false).
    pub default_route: c_int,
    /// Accept server-pushed routes (1 = true, 0 = false).
    pub accept_pushed_routes: c_int,
    /// Comma-separated CIDRs to include in VPN routing (null-terminated UTF-8, can be null).
    pub ipv4_include: *const c_char,
    /// Comma-separated CIDRs to exclude from VPN routing (null-terminated UTF-8, can be null).
    pub ipv4_exclude: *const c_char,
}

/// Session information returned after successful connection.
#[repr(C)]
pub struct SoftEtherSession {
    /// Assigned IP address (network byte order).
    pub ip_address: u32,
    /// Subnet mask (network byte order).
    pub subnet_mask: u32,
    /// Gateway IP (network byte order).
    pub gateway: u32,
    /// Primary DNS server (network byte order).
    pub dns1: u32,
    /// Secondary DNS server (network byte order).
    pub dns2: u32,
    /// Actual server IP we're connected to (for route exclusion).
    /// Null-terminated UTF-8 string in a fixed buffer.
    pub connected_server_ip: [c_char; 64],
    /// Server version.
    pub server_version: u32,
    /// Server build number.
    pub server_build: u32,
    /// MAC address used for this session (6 bytes).
    pub mac_address: [u8; 6],
    /// Gateway MAC address (6 bytes, 0 if unknown).
    pub gateway_mac: [u8; 6],
}

/// Packet buffer for sending/receiving.
/// Used to pass multiple packets across FFI boundary.
#[repr(C)]
pub struct SoftEtherPacketBuffer {
    /// Pointer to packet data array.
    /// Each packet is prefixed with 2-byte length (network byte order).
    /// Format: [len1:u16][data1][len2:u16][data2]...
    pub data: *mut u8,
    /// Total size of data buffer in bytes.
    pub capacity: usize,
    /// Number of bytes used in buffer.
    pub size: usize,
    /// Number of packets in buffer.
    pub count: c_uint,
}

/// Statistics about the VPN connection.
#[repr(C)]
#[derive(Default)]
pub struct SoftEtherStats {
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_received: u64,
    /// Packets sent.
    pub packets_sent: u64,
    /// Packets received.
    pub packets_received: u64,
    /// Connection uptime in seconds.
    pub uptime_secs: u64,
    /// Number of active connections.
    pub active_connections: c_uint,
    /// Number of reconnections.
    pub reconnect_count: c_uint,
}

/// Opaque handle to a SoftEther client instance.
/// This is actually a pointer to the internal Rust struct.
pub type SoftEtherHandle = *mut c_void;

/// Null handle constant.
pub const SOFTETHER_HANDLE_NULL: SoftEtherHandle = std::ptr::null_mut();

// Helper functions for FFI

impl SoftEtherConfig {
    /// Validate the configuration.
    pub fn is_valid(&self) -> bool {
        !self.server.is_null()
            && !self.hub.is_null()
            && !self.username.is_null()
            && !self.password_hash.is_null()
            && self.port > 0
            && self.port <= 65535
            && self.max_connections >= 1
            && self.max_connections <= 32
            && self.mtu >= 576
            && self.mtu <= 1500
    }
}

impl Default for SoftEtherSession {
    fn default() -> Self {
        Self {
            ip_address: 0,
            subnet_mask: 0,
            gateway: 0,
            dns1: 0,
            dns2: 0,
            connected_server_ip: [0; 64],
            server_version: 0,
            server_build: 0,
            mac_address: [0; 6],
            gateway_mac: [0; 6],
        }
    }
}
