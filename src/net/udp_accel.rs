//! UDP Acceleration support for SoftEther VPN.
//!
//! UDP acceleration allows VPN traffic to be sent over UDP instead of TCP,
//! providing better performance especially for real-time applications.
//!
//! Based on SoftEther's UdpAccel.c/h implementation.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use tokio::net::UdpSocket as TokioUdpSocket;
use tracing::{debug, info, warn};

use crate::crypto;
use crate::error::{Error, Result};

/// UDP acceleration common key size for version 1 (SHA-1 based).
pub const UDP_ACCELERATION_COMMON_KEY_SIZE_V1: usize = 20;

/// UDP acceleration common key size for version 2 (ChaCha20-Poly1305).
pub const UDP_ACCELERATION_COMMON_KEY_SIZE_V2: usize = 128;

/// UDP acceleration version 1.
pub const UDP_ACCEL_VERSION_1: u32 = 1;

/// UDP acceleration version 2.
pub const UDP_ACCEL_VERSION_2: u32 = 2;

/// Maximum UDP acceleration version supported.
pub const UDP_ACCEL_MAX_VERSION: u32 = 2;

/// UDP Acceleration state.
#[derive(Debug)]
pub struct UdpAccel {
    /// Protocol version (1 or 2).
    pub version: u32,
    
    /// Whether this is client mode (vs server mode).
    pub client_mode: bool,
    
    /// My encryption key (V1 - 20 bytes).
    pub my_key: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V1],
    
    /// My encryption key (V2 - 128 bytes).
    pub my_key_v2: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V2],
    
    /// Server's encryption key (V1).
    pub your_key: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V1],
    
    /// Server's encryption key (V2).
    pub your_key_v2: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V2],
    
    /// My local IP address.
    pub my_ip: IpAddr,
    
    /// My local UDP port.
    pub my_port: u16,
    
    /// Server's IP address.
    pub your_ip: Option<IpAddr>,
    
    /// Server's UDP port.
    pub your_port: Option<u16>,
    
    /// My cookie (random identifier).
    pub my_cookie: u32,
    
    /// Server's cookie.
    pub your_cookie: Option<u32>,
    
    /// Whether encryption is enabled.
    pub encryption: bool,
    
    /// Whether to use HMAC for integrity.
    pub use_hmac: bool,
    
    /// Whether plaintext mode (no encryption).
    pub plain_text_mode: bool,
    
    /// Fast disconnect detection.
    pub fast_detect: bool,
    
    /// Whether UDP acceleration is usable.
    pub is_usable: bool,
    
    /// The UDP socket (if bound).
    socket: Option<Arc<TokioUdpSocket>>,
    
    /// IV for next packet (V1).
    pub next_iv: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V1],
    
    /// IV for next packet (V2).
    pub next_iv_v2: [u8; 12],
    
    /// Disable NAT-T (NAT traversal).
    pub no_nat_t: bool,
    
    /// NAT-T transaction ID.
    pub nat_t_tran_id: u64,
    
    /// IPv6 mode.
    pub is_ipv6: bool,
}

impl UdpAccel {
    /// Create a new UDP acceleration instance.
    ///
    /// # Arguments
    /// * `local_ip` - Optional local IP to bind to
    /// * `client_mode` - Whether this is client mode
    /// * `no_nat_t` - Whether to disable NAT-T
    pub fn new(local_ip: Option<IpAddr>, client_mode: bool, no_nat_t: bool) -> Result<Self> {
        // Bind UDP socket
        let bind_addr = match local_ip {
            Some(IpAddr::V4(ip)) => SocketAddr::new(IpAddr::V4(ip), 0),
            Some(IpAddr::V6(ip)) => SocketAddr::new(IpAddr::V6(ip), 0),
            None => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        };
        
        let std_socket = UdpSocket::bind(bind_addr)
            .map_err(|e| Error::Io(e))?;
        
        // Set non-blocking for tokio
        std_socket.set_nonblocking(true)
            .map_err(|e| Error::Io(e))?;
        
        let local_addr = std_socket.local_addr()
            .map_err(|e| Error::Io(e))?;
        
        let tokio_socket = TokioUdpSocket::from_std(std_socket)
            .map_err(|e| Error::Io(e))?;
        
        // Generate random keys
        let my_key: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V1] = crypto::random_bytes();
        let my_key_v2: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V2] = crypto::random_bytes();
        let next_iv: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V1] = crypto::random_bytes();
        let next_iv_v2: [u8; 12] = crypto::random_bytes();
        
        // Generate random cookie
        let my_cookie: u32 = rand::random::<u32>() | 1; // Ensure non-zero
        
        let is_ipv6 = local_addr.is_ipv6();
        
        debug!(
            "Created UDP acceleration: local_addr={}, client_mode={}, no_nat_t={}",
            local_addr, client_mode, no_nat_t
        );
        
        Ok(Self {
            version: UDP_ACCEL_VERSION_2, // Default to V2
            client_mode,
            my_key,
            my_key_v2,
            your_key: [0u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V1],
            your_key_v2: [0u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V2],
            my_ip: local_addr.ip(),
            my_port: local_addr.port(),
            your_ip: None,
            your_port: None,
            my_cookie,
            your_cookie: None,
            encryption: true,
            use_hmac: false,
            plain_text_mode: false,
            fast_detect: false,
            is_usable: false,
            socket: Some(Arc::new(tokio_socket)),
            next_iv,
            next_iv_v2,
            no_nat_t: no_nat_t || is_ipv6, // NAT-T disabled for IPv6
            nat_t_tran_id: rand::random(),
            is_ipv6,
        })
    }
    
    /// Initialize the client side with server information.
    ///
    /// This is called after receiving the server's UDP acceleration response.
    pub fn init_client(
        &mut self,
        server_key: &[u8],
        server_ip: IpAddr,
        server_port: u16,
        server_cookie: u32,
        client_cookie: u32,
    ) -> Result<()> {
        if !self.client_mode {
            return Err(Error::invalid_state("init_client called on server mode"));
        }
        
        if server_port == 0 || server_cookie == 0 || client_cookie == 0 {
            return Err(Error::invalid_response("Invalid server UDP acceleration parameters"));
        }
        
        // Set server key based on version
        if self.version == UDP_ACCEL_VERSION_2 {
            if server_key.len() != UDP_ACCELERATION_COMMON_KEY_SIZE_V2 {
                return Err(Error::invalid_response(format!(
                    "Invalid V2 server key length: expected {}, got {}",
                    UDP_ACCELERATION_COMMON_KEY_SIZE_V2,
                    server_key.len()
                )));
            }
            self.your_key_v2.copy_from_slice(server_key);
        } else {
            if server_key.len() != UDP_ACCELERATION_COMMON_KEY_SIZE_V1 {
                return Err(Error::invalid_response(format!(
                    "Invalid V1 server key length: expected {}, got {}",
                    UDP_ACCELERATION_COMMON_KEY_SIZE_V1,
                    server_key.len()
                )));
            }
            self.your_key.copy_from_slice(server_key);
        }
        
        self.your_ip = Some(server_ip);
        self.your_port = Some(server_port);
        self.your_cookie = Some(server_cookie);
        
        // Verify our cookie matches what server echoed back
        if client_cookie != self.my_cookie {
            warn!(
                "Client cookie mismatch: expected {}, got {}",
                self.my_cookie, client_cookie
            );
            // This is not necessarily an error - just update our cookie
            self.my_cookie = client_cookie;
        }
        
        self.is_usable = true;
        
        info!(
            "UDP acceleration initialized: server={}:{}, version={}",
            server_ip, server_port, self.version
        );
        
        Ok(())
    }
    
    /// Get the UDP socket for sending/receiving.
    pub fn socket(&self) -> Option<&Arc<TokioUdpSocket>> {
        self.socket.as_ref()
    }
    
    /// Get the server address if initialized.
    pub fn server_addr(&self) -> Option<SocketAddr> {
        match (self.your_ip, self.your_port) {
            (Some(ip), Some(port)) => Some(SocketAddr::new(ip, port)),
            _ => None,
        }
    }
    
    /// Calculate the MSS (Maximum Segment Size) for UDP acceleration.
    pub fn calc_mss(&self) -> u16 {
        // Base MTU minus IP and UDP headers
        let mut mss = if self.is_ipv6 { 1280 - 40 - 8 } else { 1500 - 20 - 8 };
        
        // Subtract UDP acceleration overhead
        // Cookie (4) + Tick (8) + MyTick (8) + SeqNo (4) + IV (based on version)
        mss -= 4 + 8 + 8 + 4;
        
        if self.version == UDP_ACCEL_VERSION_2 {
            // ChaCha20-Poly1305: 12-byte nonce, 16-byte tag
            mss -= 12 + 16;
        } else {
            // V1: 20-byte IV for encryption
            mss -= 20;
            if self.use_hmac {
                // HMAC-SHA1: 20 bytes
                mss -= 20;
            }
        }
        
        mss as u16
    }
    
    /// Check if UDP acceleration is ready to use.
    pub fn is_ready(&self) -> bool {
        self.is_usable && self.socket.is_some() && self.your_ip.is_some() && self.your_port.is_some()
    }
}

/// UDP acceleration parameters to send during authentication.
#[derive(Debug, Clone)]
pub struct UdpAccelAuthParams {
    /// Whether UDP acceleration is enabled.
    pub enabled: bool,
    /// Maximum version supported.
    pub max_version: u32,
    /// Client IP address (may be zero if behind NAT).
    pub client_ip: IpAddr,
    /// Client UDP port.
    pub client_port: u16,
    /// Client key V1 (20 bytes).
    pub client_key: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V1],
    /// Client key V2 (128 bytes).
    pub client_key_v2: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V2],
}

impl UdpAccelAuthParams {
    /// Create from a UdpAccel instance.
    pub fn from_udp_accel(accel: &UdpAccel) -> Self {
        let client_ip = if accel.my_ip.is_loopback() {
            // Don't send loopback address
            match accel.my_ip {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            }
        } else {
            accel.my_ip
        };
        
        Self {
            enabled: true,
            max_version: UDP_ACCEL_MAX_VERSION,
            client_ip,
            client_port: accel.my_port,
            client_key: accel.my_key,
            client_key_v2: accel.my_key_v2,
        }
    }
}

/// UDP acceleration response from server.
#[derive(Debug, Clone)]
pub struct UdpAccelServerResponse {
    /// Whether server supports UDP acceleration.
    pub enabled: bool,
    /// Server's UDP acceleration version.
    pub version: u32,
    /// Server IP address.
    pub server_ip: IpAddr,
    /// Server UDP port.
    pub server_port: u16,
    /// Server key (V1 or V2 depending on version).
    pub server_key: Vec<u8>,
    /// Server cookie.
    pub server_cookie: u32,
    /// Client cookie (echoed back).
    pub client_cookie: u32,
    /// Whether encryption is enabled.
    pub use_encryption: bool,
    /// Whether to use HMAC.
    pub use_hmac: bool,
    /// Fast disconnect detection.
    pub fast_disconnect_detect: bool,
}

impl Default for UdpAccelServerResponse {
    fn default() -> Self {
        Self {
            enabled: false,
            version: 1,
            server_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            server_port: 0,
            server_key: Vec::new(),
            server_cookie: 0,
            client_cookie: 0,
            use_encryption: true,
            use_hmac: false,
            fast_disconnect_detect: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_udp_accel_creation() {
        let accel = UdpAccel::new(None, true, false).unwrap();
        assert!(accel.client_mode);
        assert!(accel.my_port > 0);
        assert_eq!(accel.version, UDP_ACCEL_VERSION_2);
        assert!(!accel.is_usable);
    }
    
    #[tokio::test]
    async fn test_udp_accel_auth_params() {
        let accel = UdpAccel::new(None, true, false).unwrap();
        let params = UdpAccelAuthParams::from_udp_accel(&accel);
        assert!(params.enabled);
        assert_eq!(params.max_version, UDP_ACCEL_MAX_VERSION);
        assert_eq!(params.client_port, accel.my_port);
    }
    
    #[tokio::test]
    async fn test_udp_accel_init_client() {
        let mut accel = UdpAccel::new(None, true, false).unwrap();
        
        let server_key = [0u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V2];
        let server_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let server_port = 8080u16;
        let server_cookie = 12345u32;
        let client_cookie = accel.my_cookie;
        
        accel.init_client(&server_key, server_ip, server_port, server_cookie, client_cookie).unwrap();
        
        assert!(accel.is_usable);
        assert!(accel.is_ready());
        assert_eq!(accel.your_ip, Some(server_ip));
        assert_eq!(accel.your_port, Some(server_port));
        assert_eq!(accel.your_cookie, Some(server_cookie));
    }
    
    #[tokio::test]
    async fn test_calc_mss() {
        let accel = UdpAccel::new(None, true, false).unwrap();
        let mss = accel.calc_mss();
        // Should be reasonable MTU minus overhead
        assert!(mss > 1000 && mss < 1500);
    }
}
