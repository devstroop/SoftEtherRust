//! UDP Acceleration support for SoftEther VPN.
//!
//! UDP acceleration allows VPN traffic to be sent over UDP instead of TCP,
//! providing better performance especially for real-time applications.
//!
//! Based on SoftEther's UdpAccel.c/h implementation.
//!
//! ## Packet Format (V1 - RC4 + SHA-1)
//! ```text
//! +----------------+-------------------+
//! | IV (20 bytes)  | Encrypted Payload |
//! +----------------+-------------------+
//!
//! Encrypted Payload:
//! +--------+----------+----------+------+------+------+---------+--------+
//! | Cookie | MyTick   | YourTick | Size | Flag | Data | Padding | Verify |
//! | 4B     | 8B       | 8B       | 2B   | 1B   | var  | var     | 20B    |
//! +--------+----------+----------+------+------+------+---------+--------+
//! ```
//! The Verify field is 20 zero bytes for integrity check.
//!
//! ## Packet Format (V2 - ChaCha20-Poly1305 AEAD)
//! ```text
//! +----------------+-------------------+--------+
//! | Nonce (12B)    | Encrypted Payload | Tag    |
//! +----------------+-------------------+--------+
//!                                       (16 bytes)
//!
//! Encrypted Payload (same structure, no Verify):
//! +--------+----------+----------+------+------+------+---------+
//! | Cookie | MyTick   | YourTick | Size | Flag | Data | Padding |
//! | 4B     | 8B       | 8B       | 2B   | 1B   | var  | var     |
//! +--------+----------+----------+------+------+------+---------+
//! ```
//! The 16-byte Poly1305 tag provides authenticated encryption.

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Instant;

use bytes::{Buf, BufMut};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use tokio::net::UdpSocket as TokioUdpSocket;
use tracing::{debug, info, trace, warn};

use crate::crypto::{self, Rc4};
use crate::error::{Error, Result};

/// UDP acceleration common key size for version 1 (SHA-1 based).
pub const UDP_ACCELERATION_COMMON_KEY_SIZE_V1: usize = 20;

/// UDP acceleration common key size for version 2 (ChaCha20-Poly1305).
pub const UDP_ACCELERATION_COMMON_KEY_SIZE_V2: usize = 128;

/// UDP acceleration packet IV size for V1.
pub const UDP_ACCELERATION_PACKET_IV_SIZE_V1: usize = 20;

/// UDP acceleration packet key size for V1 (derived from SHA-1).
#[allow(dead_code)]
pub const UDP_ACCELERATION_PACKET_KEY_SIZE_V1: usize = 20;

/// UDP acceleration packet IV/nonce size for V2 (ChaCha20-Poly1305).
pub const UDP_ACCELERATION_PACKET_IV_SIZE_V2: usize = 12;

/// UDP acceleration packet MAC/tag size for V2 (Poly1305).
pub const UDP_ACCELERATION_PACKET_MAC_SIZE_V2: usize = 16;

/// UDP acceleration version 1.
pub const UDP_ACCEL_VERSION_1: u32 = 1;

/// UDP acceleration version 2.
pub const UDP_ACCEL_VERSION_2: u32 = 2;

/// Maximum UDP acceleration version supported.
pub const UDP_ACCEL_MAX_VERSION: u32 = 2;

/// Maximum padding size for protocol obfuscation.
const UDP_ACCELERATION_MAX_PADDING_SIZE: usize = 32;

/// Keepalive interval range (ms).
#[allow(dead_code)]
const UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN: u64 = 1000;
#[allow(dead_code)]
const UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX: u64 = 3000;

/// Keepalive timeout - if no packet received in this time, connection is lost.
const UDP_ACCELERATION_KEEPALIVE_TIMEOUT: u64 = 9000;

/// Time window for sequence checking (ms).
const UDP_ACCELERATION_WINDOW_SIZE_MSEC: u64 = 30000;

/// Time required for continuous receive before connection is stable.
const UDP_ACCELERATION_REQUIRE_CONTINUOUS: u64 = 1000;

/// Maximum UDP packet size for PPPoE.
#[allow(dead_code)]
const MTU_FOR_PPPOE: usize = 1500 - 8; // 1492

/// Maximum temporary buffer size.
const UDP_ACCELERATION_TMP_BUF_SIZE: usize = 2048;

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

    /// Whether UDP acceleration is usable (initialized).
    pub is_usable: bool,

    /// Whether we've received any packet from peer.
    pub is_reached_once: bool,

    /// The UDP socket (if bound).
    socket: Option<Arc<TokioUdpSocket>>,

    /// IV for next packet (V1).
    pub next_iv: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V1],

    /// Nonce for next packet (V2 - 12 bytes).
    pub next_iv_v2: [u8; UDP_ACCELERATION_PACKET_IV_SIZE_V2],

    /// ChaCha20-Poly1305 encryption key for V2 (derived from my_key_v2).
    cipher_encrypt: Option<LessSafeKey>,

    /// ChaCha20-Poly1305 decryption key for V2 (derived from your_key_v2).
    cipher_decrypt: Option<LessSafeKey>,

    /// Disable NAT-T (NAT traversal).
    pub no_nat_t: bool,

    /// NAT-T transaction ID.
    pub nat_t_tran_id: u64,

    /// IPv6 mode.
    pub is_ipv6: bool,

    /// Creation time for tick calculation.
    created_at: Instant,

    /// Last tick value sent to peer.
    pub last_recv_my_tick: u64,

    /// Last tick value received from peer.
    pub last_recv_your_tick: u64,

    /// Last time we received any valid packet.
    pub last_recv_tick: u64,

    /// First time we had stable continuous receive.
    pub first_stable_receive_tick: u64,

    /// Maximum UDP packet size.
    pub max_udp_packet_size: usize,
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

        let std_socket = UdpSocket::bind(bind_addr).map_err(Error::Io)?;

        // Set non-blocking for tokio
        std_socket.set_nonblocking(true).map_err(Error::Io)?;

        let local_addr = std_socket.local_addr().map_err(Error::Io)?;

        let tokio_socket = TokioUdpSocket::from_std(std_socket).map_err(Error::Io)?;

        // Generate random keys
        let my_key: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V1] = crypto::random_bytes();
        let my_key_v2: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V2] = crypto::random_bytes();
        let next_iv: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V1] = crypto::random_bytes();
        let next_iv_v2: [u8; UDP_ACCELERATION_PACKET_IV_SIZE_V2] = crypto::random_bytes();

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
            is_reached_once: false,
            socket: Some(Arc::new(tokio_socket)),
            next_iv,
            next_iv_v2,
            cipher_encrypt: None, // Initialized in init_client for V2
            cipher_decrypt: None, // Initialized in init_client for V2
            no_nat_t: no_nat_t || is_ipv6, // NAT-T disabled for IPv6
            nat_t_tran_id: rand::random(),
            is_ipv6,
            created_at: Instant::now(),
            last_recv_my_tick: 0,
            last_recv_your_tick: 0,
            last_recv_tick: 0,
            first_stable_receive_tick: 0,
            max_udp_packet_size: if is_ipv6 { MTU_FOR_PPPOE - 40 } else { MTU_FOR_PPPOE - 20 } - 8,
        })
    }

    /// Get current tick (milliseconds since creation).
    pub fn now(&self) -> u64 {
        self.created_at.elapsed().as_millis() as u64
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
            return Err(Error::invalid_response(
                "Invalid server UDP acceleration parameters",
            ));
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
            
            // Initialize ChaCha20-Poly1305 ciphers for V2
            // Encrypt with my key, decrypt with server's key
            // ChaCha20-Poly1305 uses first 32 bytes of the 128-byte key
            let encrypt_key = UnboundKey::new(&CHACHA20_POLY1305, &self.my_key_v2[..32])
                .map_err(|_| Error::invalid_response("Failed to create V2 encrypt key"))?;
            let decrypt_key = UnboundKey::new(&CHACHA20_POLY1305, &self.your_key_v2[..32])
                .map_err(|_| Error::invalid_response("Failed to create V2 decrypt key"))?;
            
            self.cipher_encrypt = Some(LessSafeKey::new(encrypt_key));
            self.cipher_decrypt = Some(LessSafeKey::new(decrypt_key));
            
            debug!("Initialized ChaCha20-Poly1305 ciphers for UDP acceleration V2");
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

    /// Initialize UDP acceleration from server response.
    ///
    /// This is a convenience method that calls `init_client` with the
    /// response fields.
    pub fn init_from_response(&mut self, response: &UdpAccelServerResponse) -> Result<()> {
        if !response.enabled {
            return Err(Error::invalid_response("UDP acceleration not enabled"));
        }

        // Set protocol version
        self.version = response.version.min(UDP_ACCEL_MAX_VERSION);
        self.plain_text_mode = !response.use_encryption;
        self.use_hmac = response.use_hmac;
        self.fast_detect = response.fast_disconnect_detect;

        self.init_client(
            &response.server_key,
            response.server_ip,
            response.server_port,
            response.server_cookie,
            response.client_cookie,
        )
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
        let mut mss = if self.is_ipv6 {
            1280 - 40 - 8
        } else {
            1500 - 20 - 8
        };

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
        self.is_usable
            && self.socket.is_some()
            && self.your_ip.is_some()
            && self.your_port.is_some()
    }

    /// Check if send is ready (we've received packets from peer recently).
    pub fn is_send_ready(&mut self) -> bool {
        if !self.is_usable || self.your_port.is_none() || self.your_ip.is_none() {
            return false;
        }

        let now = self.now();
        let timeout = if self.fast_detect {
            UDP_ACCELERATION_KEEPALIVE_TIMEOUT / 3
        } else {
            UDP_ACCELERATION_KEEPALIVE_TIMEOUT
        };

        if self.last_recv_tick == 0 || (self.last_recv_tick + timeout) < now {
            self.first_stable_receive_tick = 0;
            return false;
        }

        (self.first_stable_receive_tick + UDP_ACCELERATION_REQUIRE_CONTINUOUS) <= now
    }

    /// Calculate V1 encryption key from common key and IV.
    /// Algorithm: SHA-1(common_key || iv)
    fn calc_key_v1(common_key: &[u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V1], iv: &[u8]) -> [u8; 20] {
        use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};
        let mut ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        ctx.update(common_key);
        ctx.update(iv);
        let digest = ctx.finish();
        let mut key = [0u8; 20];
        key.copy_from_slice(digest.as_ref());
        key
    }

    /// Encode and send a packet via UDP.
    ///
    /// # Arguments
    /// * `data` - The data to send (can be empty for keepalive)
    /// * `compressed` - Whether the data is compressed (flag byte)
    ///
    /// # Returns
    /// Number of bytes sent, or error.
    pub async fn send(&mut self, data: &[u8], compressed: bool) -> Result<usize> {
        if !self.is_ready() {
            return Err(Error::invalid_state("UDP accel not ready"));
        }

        let socket = self.socket.as_ref().unwrap();
        let server_addr = self.server_addr().unwrap();
        let now = self.now();

        // Build packet
        let mut buf = Vec::with_capacity(UDP_ACCELERATION_TMP_BUF_SIZE);

        if !self.plain_text_mode {
            if self.version > 1 {
                // V2: Add 12-byte nonce
                buf.extend_from_slice(&self.next_iv_v2);
            } else {
                // V1: Add 20-byte IV
                buf.extend_from_slice(&self.next_iv);
            }
        }

        let encrypted_start = buf.len();

        // Cookie (4 bytes)
        let cookie = self.your_cookie.unwrap_or(0);
        buf.put_u32(cookie);

        // MyTick (8 bytes) - current time
        let my_tick = if now == 0 { 1 } else { now };
        buf.put_u64(my_tick);

        // YourTick (8 bytes) - last received tick from peer
        buf.put_u64(self.last_recv_your_tick);

        // Size (2 bytes)
        buf.put_u16(data.len() as u16);

        // Flag (1 byte) - compression flag
        buf.put_u8(if compressed { 1 } else { 0 });

        // Data
        buf.extend_from_slice(data);

        if !self.plain_text_mode {
            if self.version > 1 {
                // V2: ChaCha20-Poly1305 AEAD
                let current_size = buf.len() + UDP_ACCELERATION_PACKET_MAC_SIZE_V2;
                if current_size < self.max_udp_packet_size {
                    let max_pad = (self.max_udp_packet_size - current_size).min(UDP_ACCELERATION_MAX_PADDING_SIZE);
                    let pad_size = if max_pad > 0 {
                        rand::random::<usize>() % max_pad
                    } else {
                        0
                    };
                    buf.extend(std::iter::repeat(0u8).take(pad_size));
                }

                // Encrypt using ChaCha20-Poly1305
                let cipher = self.cipher_encrypt.as_ref()
                    .ok_or_else(|| Error::invalid_state("V2 cipher not initialized"))?;
                
                let nonce = Nonce::assume_unique_for_key(self.next_iv_v2);
                
                // Get plaintext to encrypt
                let plaintext = buf[encrypted_start..].to_vec();
                let plaintext_len = plaintext.len();
                
                // Create buffer for in-place encryption with room for tag
                let mut in_out = plaintext;
                in_out.resize(plaintext_len + UDP_ACCELERATION_PACKET_MAC_SIZE_V2, 0);
                
                // Use seal_in_place_separate_tag for encryption
                let (in_out_data, tag_buf) = in_out.split_at_mut(plaintext_len);
                let tag = cipher.seal_in_place_separate_tag(nonce, Aad::empty(), in_out_data)
                    .map_err(|_| Error::protocol("V2 encryption failed"))?;
                tag_buf.copy_from_slice(tag.as_ref());
                
                // Replace encrypted portion in buf
                buf.truncate(encrypted_start);
                buf.extend_from_slice(&in_out);

                // Update next nonce (use first 12 bytes of encrypted data)
                self.next_iv_v2.copy_from_slice(&buf[encrypted_start..encrypted_start + UDP_ACCELERATION_PACKET_IV_SIZE_V2]);
            } else {
                // V1: RC4 + SHA-1
                // Add padding for security
                let current_size = buf.len() + UDP_ACCELERATION_PACKET_IV_SIZE_V1;
                if current_size < self.max_udp_packet_size {
                    let max_pad = (self.max_udp_packet_size - current_size).min(UDP_ACCELERATION_MAX_PADDING_SIZE);
                    let pad_size = if max_pad > 0 {
                        rand::random::<usize>() % max_pad
                    } else {
                        0
                    };
                    buf.extend(std::iter::repeat(0u8).take(pad_size));
                }

                // Add verify field (20 zero bytes for integrity check)
                buf.extend_from_slice(&[0u8; UDP_ACCELERATION_PACKET_IV_SIZE_V1]);

                // Encrypt the payload (everything after IV)
                let key = Self::calc_key_v1(&self.my_key, &self.next_iv);
                let mut cipher = Rc4::new(&key);
                cipher.process(&mut buf[encrypted_start..]);

                // Update next IV (use last 20 bytes of encrypted data)
                let new_iv_start = buf.len() - UDP_ACCELERATION_PACKET_IV_SIZE_V1;
                self.next_iv.copy_from_slice(&buf[new_iv_start..]);
            }
        }

        // Send
        let sent = socket.send_to(&buf, server_addr).await.map_err(Error::Io)?;
        trace!("UDP accel V{} sent {} bytes to {}", self.version, sent, server_addr);

        Ok(sent)
    }

    /// Send a keepalive packet.
    pub async fn send_keepalive(&mut self) -> Result<usize> {
        self.send(&[], false).await
    }

    /// Process a received UDP packet.
    ///
    /// # Arguments
    /// * `buf` - The received packet data
    /// * `src_addr` - Source address of the packet
    ///
    /// # Returns
    /// The decrypted payload data and compression flag, or None if invalid.
    pub fn process_recv(&mut self, buf: &[u8], src_addr: SocketAddr) -> Option<(Vec<u8>, bool)> {
        let now = self.now();

        if self.version > 1 {
            self.process_recv_v2(buf, src_addr, now)
        } else {
            self.process_recv_v1(buf, src_addr, now)
        }
    }

    /// Process V1 packet (RC4 + SHA-1).
    fn process_recv_v1(&mut self, buf: &[u8], src_addr: SocketAddr, now: u64) -> Option<(Vec<u8>, bool)> {
        let min_size = UDP_ACCELERATION_PACKET_IV_SIZE_V1 + 4 + 8 + 8 + 2 + 1;
        if buf.len() < min_size {
            trace!("UDP accel V1 packet too small: {} bytes", buf.len());
            return None;
        }

        let mut data = buf.to_vec();
        let iv = &buf[..UDP_ACCELERATION_PACKET_IV_SIZE_V1];
        let encrypted = &mut data[UDP_ACCELERATION_PACKET_IV_SIZE_V1..];
        let encrypted_len = encrypted.len();

        if !self.plain_text_mode {
            // Decrypt
            let key = Self::calc_key_v1(&self.your_key, iv);
            let mut cipher = Rc4::new(&key);
            cipher.process(encrypted);

            // Verify integrity (last 20 bytes should be zeros)
            let verify_start = encrypted_len - UDP_ACCELERATION_PACKET_IV_SIZE_V1;
            if encrypted[verify_start..].iter().any(|&b| b != 0) {
                trace!("UDP accel V1 integrity check failed");
                return None;
            }
        }

        self.parse_decrypted_payload(encrypted, src_addr, now)
    }

    /// Process V2 packet (ChaCha20-Poly1305 AEAD).
    fn process_recv_v2(&mut self, buf: &[u8], src_addr: SocketAddr, now: u64) -> Option<(Vec<u8>, bool)> {
        let min_size = UDP_ACCELERATION_PACKET_IV_SIZE_V2 + UDP_ACCELERATION_PACKET_MAC_SIZE_V2 + 4 + 8 + 8 + 2 + 1;
        if buf.len() < min_size {
            trace!("UDP accel V2 packet too small: {} bytes", buf.len());
            return None;
        }

        let nonce_bytes = &buf[..UDP_ACCELERATION_PACKET_IV_SIZE_V2];
        let ciphertext = &buf[UDP_ACCELERATION_PACKET_IV_SIZE_V2..];
        
        if ciphertext.len() < UDP_ACCELERATION_PACKET_MAC_SIZE_V2 {
            trace!("UDP accel V2 ciphertext too small");
            return None;
        }

        if self.plain_text_mode {
            // No decryption needed
            self.parse_decrypted_payload(&mut ciphertext.to_vec(), src_addr, now)
        } else {
            // Decrypt with ChaCha20-Poly1305
            let cipher = self.cipher_decrypt.as_ref()?;
            
            let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).ok()?;
            let mut in_out = ciphertext.to_vec();
            
            // open_in_place decrypts and verifies the tag
            let plaintext = cipher.open_in_place(nonce, Aad::empty(), &mut in_out).ok()?;
            
            self.parse_decrypted_payload(&mut plaintext.to_vec(), src_addr, now)
        }
    }

    /// Parse decrypted payload (common for V1 and V2).
    fn parse_decrypted_payload(&mut self, data: &[u8], src_addr: SocketAddr, now: u64) -> Option<(Vec<u8>, bool)> {
        if data.len() < 4 + 8 + 8 + 2 + 1 {
            trace!("UDP accel decrypted payload too small");
            return None;
        }

        let mut cursor = Cursor::new(data);

        // Cookie
        let cookie = cursor.get_u32();
        if cookie != self.my_cookie {
            trace!("UDP accel cookie mismatch: expected {}, got {}", self.my_cookie, cookie);
            return None;
        }

        // MyTick (sender's tick)
        let my_tick = cursor.get_u64();

        // YourTick (our tick echoed back)
        let your_tick = cursor.get_u64();

        // Size
        let inner_size = cursor.get_u16() as usize;

        // Flag
        let flag = cursor.get_u8();
        let compressed = flag != 0;

        // Validate remaining data
        let remaining = cursor.remaining();
        if remaining < inner_size {
            trace!("UDP accel data too short: need {}, have {}", inner_size, remaining);
            return None;
        }

        // Extract inner data
        let pos = cursor.position() as usize;
        let inner_data = if inner_size > 0 {
            data[pos..pos + inner_size].to_vec()
        } else {
            Vec::new()
        };

        // Check for replay (tick must be within window)
        if my_tick < self.last_recv_your_tick {
            if (self.last_recv_your_tick - my_tick) >= UDP_ACCELERATION_WINDOW_SIZE_MSEC {
                trace!("UDP accel replay detected");
                return None;
            }
        }

        // Update state
        self.last_recv_my_tick = self.last_recv_my_tick.max(your_tick);
        self.last_recv_your_tick = self.last_recv_your_tick.max(my_tick);

        // Update peer address if needed
        if let Some(ref current_ip) = self.your_ip {
            if *current_ip != src_addr.ip() || self.your_port != Some(src_addr.port()) {
                debug!("UDP accel peer address changed: {} -> {}", 
                    SocketAddr::new(*current_ip, self.your_port.unwrap_or(0)),
                    src_addr);
                self.your_ip = Some(src_addr.ip());
                self.your_port = Some(src_addr.port());
            }
        }

        // Update receive timing
        if self.last_recv_my_tick != 0 {
            if (self.last_recv_my_tick + UDP_ACCELERATION_WINDOW_SIZE_MSEC) >= now {
                self.last_recv_tick = now;
                self.is_reached_once = true;

                if self.first_stable_receive_tick == 0 {
                    self.first_stable_receive_tick = now;
                }
            }
        }

        trace!("UDP accel received {} bytes (compressed={})", inner_data.len(), compressed);
        Some((inner_data, compressed))
    }

    /// Receive a packet from the UDP socket.
    ///
    /// This is a non-blocking receive that returns immediately if no data.
    pub async fn try_recv(&self) -> Result<Option<(Vec<u8>, SocketAddr)>> {
        let socket = match &self.socket {
            Some(s) => s,
            None => return Err(Error::invalid_state("No UDP socket")),
        };

        let mut buf = vec![0u8; UDP_ACCELERATION_TMP_BUF_SIZE];
        
        match socket.try_recv_from(&mut buf) {
            Ok((len, addr)) => {
                buf.truncate(len);
                Ok(Some((buf, addr)))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Ok(None)
            }
            Err(e) => Err(Error::Io(e)),
        }
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

        accel
            .init_client(
                &server_key,
                server_ip,
                server_port,
                server_cookie,
                client_cookie,
            )
            .unwrap();

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
