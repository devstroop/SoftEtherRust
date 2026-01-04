//! Tunnel runner - main packet processing loop.
//!
//! This module handles the actual VPN data plane:
//! - Create and configure TUN device
//! - DHCP discovery through tunnel
//! - ARP for gateway MAC discovery
//! - Bidirectional packet forwarding
//! - Multi-connection support for half-connection mode
//! - RC4 tunnel encryption (when UseFastRC4 is enabled)

use std::net::Ipv4Addr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use std::sync::atomic::Ordering;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use tokio::sync::mpsc;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use tokio::time::interval;
use tokio::time::timeout;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use tracing::error;
use tracing::{debug, info, warn};

use crate::adapter::TunAdapter;
#[cfg(target_os = "linux")]
use crate::adapter::TunDevice;
#[cfg(target_os = "macos")]
use crate::adapter::UtunDevice;
#[cfg(target_os = "windows")]
use crate::adapter::WintunDevice;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use crate::client::ConcurrentReader;
use crate::client::{ConnectionManager, VpnConnection};
use crate::crypto::{Rc4, Rc4KeyPair};
use crate::error::{Error, Result};
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use crate::packet::ArpHandler;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use crate::packet::BROADCAST_MAC;
use crate::packet::{DhcpClient, DhcpConfig, DhcpState};
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use crate::protocol::decompress_into;
use crate::protocol::{compress, decompress, is_compressed, TunnelCodec};

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use super::DataLoopState;

/// Configuration for the tunnel runner.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// Keepalive interval in seconds.
    pub keepalive_interval: u64,
    /// DHCP timeout in seconds.
    pub dhcp_timeout: u64,
    /// TUN device MTU.
    pub mtu: u16,
    /// Whether to set default route (all traffic through VPN).
    pub default_route: bool,
    /// Routes to add automatically (CIDR prefix lengths).
    /// If empty, will auto-detect from DHCP and add VPN subnet route.
    pub routes: Vec<RouteConfig>,
    /// Whether to compress outgoing packets (must match auth setting).
    pub use_compress: bool,
    /// VPN server IP address (used for host route when default_route is true).
    pub vpn_server_ip: Option<Ipv4Addr>,
    /// RC4 key pair for tunnel encryption (UseFastRC4 mode).
    /// If None, either encryption is disabled or UseSSLDataEncryption is used (TLS handles it).
    pub rc4_key_pair: Option<Rc4KeyPair>,
}

/// Route configuration.
#[derive(Debug, Clone)]
pub struct RouteConfig {
    /// Destination network.
    pub dest: Ipv4Addr,
    /// Prefix length (e.g., 16 for /16).
    pub prefix_len: u8,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            keepalive_interval: 5,
            dhcp_timeout: 30,
            mtu: 1400,
            default_route: false,
            routes: Vec::new(),
            use_compress: false,
            vpn_server_ip: None,
            rc4_key_pair: None,
        }
    }
}

/// Generate a random MAC address with local/unicast bits set.
fn generate_mac() -> [u8; 6] {
    let mut mac = [0u8; 6];
    crate::crypto::fill_random(&mut mac);
    // Set local bit, clear multicast bit
    mac[0] = (mac[0] | 0x02) & 0xFE;
    mac
}

/// Tunnel runner handles the VPN data loop.
pub struct TunnelRunner {
    config: TunnelConfig,
    mac: [u8; 6],
    running: Arc<AtomicBool>,
}

/// RC4 encryption state for tunnel data.
///
/// RC4 is a streaming cipher - each cipher instance maintains state
/// and MUST NOT be reset between packets. Send and recv use separate ciphers.
pub struct TunnelEncryption {
    /// RC4 send cipher (for encrypting outgoing data).
    send_cipher: Rc4,
    /// RC4 recv cipher (for decrypting incoming data).
    recv_cipher: Rc4,
}

impl TunnelEncryption {
    /// Create from RC4 key pair (client mode).
    pub fn new(key_pair: &Rc4KeyPair) -> Self {
        let (send_cipher, recv_cipher) = key_pair.create_client_ciphers();
        Self {
            send_cipher,
            recv_cipher,
        }
    }

    /// Encrypt data in-place for sending.
    #[inline]
    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.send_cipher.process(data);
    }

    /// Decrypt data in-place after receiving.
    #[inline]
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.recv_cipher.process(data);
    }
}

impl TunnelRunner {
    /// Create a new tunnel runner.
    pub fn new(config: TunnelConfig) -> Self {
        if config.rc4_key_pair.is_some() {
            info!("RC4 tunnel encryption enabled (UseFastRC4 mode)");
        } else {
            debug!("No RC4 encryption (using TLS layer or encryption disabled)");
        }

        Self {
            config,
            mac: generate_mac(),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Create encryption state if RC4 keys are configured.
    fn create_encryption(&self) -> Option<TunnelEncryption> {
        self.config.rc4_key_pair.as_ref().map(TunnelEncryption::new)
    }

    /// Check if RC4 encryption is enabled.
    #[inline]
    pub fn is_encrypted(&self) -> bool {
        self.config.rc4_key_pair.is_some()
    }

    /// Get the running flag for external control.
    pub fn running(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }

    /// Run the tunnel data loop.
    ///
    /// This is the main entry point after authentication.
    /// It will:
    /// 1. Perform DHCP through the tunnel
    /// 2. Create and configure a TUN device
    /// 3. Run the packet forwarding loop
    pub async fn run(&mut self, conn: &mut VpnConnection) -> Result<()> {
        debug!(mac = %format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]),
            "Tunnel runner initialized");
        info!("Starting VPN tunnel");

        // Step 1: Perform DHCP to get IP configuration
        let dhcp_config = self.perform_dhcp(conn).await?;
        info!(ip = %dhcp_config.ip, gateway = ?dhcp_config.gateway, dns = ?dhcp_config.dns1,
            "DHCP configuration received");

        // Step 2: Create TUN device
        #[cfg(target_os = "macos")]
        let mut tun = UtunDevice::new(None)
            .map_err(|e| Error::TunDevice(format!("Failed to create TUN: {e}")))?;
        #[cfg(target_os = "linux")]
        let mut tun = TunDevice::new(None)
            .map_err(|e| Error::TunDevice(format!("Failed to create TUN: {}", e)))?;
        #[cfg(target_os = "windows")]
        let mut tun = WintunDevice::new(None)
            .map_err(|e| Error::TunDevice(format!("Failed to create TUN: {}", e)))?;
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        return Err(Error::TunDevice(
            "TUN device not supported on this platform".to_string(),
        ));

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        {
            debug!(device = %tun.name(), "TUN device created");

            // Step 3: Configure TUN device
            tun.configure(dhcp_config.ip, dhcp_config.netmask)
                .map_err(|e| Error::TunDevice(format!("Failed to configure TUN: {e}")))?;
            tun.set_up()
                .map_err(|e| Error::TunDevice(format!("Failed to bring up TUN: {e}")))?;
            tun.set_mtu(self.config.mtu)
                .map_err(|e| Error::TunDevice(format!("Failed to set MTU: {e}")))?;

            // Step 4: Set up routes
            self.configure_routes(&tun, &dhcp_config)?;

            info!(device = %tun.name(), ip = %dhcp_config.ip, mtu = self.config.mtu,
            "TUN interface configured");

            // Step 5: Run the data loop
            self.run_data_loop(conn, &mut tun, &dhcp_config).await
        }
    }

    /// Run the tunnel with multi-connection support.
    ///
    /// This is similar to `run()` but uses a ConnectionManager that can handle
    /// multiple TCP connections in half-connection mode.
    pub async fn run_multi(&mut self, conn_mgr: &mut ConnectionManager) -> Result<()> {
        debug!(mac = %format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]),
            "Tunnel runner initialized (multi-connection)");
        info!("Starting VPN tunnel with multiple connections");

        // Step 1: Establish additional connections BEFORE DHCP
        // In half-connection mode, the server won't respond until all connections are established
        if conn_mgr.needs_more_connections() {
            conn_mgr.establish_additional_connections().await?;
        }

        // Step 2: Perform DHCP to get IP configuration
        let dhcp_config = self.perform_dhcp_multi(conn_mgr).await?;
        info!(ip = %dhcp_config.ip, gateway = ?dhcp_config.gateway, dns = ?dhcp_config.dns1,
            "DHCP configuration received");

        // Additional connections already established above
        if conn_mgr.needs_more_connections() {
            conn_mgr.establish_additional_connections().await?;
        }

        // Step 3: Create TUN device
        #[cfg(target_os = "macos")]
        let mut tun = UtunDevice::new(None)
            .map_err(|e| Error::TunDevice(format!("Failed to create TUN: {e}")))?;
        #[cfg(target_os = "linux")]
        let mut tun = TunDevice::new(None)
            .map_err(|e| Error::TunDevice(format!("Failed to create TUN: {}", e)))?;
        #[cfg(target_os = "windows")]
        let mut tun = WintunDevice::new(None)
            .map_err(|e| Error::TunDevice(format!("Failed to create TUN: {}", e)))?;
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        return Err(Error::TunDevice(
            "TUN device not supported on this platform".to_string(),
        ));

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        {
            debug!(device = %tun.name(), "TUN device created");

            // Step 4: Configure TUN device
            tun.configure(dhcp_config.ip, dhcp_config.netmask)
                .map_err(|e| Error::TunDevice(format!("Failed to configure TUN: {e}")))?;
            tun.set_up()
                .map_err(|e| Error::TunDevice(format!("Failed to bring up TUN: {e}")))?;
            tun.set_mtu(self.config.mtu)
                .map_err(|e| Error::TunDevice(format!("Failed to set MTU: {e}")))?;

            // Step 5: Set up routes
            self.configure_routes(&tun, &dhcp_config)?;

            info!(device = %tun.name(), ip = %dhcp_config.ip, mtu = self.config.mtu,
            "TUN interface configured");

            // Step 6: Run the data loop with multi-connection support
            self.run_data_loop_multi(conn_mgr, &mut tun, &dhcp_config)
                .await
        }
    }

    /// Configure routes for VPN traffic.
    ///
    /// This sets up routing so traffic to the VPN subnet goes through the TUN device.
    #[allow(dead_code)]
    fn configure_routes(&self, tun: &impl TunAdapter, dhcp_config: &DhcpConfig) -> Result<()> {
        // CRITICAL: If default route is requested, add the VPN server host route FIRST
        // This ensures the VPN connection itself doesn't get routed through the VPN
        if self.config.default_route {
            if let Some(gateway) = dhcp_config.gateway {
                // set_default_route adds the host route first internally, then the split-tunnel routes
                tun.set_default_route(gateway, self.config.vpn_server_ip)
                    .map_err(|e| Error::TunDevice(format!("Failed to set default route: {e}")))?;
            }
        }

        // If explicit routes are configured, use those
        if !self.config.routes.is_empty() {
            for route in &self.config.routes {
                tun.add_route_via_interface(route.dest, route.prefix_len)
                    .map_err(|e| Error::TunDevice(format!("Failed to add route: {e}")))?;
            }
        } else {
            // Auto-detect VPN subnet from DHCP config (only if default_route is false)
            // When default_route is true, all traffic goes through VPN anyway
            if !self.config.default_route {
                // Calculate network address from IP and netmask
                let ip_octets = dhcp_config.ip.octets();
                let mask_octets = dhcp_config.netmask.octets();

                // Calculate prefix length from netmask
                let prefix_len: u8 = mask_octets.iter().map(|b| b.count_ones() as u8).sum();

                // Calculate network address
                let network = Ipv4Addr::new(
                    ip_octets[0] & mask_octets[0],
                    ip_octets[1] & mask_octets[1],
                    ip_octets[2] & mask_octets[2],
                    ip_octets[3] & mask_octets[3],
                );

                // For typical VPN setups, we often want a broader route
                // If the netmask is /24 or smaller but IP looks like 10.x.x.x, use /16
                // This is a common pattern for SoftEther VPN
                let (route_network, route_prefix) = if ip_octets[0] == 10 && prefix_len >= 16 {
                    // Use /16 for 10.x.x.x networks
                    let net = Ipv4Addr::new(ip_octets[0], ip_octets[1], 0, 0);
                    (net, 16u8)
                } else if ip_octets[0] == 172
                    && (ip_octets[1] >= 16 && ip_octets[1] <= 31)
                    && prefix_len >= 12
                {
                    // Use /12 for 172.16-31.x.x networks
                    let net = Ipv4Addr::new(172, 16, 0, 0);
                    (net, 12u8)
                } else if ip_octets[0] == 192 && ip_octets[1] == 168 && prefix_len >= 16 {
                    // Use /16 for 192.168.x.x networks
                    let net = Ipv4Addr::new(192, 168, 0, 0);
                    (net, 16u8)
                } else {
                    // Use the exact network from DHCP
                    (network, prefix_len)
                };

                debug!(network = %route_network, prefix = route_prefix, "Adding VPN subnet route");
                tun.add_route_via_interface(route_network, route_prefix)
                    .map_err(|e| {
                        Error::TunDevice(format!("Failed to add VPN subnet route: {e}"))
                    })?;
            }
        }

        // Configure DNS servers from DHCP
        tun.configure_dns(dhcp_config.dns1, dhcp_config.dns2)
            .map_err(|e| Error::TunDevice(format!("Failed to configure DNS: {e}")))?;

        Ok(())
    }

    /// Perform DHCP through the tunnel.
    async fn perform_dhcp(&self, conn: &mut VpnConnection) -> Result<DhcpConfig> {
        let mut dhcp = DhcpClient::new(self.mac);
        let mut codec = TunnelCodec::new();
        let mut buf = vec![0u8; 65536];
        let mut send_buf = vec![0u8; 2048];

        let deadline = Instant::now() + Duration::from_secs(self.config.dhcp_timeout);

        // Send DHCP DISCOVER
        let discover = dhcp.build_discover();
        debug!(bytes = discover.len(), "Sending DHCP DISCOVER");
        self.send_frame(conn, &discover, &mut send_buf).await?;

        // Wait for OFFER
        loop {
            if Instant::now() > deadline {
                return Err(Error::TimeoutMessage(
                    "DHCP timeout - no OFFER received".into(),
                ));
            }

            match timeout(Duration::from_secs(3), conn.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    debug!("Received {} bytes from tunnel", n);
                    // Decode tunnel frames
                    let frames = codec.feed(&buf[..n])?;
                    for frame in frames {
                        if frame.is_keepalive() {
                            debug!("Received keepalive frame");
                            continue;
                        }
                        if let Some(packets) = frame.packets() {
                            for packet in packets {
                                // Check if packet is compressed and decompress if needed
                                let packet_data: Vec<u8> = if is_compressed(packet) {
                                    match decompress(packet) {
                                        Ok(decompressed) => {
                                            debug!(
                                                "Decompressed {} -> {} bytes",
                                                packet.len(),
                                                decompressed.len()
                                            );
                                            decompressed
                                        }
                                        Err(e) => {
                                            warn!("Decompression failed: {}", e);
                                            continue;
                                        }
                                    }
                                } else {
                                    packet.to_vec()
                                };

                                // Log packet details
                                if packet_data.len() >= 14 {
                                    let ethertype =
                                        format!("0x{:02X}{:02X}", packet_data[12], packet_data[13]);
                                    debug!(
                                        "Packet: {} bytes, ethertype={}",
                                        packet_data.len(),
                                        ethertype
                                    );
                                }

                                // Check if this is a DHCP response (UDP port 68)
                                if self.is_dhcp_response(&packet_data) {
                                    debug!("DHCP response received");
                                    if dhcp.process_response(&packet_data) {
                                        // Got ACK
                                        return Ok(dhcp.config().clone());
                                    } else if dhcp.state() == DhcpState::DiscoverSent {
                                        // Got OFFER, send REQUEST
                                        if let Some(request) = dhcp.build_request() {
                                            debug!("Sending DHCP REQUEST");
                                            self.send_frame(conn, &request, &mut send_buf).await?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(Ok(_)) => {
                    return Err(Error::ConnectionFailed(
                        "Connection closed during DHCP".into(),
                    ));
                }
                Ok(Err(e)) => {
                    return Err(Error::Io(e));
                }
                Err(_) => {
                    // Timeout, retry DISCOVER if still in initial state
                    if dhcp.state() == DhcpState::DiscoverSent {
                        warn!("DHCP timeout, retrying DISCOVER");
                        let discover = dhcp.build_discover();
                        self.send_frame(conn, &discover, &mut send_buf).await?;
                    } else if dhcp.state() == DhcpState::RequestSent {
                        warn!("DHCP timeout, retrying REQUEST");
                        if let Some(request) = dhcp.build_request() {
                            self.send_frame(conn, &request, &mut send_buf).await?;
                        }
                    }
                }
            }
        }
    }

    /// Check if an Ethernet frame is a DHCP response (UDP dst port 68).
    fn is_dhcp_response(&self, frame: &[u8]) -> bool {
        // Ethernet(14) + IP header(20 min) + UDP header(8)
        if frame.len() < 42 {
            return false;
        }

        // Check EtherType is IPv4
        if frame[12] != 0x08 || frame[13] != 0x00 {
            return false;
        }

        // Check IP protocol is UDP (17)
        if frame[23] != 17 {
            return false;
        }

        // Check UDP destination port is 68 (DHCP client)
        let dst_port = u16::from_be_bytes([frame[36], frame[37]]);
        dst_port == 68
    }

    /// Send an Ethernet frame through the tunnel.
    async fn send_frame(
        &self,
        conn: &mut VpnConnection,
        frame: &[u8],
        buf: &mut [u8],
    ) -> Result<()> {
        // Compress if enabled
        let data_to_send: std::borrow::Cow<[u8]> = if self.config.use_compress {
            match compress(frame) {
                Ok(compressed) => {
                    debug!("Compressed {} -> {} bytes", frame.len(), compressed.len());
                    std::borrow::Cow::Owned(compressed)
                }
                Err(e) => {
                    warn!("Compression failed, sending uncompressed: {}", e);
                    std::borrow::Cow::Borrowed(frame)
                }
            }
        } else {
            std::borrow::Cow::Borrowed(frame)
        };

        // Encode as tunnel packet: [num_blocks=1][size][data]
        let total_len = 4 + 4 + data_to_send.len();
        if buf.len() < total_len {
            return Err(Error::Protocol("Send buffer too small".into()));
        }

        buf[0..4].copy_from_slice(&1u32.to_be_bytes());
        buf[4..8].copy_from_slice(&(data_to_send.len() as u32).to_be_bytes());
        buf[8..8 + data_to_send.len()].copy_from_slice(&data_to_send);

        conn.write_all(&buf[..total_len]).await?;
        Ok(())
    }

    /// Send an Ethernet frame through the tunnel with optional RC4 encryption.
    async fn send_frame_encrypted(
        &self,
        conn: &mut VpnConnection,
        frame: &[u8],
        buf: &mut [u8],
        encryption: &mut Option<TunnelEncryption>,
    ) -> Result<()> {
        // Compress if enabled
        let data_to_send: std::borrow::Cow<[u8]> = if self.config.use_compress {
            match compress(frame) {
                Ok(compressed) => {
                    debug!("Compressed {} -> {} bytes", frame.len(), compressed.len());
                    std::borrow::Cow::Owned(compressed)
                }
                Err(e) => {
                    warn!("Compression failed, sending uncompressed: {}", e);
                    std::borrow::Cow::Borrowed(frame)
                }
            }
        } else {
            std::borrow::Cow::Borrowed(frame)
        };

        // Encode as tunnel packet: [num_blocks=1][size][data]
        let total_len = 4 + 4 + data_to_send.len();
        if buf.len() < total_len {
            return Err(Error::Protocol("Send buffer too small".into()));
        }

        buf[0..4].copy_from_slice(&1u32.to_be_bytes());
        buf[4..8].copy_from_slice(&(data_to_send.len() as u32).to_be_bytes());
        buf[8..8 + data_to_send.len()].copy_from_slice(&data_to_send);

        // Encrypt before sending if encryption is enabled
        if let Some(ref mut enc) = encryption {
            enc.encrypt(&mut buf[..total_len]);
        }

        conn.write_all(&buf[..total_len]).await?;
        Ok(())
    }

    /// Run the main data forwarding loop.
    ///
    /// Zero-copy optimized path:
    /// - Outbound: TUN read → inline Ethernet wrap → direct send
    /// - Inbound: Network read → direct TUN write (skip Ethernet header)
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    async fn run_data_loop(
        &self,
        conn: &mut VpnConnection,
        tun: &mut impl TunAdapter,
        dhcp_config: &DhcpConfig,
    ) -> Result<()> {
        self.run_data_loop_unix(conn, tun, dhcp_config).await
    }

    #[cfg(target_os = "windows")]
    async fn run_data_loop(
        &self,
        conn: &mut VpnConnection,
        tun: &mut WintunDevice,
        dhcp_config: &DhcpConfig,
    ) -> Result<()> {
        self.run_data_loop_windows(conn, tun, dhcp_config).await
    }

    /// Unix-specific data loop implementation using libc poll/read.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    async fn run_data_loop_unix(
        &self,
        conn: &mut VpnConnection,
        tun: &mut impl TunAdapter,
        dhcp_config: &DhcpConfig,
    ) -> Result<()> {
        let mut state = DataLoopState::new(self.mac);
        let gateway = dhcp_config.gateway.unwrap_or(dhcp_config.ip);
        state.configure(dhcp_config.ip, gateway);

        let mut codec = TunnelCodec::new();

        // Initialize RC4 encryption if enabled
        let mut encryption = self.create_encryption();
        if encryption.is_some() {
            info!("RC4 encryption active for tunnel data");
        }

        // Pre-allocated buffers - sized for maximum packets
        // Network receive buffer
        let mut net_buf = vec![0u8; 65536];
        // Send buffer: 4 (utun header) + 14 (eth) + 1400 (MTU) + 8 (tunnel header) + compression overhead
        let mut send_buf = vec![0u8; 4096];
        // Decompression buffer (reused to avoid allocation per packet)
        let mut decomp_buf = vec![0u8; 4096];

        // TUN write buffer with utun header space pre-allocated
        // Layout: [4-byte utun header][IP packet]
        let mut tun_write_buf = vec![0u8; 2048];

        // Set up ARP handler
        let mut arp = ArpHandler::new(self.mac);
        arp.configure(dhcp_config.ip, gateway);

        // Send gratuitous ARP to announce our presence
        let garp = arp.build_gratuitous_arp();
        self.send_frame_encrypted(conn, &garp, &mut send_buf, &mut encryption)
            .await?;
        debug!("Sent gratuitous ARP");

        // Send ARP request for gateway
        let gateway_arp = arp.build_gateway_request();
        self.send_frame_encrypted(conn, &gateway_arp, &mut send_buf, &mut encryption)
            .await?;
        debug!("Sent gateway ARP request");

        let mut keepalive_interval = interval(Duration::from_secs(self.config.keepalive_interval));
        let mut last_activity = Instant::now();

        // Zero-copy TUN reader using fixed buffer
        // macOS utun: [4-byte protocol header][IP packet]
        // Linux tun:  [IP packet] (no header with IFF_NO_PI)
        let (tun_tx, mut tun_rx) = mpsc::channel::<(usize, [u8; 2048])>(256);
        let tun_fd = tun.raw_fd();
        let running = self.running.clone();

        // Spawn blocking TUN reader task - zero allocation in hot path
        let tun_reader = tokio::task::spawn_blocking(move || {
            // Fixed buffer - no allocation per packet
            let mut read_buf = [0u8; 2048];

            while running.load(Ordering::SeqCst) {
                // Poll with 1ms timeout for minimal latency
                let mut poll_fds = [libc::pollfd {
                    fd: tun_fd,
                    events: libc::POLLIN,
                    revents: 0,
                }];

                let poll_result = unsafe {
                    libc::poll(poll_fds.as_mut_ptr(), 1, 1) // 1ms timeout for low latency
                };

                if poll_result > 0 && (poll_fds[0].revents & libc::POLLIN) != 0 {
                    let n = unsafe {
                        libc::read(
                            tun_fd,
                            read_buf.as_mut_ptr() as *mut libc::c_void,
                            read_buf.len(),
                        )
                    };

                    // macOS utun has 4-byte header, Linux tun doesn't
                    #[cfg(target_os = "macos")]
                    let min_len = 4;
                    #[cfg(target_os = "linux")]
                    let min_len = 1;

                    if n > min_len as isize {
                        // Send the buffer with length - receiver will extract IP packet
                        // Channel copies the fixed buffer (unavoidable for cross-thread)
                        if tun_tx.blocking_send((n as usize, read_buf)).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        info!("VPN tunnel active");

        let our_ip = dhcp_config.ip;
        let use_compress = self.config.use_compress;
        let my_mac = self.mac;

        while self.running.load(Ordering::SeqCst) {
            tokio::select! {
                // Biased: prioritize data paths over timers to minimize latency
                biased;

                // Packet from TUN device (from local applications)
                Some((len, tun_buf)) = tun_rx.recv() => {
                    // macOS utun: [4-byte header][IP packet] - IP starts at offset 4
                    // Linux tun:  [IP packet] - IP starts at offset 0
                    #[cfg(target_os = "macos")]
                    let ip_packet = &tun_buf[4..len];
                    #[cfg(target_os = "linux")]
                    let ip_packet = &tun_buf[..len];

                    if ip_packet.is_empty() {
                        continue;
                    }

                    let gateway_mac = arp.gateway_mac_or_broadcast();

                    // Zero-copy path: build tunnel frame directly in send_buf
                    // Layout: [4: num_blocks][4: block_size][14: eth header][IP packet]
                    let eth_len = 14 + ip_packet.len();
                    let total_len = 8 + eth_len;

                    if total_len > send_buf.len() {
                        warn!("Packet too large: {}", ip_packet.len());
                        continue;
                    }

                    // Determine IP version
                    let ip_version = (ip_packet[0] >> 4) & 0x0F;
                    if ip_version != 4 && ip_version != 6 {
                        continue;
                    }

                    if use_compress {
                        // Compression path - needs intermediate buffer
                        // Build ethernet frame first
                        let eth_start = 8;
                        send_buf[eth_start..eth_start + 6].copy_from_slice(&gateway_mac);
                        send_buf[eth_start + 6..eth_start + 12].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[eth_start + 12] = 0x08;
                            send_buf[eth_start + 13] = 0x00;
                        } else {
                            send_buf[eth_start + 12] = 0x86;
                            send_buf[eth_start + 13] = 0xDD;
                        }
                        send_buf[eth_start + 14..eth_start + 14 + ip_packet.len()]
                            .copy_from_slice(ip_packet);

                        let eth_frame = &send_buf[eth_start..eth_start + eth_len];

                        // Compress to decomp_buf (reused buffer)
                        match compress(eth_frame) {
                            Ok(compressed) => {
                                let comp_total = 8 + compressed.len();
                                if comp_total <= send_buf.len() {
                                    // Write header
                                    send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                    send_buf[4..8].copy_from_slice(&(compressed.len() as u32).to_be_bytes());
                                    send_buf[8..8 + compressed.len()].copy_from_slice(&compressed);
                                    // Encrypt before sending
                                    if let Some(ref mut enc) = encryption {
                                        enc.encrypt(&mut send_buf[..comp_total]);
                                    }
                                    conn.write_all(&send_buf[..comp_total]).await?;
                                }
                            }
                            Err(e) => {
                                warn!("Compression failed: {}", e);
                                // Fall back to uncompressed
                                send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                                // Encrypt before sending
                                if let Some(ref mut enc) = encryption {
                                    enc.encrypt(&mut send_buf[..total_len]);
                                }
                                conn.write_all(&send_buf[..total_len]).await?;
                            }
                        }
                    } else {
                        // Zero-copy uncompressed path
                        // num_blocks = 1
                        send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                        // block_size = eth_len
                        send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                        // Ethernet header
                        send_buf[8..14].copy_from_slice(&gateway_mac);
                        send_buf[14..20].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[20] = 0x08;
                            send_buf[21] = 0x00;
                        } else {
                            send_buf[20] = 0x86;
                            send_buf[21] = 0xDD;
                        }
                        // IP packet - single copy
                        send_buf[22..22 + ip_packet.len()].copy_from_slice(ip_packet);

                        // Encrypt before sending
                        if let Some(ref mut enc) = encryption {
                            enc.encrypt(&mut send_buf[..total_len]);
                        }
                        conn.write_all(&send_buf[..total_len]).await?;
                    }

                    last_activity = Instant::now();
                }

                // Data from VPN connection
                result = conn.read(&mut net_buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            // Decrypt received data if RC4 encryption is enabled
                            if let Some(ref mut enc) = encryption {
                                enc.decrypt(&mut net_buf[..n]);
                            }

                            // Decode frames
                            match codec.feed(&net_buf[..n]) {
                                Ok(frames) => {
                                    for frame in frames {
                                        if frame.is_keepalive() {
                                            debug!("Received keepalive");
                                            continue;
                                        }

                                        // Process each packet in the frame
                                        if let Some(packets) = frame.packets() {
                                            for packet in packets {
                                                // Decompress if needed
                                                let frame_data: &[u8] = if is_compressed(packet) {
                                                    match decompress_into(packet, &mut decomp_buf) {
                                                        Ok(len) => &decomp_buf[..len],
                                                        Err(_) => continue,
                                                    }
                                                } else {
                                                    packet
                                                };

                                                // Process frame with mutable ARP access
                                                if let Err(e) = self.process_frame_zerocopy(
                                                    tun_fd,
                                                    &mut tun_write_buf,
                                                    &mut arp,
                                                    frame_data,
                                                    our_ip,
                                                ) {
                                                    error!("Process error: {}", e);
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Decode error: {}", e);
                                }
                            }

                            // Send any pending ARP replies
                            if let Some(reply) = arp.build_pending_reply() {
                                if let Err(e) = self.send_frame_encrypted(conn, &reply, &mut send_buf, &mut encryption).await {
                                    error!("Failed to send ARP reply: {}", e);
                                } else {
                                    debug!("Sent ARP reply");
                                }
                                arp.take_pending_reply();
                            }

                            last_activity = Instant::now();
                        }
                        Ok(_) => {
                            warn!("Server closed connection");
                            break;
                        }
                        Err(e) => {
                            error!(error = %e, "Network read failed");
                            break;
                        }
                    }
                }

                // Keepalive timer
                _ = keepalive_interval.tick() => {
                    // Send keepalive if no recent activity
                    if last_activity.elapsed() > Duration::from_secs(3) {
                        let keepalive = TunnelCodec::encode_keepalive_direct(
                            32,
                            &mut send_buf,
                        );
                        if let Some(ka) = keepalive {
                            // Encrypt keepalive before sending
                            let ka_len = ka.len();
                            if let Some(ref mut enc) = encryption {
                                enc.encrypt(&mut send_buf[..ka_len]);
                            }
                            conn.write_all(&send_buf[..ka_len]).await?;
                            debug!("Sent keepalive");
                        }
                    }

                    // Periodic gratuitous ARP
                    if arp.should_send_periodic_garp() {
                        let garp = arp.build_gratuitous_arp();
                        self.send_frame_encrypted(conn, &garp, &mut send_buf, &mut encryption).await?;
                        arp.mark_garp_sent();
                        debug!("Sent periodic GARP");
                    }
                }
            }
        }

        info!("VPN tunnel stopped");
        tun_reader.abort();
        Ok(())
    }

    /// Windows-specific data loop implementation using Wintun.
    #[cfg(target_os = "windows")]
    async fn run_data_loop_windows(
        &self,
        conn: &mut VpnConnection,
        tun: &mut WintunDevice,
        dhcp_config: &DhcpConfig,
    ) -> Result<()> {
        let mut state = DataLoopState::new(self.mac);
        let gateway = dhcp_config.gateway.unwrap_or(dhcp_config.ip);
        state.configure(dhcp_config.ip, gateway);

        let mut codec = TunnelCodec::new();

        // Initialize RC4 encryption if enabled
        let mut encryption = self.create_encryption();
        if encryption.is_some() {
            info!("RC4 encryption active for tunnel data (Windows)");
        }

        // Pre-allocated buffers
        let mut net_buf = vec![0u8; 65536];
        let mut send_buf = vec![0u8; 4096];
        let mut decomp_buf = vec![0u8; 4096];

        // Set up ARP handler
        let mut arp = ArpHandler::new(self.mac);
        arp.configure(dhcp_config.ip, gateway);

        // Send gratuitous ARP to announce our presence
        let garp = arp.build_gratuitous_arp();
        self.send_frame_encrypted(conn, &garp, &mut send_buf, &mut encryption)
            .await?;
        debug!("Sent gratuitous ARP");

        // Send ARP request for gateway
        let gateway_arp = arp.build_gateway_request();
        self.send_frame_encrypted(conn, &gateway_arp, &mut send_buf, &mut encryption)
            .await?;
        debug!("Sent gateway ARP request");

        let mut keepalive_interval = interval(Duration::from_secs(self.config.keepalive_interval));
        let mut last_activity = Instant::now();

        // Set up TUN reader channel
        let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(256);
        let session = tun.session();
        let running = self.running.clone();

        // Spawn blocking TUN reader task for Windows with optimized polling
        let tun_reader = tokio::task::spawn_blocking(move || {
            // Use a tight loop with try_receive for lower latency
            // Fall back to blocking receive when no packets are available
            let mut idle_count = 0u32;

            while running.load(Ordering::SeqCst) {
                // Try non-blocking receive first for lower latency
                match session.try_receive() {
                    Ok(Some(packet)) => {
                        let bytes = packet.bytes().to_vec();
                        if tun_tx.blocking_send(bytes).is_err() {
                            break;
                        }
                        idle_count = 0; // Reset idle counter on successful receive
                    }
                    Ok(None) => {
                        // No packet available
                        idle_count += 1;
                        if idle_count > 100 {
                            // After many idle iterations, use blocking receive to save CPU
                            match session.receive_blocking() {
                                Ok(packet) => {
                                    let bytes = packet.bytes().to_vec();
                                    if tun_tx.blocking_send(bytes).is_err() {
                                        break;
                                    }
                                }
                                Err(_) => {
                                    std::thread::sleep(Duration::from_micros(100));
                                }
                            }
                            idle_count = 0;
                        } else {
                            // Brief yield to prevent busy-waiting while staying responsive
                            std::thread::yield_now();
                        }
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_micros(100));
                        idle_count = 0;
                    }
                }
            }
        });

        info!("VPN tunnel active (Windows)");

        let our_ip = dhcp_config.ip;
        let use_compress = self.config.use_compress;
        let my_mac = self.mac;

        while self.running.load(Ordering::SeqCst) {
            tokio::select! {
                biased;

                // Packet from TUN device (from local applications)
                Some(ip_packet) = tun_rx.recv() => {
                    if ip_packet.is_empty() {
                        continue;
                    }

                    let gateway_mac = arp.gateway_mac_or_broadcast();

                    // Build tunnel frame
                    let eth_len = 14 + ip_packet.len();
                    let total_len = 8 + eth_len;

                    if total_len > send_buf.len() {
                        warn!("Packet too large: {}", ip_packet.len());
                        continue;
                    }

                    let ip_version = (ip_packet[0] >> 4) & 0x0F;
                    if ip_version != 4 && ip_version != 6 {
                        continue;
                    }

                    if use_compress {
                        // Compression path
                        let eth_start = 8;
                        send_buf[eth_start..eth_start + 6].copy_from_slice(&gateway_mac);
                        send_buf[eth_start + 6..eth_start + 12].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[eth_start + 12] = 0x08;
                            send_buf[eth_start + 13] = 0x00;
                        } else {
                            send_buf[eth_start + 12] = 0x86;
                            send_buf[eth_start + 13] = 0xDD;
                        }
                        send_buf[eth_start + 14..eth_start + 14 + ip_packet.len()]
                            .copy_from_slice(&ip_packet);

                        let eth_frame = &send_buf[eth_start..eth_start + eth_len];

                        match compress(eth_frame) {
                            Ok(compressed) => {
                                let comp_total = 8 + compressed.len();
                                if comp_total <= send_buf.len() {
                                    send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                    send_buf[4..8].copy_from_slice(&(compressed.len() as u32).to_be_bytes());
                                    send_buf[8..8 + compressed.len()].copy_from_slice(&compressed);
                                    // Encrypt before sending
                                    if let Some(ref mut enc) = encryption {
                                        enc.encrypt(&mut send_buf[..comp_total]);
                                    }
                                    conn.write_all(&send_buf[..comp_total]).await?;
                                }
                            }
                            Err(e) => {
                                warn!("Compression failed: {}", e);
                                send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                                // Encrypt before sending
                                if let Some(ref mut enc) = encryption {
                                    enc.encrypt(&mut send_buf[..total_len]);
                                }
                                conn.write_all(&send_buf[..total_len]).await?;
                            }
                        }
                    } else {
                        // Uncompressed path
                        send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                        send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                        send_buf[8..14].copy_from_slice(&gateway_mac);
                        send_buf[14..20].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[20] = 0x08;
                            send_buf[21] = 0x00;
                        } else {
                            send_buf[20] = 0x86;
                            send_buf[21] = 0xDD;
                        }
                        send_buf[22..22 + ip_packet.len()].copy_from_slice(&ip_packet);

                        // Encrypt before sending
                        if let Some(ref mut enc) = encryption {
                            enc.encrypt(&mut send_buf[..total_len]);
                        }
                        conn.write_all(&send_buf[..total_len]).await?;
                    }

                    last_activity = Instant::now();
                }

                // Data from VPN connection
                result = conn.read(&mut net_buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            // Decrypt received data if RC4 encryption is enabled
                            if let Some(ref mut enc) = encryption {
                                enc.decrypt(&mut net_buf[..n]);
                            }

                            match codec.feed(&net_buf[..n]) {
                                Ok(frames) => {
                                    for frame in frames {
                                        if frame.is_keepalive() {
                                            debug!("Received keepalive");
                                            continue;
                                        }

                                        if let Some(packets) = frame.packets() {
                                            for packet in packets {
                                                let frame_data: &[u8] = if is_compressed(packet) {
                                                    match decompress_into(packet, &mut decomp_buf) {
                                                        Ok(len) => &decomp_buf[..len],
                                                        Err(_) => continue,
                                                    }
                                                } else {
                                                    packet
                                                };

                                                if let Err(e) = self.process_frame_windows(
                                                    tun,
                                                    &mut arp,
                                                    frame_data,
                                                    our_ip,
                                                ) {
                                                    error!("Process error: {}", e);
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Decode error: {}", e);
                                }
                            }

                            // Send any pending ARP replies
                            if let Some(reply) = arp.build_pending_reply() {
                                if let Err(e) = self.send_frame_encrypted(conn, &reply, &mut send_buf, &mut encryption).await {
                                    error!("Failed to send ARP reply: {}", e);
                                } else {
                                    debug!("Sent ARP reply");
                                }
                                arp.take_pending_reply();
                            }

                            last_activity = Instant::now();
                        }
                        Ok(_) => {
                            warn!("Server closed connection");
                            break;
                        }
                        Err(e) => {
                            error!(error = %e, "Network read failed");
                            break;
                        }
                    }
                }

                // Keepalive timer
                _ = keepalive_interval.tick() => {
                    if last_activity.elapsed() > Duration::from_secs(3) {
                        let keepalive = TunnelCodec::encode_keepalive_direct(32, &mut send_buf);
                        if let Some(ka) = keepalive {
                            // Encrypt keepalive before sending
                            let ka_len = ka.len();
                            if let Some(ref mut enc) = encryption {
                                enc.encrypt(&mut send_buf[..ka_len]);
                            }
                            conn.write_all(&send_buf[..ka_len]).await?;
                            debug!("Sent keepalive");
                        }
                    }

                    // Periodic gratuitous ARP
                    if arp.should_send_periodic_garp() {
                        let garp = arp.build_gratuitous_arp();
                        self.send_frame_encrypted(conn, &garp, &mut send_buf, &mut encryption).await?;
                        arp.mark_garp_sent();
                        debug!("Sent periodic GARP");
                    }
                }
            }
        }

        info!("VPN tunnel stopped");
        tun_reader.abort();
        Ok(())
    }

    /// Process an incoming frame for Windows (using Wintun).
    #[cfg(target_os = "windows")]
    #[inline]
    fn process_frame_windows(
        &self,
        tun: &mut WintunDevice,
        arp: &mut ArpHandler,
        frame: &[u8],
        our_ip: Ipv4Addr,
    ) -> Result<()> {
        if frame.len() < 14 {
            return Ok(());
        }

        let dst_mac: [u8; 6] = frame[0..6].try_into().unwrap();
        if dst_mac != self.mac && dst_mac != BROADCAST_MAC {
            return Ok(());
        }

        let ether_type = u16::from_be_bytes([frame[12], frame[13]]);

        match ether_type {
            0x0800 => {
                // IPv4
                let ip_packet = &frame[14..];
                if ip_packet.len() >= 20 {
                    let dst_ip =
                        Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);

                    if dst_ip == our_ip || dst_ip.is_broadcast() || dst_ip.is_multicast() {
                        // Write directly to Wintun
                        let _ = tun.write(ip_packet);
                    }
                }
            }
            0x86DD => {
                // IPv6
                let ip_packet = &frame[14..];
                let _ = tun.write(ip_packet);
            }
            0x0806 => {
                // ARP
                debug!("Received ARP packet ({} bytes)", frame.len());
                if let Some(_reply) = arp.process_arp(frame) {
                    debug!("ARP reply queued");
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Process an incoming frame with zero-copy TUN write (Unix only).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[inline]
    #[allow(unused_variables)] // tun_buf is only used on macOS, not Linux
    fn process_frame_zerocopy(
        &self,
        tun_fd: i32,
        tun_buf: &mut [u8],
        arp: &mut ArpHandler,
        frame: &[u8],
        our_ip: Ipv4Addr,
    ) -> Result<()> {
        if frame.len() < 14 {
            return Ok(());
        }

        // Check destination MAC
        let dst_mac: [u8; 6] = frame[0..6].try_into().unwrap();
        if dst_mac != self.mac && dst_mac != BROADCAST_MAC {
            return Ok(()); // Not for us
        }

        let ether_type = u16::from_be_bytes([frame[12], frame[13]]);

        match ether_type {
            0x0800 => {
                // IPv4 - extract and write to TUN
                let ip_packet = &frame[14..];
                if ip_packet.len() >= 20 {
                    let dst_ip =
                        Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);

                    if dst_ip == our_ip || dst_ip.is_broadcast() || dst_ip.is_multicast() {
                        // Write to TUN device
                        // macOS utun: needs 4-byte protocol header
                        // Linux tun: raw IP packet (IFF_NO_PI)
                        #[cfg(target_os = "macos")]
                        {
                            let total_len = 4 + ip_packet.len();
                            if total_len <= tun_buf.len() {
                                // AF_INET = 2 in network byte order
                                tun_buf[0..4]
                                    .copy_from_slice(&(libc::AF_INET as u32).to_be_bytes());
                                tun_buf[4..total_len].copy_from_slice(ip_packet);

                                unsafe {
                                    libc::write(
                                        tun_fd,
                                        tun_buf.as_ptr() as *const libc::c_void,
                                        total_len,
                                    );
                                }
                            }
                        }
                        #[cfg(target_os = "linux")]
                        {
                            // Linux: write raw IP packet directly
                            unsafe {
                                libc::write(
                                    tun_fd,
                                    ip_packet.as_ptr() as *const libc::c_void,
                                    ip_packet.len(),
                                );
                            }
                        }
                    }
                }
            }
            0x86DD => {
                // IPv6
                let ip_packet = &frame[14..];
                #[cfg(target_os = "macos")]
                {
                    let total_len = 4 + ip_packet.len();
                    if total_len <= tun_buf.len() {
                        // AF_INET6 = 30 on macOS in network byte order
                        tun_buf[0..4].copy_from_slice(&(libc::AF_INET6 as u32).to_be_bytes());
                        tun_buf[4..total_len].copy_from_slice(ip_packet);

                        unsafe {
                            libc::write(tun_fd, tun_buf.as_ptr() as *const libc::c_void, total_len);
                        }
                    }
                }
                #[cfg(target_os = "linux")]
                {
                    // Linux: write raw IP packet directly
                    unsafe {
                        libc::write(
                            tun_fd,
                            ip_packet.as_ptr() as *const libc::c_void,
                            ip_packet.len(),
                        );
                    }
                }
            }
            0x0806 => {
                // ARP - process to learn gateway MAC and respond to requests
                debug!("Received ARP packet ({} bytes)", frame.len());
                if let Some(_reply) = arp.process_arp(frame) {
                    // Reply is built but we don't send it from here
                    // The main loop will check for pending replies
                    debug!("ARP reply queued");
                }
            }
            _ => {}
        }

        Ok(())
    }

    // ========== Multi-Connection Support Methods ==========

    /// Perform DHCP through the tunnel using ConnectionManager.
    async fn perform_dhcp_multi(&self, conn_mgr: &mut ConnectionManager) -> Result<DhcpConfig> {
        let mut dhcp = DhcpClient::new(self.mac);
        // One codec per receive connection for stateful parsing
        let num_conns = conn_mgr.connection_count();
        let mut codecs: Vec<TunnelCodec> = (0..num_conns).map(|_| TunnelCodec::new()).collect();
        let mut buf = vec![0u8; 65536];
        let mut send_buf = vec![0u8; 2048];

        let deadline = Instant::now() + Duration::from_secs(self.config.dhcp_timeout);

        // Get all receive-capable connection indices
        let recv_conn_indices: Vec<usize> = conn_mgr
            .all_connections()
            .iter()
            .enumerate()
            .filter(|(_, c)| c.direction.can_recv())
            .map(|(i, _)| i)
            .collect();

        debug!(
            connections = recv_conn_indices.len(),
            "DHCP using receive connections"
        );

        // Send DHCP DISCOVER
        let discover = dhcp.build_discover();
        debug!(bytes = discover.len(), "Sending DHCP DISCOVER");
        self.send_frame_multi(conn_mgr, &discover, &mut send_buf)
            .await?;

        let mut last_send = Instant::now();
        let mut poll_idx = 0;

        // Use longer timeout per read - we want to actually wait for data
        // With 1 connection, we can afford to wait longer
        let per_conn_timeout_ms = if recv_conn_indices.len() <= 1 {
            100
        } else {
            std::cmp::max(10, 100 / recv_conn_indices.len() as u64)
        };

        // Wait for OFFER/ACK
        loop {
            if Instant::now() > deadline {
                return Err(Error::TimeoutMessage(
                    "DHCP timeout - no response received".into(),
                ));
            }

            // Retry DHCP if no response for 1 second (server may be slow)
            if last_send.elapsed() > Duration::from_millis(1000) {
                if dhcp.state() == DhcpState::DiscoverSent {
                    warn!("DHCP timeout, retrying DISCOVER");
                    let discover = dhcp.build_discover();
                    self.send_frame_multi(conn_mgr, &discover, &mut send_buf)
                        .await?;
                } else if dhcp.state() == DhcpState::RequestSent {
                    warn!("DHCP timeout, retrying REQUEST");
                    if let Some(request) = dhcp.build_request() {
                        self.send_frame_multi(conn_mgr, &request, &mut send_buf)
                            .await?;
                    }
                }
                last_send = Instant::now();
            }

            if recv_conn_indices.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }

            // Poll each connection with very short timeout
            for _ in 0..recv_conn_indices.len() {
                let conn_idx = recv_conn_indices[poll_idx % recv_conn_indices.len()];
                poll_idx += 1;

                let recv_conn = match conn_mgr.get_mut(conn_idx) {
                    Some(c) => c,
                    None => continue,
                };

                match timeout(
                    Duration::from_millis(per_conn_timeout_ms),
                    recv_conn.conn.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(n)) if n > 0 => {
                        recv_conn.touch();
                        recv_conn.bytes_received += n as u64;

                        debug!("Received {} bytes from tunnel (connection {})", n, conn_idx);

                        // Decode tunnel frames
                        let frames = codecs[conn_idx].feed(&buf[..n])?;
                        for frame in frames {
                            if frame.is_keepalive() {
                                debug!("Received keepalive frame");
                                continue;
                            }
                            if let Some(packets) = frame.packets() {
                                for packet in packets {
                                    // Check if packet is compressed and decompress if needed
                                    let packet_data: Vec<u8> = if is_compressed(packet) {
                                        match decompress(packet) {
                                            Ok(decompressed) => {
                                                debug!(
                                                    "Decompressed {} -> {} bytes",
                                                    packet.len(),
                                                    decompressed.len()
                                                );
                                                decompressed
                                            }
                                            Err(e) => {
                                                warn!("Decompression failed: {}", e);
                                                continue;
                                            }
                                        }
                                    } else {
                                        packet.to_vec()
                                    };

                                    // Log packet details
                                    if packet_data.len() >= 14 {
                                        let ethertype = format!(
                                            "0x{:02X}{:02X}",
                                            packet_data[12], packet_data[13]
                                        );
                                        debug!(
                                            "Packet: {} bytes, ethertype={}",
                                            packet_data.len(),
                                            ethertype
                                        );
                                    }

                                    // Check if this is a DHCP response (UDP port 68)
                                    if self.is_dhcp_response(&packet_data) {
                                        debug!(conn = conn_idx, "DHCP response received");
                                        if dhcp.process_response(&packet_data) {
                                            // Got ACK
                                            return Ok(dhcp.config().clone());
                                        } else if dhcp.state() == DhcpState::DiscoverSent {
                                            // Got OFFER, send REQUEST
                                            if let Some(request) = dhcp.build_request() {
                                                debug!("Sending DHCP REQUEST");
                                                self.send_frame_multi(
                                                    conn_mgr,
                                                    &request,
                                                    &mut send_buf,
                                                )
                                                .await?;
                                                last_send = Instant::now();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(Ok(_)) => {} // Zero bytes
                    Ok(Err(e)) => {
                        warn!("Read error on connection {}: {}", conn_idx, e);
                    }
                    Err(_) => {} // Timeout, try next
                }
            }
        }
    }

    /// Send an Ethernet frame through the tunnel using ConnectionManager.
    async fn send_frame_multi(
        &self,
        conn_mgr: &mut ConnectionManager,
        frame: &[u8],
        buf: &mut [u8],
    ) -> Result<()> {
        // Compress if enabled
        let data_to_send: std::borrow::Cow<[u8]> = if self.config.use_compress {
            match compress(frame) {
                Ok(compressed) => {
                    debug!("Compressed {} -> {} bytes", frame.len(), compressed.len());
                    std::borrow::Cow::Owned(compressed)
                }
                Err(e) => {
                    warn!("Compression failed, sending uncompressed: {}", e);
                    std::borrow::Cow::Borrowed(frame)
                }
            }
        } else {
            std::borrow::Cow::Borrowed(frame)
        };

        // Encode as tunnel packet: [num_blocks=1][size][data]
        let total_len = 4 + 4 + data_to_send.len();
        if buf.len() < total_len {
            return Err(Error::Protocol("Send buffer too small".into()));
        }

        buf[0..4].copy_from_slice(&1u32.to_be_bytes());
        buf[4..8].copy_from_slice(&(data_to_send.len() as u32).to_be_bytes());
        buf[8..8 + data_to_send.len()].copy_from_slice(&data_to_send);

        conn_mgr.write_all(&buf[..total_len]).await?;
        Ok(())
    }

    /// Run the main data forwarding loop with multi-connection support.
    ///
    /// Uses ConcurrentReader for receive-only connections (half-connection mode),
    /// and also handles bidirectional connections directly in the main loop.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    async fn run_data_loop_multi(
        &self,
        conn_mgr: &mut ConnectionManager,
        tun: &mut impl TunAdapter,
        dhcp_config: &DhcpConfig,
    ) -> Result<()> {
        let mut state = DataLoopState::new(self.mac);
        let gateway = dhcp_config.gateway.unwrap_or(dhcp_config.ip);
        state.configure(dhcp_config.ip, gateway);

        // Get the total number of connections before extraction
        let total_conns = conn_mgr.connection_count();

        // Extract receive-only connections for concurrent reading.
        // Bidirectional connections stay in conn_mgr for both send AND receive.
        let recv_conns = conn_mgr.take_recv_connections();
        let num_recv = recv_conns.len();
        let num_bidir = conn_mgr.connection_count(); // Bidirectional connections remaining

        // Create concurrent reader for receive-only connections (may be empty!)
        let mut concurrent_reader = if !recv_conns.is_empty() {
            Some(ConcurrentReader::new(recv_conns, 256))
        } else {
            None
        };

        // One codec per original connection index for stateful frame parsing
        let mut codecs: Vec<TunnelCodec> = (0..total_conns).map(|_| TunnelCodec::new()).collect();

        // Buffer for reading from bidirectional connections
        let mut bidir_read_buf = vec![0u8; 8192];

        let mut send_buf = vec![0u8; 4096];
        let mut decomp_buf = vec![0u8; 4096];
        let mut tun_write_buf = vec![0u8; 2048];

        // Set up ARP handler
        let mut arp = ArpHandler::new(self.mac);
        arp.configure(dhcp_config.ip, gateway);

        // Send gratuitous ARP to announce our presence
        let garp = arp.build_gratuitous_arp();
        self.send_frame_multi(conn_mgr, &garp, &mut send_buf)
            .await?;
        debug!("Sent gratuitous ARP");

        // Send ARP request for gateway
        let gateway_arp = arp.build_gateway_request();
        self.send_frame_multi(conn_mgr, &gateway_arp, &mut send_buf)
            .await?;
        debug!("Sent gateway ARP request");

        let mut keepalive_interval = interval(Duration::from_secs(self.config.keepalive_interval));
        let mut last_activity = Instant::now();

        // Zero-copy TUN reader using fixed buffer
        let (tun_tx, mut tun_rx) = mpsc::channel::<(usize, [u8; 2048])>(256);
        let tun_fd = tun.raw_fd();
        let running = self.running.clone();

        // Spawn blocking TUN reader task
        let tun_reader = tokio::task::spawn_blocking(move || {
            let mut read_buf = [0u8; 2048];

            while running.load(Ordering::SeqCst) {
                let mut poll_fds = [libc::pollfd {
                    fd: tun_fd,
                    events: libc::POLLIN,
                    revents: 0,
                }];

                let poll_result = unsafe {
                    libc::poll(poll_fds.as_mut_ptr(), 1, 1) // 1ms timeout for low latency
                };

                if poll_result > 0 && (poll_fds[0].revents & libc::POLLIN) != 0 {
                    let n = unsafe {
                        libc::read(
                            tun_fd,
                            read_buf.as_mut_ptr() as *mut libc::c_void,
                            read_buf.len(),
                        )
                    };

                    #[cfg(target_os = "macos")]
                    let min_len = 4;
                    #[cfg(target_os = "linux")]
                    let min_len = 1;

                    if n > min_len as isize && tun_tx.blocking_send((n as usize, read_buf)).is_err()
                    {
                        break;
                    }
                }
            }
        });

        info!(
            connections = total_conns,
            recv_only = num_recv,
            bidirectional = num_bidir,
            "VPN tunnel active"
        );

        let our_ip = dhcp_config.ip;
        let use_compress = self.config.use_compress;
        let my_mac = self.mac;

        while self.running.load(Ordering::SeqCst) {
            // Helper macro to process received VPN data
            macro_rules! process_vpn_data {
                ($conn_idx:expr, $data:expr) => {{
                    match codecs.get_mut($conn_idx).map(|c| c.feed($data)) {
                        Some(Ok(frames)) => {
                            for frame in frames {
                                if frame.is_keepalive() {
                                    debug!("Received keepalive on conn {}", $conn_idx);
                                    continue;
                                }

                                if let Some(packets) = frame.packets() {
                                    for packet in packets {
                                        let frame_data: &[u8] = if is_compressed(packet) {
                                            match decompress_into(packet, &mut decomp_buf) {
                                                Ok(len) => &decomp_buf[..len],
                                                Err(_) => continue,
                                            }
                                        } else {
                                            packet
                                        };

                                        if let Err(e) = self.process_frame_zerocopy(
                                            tun_fd,
                                            &mut tun_write_buf,
                                            &mut arp,
                                            frame_data,
                                            our_ip,
                                        ) {
                                            error!("Process error: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                        Some(Err(e)) => {
                            error!("Decode error on conn {}: {}", $conn_idx, e);
                        }
                        None => {}
                    }

                    // Send any pending ARP replies
                    if let Some(reply) = arp.build_pending_reply() {
                        if let Err(e) = self.send_frame_multi(conn_mgr, &reply, &mut send_buf).await
                        {
                            error!("Failed to send ARP reply: {}", e);
                        } else {
                            debug!("Sent ARP reply");
                        }
                        arp.take_pending_reply();
                    }

                    last_activity = Instant::now();
                }};
            }

            // Create futures for reading
            // 1. Concurrent reader for receive-only connections (half-connection mode)
            let concurrent_recv = async {
                if let Some(ref mut reader) = concurrent_reader {
                    reader.recv().await
                } else {
                    // No concurrent reader - pend forever
                    std::future::pending().await
                }
            };

            // 2. Direct read from bidirectional connections in conn_mgr
            let bidir_recv = async {
                if num_bidir > 0 {
                    conn_mgr.read_any(&mut bidir_read_buf).await
                } else {
                    // No bidirectional connections - pend forever
                    std::future::pending::<std::io::Result<(usize, usize)>>().await
                }
            };

            tokio::select! {
                // Biased: prioritize data paths over timers to minimize latency
                biased;

                // Packet from TUN device (from local applications)
                Some((len, tun_buf)) = tun_rx.recv() => {
                    #[cfg(target_os = "macos")]
                    let ip_packet = &tun_buf[4..len];
                    #[cfg(target_os = "linux")]
                    let ip_packet = &tun_buf[..len];

                    if ip_packet.is_empty() {
                        continue;
                    }

                    let gateway_mac = arp.gateway_mac_or_broadcast();

                    // Build tunnel frame
                    let eth_len = 14 + ip_packet.len();
                    let total_len = 8 + eth_len;

                    if total_len > send_buf.len() {
                        warn!("Packet too large: {}", ip_packet.len());
                        continue;
                    }

                    let ip_version = (ip_packet[0] >> 4) & 0x0F;
                    if ip_version != 4 && ip_version != 6 {
                        continue;
                    }

                    if use_compress {
                        // Compression path
                        let eth_start = 8;
                        send_buf[eth_start..eth_start + 6].copy_from_slice(&gateway_mac);
                        send_buf[eth_start + 6..eth_start + 12].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[eth_start + 12] = 0x08;
                            send_buf[eth_start + 13] = 0x00;
                        } else {
                            send_buf[eth_start + 12] = 0x86;
                            send_buf[eth_start + 13] = 0xDD;
                        }
                        send_buf[eth_start + 14..eth_start + 14 + ip_packet.len()]
                            .copy_from_slice(ip_packet);

                        let eth_frame = &send_buf[eth_start..eth_start + eth_len];

                        match compress(eth_frame) {
                            Ok(compressed) => {
                                let comp_total = 8 + compressed.len();
                                if comp_total <= send_buf.len() {
                                    send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                    send_buf[4..8].copy_from_slice(&(compressed.len() as u32).to_be_bytes());
                                    send_buf[8..8 + compressed.len()].copy_from_slice(&compressed);
                                    conn_mgr.write_all(&send_buf[..comp_total]).await?;
                                }
                            }
                            Err(e) => {
                                warn!("Compression failed: {}", e);
                                send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                                conn_mgr.write_all(&send_buf[..total_len]).await?;
                            }
                        }
                    } else {
                        // Uncompressed path
                        send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                        send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                        send_buf[8..14].copy_from_slice(&gateway_mac);
                        send_buf[14..20].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[20] = 0x08;
                            send_buf[21] = 0x00;
                        } else {
                            send_buf[20] = 0x86;
                            send_buf[21] = 0xDD;
                        }
                        send_buf[22..22 + ip_packet.len()].copy_from_slice(ip_packet);

                        conn_mgr.write_all(&send_buf[..total_len]).await?;
                    }

                    last_activity = Instant::now();
                }

                // Data from receive-only connections via ConcurrentReader
                Some(packet) = concurrent_recv => {
                    let conn_idx = packet.conn_index;
                    let data = &packet.data[..];
                    process_vpn_data!(conn_idx, data);
                }

                // Data from bidirectional connections (direct read)
                result = bidir_recv => {
                    if let Ok((conn_idx, n)) = result {
                        if n > 0 {
                            let data = &bidir_read_buf[..n];
                            process_vpn_data!(conn_idx, data);
                        }
                    }
                }

                // Keepalive timer
                _ = keepalive_interval.tick() => {
                    if last_activity.elapsed() > Duration::from_secs(3) {
                        let keepalive = TunnelCodec::encode_keepalive_direct(
                            32,
                            &mut send_buf,
                        );
                        if let Some(ka) = keepalive {
                            conn_mgr.write_all(ka).await?;
                            debug!("Sent keepalive");
                        }
                    }

                    if arp.should_send_periodic_garp() {
                        let garp = arp.build_gratuitous_arp();
                        self.send_frame_multi(conn_mgr, &garp, &mut send_buf).await?;
                        arp.mark_garp_sent();
                        debug!("Sent periodic GARP");
                    }
                }
            }
        }

        info!("VPN tunnel stopped");

        // Cleanup
        if let Some(ref mut reader) = concurrent_reader {
            reader.shutdown();
            let recv_stats = reader.bytes_received();
            let total_recv: u64 = recv_stats.iter().map(|(_, b)| b).sum();
            debug!(
                bytes = total_recv,
                connections = recv_stats.len(),
                "Concurrent reader shutdown"
            );
        }
        tun_reader.abort();

        Ok(())
    }

    /// Windows-specific multi-connection data loop.
    /// Note: On Windows, this falls back to single-connection behavior since
    /// the Wintun API doesn't support the same zero-copy optimizations.
    #[cfg(target_os = "windows")]
    async fn run_data_loop_multi(
        &self,
        conn_mgr: &mut ConnectionManager,
        tun: &mut WintunDevice,
        dhcp_config: &DhcpConfig,
    ) -> Result<()> {
        let mut state = DataLoopState::new(self.mac);
        let gateway = dhcp_config.gateway.unwrap_or(dhcp_config.ip);
        state.configure(dhcp_config.ip, gateway);

        // Get the total number of connections
        let total_conns = conn_mgr.connection_count();
        let recv_conns = conn_mgr.take_recv_connections();
        let num_recv = recv_conns.len();
        let num_bidir = conn_mgr.connection_count();

        let mut concurrent_reader = if !recv_conns.is_empty() {
            Some(ConcurrentReader::new(recv_conns, 256))
        } else {
            None
        };

        let mut codecs: Vec<TunnelCodec> = (0..total_conns).map(|_| TunnelCodec::new()).collect();
        let mut bidir_read_buf = vec![0u8; 8192];
        let mut send_buf = vec![0u8; 4096];
        let mut decomp_buf = vec![0u8; 4096];

        let mut arp = ArpHandler::new(self.mac);
        arp.configure(dhcp_config.ip, gateway);

        let garp = arp.build_gratuitous_arp();
        self.send_frame_multi(conn_mgr, &garp, &mut send_buf)
            .await?;
        debug!("Sent gratuitous ARP");

        let gateway_arp = arp.build_gateway_request();
        self.send_frame_multi(conn_mgr, &gateway_arp, &mut send_buf)
            .await?;
        debug!("Sent gateway ARP request");

        let mut keepalive_interval = interval(Duration::from_secs(self.config.keepalive_interval));
        let mut last_activity = Instant::now();

        let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(256);
        let session = tun.session();
        let running = self.running.clone();

        let tun_reader = tokio::task::spawn_blocking(move || {
            while running.load(Ordering::SeqCst) {
                match session.receive_blocking() {
                    Ok(packet) => {
                        let bytes = packet.bytes().to_vec();
                        if tun_tx.blocking_send(bytes).is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        });

        info!(
            connections = total_conns,
            recv_only = num_recv,
            bidirectional = num_bidir,
            "VPN tunnel active (Windows)"
        );

        let our_ip = dhcp_config.ip;
        let use_compress = self.config.use_compress;
        let my_mac = self.mac;

        while self.running.load(Ordering::SeqCst) {
            // Helper macro to process received VPN data
            macro_rules! process_vpn_data {
                ($conn_idx:expr, $data:expr) => {{
                    match codecs.get_mut($conn_idx).map(|c| c.feed($data)) {
                        Some(Ok(frames)) => {
                            for frame in frames {
                                if frame.is_keepalive() {
                                    debug!("Received keepalive on conn {}", $conn_idx);
                                    continue;
                                }

                                if let Some(packets) = frame.packets() {
                                    for packet in packets {
                                        let frame_data: &[u8] = if is_compressed(packet) {
                                            match decompress_into(packet, &mut decomp_buf) {
                                                Ok(len) => &decomp_buf[..len],
                                                Err(_) => continue,
                                            }
                                        } else {
                                            packet
                                        };

                                        if let Err(e) = self.process_frame_windows(
                                            tun, &mut arp, frame_data, our_ip,
                                        ) {
                                            error!("Process error: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                        Some(Err(e)) => {
                            error!("Decode error on conn {}: {}", $conn_idx, e);
                        }
                        None => {}
                    }

                    if let Some(reply) = arp.build_pending_reply() {
                        if let Err(e) = self.send_frame_multi(conn_mgr, &reply, &mut send_buf).await
                        {
                            error!("Failed to send ARP reply: {}", e);
                        } else {
                            debug!("Sent ARP reply");
                        }
                        arp.take_pending_reply();
                    }

                    last_activity = Instant::now();
                }};
            }

            let concurrent_recv = async {
                if let Some(ref mut reader) = concurrent_reader {
                    reader.recv().await
                } else {
                    std::future::pending().await
                }
            };

            let bidir_recv = async {
                if num_bidir > 0 {
                    conn_mgr.read_any(&mut bidir_read_buf).await
                } else {
                    std::future::pending::<std::io::Result<(usize, usize)>>().await
                }
            };

            tokio::select! {
                biased;

                Some(ip_packet) = tun_rx.recv() => {
                    if ip_packet.is_empty() {
                        continue;
                    }

                    let gateway_mac = arp.gateway_mac_or_broadcast();
                    let eth_len = 14 + ip_packet.len();
                    let total_len = 8 + eth_len;

                    if total_len > send_buf.len() {
                        warn!("Packet too large: {}", ip_packet.len());
                        continue;
                    }

                    let ip_version = (ip_packet[0] >> 4) & 0x0F;
                    if ip_version != 4 && ip_version != 6 {
                        continue;
                    }

                    if use_compress {
                        let eth_start = 8;
                        send_buf[eth_start..eth_start + 6].copy_from_slice(&gateway_mac);
                        send_buf[eth_start + 6..eth_start + 12].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[eth_start + 12] = 0x08;
                            send_buf[eth_start + 13] = 0x00;
                        } else {
                            send_buf[eth_start + 12] = 0x86;
                            send_buf[eth_start + 13] = 0xDD;
                        }
                        send_buf[eth_start + 14..eth_start + 14 + ip_packet.len()]
                            .copy_from_slice(&ip_packet);

                        let eth_frame = &send_buf[eth_start..eth_start + eth_len];

                        match compress(eth_frame) {
                            Ok(compressed) => {
                                let comp_total = 8 + compressed.len();
                                if comp_total <= send_buf.len() {
                                    send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                    send_buf[4..8].copy_from_slice(&(compressed.len() as u32).to_be_bytes());
                                    send_buf[8..8 + compressed.len()].copy_from_slice(&compressed);
                                    conn_mgr.write_all(&send_buf[..comp_total]).await?;
                                }
                            }
                            Err(e) => {
                                warn!("Compression failed: {}", e);
                                send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                                conn_mgr.write_all(&send_buf[..total_len]).await?;
                            }
                        }
                    } else {
                        send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                        send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                        send_buf[8..14].copy_from_slice(&gateway_mac);
                        send_buf[14..20].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[20] = 0x08;
                            send_buf[21] = 0x00;
                        } else {
                            send_buf[20] = 0x86;
                            send_buf[21] = 0xDD;
                        }
                        send_buf[22..22 + ip_packet.len()].copy_from_slice(&ip_packet);

                        conn_mgr.write_all(&send_buf[..total_len]).await?;
                    }

                    last_activity = Instant::now();
                }

                Some(packet) = concurrent_recv => {
                    let conn_idx = packet.conn_index;
                    let data = &packet.data[..];
                    process_vpn_data!(conn_idx, data);
                }

                result = bidir_recv => {
                    if let Ok((conn_idx, n)) = result {
                        if n > 0 {
                            let data = &bidir_read_buf[..n];
                            process_vpn_data!(conn_idx, data);
                        }
                    }
                }

                _ = keepalive_interval.tick() => {
                    if last_activity.elapsed() > Duration::from_secs(3) {
                        let keepalive = TunnelCodec::encode_keepalive_direct(32, &mut send_buf);
                        if let Some(ka) = keepalive {
                            conn_mgr.write_all(ka).await?;
                            debug!("Sent keepalive");
                        }
                    }

                    if arp.should_send_periodic_garp() {
                        let garp = arp.build_gratuitous_arp();
                        self.send_frame_multi(conn_mgr, &garp, &mut send_buf).await?;
                        arp.mark_garp_sent();
                        debug!("Sent periodic GARP");
                    }
                }
            }
        }

        info!("VPN tunnel stopped");

        if let Some(ref mut reader) = concurrent_reader {
            reader.shutdown();
            let recv_stats = reader.bytes_received();
            let total_recv: u64 = recv_stats.iter().map(|(_, b)| b).sum();
            debug!(
                bytes = total_recv,
                connections = recv_stats.len(),
                "Concurrent reader shutdown"
            );
        }
        tun_reader.abort();

        Ok(())
    }
}
