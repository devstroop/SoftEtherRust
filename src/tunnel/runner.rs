//! Tunnel runner - main packet processing loop.
//!
//! This module handles the actual VPN data plane:
//! - Create and configure TUN device
//! - DHCP discovery through tunnel
//! - ARP for gateway MAC discovery
//! - Bidirectional packet forwarding

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};

use crate::adapter::{TunAdapter, UtunDevice};
use crate::client::VpnConnection;
use crate::error::{Error, Result};
use crate::protocol::{TunnelCodec, is_compressed, decompress, compress};

use super::{
    ArpHandler, DhcpClient, DhcpConfig, DhcpState, DataLoopState,
    unwrap_ethernet_to_ip,
    BROADCAST_MAC,
};

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

impl TunnelRunner {
    /// Create a new tunnel runner.
    pub fn new(config: TunnelConfig) -> Self {
        Self {
            config,
            mac: generate_mac(),
            running: Arc::new(AtomicBool::new(true)),
        }
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
        info!("Starting tunnel runner with MAC {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]);

        // Step 1: Perform DHCP to get IP configuration
        let dhcp_config = self.perform_dhcp(conn).await?;
        info!("DHCP complete: IP={}, Gateway={:?}, DNS={:?}",
            dhcp_config.ip, dhcp_config.gateway, dhcp_config.dns1);

        // Step 2: Create TUN device
        let mut tun = UtunDevice::new(None)
            .map_err(|e| Error::TunDevice(format!("Failed to create TUN: {}", e)))?;
        info!("Created TUN device: {}", tun.name());

        // Step 3: Configure TUN device
        tun.configure(dhcp_config.ip, dhcp_config.netmask)
            .map_err(|e| Error::TunDevice(format!("Failed to configure TUN: {}", e)))?;
        tun.set_up()
            .map_err(|e| Error::TunDevice(format!("Failed to bring up TUN: {}", e)))?;
        tun.set_mtu(self.config.mtu)
            .map_err(|e| Error::TunDevice(format!("Failed to set MTU: {}", e)))?;

        // Step 4: Set up routes
        self.configure_routes(&tun, &dhcp_config)?;

        info!("TUN device {} configured with IP {}", tun.name(), dhcp_config.ip);

        // Step 5: Run the data loop
        self.run_data_loop(conn, &mut tun, &dhcp_config).await
    }

    /// Configure routes for VPN traffic.
    ///
    /// This sets up routing so traffic to the VPN subnet goes through the TUN device.
    fn configure_routes(&self, tun: &UtunDevice, dhcp_config: &DhcpConfig) -> Result<()> {
        // If explicit routes are configured, use those
        if !self.config.routes.is_empty() {
            for route in &self.config.routes {
                tun.add_route_via_interface(route.dest, route.prefix_len)
                    .map_err(|e| Error::TunDevice(format!("Failed to add route: {}", e)))?;
            }
            return Ok(());
        }

        // Auto-detect VPN subnet from DHCP config
        // Calculate network address from IP and netmask
        let ip_octets = dhcp_config.ip.octets();
        let mask_octets = dhcp_config.netmask.octets();
        
        // Calculate prefix length from netmask
        let prefix_len: u8 = mask_octets
            .iter()
            .map(|b| b.count_ones() as u8)
            .sum();

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
        } else if ip_octets[0] == 172 && (ip_octets[1] >= 16 && ip_octets[1] <= 31) && prefix_len >= 12 {
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

        info!("Adding route for VPN subnet: {}/{}", route_network, route_prefix);
        tun.add_route_via_interface(route_network, route_prefix)
            .map_err(|e| Error::TunDevice(format!("Failed to add VPN subnet route: {}", e)))?;

        // If default route is requested, also set that
        if self.config.default_route {
            if let Some(gateway) = dhcp_config.gateway {
                tun.set_default_route(gateway, self.config.vpn_server_ip)
                    .map_err(|e| Error::TunDevice(format!("Failed to set default route: {}", e)))?;
            }
        }

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
        info!("Sending DHCP DISCOVER ({} bytes)", discover.len());
        debug!("DHCP DISCOVER: {:02X?}", &discover[..std::cmp::min(64, discover.len())]);
        self.send_frame(conn, &discover, &mut send_buf).await?;

        // Wait for OFFER
        loop {
            if Instant::now() > deadline {
                return Err(Error::TimeoutMessage("DHCP timeout - no OFFER received".into()));
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
                                            debug!("Decompressed {} -> {} bytes", packet.len(), decompressed.len());
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
                                    let ethertype = format!("0x{:02X}{:02X}", packet_data[12], packet_data[13]);
                                    debug!("Packet: {} bytes, ethertype={}", packet_data.len(), ethertype);
                                }
                                
                                // Check if this is a DHCP response (UDP port 68)
                                if self.is_dhcp_response(&packet_data) {
                                    info!("DHCP response packet detected!");
                                    if dhcp.process_response(&packet_data) {
                                        // Got ACK
                                        return Ok(dhcp.config().clone());
                                    } else if dhcp.state() == DhcpState::DiscoverSent {
                                        // Got OFFER, send REQUEST
                                        if let Some(request) = dhcp.build_request() {
                                            info!("Sending DHCP REQUEST");
                                            self.send_frame(conn, &request, &mut send_buf).await?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(Ok(_)) => {
                    return Err(Error::ConnectionFailed("Connection closed during DHCP".into()));
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
    async fn send_frame(&self, conn: &mut VpnConnection, frame: &[u8], buf: &mut [u8]) -> Result<()> {
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

    /// Run the main data forwarding loop.
    async fn run_data_loop(
        &self,
        conn: &mut VpnConnection,
        tun: &mut UtunDevice,
        dhcp_config: &DhcpConfig,
    ) -> Result<()> {
        let mut state = DataLoopState::new(self.mac);
        let gateway = dhcp_config.gateway.unwrap_or(dhcp_config.ip);
        state.configure(dhcp_config.ip, gateway);

        let mut codec = TunnelCodec::new();
        let mut net_buf = vec![0u8; 65536];
        let mut send_buf = vec![0u8; 2048];

        // Set up ARP handler
        let mut arp = ArpHandler::new(self.mac);
        arp.configure(dhcp_config.ip, gateway);

        // Send gratuitous ARP to announce our presence
        let garp = arp.build_gratuitous_arp();
        self.send_frame(conn, &garp, &mut send_buf).await?;
        debug!("Sent gratuitous ARP");

        // Send ARP request for gateway
        let gateway_arp = arp.build_gateway_request();
        self.send_frame(conn, &gateway_arp, &mut send_buf).await?;
        debug!("Sent gateway ARP request");

        let mut keepalive_interval = interval(Duration::from_secs(self.config.keepalive_interval));
        let mut last_activity = Instant::now();

        // Use channels for TUN reading since it's blocking
        // Use larger channel buffer for throughput, but process immediately for latency
        let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(256);
        let tun_fd = tun.raw_fd();
        let running = self.running.clone();

        // Spawn blocking TUN reader task with optimized polling
        let tun_reader = tokio::task::spawn_blocking(move || {
            let buf_size = 2048;
            while running.load(Ordering::SeqCst) {
                // Use shorter poll timeout for lower latency (10ms instead of 100ms)
                let mut poll_fds = [libc::pollfd {
                    fd: tun_fd,
                    events: libc::POLLIN,
                    revents: 0,
                }];
                
                let poll_result = unsafe {
                    libc::poll(poll_fds.as_mut_ptr(), 1, 10) // 10ms timeout for low latency
                };
                
                if poll_result > 0 && (poll_fds[0].revents & libc::POLLIN) != 0 {
                    // Data available - read with utun header handling
                    let mut full_buf = vec![0u8; buf_size + 4];
                    let n = unsafe {
                        libc::read(
                            tun_fd,
                            full_buf.as_mut_ptr() as *mut libc::c_void,
                            full_buf.len(),
                        )
                    };

                    if n > 4 {
                        let n = n as usize;
                        // Skip 4-byte utun header
                        let packet = full_buf[4..n].to_vec();
                        if tun_tx.blocking_send(packet).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        info!("Data loop started, press Ctrl+C to disconnect");

        while self.running.load(Ordering::SeqCst) {
            tokio::select! {
                // Packet from TUN device (from local applications)
                Some(ip_packet) = tun_rx.recv() => {
                    // Wrap in Ethernet and send through tunnel
                    let gateway_mac = arp.gateway_mac_or_broadcast();
                    
                    // Build Ethernet frame manually
                    let mut eth_frame = vec![0u8; 14 + ip_packet.len()];
                    eth_frame[0..6].copy_from_slice(&gateway_mac);  // dst MAC
                    eth_frame[6..12].copy_from_slice(&self.mac);    // src MAC
                    
                    // EtherType based on IP version
                    let ip_version = (ip_packet[0] >> 4) & 0x0F;
                    if ip_version == 4 {
                        eth_frame[12] = 0x08;
                        eth_frame[13] = 0x00;
                    } else if ip_version == 6 {
                        eth_frame[12] = 0x86;
                        eth_frame[13] = 0xDD;
                    } else {
                        continue; // Unknown IP version
                    }
                    
                    eth_frame[14..].copy_from_slice(&ip_packet);
                    
                    self.send_frame(conn, &eth_frame, &mut send_buf).await?;
                    last_activity = Instant::now();
                    debug!("TUN -> VPN: {} bytes", ip_packet.len());
                }

                // Data from VPN connection
                result = conn.read(&mut net_buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            let frames = codec.feed(&net_buf[..n])?;
                            for frame in frames {
                                if let Some(packets) = frame.packets() {
                                    for packet in packets {
                                        // Decompress if needed
                                        let packet_data: Vec<u8> = if is_compressed(packet) {
                                            match decompress(packet) {
                                                Ok(decompressed) => decompressed,
                                                Err(e) => {
                                                    warn!("Decompression failed: {}", e);
                                                    continue;
                                                }
                                            }
                                        } else {
                                            packet.to_vec()
                                        };
                                        
                                        self.process_incoming_frame(
                                            tun,
                                            conn,
                                            &mut arp,
                                            &packet_data,
                                            dhcp_config.ip,
                                            &mut send_buf,
                                        ).await?;
                                    }
                                }
                            }
                            last_activity = Instant::now();
                        }
                        Ok(_) => {
                            info!("Connection closed by server");
                            break;
                        }
                        Err(e) => {
                            error!("Network read error: {}", e);
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
                            conn.write_all(ka).await?;
                            debug!("Sent keepalive");
                        }
                    }
                    
                    // Periodic gratuitous ARP
                    if arp.should_send_periodic_garp() {
                        let garp = arp.build_gratuitous_arp();
                        self.send_frame(conn, &garp, &mut send_buf).await?;
                        arp.mark_garp_sent();
                        debug!("Sent periodic GARP");
                    }
                }
            }
        }

        info!("Data loop ended");
        tun_reader.abort();
        Ok(())
    }

    /// Process an incoming Ethernet frame from the tunnel.
    async fn process_incoming_frame(
        &self,
        tun: &mut UtunDevice,
        conn: &mut VpnConnection,
        arp: &mut ArpHandler,
        frame: &[u8],
        our_ip: Ipv4Addr,
        send_buf: &mut [u8],
    ) -> Result<()> {
        if frame.len() < 14 {
            return Ok(());
        }

        // Check if it's addressed to us
        let dst_mac: [u8; 6] = frame[0..6].try_into().unwrap();
        if dst_mac != self.mac && dst_mac != BROADCAST_MAC {
            // Not for us
            return Ok(());
        }

        let ether_type = u16::from_be_bytes([frame[12], frame[13]]);

        match ether_type {
            0x0800 => {
                // IPv4 - extract and send to TUN
                if let Some(ip_packet) = unwrap_ethernet_to_ip(frame) {
                    // Verify destination IP matches ours
                    if ip_packet.len() >= 20 {
                        let dst_ip = Ipv4Addr::new(
                            ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]
                        );
                        
                        if dst_ip == our_ip || dst_ip.is_broadcast() || dst_ip.is_multicast() {
                            // Write to TUN device (with utun header)
                            let mut tun_buf = vec![0u8; ip_packet.len() + 4];
                            // Protocol family (AF_INET = 2)
                            tun_buf[0..4].copy_from_slice(&(libc::AF_INET as u32).to_be_bytes());
                            tun_buf[4..].copy_from_slice(ip_packet);
                            
                            let n = unsafe {
                                libc::write(
                                    tun.raw_fd(),
                                    tun_buf.as_ptr() as *const libc::c_void,
                                    tun_buf.len(),
                                )
                            };
                            
                            if n > 0 {
                                debug!("VPN -> TUN: {} bytes to {}", ip_packet.len(), dst_ip);
                            }
                        }
                    }
                }
            }
            0x0806 => {
                // ARP
                if let Some(reply) = arp.process_arp(frame) {
                    self.send_frame(conn, &reply, send_buf).await?;
                    debug!("Sent ARP reply");
                }
            }
            _ => {
                debug!("Unknown EtherType: 0x{:04X}", ether_type);
            }
        }

        Ok(())
    }
}
