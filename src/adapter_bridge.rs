use anyhow::Result;
use tracing::{debug, info, warn};
use std::time::{Duration, Instant};

#[cfg(feature = "adapter")]
use adapter::VirtualAdapter;

use super::VpnClient;
use crate::adapter_bridge_packets::generate_next_packet;

/// DHCP state machine (matches Zig implementation)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    Init,
    ArpAnnounceSent,
    Ipv6NaSent,
    Ipv6RsSent,
    DiscoverSent,
    OfferReceived,
    RequestSent,
    Configured,
}

/// Packet generator state
pub struct PacketGeneratorState {
    pub dhcp_state: DhcpState,
    pub last_state_change: Instant,
    pub last_dhcp_send: Instant,
    pub last_keepalive: Instant,
    pub dhcp_retry_count: u32,
    pub dhcp_xid: u32,
    pub our_mac: [u8; 6],
    pub our_ip: Option<[u8; 4]>,
    pub gateway_ip: Option<[u8; 4]>,
    pub gateway_mac: Option<[u8; 6]>,
    pub offered_ip: Option<[u8; 4]>,
    pub dhcp_server_ip: Option<[u8; 4]>,
    pub need_gateway_arp: bool,
    pub connection_start: Instant,
}

impl VpnClient {
    /// Start the virtual adapter and bi-directional bridging between the adapter and the session/dataplane
    ///
    /// This method creates a virtual network interface and establishes bidirectional packet forwarding
    /// between the adapter and the VPN dataplane. It sets up async tasks for continuous packet processing.
    ///
    /// Architecture:
    ///   VPN Server (L2) ←→ Translator ←→ utun Device (L3) ←→ Kernel
    ///
    /// The translator performs L2↔L3 conversion:
    ///   - Server → Client: Ethernet frames → IP packets (strip 14-byte header, handle ARP)
    ///   - Client → Server: IP packets → Ethernet frames (add 14-byte header with gateway MAC)
    ///
    /// Process Flow:
    ///   1. Create virtual adapter if not already exists
    ///   2. Set up bidirectional channels for packet forwarding
    ///   3. Spawn async tasks for adapter->dataplane and dataplane->adapter bridging
    ///   4. Mark bridging as ready
    ///
    /// Packet Flow:
    ///   - Adapter → Dataplane: Reads IP packets from utun, converts to Ethernet, forwards to VPN tunnel
    ///   - Dataplane → Adapter: Receives Ethernet frames from tunnel, converts to IP, writes to utun
    ///
    /// Concurrency:
    ///   - Adapter is moved into async tasks
    ///   - Uses Arc<Mutex<VirtualAdapter>> for shared access
    ///   - Separate tasks for each direction
    ///
    /// Parameters:
    ///   - mac_address: Optional MAC address for the virtual adapter
    ///
    /// Returns:
    ///   - Result<()>: Success or error during adapter/bridge setup
    pub(crate) async fn start_adapter_and_bridge(
        &mut self,
        mac_address: Option<String>,
    ) -> Result<()> {
        #[cfg(not(feature = "adapter"))]
        {
            // No adapter bridging when the adapter feature is disabled
            self.bridge_ready = false;
            return Ok(());
        }
        
        // Ensure adapter exists
        #[cfg(feature = "adapter")]
        {
            if self.adapter.is_none() {
                let name = self.config.client.interface_name.clone();
                self.adapter = Some(VirtualAdapter::new(name, mac_address));
                if let Some(adp) = &mut self.adapter {
                    adp.create().await?;
                }
            }

            // Generate deterministic MAC address from interface name
            let adapter_ref = self.adapter.as_ref().unwrap();
            let ifname = adapter_ref.name();
            let our_mac = self.generate_adapter_mac(ifname);
            
            // Move adapter into Arc<Mutex<>> for shared access across tasks
            let adapter = std::sync::Arc::new(tokio::sync::Mutex::new(
                self.adapter.take().unwrap()
            ));
            let adapter1 = adapter.clone();
            let adapter_for_arp = adapter.clone(); // Clone for ARP checking
            let adapter2 = adapter.clone();

            // Channel for adapter -> dataplane (IP → Ethernet)
            let (adapter_to_dp_tx, adapter_to_dp_rx) = tokio::sync::mpsc::unbounded_channel();
            let adapter_to_dp_tx_task2 = adapter_to_dp_tx.clone(); // Clone for task2
            self.dataplane
                .as_ref()
                .unwrap()
                .set_adapter_tx(adapter_to_dp_rx);

            // Channel for dataplane -> adapter (Ethernet → IP)
            let (dp_to_adapter_tx, mut dp_to_adapter_rx) = tokio::sync::mpsc::unbounded_channel();
            self.dataplane
                .as_ref()
                .unwrap()
                .set_adapter_rx(dp_to_adapter_tx);
            
            // Channel for DHCP responses (Task3 -> Task1)
            let (dhcp_response_tx, mut dhcp_response_rx) = tokio::sync::mpsc::unbounded_channel();

            // Task 1: Proactive packet generator (DHCP, ARP, keep-alive)
            // This mimics Zig's MacOsTunGetNextPacket() behavior
            let task1 = tokio::spawn(async move {
                // CRITICAL: Wait for session to fully transition to tunneling mode
                // before sending any packets. Without this delay, the TLS stream
                // may not be ready, causing TX to hang and RX to fail.
                // This matches Zig's StartTunnelingMode() behavior.
                info!("⏳ Waiting for session to fully establish before sending packets...");
                tokio::time::sleep(Duration::from_millis(500)).await;
                info!("✅ Session ready, starting packet generation");
                
                let mut state = PacketGeneratorState {
                    dhcp_state: DhcpState::Init,
                    last_state_change: Instant::now(),
                    last_dhcp_send: Instant::now(),
                    last_keepalive: Instant::now(),
                    dhcp_retry_count: 0,
                    dhcp_xid: rand::random::<u32>(),
                    our_mac,
                    our_ip: None,
                    gateway_ip: None,
                    gateway_mac: None,
                    offered_ip: None,
                    dhcp_server_ip: None,
                    need_gateway_arp: false,
                    connection_start: Instant::now(),
                };
                
                info!("🚀 Packet generator started with MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    our_mac[0], our_mac[1], our_mac[2], our_mac[3], our_mac[4], our_mac[5]);
                
                loop {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    
                    // Send proactive ARP request to learn gateway MAC
                    if state.dhcp_state == DhcpState::Configured && 
                       state.need_gateway_arp && 
                       state.gateway_mac.is_none() &&
                       state.gateway_ip.is_some() &&
                       state.our_ip.is_some() {
                        
                        // Send ARP request every 1 second until gateway MAC learned
                        if state.last_dhcp_send.elapsed() > Duration::from_secs(1) {
                            let gateway_ip = state.gateway_ip.unwrap();
                            let our_ip_arr = state.our_ip.unwrap();
                            let our_ip = std::net::Ipv4Addr::new(our_ip_arr[0], our_ip_arr[1], our_ip_arr[2], our_ip_arr[3]);
                            let gateway_ipv4 = std::net::Ipv4Addr::new(gateway_ip[0], gateway_ip[1], gateway_ip[2], gateway_ip[3]);
                            
                            // Build ARP request frame (42 bytes: 14 Ethernet + 28 ARP)
                            let mut arp_frame = vec![0u8; 42];
                            
                            // Ethernet header: broadcast destination
                            arp_frame[0..6].copy_from_slice(&[0xFF; 6]);
                            arp_frame[6..12].copy_from_slice(&our_mac);
                            arp_frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP
                            
                            // ARP header
                            arp_frame[14..16].copy_from_slice(&0x0001u16.to_be_bytes()); // Hardware: Ethernet
                            arp_frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // Protocol: IPv4
                            arp_frame[18] = 6; // Hardware size
                            arp_frame[19] = 4; // Protocol size
                            arp_frame[20..22].copy_from_slice(&0x0001u16.to_be_bytes()); // Operation: Request
                            arp_frame[22..28].copy_from_slice(&our_mac); // Sender MAC
                            arp_frame[28..32].copy_from_slice(&our_ip.octets()); // Sender IP
                            arp_frame[32..38].copy_from_slice(&[0x00; 6]); // Target MAC (unknown)
                            arp_frame[38..42].copy_from_slice(&gateway_ipv4.octets()); // Target IP
                            
                            info!("📡 Sending ARP request: Who has {}? Tell {}", gateway_ipv4, our_ip);
                            if let Err(e) = adapter_to_dp_tx.send(arp_frame) {
                                warn!("Failed to send ARP request: {}", e);
                            }
                            state.last_dhcp_send = Instant::now();
                        }
                        
                        // Check if translator learned gateway MAC
                        let adapter_lock = adapter_for_arp.lock().await;
                        if let Some((__gw_ip, gw_mac)) = adapter_lock.translator().gateway_info() {
                            info!("✅ Gateway MAC learned from translator: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                gw_mac[0], gw_mac[1], gw_mac[2], gw_mac[3], gw_mac[4], gw_mac[5]);
                            state.gateway_mac = Some(gw_mac);
                            state.need_gateway_arp = false;
                        }
                        drop(adapter_lock);
                    }
                    
                    // Check for DHCP responses from Task3
                    while let Ok(response) = dhcp_response_rx.try_recv() {
                        use crate::adapter_bridge_packets::DhcpResponse;
                        match response {
                            DhcpResponse::Offer { yiaddr, server_id, .. } => {
                                info!("📨 DHCP OFFER received: {}.{}.{}.{}", 
                                    yiaddr[0], yiaddr[1], yiaddr[2], yiaddr[3]);
                                state.offered_ip = Some(yiaddr);
                                state.dhcp_server_ip = Some(server_id);
                                state.dhcp_state = DhcpState::OfferReceived;
                                state.last_state_change = Instant::now();
                            }
                            DhcpResponse::Ack { yiaddr, mask, router, dns1, dns2 } => {
                                info!("✅ DHCP ACK received: IP={}.{}.{}.{}, Mask={}.{}.{}.{}, Gateway={}.{}.{}.{}",
                                    yiaddr[0], yiaddr[1], yiaddr[2], yiaddr[3],
                                    mask[0], mask[1], mask[2], mask[3],
                                    router[0], router[1], router[2], router[3]);
                                state.our_ip = Some(yiaddr);
                                state.gateway_ip = Some(router);
                                state.need_gateway_arp = true;
                                state.dhcp_state = DhcpState::Configured;
                                state.last_state_change = Instant::now();
                                
                                // Set gateway IP on translator for MAC learning
                                let gateway_ipv4 = std::net::Ipv4Addr::new(router[0], router[1], router[2], router[3]);
                                let mut adapter_lock = adapter_for_arp.lock().await;
                                adapter_lock.translator_mut().set_gateway_ip(gateway_ipv4);
                                drop(adapter_lock);
                                info!("🎯 Gateway IP configured on translator: {}", gateway_ipv4);
                                
                                if dns1[0] != 0 || dns1[1] != 0 || dns1[2] != 0 || dns1[3] != 0 {
                                    info!("🌐 DNS1: {}.{}.{}.{}", dns1[0], dns1[1], dns1[2], dns1[3]);
                                }
                                if dns2[0] != 0 || dns2[1] != 0 || dns2[2] != 0 || dns2[3] != 0 {
                                    info!("🌐 DNS2: {}.{}.{}.{}", dns2[0], dns2[1], dns2[2], dns2[3]);
                                }
                            }
                        }
                    }
                    
                    if let Some(packet) = generate_next_packet(&mut state).await {
                        // Debug frame details before sending
                        if packet.len() >= 14 {
                            let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
                            let frame_type = match ethertype {
                                0x0800 => "IPv4",
                                0x0806 => "ARP",
                                0x86DD => "IPv6",
                                _ => "Other",
                            };
                            info!(
                                "📤 Link TX (generated): {} frame to VPN (len={}, dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, src={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, type=0x{:04x})",
                                frame_type, packet.len(),
                                packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
                                packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
                                ethertype
                            );
                        }
                        debug!("📤 Generated packet: {} bytes, sending to dataplane", packet.len());
                        if let Err(e) = adapter_to_dp_tx.send(packet) {
                            warn!("Failed to send packet to dataplane: {}", e);
                            break;
                        }
                    }
                }
            });

            // Task 2: Read IP packets from utun, convert to Ethernet, send to VPN server
            let task2 = tokio::spawn(async move {
                loop {
                    let mut adapter_lock = adapter1.lock().await;
                    match adapter_lock.read_ip_packet().await {
                        Ok(Some(ip_packet)) => {
                            debug!(
                                "Adapter bridge: read IP packet from utun, len={}",
                                ip_packet.len()
                            );
                            
                            // Convert IP → Ethernet
                            match adapter_lock.translator_mut().ip_to_ethernet(&ip_packet) {
                                Ok(eth_frame) => {
                                    // Debug frame details before sending
                                    if eth_frame.len() >= 14 {
                                        let ethertype = u16::from_be_bytes([eth_frame[12], eth_frame[13]]);
                                        let frame_type = match ethertype {
                                            0x0800 => "IPv4",
                                            0x0806 => "ARP",
                                            0x86DD => "IPv6",
                                            _ => "Other",
                                        };
                                        info!(
                                            "📤 Link TX: {} frame to VPN (len={}, dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, src={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, type=0x{:04x})",
                                            frame_type, eth_frame.len(),
                                            eth_frame[0], eth_frame[1], eth_frame[2], eth_frame[3], eth_frame[4], eth_frame[5],
                                            eth_frame[6], eth_frame[7], eth_frame[8], eth_frame[9], eth_frame[10], eth_frame[11],
                                            ethertype
                                        );
                                    }
                                    debug!(
                                        "Adapter bridge: converted to Ethernet frame, len={}",
                                        eth_frame.len()
                                    );
                                    drop(adapter_lock); // Release lock before sending
                                    let _ = adapter_to_dp_tx_task2.send(eth_frame);
                                }
                                Err(e) => {
                                    warn!("Adapter bridge: failed to convert IP to Ethernet: {}", e);
                                }
                            }
                        }
                        Ok(None) => {
                            drop(adapter_lock);
                            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                        }
                        Err(e) => {
                            warn!("Adapter bridge: error reading from utun: {}", e);
                            break;
                        }
                    }
                }
            });

            // Task 3: Receive Ethernet frames from VPN server, convert to IP, write to utun
            let task3 = tokio::spawn(async move {
                info!("🔄 Task3 (VPN→utun) started, waiting for Ethernet frames from dataplane");
                while let Some(eth_frame) = dp_to_adapter_rx.recv().await {
                    // Debug frame details
                    if eth_frame.len() >= 14 {
                        let ethertype = u16::from_be_bytes([eth_frame[12], eth_frame[13]]);
                        let frame_type = match ethertype {
                            0x0800 => "IPv4",
                            0x0806 => "ARP",
                            0x86DD => "IPv6",
                            _ => "Other",
                        };
                        info!(
                            "📬 Link RX: {} frame from VPN (len={}, dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, src={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, type=0x{:04x})",
                            frame_type, eth_frame.len(),
                            eth_frame[0], eth_frame[1], eth_frame[2], eth_frame[3], eth_frame[4], eth_frame[5],
                            eth_frame[6], eth_frame[7], eth_frame[8], eth_frame[9], eth_frame[10], eth_frame[11],
                            ethertype
                        );
                    }
                    info!(
                        "📨 Task3: received Ethernet frame from dataplane, len={} bytes",
                        eth_frame.len()
                    );
                    
                    // Add hex dump for packets that might be DHCP (UDP port 67/68)
                    if eth_frame.len() >= 42 {
                        let ethertype = u16::from_be_bytes([eth_frame[12], eth_frame[13]]);
                        if ethertype == 0x0800 { // IPv4
                            // Get IP header length (IHL field in low 4 bits of first byte)
                            if eth_frame.len() >= 15 {
                                let ihl = (eth_frame[14] & 0x0F) as usize * 4;
                                let ip_proto = eth_frame.get(14 + 9).copied();
                                let udp_offset = 14 + ihl;
                                
                                if ip_proto == Some(17) && eth_frame.len() >= udp_offset + 4 { // UDP
                                    let src_port = u16::from_be_bytes([eth_frame[udp_offset], eth_frame[udp_offset + 1]]);
                                    let dst_port = u16::from_be_bytes([eth_frame[udp_offset + 2], eth_frame[udp_offset + 3]]);
                                    if src_port == 67 || dst_port == 68 || src_port == 68 || dst_port == 67 {
                                        info!("🔍 POTENTIAL DHCP PACKET (UDP {}→{}, IHL={}), len={}", src_port, dst_port, ihl, eth_frame.len());
                                        // Hex dump first 128 bytes (or full packet if smaller)
                                        let dump_len = eth_frame.len().min(128);
                                        let hex: String = eth_frame[..dump_len]
                                            .chunks(16)
                                            .enumerate()
                                            .map(|(i, chunk)| {
                                                let hex_part: String = chunk.iter()
                                                    .map(|b| format!("{:02x}", b))
                                                    .collect::<Vec<_>>()
                                                    .join(" ");
                                                format!("  {:04x}: {}", i * 16, hex_part)
                                            })
                                            .collect::<Vec<_>>()
                                            .join("\n");
                                        info!("📦 HEX DUMP (first {} bytes):\n{}", dump_len, hex);
                                    }
                                }
                            }
                        }
                    }
                    
                    // Check if this is a DHCP response before processing
                    if let Some(dhcp_response) = crate::adapter_bridge_packets::parse_dhcp_response(&eth_frame) {
                        info!("✅ DHCP RESPONSE PARSED: {:?}", dhcp_response);
                        let _ = dhcp_response_tx.send(dhcp_response);
                        // Don't write DHCP responses to utun - they're handled internally
                        continue;
                    }
                    
                    let mut adapter_lock = adapter2.lock().await;
                    
                    // Convert Ethernet → IP (handles ARP internally)
                    match adapter_lock.translator_mut().ethernet_to_ip(&eth_frame) {
                        Ok(Some(ip_packet)) => {
                            debug!(
                                "Adapter bridge: converted to IP packet, len={}",
                                ip_packet.len()
                            );
                            
                            // Write IP packet to utun
                            if let Err(e) = adapter_lock.write_ip_packet(&ip_packet).await {
                                warn!("Failed to write IP packet to utun: {}", e);
                                break;
                            } else {
                                debug!(
                                    "Adapter bridge: wrote IP packet to utun, len={}",
                                    ip_packet.len()
                                );
                            }
                        }
                        Ok(None) => {
                            // ARP handled internally, no IP packet to write
                            debug!("Adapter bridge: ARP frame handled internally");
                        }
                        Err(e) => {
                            warn!("Adapter bridge: failed to convert Ethernet to IP: {}", e);
                        }
                    }
                }
            });

            self.aux_tasks.push(task1);
            self.aux_tasks.push(task2);
            self.aux_tasks.push(task3);

            // Store adapter back (wrapped in Arc)
            // Note: We can't put it back because it's moved into Arc
            // This is a design trade-off - adapter is now shared across tasks

            info!("Adapter bridging started successfully with L2/L3 translation");
            self.bridge_ready = true;
        }
        
        Ok(())
    }
}
