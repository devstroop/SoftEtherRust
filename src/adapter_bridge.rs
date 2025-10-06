use anyhow::Result;
use tracing::{debug, info, warn, trace};
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
                    info!(
                        "📨 Task3: received Ethernet frame from dataplane, len={} bytes",
                        eth_frame.len()
                    );
                    
                    // Check if this is a DHCP response before processing
                    if let Some(dhcp_response) = crate::adapter_bridge_packets::parse_dhcp_response(&eth_frame) {
                        trace!("📬 Parsed DHCP response, forwarding to packet generator");
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
