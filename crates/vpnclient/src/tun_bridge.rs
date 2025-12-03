//! TUN/TAP device bridge for macOS
//!
//! This module bridges the DataPlane with the OS utun device, enabling
//! bidirectional packet flow between the VPN tunnel and the operating system.
//!
//! **Key Architecture Change**: Uses VirtualTap L2↔L3 translator
//! - SoftEther protocol is Layer 2 (Ethernet frames)
//! - macOS utun is Layer 3 (IP packets)
//! - VirtualTap handles translation + ARP internally
//!
//! Architecture:
//!   OS → utun (IP) → [L3→L2] VirtualTap → DataPlane → VPN Links → Server
//!   Server → VPN Links → DataPlane → [L2→L3] VirtualTap → utun (IP) → OS

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use virtualtap::{VirtualTap, VirtualTapConfig, TunDevice, RouteManager, build_dhcp_discover, build_dhcp_request};
use std::sync::{Arc, Mutex};

/// DHCP state machine
#[derive(Debug, Clone, Copy, PartialEq)]
enum DhcpState {
    Init,
    Discovering,
    OfferReceived,
    Requesting,
    Bound,
}

/// Shared DHCP state between tasks
#[derive(Debug, Clone)]
struct DhcpSharedState {
    state: Arc<Mutex<DhcpState>>,
    xid: Arc<Mutex<u32>>,
    offered_ip: Arc<Mutex<u32>>,
    server_ip: Arc<Mutex<u32>>,
    // ✅ Cache OFFER values (server sends abbreviated ACK without these)
    cached_subnet_mask: Arc<Mutex<[u8; 4]>>,
    cached_gateway: Arc<Mutex<[u8; 4]>>,
    cached_dns_servers: Arc<Mutex<Vec<[u8; 4]>>>,
    // Route manager (kept alive for session duration)
    route_manager: Arc<Mutex<Option<RouteManager>>>,
}

impl DhcpSharedState {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(DhcpState::Init)),
            xid: Arc::new(Mutex::new(rand::random())),
            offered_ip: Arc::new(Mutex::new(0)),
            server_ip: Arc::new(Mutex::new(0)),
            cached_subnet_mask: Arc::new(Mutex::new([0, 0, 0, 0])),
            cached_gateway: Arc::new(Mutex::new([0, 0, 0, 0])),
            cached_dns_servers: Arc::new(Mutex::new(Vec::new())),            route_manager: Arc::new(Mutex::new(None)),        }
    }
}

/// Maximum packet size for TUN device
const MAX_PACKET_SIZE: usize = 2048;

// TunDevice is now imported from virtualtap crate (pure Rust implementation)

/// Spawn bidirectional bridge tasks between TUN device and DataPlane
/// with L2↔L3 translation via VirtualTap
///
/// # Arguments
/// * `dataplane` - The DataPlane instance
/// * `mac_address` - MAC address for the virtual adapter
/// * `server_ip` - Optional VPN server IP for host route configuration
///
/// # Returns
/// Tuple of (tun_device_name, l2_injection_tx, rx_task, tx_task, l2_inject_task)
/// where l2_injection_tx is a channel for injecting L2 Ethernet frames (for DHCP)
pub fn spawn_tun_bridge(
    dataplane: cedar::DataPlane,
    mac_address: [u8; 6],
    server_ip: Option<[u8; 4]>,
) -> Result<(String, mpsc::UnboundedSender<Vec<u8>>, tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    info!("Starting TUN bridge with VirtualTap L2↔L3 translation");

    // Create shared DHCP state
    let dhcp_state = DhcpSharedState::new();

    // Create TUN device
    let tun_device = TunDevice::create()
        .map_err(|e| anyhow::anyhow!("Failed to create TUN device: {}", e))?;
    
    let device_name = tun_device.name().to_string();
    let device_name_for_routes = device_name.clone(); // Clone for route configuration
    info!("TUN device created: {} (fd={})", device_name, tun_device.fd());

    // Create VirtualTap translator (pure Rust!)
    let config = VirtualTapConfig {
        our_mac: mac_address,
        verbose: true,  // Enable verbose logging to see gateway MAC usage
    };

    let translator = VirtualTap::new(config);
    let translator = std::sync::Arc::new(translator);

    // Create channels for bidirectional communication
    let (tun_to_dp_tx, tun_to_dp_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (dp_to_tun_tx, mut dp_to_tun_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    
    // Create L2 injection channel for DHCP (Ethernet frames that need to go to DataPlane)
    let (l2_inject_tx, mut l2_inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Wire DataPlane to channels
    dataplane.set_adapter_rx(dp_to_tun_tx.clone()); // DataPlane → TUN (receives L2 frames)
    dataplane.set_adapter_tx(tun_to_dp_rx);          // TUN → DataPlane (sends L2 frames)

    // Clone for tasks
    let tun_rx = std::sync::Arc::new(tun_device);
    let tun_tx = tun_rx.clone();
    let translator_rx = translator.clone();
    let translator_tx = translator.clone();
    let tun_to_dp_tx_clone = tun_to_dp_tx.clone(); // Clone for TX task (ARP replies)
    let dataplane_for_l2_inject = dataplane.clone(); // Clone for L2 injection (DHCP)

    // Task 1: TUN RX (OS → DataPlane)
    // Reads IP packets from utun, converts to Ethernet frames, sends to DataPlane
    let rx_task = tokio::task::spawn_blocking(move || {
        info!("TUN RX task started (OS → VirtualTap → DataPlane)");
        
        loop {
            // Read IP packet from TUN device
            let ip_packet = match tun_rx.read() {
                Ok(Some(pkt)) => pkt,
                Ok(None) => {
                    // No data available (non-blocking)
                    std::thread::sleep(std::time::Duration::from_micros(100));
                    continue;
                }
                Err(e) => {
                    warn!("TUN RX: read error: {}", e);
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
            };
            
            if ip_packet.is_empty() {
                continue;
            }
            
            debug!("TUN RX: received {} bytes IP packet from OS", ip_packet.len());
            
            // Convert IP packet (L3) to Ethernet frame (L2) using pure Rust VirtualTap
            let eth_frame = match translator_rx.ip_to_ethernet(&ip_packet) {
                Ok(frame) => frame,
                Err(e) => {
                    warn!("TUN RX: L3→L2 translation failed: {}", e);
                    continue;
                }
            };
            
            debug!("TUN RX: translated {} bytes IP → {} bytes Ethernet", ip_packet.len(), eth_frame.len());
            
            // Send Ethernet frame to DataPlane
            if let Err(e) = tun_to_dp_tx.send(eth_frame) {
                warn!("TUN RX: DataPlane channel closed: {}", e);
                break;
            }
        }
        
        info!("TUN RX task ended");
    });

    // Task 2: TUN TX (DataPlane → OS) + DHCP Intercept
    // Receives Ethernet frames from DataPlane, converts to IP packets, writes to utun
    // ALSO intercepts DHCP OFFER from server and automatically sends DHCP REQUEST
    let dhcp_state_tx = dhcp_state.clone();
    let l2_inject_dhcp_response = l2_inject_tx.clone();
    let mac_for_dhcp = mac_address;
    let tx_task = tokio::task::spawn_blocking(move || {
        info!("TUN TX task started (DataPlane → VirtualTap → OS) + DHCP intercept");
        
        // Create a runtime for receiving from async channel
        let rt = tokio::runtime::Handle::current();
        
        loop {
            // Block on async channel receive
            let eth_frame = match rt.block_on(dp_to_tun_rx.recv()) {
                Some(frame) => frame,
                None => {
                    warn!("TUN TX: DataPlane channel closed");
                    break;
                }
            };
            
            debug!("TUN TX: received {} bytes Ethernet frame from DataPlane", eth_frame.len());
            
            // ✅ ARP INTERCEPT: Handle ARP requests from server (bridge mode)
            if let Some(arp_info) = virtualtap::parse_arp(&eth_frame) {
                // **ALWAYS learn gateway MAC from ANY ARP packet from gateway IP**
                let gateway_ip = *dhcp_state_tx.server_ip.lock().unwrap();
                if gateway_ip != 0 {
                    let sender_ip_u32 = u32::from_be_bytes(arp_info.sender_ip);
                    if sender_ip_u32 == gateway_ip || arp_info.sender_ip == [10, 21, 0, 1] {
                        // Learn gateway MAC from this ARP packet
                        info!("[ARP] ✅ Learned gateway MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} from IP {}.{}.{}.{}",
                            arp_info.sender_mac[0], arp_info.sender_mac[1], arp_info.sender_mac[2],
                            arp_info.sender_mac[3], arp_info.sender_mac[4], arp_info.sender_mac[5],
                            arp_info.sender_ip[0], arp_info.sender_ip[1], arp_info.sender_ip[2], arp_info.sender_ip[3]);
                        
                        // Tell VirtualTap about gateway IP so it can learn MAC for L3→L2
                        translator_tx.set_gateway_ip(sender_ip_u32);
                    }
                }
                
                if arp_info.operation == 1 { // ARP Request
                    info!("[ARP] Request: who-has {}.{}.{}.{} tell {}.{}.{}.{}",
                        arp_info.target_ip[0], arp_info.target_ip[1], arp_info.target_ip[2], arp_info.target_ip[3],
                        arp_info.sender_ip[0], arp_info.sender_ip[1], arp_info.sender_ip[2], arp_info.sender_ip[3]);
                    
                    // ✅ CRITICAL: Learn gateway MAC from ANY ARP request from likely gateway (.0.1)
                    // The gateway always sends ARPs with its MAC - learn it immediately!
                    // This is essential for L3→L2 translation when sending packets back
                    if arp_info.sender_ip[2] == 0 && arp_info.sender_ip[3] == 1 {
                        translator_tx.set_gateway_mac(arp_info.sender_mac);
                        info!("[ARP] 🎯 Learned gateway MAC from {}.{}.{}.{}: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            arp_info.sender_ip[0], arp_info.sender_ip[1], arp_info.sender_ip[2], arp_info.sender_ip[3],
                            arp_info.sender_mac[0], arp_info.sender_mac[1], arp_info.sender_mac[2],
                            arp_info.sender_mac[3], arp_info.sender_mac[4], arp_info.sender_mac[5]);
                    }
                    
                    // Check if we have an assigned IP from DHCP
                    let our_ip = *dhcp_state_tx.offered_ip.lock().unwrap();
                    if our_ip != 0 {
                        let our_ip_bytes = our_ip.to_be_bytes();
                        let target_ip_u32 = u32::from_be_bytes(arp_info.target_ip);
                        
                        // If ARP is asking for OUR IP, send ARP reply
                        if target_ip_u32 == our_ip {
                            info!("[ARP] ✅ Sending ARP reply: {} is at {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                format!("{}.{}.{}.{}", our_ip_bytes[0], our_ip_bytes[1], our_ip_bytes[2], our_ip_bytes[3]),
                                mac_for_dhcp[0], mac_for_dhcp[1], mac_for_dhcp[2], mac_for_dhcp[3], mac_for_dhcp[4], mac_for_dhcp[5]);
                            
                            let arp_reply = virtualtap::build_arp_reply(
                                mac_for_dhcp,
                                our_ip_bytes,
                                arp_info.sender_mac,
                                arp_info.sender_ip,
                            );
                            
                            if let Err(e) = l2_inject_dhcp_response.send(arp_reply) {
                                warn!("[ARP] Failed to send ARP reply: {}", e);
                            }
                        }
                    }
                }
                // Don't process ARP packets further, return to loop
                continue;
            }
            
            // ✅ DHCP INTERCEPT: Check if this is a DHCP OFFER or ACK from server
            // Use VirtualTap's try_parse_dhcp method (internal parsing)
            let dhcp_check = {
                // Parse DHCP manually since try_parse_dhcp is private
                translator_tx.ethernet_to_ip(&eth_frame).ok(); // This will trigger internal DHCP parsing
                
                // For now, check if it's DHCP by looking at packet structure
                if eth_frame.len() > 282 { // Min DHCP size
                    // Check for DHCP signature
                    if eth_frame.len() >= 14 + 20 + 8 + 236 {
                        let ethertype = u16::from_be_bytes([eth_frame[12], eth_frame[13]]);
                        if ethertype == 0x0800 { // IPv4
                            let ip_start = 14;
                            let ip_proto = eth_frame[ip_start + 9];
                            if ip_proto == 17 { // UDP
                                let ihl = ((eth_frame[ip_start] & 0x0F) * 4) as usize;
                                let udp_start = ip_start + ihl;
                                if eth_frame.len() > udp_start + 8 {
                                    let src_port = u16::from_be_bytes([eth_frame[udp_start], eth_frame[udp_start + 1]]);
                                    let dst_port = u16::from_be_bytes([eth_frame[udp_start + 2], eth_frame[udp_start + 3]]);
                                    
                                    // Check if DHCP ports
                                    if (src_port == 67 && dst_port == 68) || (src_port == 68 && dst_port == 67) {
                                        // Parse DHCP using the exported parse_dhcp function
                                        let udp_payload = &eth_frame[udp_start + 8..];
                                        virtualtap::parse_dhcp(udp_payload)
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            
            if let Some(dhcp_info) = dhcp_check {
                // Note: parse_dhcp doesn't return xid, we track it separately in shared state
                match dhcp_info.message_type {
                        2 => { // DHCP OFFER
                            let offered_ip = u32::from_be_bytes(dhcp_info.offered_ip);
                            let server_ip = u32::from_be_bytes(dhcp_info.server_ip);
                            
                            info!("[DHCP] ✅ OFFER received: IP={}.{}.{}.{} from server {}.{}.{}.{}",
                                dhcp_info.offered_ip[0], dhcp_info.offered_ip[1], dhcp_info.offered_ip[2], dhcp_info.offered_ip[3],
                                dhcp_info.server_ip[0], dhcp_info.server_ip[1], dhcp_info.server_ip[2], dhcp_info.server_ip[3]);
                            
                            // ✅ Cache OFFER values (server sends abbreviated ACK without options!)
                            *dhcp_state_tx.cached_subnet_mask.lock().unwrap() = dhcp_info.subnet_mask;
                            *dhcp_state_tx.cached_gateway.lock().unwrap() = dhcp_info.gateway;
                            *dhcp_state_tx.cached_dns_servers.lock().unwrap() = dhcp_info.dns_servers.clone();
                            
                            info!("[DHCP] 💾 Cached from OFFER: Mask={}.{}.{}.{}, Gateway={}.{}.{}.{}, DNS={}",
                                dhcp_info.subnet_mask[0], dhcp_info.subnet_mask[1], dhcp_info.subnet_mask[2], dhcp_info.subnet_mask[3],
                                dhcp_info.gateway[0], dhcp_info.gateway[1], dhcp_info.gateway[2], dhcp_info.gateway[3],
                                dhcp_info.dns_servers.len());
                            
                            // Update state
                            *dhcp_state_tx.state.lock().unwrap() = DhcpState::OfferReceived;
                            *dhcp_state_tx.offered_ip.lock().unwrap() = offered_ip;
                            *dhcp_state_tx.server_ip.lock().unwrap() = server_ip;
                            
                            // Send DHCP REQUEST immediately
                            info!("[DHCP] Sending REQUEST for IP={}.{}.{}.{}",
                                dhcp_info.offered_ip[0], dhcp_info.offered_ip[1], dhcp_info.offered_ip[2], dhcp_info.offered_ip[3]);
                            
                            let current_xid = *dhcp_state_tx.xid.lock().unwrap();
                            let request = build_dhcp_request(mac_for_dhcp, current_xid, offered_ip.to_be_bytes(), server_ip.to_be_bytes());
                            if let Err(e) = l2_inject_dhcp_response.send(request) {
                                warn!("[DHCP] Failed to send REQUEST: {}", e);
                            } else {
                                *dhcp_state_tx.state.lock().unwrap() = DhcpState::Requesting;
                                info!("[DHCP] REQUEST sent to server");
                            }
                        }
                        5 => { // DHCP ACK
                            // ✅ Use cached OFFER values (server sends abbreviated ACK without options!)
                            let subnet_mask = *dhcp_state_tx.cached_subnet_mask.lock().unwrap();
                            let gateway = *dhcp_state_tx.cached_gateway.lock().unwrap();
                            let dns_servers = dhcp_state_tx.cached_dns_servers.lock().unwrap().clone();
                            
                            info!("[●] DHCP: Assigned IP {}.{}.{}.{}", dhcp_info.offered_ip[0], dhcp_info.offered_ip[1], dhcp_info.offered_ip[2], dhcp_info.offered_ip[3]);
                            info!("[●] DHCP: Subnet mask {}.{}.{}.{}", subnet_mask[0], subnet_mask[1], subnet_mask[2], subnet_mask[3]);
                            info!("[●] DHCP: Gateway {}.{}.{}.{}", gateway[0], gateway[1], gateway[2], gateway[3]);
                            if !dns_servers.is_empty() {
                                let dns_strs: Vec<String> = dns_servers.iter()
                                    .map(|dns| format!("{}.{}.{}.{}", dns[0], dns[1], dns[2], dns[3]))
                                    .collect();
                                info!("[●] DHCP: DNS servers: {}", dns_strs.join(", "));
                            }
                            
                            *dhcp_state_tx.state.lock().unwrap() = DhcpState::Bound;
                            
                            // ✅ Apply route configuration for full tunnel mode
                            let device_name_clone = device_name_for_routes.clone();
                            let dhcp_state_for_routes = dhcp_state_tx.clone();
                            tokio::spawn(async move {
                                let mut route_mgr = RouteManager::new();
                                
                                // 1. Get and save original default gateway
                                if let Err(e) = route_mgr.get_default_gateway() {
                                    warn!("Failed to get default gateway: {}", e);
                                    return;
                                }
                                
                                // 2. Configure TUN interface with IP and netmask
                                if let Err(e) = route_mgr.configure_interface(
                                    &device_name_clone,
                                    dhcp_info.offered_ip,
                                    subnet_mask,
                                ) {
                                    warn!("Failed to configure interface: {}", e);
                                    return;
                                }
                                
                                // 3. Host route for VPN server was already added in vpnclient.rs
                                // BEFORE the data link was established (critical for connection stability)
                                // We don't add it again here to avoid duplicate route errors
                                
                                // 4. Replace default gateway with VPN gateway (full tunnel mode)
                                if let Err(e) = route_mgr.replace_default_gateway(gateway) {
                                    warn!("Failed to replace default gateway: {}", e);
                                    return;
                                }
                                
                                info!("[●] VPN: Full tunnel mode configured successfully");
                                
                                // Store RouteManager in shared state to keep it alive
                                // It will be dropped when the VPN disconnects
                                *dhcp_state_for_routes.route_manager.lock().unwrap() = Some(route_mgr);
                            });
                        }
                        _ => {}
                }
            }
            
            // Convert Ethernet frame (L2) to IP packet (L3) using pure Rust VirtualTap
            let result = translator_tx.ethernet_to_ip(&eth_frame);
            
            match result {
                Ok(Some(ip_packet)) => {
                    // IP packet extracted - send to TUN device
                    debug!("TUN TX: translated {} bytes Ethernet → {} bytes IP", eth_frame.len(), ip_packet.len());
                    
                    match tun_tx.write(&ip_packet) {
                        Ok(n) => {
                            if n != ip_packet.len() {
                                warn!("TUN TX: partial write ({}/{})", n, ip_packet.len());
                            }
                        }
                        Err(e) => {
                            warn!("TUN TX: write error: {}", e);
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                    }
                }
                Ok(None) => {
                    // Non-IP packet (e.g., ARP) - ignored by TUN device
                    debug!("TUN TX: Non-IP packet ignored");
                }
                Err(e) => {
                    warn!("TUN TX: L2→L3 translation failed: {}", e);
                }
            }
        }
        
        info!("TUN TX task ended");
    });

    // Task 3: Forward L2 injection frames to DataPlane (for DHCP)
    let l2_inject_task = tokio::spawn(async move {
        info!("L2 injection forwarder started");
        while let Some(frame) = l2_inject_rx.recv().await {
            debug!("L2 injection: received {} bytes, calling DataPlane::send_frame()", frame.len());
            if !dataplane_for_l2_inject.send_frame(frame) {
                warn!("L2 injection: DataPlane::send_frame() failed");
                break;
            }
            debug!("L2 injection: successfully sent to DataPlane");
        }
        info!("L2 injection forwarder ended");
    });

    // Task 4: DHCP client (sends DISCOVER/REQUEST, waits for OFFER/ACK from server)
    let l2_inject_dhcp = l2_inject_tx.clone();
    let dhcp_state_discover = dhcp_state.clone();
    let dhcp_task = tokio::spawn(async move {
        info!("[DHCP] Starting DHCP client (sends to server via DataPlane)");
        
        // Wait 2 seconds for session AND data link to be fully established
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        
        // Get XID from shared state
        let xid = *dhcp_state_discover.xid.lock().unwrap();
        info!("[DHCP] Sending DISCOVER (xid=0x{:08x}, MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
            xid, mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);
        
        // Update state
        *dhcp_state_discover.state.lock().unwrap() = DhcpState::Discovering;
        
        // Send DHCP DISCOVER
        let discover = build_dhcp_discover(mac_address, xid);
        if let Err(e) = l2_inject_dhcp.send(discover) {
            warn!("[DHCP] Failed to send DISCOVER: {}", e);
            return;
        }
        
        info!("[DHCP] DISCOVER sent to server, waiting for OFFER...");
        info!("[DHCP] (OFFER will be intercepted by TX task and REQUEST sent automatically)");
        
        // Note: DHCP OFFER/ACK will be received in the DataPlane → TUN RX path
        // The TX task will intercept them and automatically send REQUEST/apply config
    });

    Ok((device_name, l2_inject_tx, rx_task, tx_task, l2_inject_task, dhcp_task))
}
