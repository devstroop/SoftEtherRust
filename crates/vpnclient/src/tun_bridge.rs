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
use virtualtap::{TunDevice, VirtualTapConfig, VirtualTapTranslator};

/// Maximum packet size for TUN device
const MAX_PACKET_SIZE: usize = 2048;

/// Spawn bidirectional bridge tasks between TUN device and DataPlane
/// with L2↔L3 translation via VirtualTap
///
/// # Arguments
/// * `dataplane` - The DataPlane instance
/// * `mac_address` - MAC address for the virtual adapter
///
/// # Returns
/// Tuple of (tun_device_name, l2_injection_tx, rx_task, tx_task, l2_inject_task)
/// where l2_injection_tx is a channel for injecting L2 Ethernet frames (for DHCP)
pub fn spawn_tun_bridge(
    dataplane: cedar::DataPlane,
    mac_address: [u8; 6],
) -> Result<(String, mpsc::UnboundedSender<Vec<u8>>, tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    info!("Starting TUN bridge with VirtualTap L2↔L3 translation");

    // Create TUN device
    let tun_device = TunDevice::create()
        .map_err(|e| anyhow::anyhow!("Failed to create TUN device: {}", e))?;
    
    let device_name = tun_device.name().to_string();
    info!("TUN device created: {} (fd={})", device_name, tun_device.fd());

    // Create VirtualTap translator
    let config = VirtualTapConfig {
        our_mac: mac_address,
        our_ip: 0,              // Will be learned from DHCP
        gateway_ip: 0,          // Will be learned from DHCP
        gateway_mac: [0; 6],    // Will be learned from ARP
        handle_arp: true,       // Let VirtualTap handle ARP internally
        learn_ip: true,         // Auto-learn IP from DHCP packets
        learn_gateway_mac: true, // Auto-learn gateway MAC from ARP
        enable_dns_cache: true,
        verbose: true,          // Enable verbose logging to debug protocol issues
    };

    let translator = VirtualTapTranslator::new(config)
        .ok_or_else(|| anyhow::anyhow!("Failed to create VirtualTap translator"))?;
    
    let translator = std::sync::Arc::new(std::sync::Mutex::new(translator));

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
    let tun_to_dp_tx_l2_inject = tun_to_dp_tx.clone(); // Clone for L2 injection

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
            
            // Convert IP packet (L3) to Ethernet frame (L2)
            let eth_frame = match translator_rx.lock() {
                Ok(mut t) => match t.ip_to_ethernet(&ip_packet) {
                    Ok(frame) => frame,
                    Err(e) => {
                        warn!("TUN RX: L3→L2 translation failed (error={})", e);
                        continue;
                    }
                },
                Err(e) => {
                    warn!("TUN RX: Failed to lock translator: {}", e);
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

    // Task 2: TUN TX (DataPlane → OS)
    // Receives Ethernet frames from DataPlane, converts to IP packets, writes to utun
    let tx_task = tokio::task::spawn_blocking(move || {
        info!("TUN TX task started (DataPlane → VirtualTap → OS)");
        
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
            
            // Convert Ethernet frame (L2) to IP packet (L3)
            let result = match translator_tx.lock() {
                Ok(mut t) => t.ethernet_to_ip(&eth_frame),
                Err(e) => {
                    warn!("TUN TX: Failed to lock translator: {}", e);
                    continue;
                }
            };
            
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
                    // ARP packet handled internally by VirtualTap
                    debug!("TUN TX: ARP packet handled by VirtualTap");
                    
                    // Check for pending ARP replies to send back to server
                    if let Ok(mut t) = translator_tx.lock() {
                        while t.has_pending_arp_reply() {
                            match t.pop_arp_reply() {
                                Ok(Some(arp_reply)) => {
                                    debug!("TUN TX: Sending ARP reply back to server ({} bytes)", arp_reply.len());
                                    if let Err(e) = tun_to_dp_tx_clone.send(arp_reply) {
                                        warn!("TUN TX: Failed to send ARP reply: {}", e);
                                        break;
                                    }
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    warn!("TUN TX: Failed to pop ARP reply (error={})", e);
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("TUN TX: L2→L3 translation failed (error={})", e);
                }
            }
        }
        
        info!("TUN TX task ended");
    });

    // Task 3: Forward L2 injection frames to DataPlane (for DHCP)
    let l2_inject_task = tokio::spawn(async move {
        info!("L2 injection forwarder started");
        while let Some(frame) = l2_inject_rx.recv().await {
            debug!("L2 injection: received {} bytes, forwarding to DataPlane", frame.len());
            if let Err(e) = tun_to_dp_tx_l2_inject.send(frame) {
                warn!("L2 injection: Failed to forward frame to DataPlane: {}", e);
                break;
            }
            debug!("L2 injection: successfully forwarded to DataPlane");
        }
        info!("L2 injection forwarder ended");
    });

    Ok((device_name, l2_inject_tx, rx_task, tx_task, l2_inject_task))
}
