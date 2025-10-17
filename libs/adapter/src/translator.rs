//! L2↔L3 Protocol Translator
//!
//! Handles bidirectional conversion between Layer 2 (Ethernet frames) and Layer 3 (IP packets).
//! This is critical for using TUN devices (L3) with protocols that expect TAP devices (L2).
//!
//! Key responsibilities:
//! - Convert IP packets → Ethernet frames (for sending to VPN)
//! - Convert Ethernet frames → IP packets (for writing to TUN)
//! - Learn gateway MAC address from ARP replies
//! - Handle ARP requests/replies internally

use anyhow::{Context, Result};
use log::{debug, info, trace, warn};
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::arp::ArpHandler;

/// Configuration options for the translator
#[derive(Debug, Clone)]
pub struct TranslatorOptions {
    /// Our MAC address
    pub our_mac: [u8; 6],
    /// Learn our IP from outgoing packets
    pub learn_ip: bool,
    /// Verbose logging
    pub verbose: bool,
}

impl Default for TranslatorOptions {
    fn default() -> Self {
        Self {
            our_mac: [0x5E, 0x00, 0x53, 0xFF, 0xFF, 0xFF], // SoftEther default
            learn_ip: true,
            verbose: false,
        }
    }
}

/// L2/L3 Protocol Translator
///
/// Converts between Ethernet frames (Layer 2) and IP packets (Layer 3).
/// This is essential because:
/// - SoftEther VPN protocol works at Layer 2 (sends/receives Ethernet frames)
/// - TUN devices work at Layer 3 (send/receive IP packets only)
pub struct L2L3Translator {
    options: TranslatorOptions,
    
    // Learned network information
    our_ip: Option<Ipv4Addr>,
    gateway_ip: Option<Ipv4Addr>,
    gateway_mac: Option<[u8; 6]>,
    last_gateway_learn: u64,
    
    // ARP handling
    arp_handler: ArpHandler,
    
    // ARP reply queue (for replies that need to be sent back to VPN)
    arp_reply_queue: Vec<Vec<u8>>,
    
    // Statistics
    packets_translated_l2_to_l3: u64,
    packets_translated_l3_to_l2: u64,
    arp_requests_handled: u64,
    arp_replies_learned: u64,
}

impl L2L3Translator {
    /// Create a new L2/L3 translator
    pub fn new(options: TranslatorOptions) -> Self {
        let our_mac = options.our_mac;
        Self {
            arp_handler: ArpHandler::new(our_mac),
            options,
            our_ip: None,
            gateway_ip: None,
            gateway_mac: None,
            last_gateway_learn: 0,
            arp_reply_queue: Vec::new(),
            packets_translated_l2_to_l3: 0,
            packets_translated_l3_to_l2: 0,
            arp_requests_handled: 0,
            arp_replies_learned: 0,
        }
    }
    
    /// Set the gateway IP address
    pub fn set_gateway_ip(&mut self, gateway_ip: Ipv4Addr) {
        debug!("Setting gateway IP: {}", gateway_ip);
        self.gateway_ip = Some(gateway_ip);
    }
    
    /// Set the gateway MAC address (learned from DHCP response)
    /// This is what Zig does: zig_adapter_set_gateway_mac(ctx->zig_adapter, gateway_mac)
    pub fn set_gateway_mac(&mut self, gateway_mac: [u8; 6]) {
        debug!("Setting gateway MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            gateway_mac[0], gateway_mac[1], gateway_mac[2], gateway_mac[3], gateway_mac[4], gateway_mac[5]);
        self.gateway_mac = Some(gateway_mac);
    }
    
    /// Get the learned gateway MAC address
    pub fn gateway_mac(&self) -> Option<[u8; 6]> {
        self.gateway_mac
    }
    
    /// Get our IP address (if learned)
    pub fn our_ip(&self) -> Option<Ipv4Addr> {
        self.our_ip
    }
    
    /// Get both gateway IP and MAC (if learned)
    pub fn gateway_info(&self) -> Option<(Ipv4Addr, [u8; 6])> {
        match (self.gateway_ip, self.gateway_mac) {
            (Some(ip), Some(mac)) => Some((ip, mac)),
            _ => None,
        }
    }
    
    /// Get statistics
    pub fn stats(&self) -> TranslatorStats {
        TranslatorStats {
            l2_to_l3: self.packets_translated_l2_to_l3,
            l3_to_l2: self.packets_translated_l3_to_l2,
            arp_handled: self.arp_requests_handled,
            arp_learned: self.arp_replies_learned,
        }
    }
    
    /// Convert IP packet (L3) → Ethernet frame (L2)
    /// Used when sending packets from TUN device to VPN (which expects Ethernet)
    pub fn ip_to_ethernet(&mut self, ip_packet: &[u8]) -> Result<Vec<u8>> {
        if ip_packet.is_empty() {
            return Err(anyhow::anyhow!("Empty IP packet"));
        }
        
        // Learn our IP from source address if enabled
        if self.options.learn_ip && self.our_ip.is_none() {
            if ip_packet.len() >= 20 && (ip_packet[0] & 0xF0) == 0x40 {
                // IPv4 packet
                let src_ip_bytes = [ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]];
                let src_ip = Ipv4Addr::from(src_ip_bytes);
                
                // Ignore link-local addresses (169.254.x.x)
                if !src_ip.is_link_local() {
                    self.our_ip = Some(src_ip);
                    if self.options.verbose {
                        info!("🔍 Learned our IP: {}", src_ip);
                    }
                    
                    // If we don't have a gateway IP configured, guess it as .1 of our subnet
                    if self.gateway_ip.is_none() {
                        let octets = src_ip.octets();
                        let gateway = Ipv4Addr::new(octets[0], octets[1], octets[2], 1);
                        self.gateway_ip = Some(gateway);
                        if self.options.verbose {
                            info!("💡 Auto-configured gateway IP as: {}", gateway);
                        }
                    }
                }
            }
        }
        
        // Determine EtherType and destination MAC
        let ethertype: u16;
        let dest_mac: [u8; 6];
        
        let version = (ip_packet[0] & 0xF0) >> 4;
        match version {
            4 => {
                // IPv4 packet
                ethertype = 0x0800;
                
                // Use learned gateway MAC if available, otherwise broadcast
                dest_mac = self.gateway_mac.unwrap_or([0xFF; 6]);
                
                if self.gateway_mac.is_none() && self.options.verbose {
                    debug!("⚠️ L3→L2: No gateway MAC learned yet, using broadcast");
                } else if self.options.verbose {
                    let gw = self.gateway_mac.unwrap();
                    debug!("✅ L3→L2: Using learned gateway MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        gw[0], gw[1], gw[2], gw[3], gw[4], gw[5]);
                }
            }
            6 => {
                // IPv6 packet
                ethertype = 0x86DD;
                dest_mac = [0xFF; 6]; // Broadcast for IPv6
            }
            _ => {
                return Err(anyhow::anyhow!("Invalid IP version: {}", version));
            }
        }
        
        // Build Ethernet frame: [dest_mac(6)][src_mac(6)][ethertype(2)][payload]
        let mut frame = Vec::with_capacity(14 + ip_packet.len());
        frame.extend_from_slice(&dest_mac);
        frame.extend_from_slice(&self.options.our_mac);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(ip_packet);
        
        self.packets_translated_l3_to_l2 += 1;
        
        if self.options.verbose {
            trace!(
                "L3→L2: {} bytes IP → {} bytes Ethernet (type=0x{:04x})",
                ip_packet.len(),
                frame.len(),
                ethertype
            );
        }
        
        Ok(frame)
    }
    
    /// Convert Ethernet frame (L2) → IP packet (L3)
    /// Used when receiving packets from VPN (Ethernet) to write to TUN (IP only)
    ///
    /// Returns:
    /// - `Ok(Some(ip_packet))` - IP packet ready for TUN device
    /// - `Ok(None)` - ARP packet handled internally, no output
    /// - `Err(...)` - Invalid packet
    pub fn ethernet_to_ip(&mut self, eth_frame: &[u8]) -> Result<Option<Vec<u8>>> {
        if eth_frame.len() < 14 {
            return Err(anyhow::anyhow!("Ethernet frame too short: {} bytes", eth_frame.len()));
        }
        
        // Parse Ethernet header
        // [dest_mac(6)][src_mac(6)][ethertype(2)][payload]
        let _dest_mac = &eth_frame[0..6];
        let src_mac: [u8; 6] = eth_frame[6..12].try_into().unwrap();
        let ethertype = u16::from_be_bytes([eth_frame[12], eth_frame[13]]);
        let payload = &eth_frame[14..];
        
        // 🔥 CRITICAL FIX: Learn gateway MAC from FIRST incoming packet from VPN
        // In LocalBridge mode, we must learn gateway MAC immediately from any IPv4 traffic
        if self.gateway_mac.is_none() && ethertype == 0x0800 && payload.len() >= 20 {
            let src_ip_bytes = [payload[12], payload[13], payload[14], payload[15]];
            let src_ip = Ipv4Addr::from(src_ip_bytes);
            
            // Learn from any non-link-local IPv4 packet from VPN
            if !src_ip.is_link_local() && !src_ip.is_broadcast() && !src_ip.is_multicast() {
                self.gateway_mac = Some(src_mac);
                info!("🎯 Learned gateway MAC from FIRST incoming packet: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (src_ip={})",
                    src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], src_ip);
            }
        }
        
        match ethertype {
            0x0806 => {
                // ARP packet - handle internally
                self.handle_arp_frame(eth_frame)
                    .context("Failed to handle ARP frame")?;
                Ok(None) // ARP handled, no IP packet output
            }
            0x0800 => {
                // IPv4 packet - strip Ethernet header and return IP packet
                self.packets_translated_l2_to_l3 += 1;
                
                // 🔥 CRITICAL FIX: Learn gateway MAC from ANY incoming IPv4 packet from VPN
                // In LocalBridge mode, there's no ARP reply - we must learn MAC from traffic
                if self.gateway_mac.is_none() && payload.len() >= 20 {
                    let src_ip_bytes = [payload[12], payload[13], payload[14], payload[15]];
                    let src_ip = Ipv4Addr::from(src_ip_bytes);
                    
                    // Learn MAC from any packet in our subnet (not from us, not link-local)
                    if let Some(our_ip) = self.our_ip {
                        if src_ip != our_ip && !src_ip.is_link_local() {
                            // Check if source is in same subnet
                            let our_octets = our_ip.octets();
                            let src_octets = src_ip.octets();
                            
                            // Same /24 subnet check (conservative)
                            if our_octets[0] == src_octets[0] && 
                               our_octets[1] == src_octets[1] &&
                               our_octets[2] == src_octets[2] {
                                
                                let src_mac: [u8; 6] = eth_frame[6..12].try_into().unwrap_or([0; 6]);
                                self.gateway_mac = Some(src_mac);
                                
                                info!("🎯 Learned gateway MAC from incoming packet: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (src_ip={})",
                                    src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], src_ip);
                            }
                        }
                    }
                }
                
                if self.options.verbose {
                    trace!(
                        "L2→L3: {} bytes Ethernet → {} bytes IPv4",
                        eth_frame.len(),
                        payload.len()
                    );
                }
                
                Ok(Some(payload.to_vec()))
            }
            0x86DD => {
                // IPv6 packet - strip Ethernet header and return IP packet
                self.packets_translated_l2_to_l3 += 1;
                
                if self.options.verbose {
                    trace!(
                        "L2→L3: {} bytes Ethernet → {} bytes IPv6",
                        eth_frame.len(),
                        payload.len()
                    );
                }
                
                Ok(Some(payload.to_vec()))
            }
            _ => {
                warn!("Unknown EtherType: 0x{:04x}, ignoring packet", ethertype);
                Ok(None)
            }
        }
    }
    
    /// Handle ARP frame
    ///
    /// Processes ARP requests and replies:
    /// - ARP Request: Queue a reply if it's for our IP
    /// - ARP Reply: Learn gateway MAC if it's from our gateway
    fn handle_arp_frame(&mut self, eth_frame: &[u8]) -> Result<()> {
        if eth_frame.len() < 42 {
            // Ethernet (14) + ARP (28) = 42 bytes minimum
            return Err(anyhow::anyhow!("ARP frame too short: {} bytes", eth_frame.len()));
        }
        
        // ARP packet format (after 14-byte Ethernet header):
        // [hardware_type(2)][protocol_type(2)][hw_len(1)][proto_len(1)]
        // [operation(2)][sender_mac(6)][sender_ip(4)][target_mac(6)][target_ip(4)]
        
        let arp_data = &eth_frame[14..];
        
        let hardware_type = u16::from_be_bytes([arp_data[0], arp_data[1]]);
        let protocol_type = u16::from_be_bytes([arp_data[2], arp_data[3]]);
        let operation = u16::from_be_bytes([arp_data[6], arp_data[7]]);
        
        // Validate it's Ethernet + IPv4
        if hardware_type != 1 || protocol_type != 0x0800 {
            return Ok(()); // Ignore non-Ethernet/IPv4 ARP
        }
        
        // Parse addresses
        let sender_mac: [u8; 6] = arp_data[8..14].try_into()?;
        let sender_ip = Ipv4Addr::new(arp_data[14], arp_data[15], arp_data[16], arp_data[17]);
        let target_ip = Ipv4Addr::new(arp_data[24], arp_data[25], arp_data[26], arp_data[27]);
        
        match operation {
            1 => {
                // ARP Request: "Who has target_ip? Tell sender_ip"
                self.arp_requests_handled += 1;
                
                if self.options.verbose {
                    debug!(
                        "ARP Request: Who has {}? Tell {} (MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
                        target_ip, sender_ip,
                        sender_mac[0], sender_mac[1], sender_mac[2],
                        sender_mac[3], sender_mac[4], sender_mac[5]
                    );
                }
                
                // If it's asking for our IP, queue an ARP reply
                if let Some(our_ip) = self.our_ip {
                    if target_ip == our_ip {
                        let reply = self.arp_handler.build_arp_reply(
                            our_ip,
                            sender_mac,
                            sender_ip,
                        )?;
                        
                        // Limit queue size to prevent memory overflow
                        if self.arp_reply_queue.len() < 10 {
                            self.arp_reply_queue.push(reply);
                            debug!("📤 Queued ARP reply: {} is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                our_ip,
                                self.options.our_mac[0], self.options.our_mac[1], self.options.our_mac[2],
                                self.options.our_mac[3], self.options.our_mac[4], self.options.our_mac[5]
                            );
                        } else {
                            warn!("ARP reply queue full, dropping reply");
                        }
                    }
                }
            }
            2 => {
                // ARP Reply: "sender_ip is at sender_mac"
                if self.options.verbose {
                    debug!(
                        "ARP Reply: {} is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        sender_ip,
                        sender_mac[0], sender_mac[1], sender_mac[2],
                        sender_mac[3], sender_mac[4], sender_mac[5]
                    );
                }
                
                // If it's from our gateway, learn the MAC
                if let Some(gateway_ip) = self.gateway_ip {
                    if sender_ip == gateway_ip {
                        self.gateway_mac = Some(sender_mac);
                        self.last_gateway_learn = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        self.arp_replies_learned += 1;
                        
                        info!(
                            "🎯 Learned gateway MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            sender_mac[0], sender_mac[1], sender_mac[2],
                            sender_mac[3], sender_mac[4], sender_mac[5]
                        );
                    }
                }
            }
            _ => {
                warn!("Unknown ARP operation: {}", operation);
            }
        }
        
        Ok(())
    }
    
    /// Get the next queued ARP reply (if any)
    pub fn pop_arp_reply(&mut self) -> Option<Vec<u8>> {
        if self.arp_reply_queue.is_empty() {
            None
        } else {
            Some(self.arp_reply_queue.remove(0))
        }
    }
    
    /// Check if there are pending ARP replies
    pub fn has_pending_arp_replies(&self) -> bool {
        !self.arp_reply_queue.is_empty()
    }
}

/// Statistics for the translator
#[derive(Debug, Clone, Copy)]
pub struct TranslatorStats {
    pub l2_to_l3: u64,
    pub l3_to_l2: u64,
    pub arp_handled: u64,
    pub arp_learned: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translator_creation() {
        let options = TranslatorOptions::default();
        let translator = L2L3Translator::new(options);
        assert!(translator.gateway_mac().is_none());
    }
    
    #[test]
    fn test_ip_to_ethernet_ipv4() {
        let options = TranslatorOptions::default();
        let mut translator = L2L3Translator::new(options);
        
        // Simple IPv4 packet (version=4, header_len=5)
        let ip_packet = vec![
            0x45, 0x00, 0x00, 0x54, // Version, IHL, TOS, Total Length
            0x00, 0x00, 0x40, 0x00, // ID, Flags, Fragment Offset
            0x40, 0x11, 0x00, 0x00, // TTL, Protocol (UDP), Checksum
            192, 168, 1, 100,       // Source IP
            192, 168, 1, 1,         // Dest IP
        ];
        
        let result = translator.ip_to_ethernet(&ip_packet);
        assert!(result.is_ok());
        
        let frame = result.unwrap();
        assert_eq!(frame.len(), 14 + ip_packet.len());
        
        // Check EtherType (IPv4 = 0x0800)
        assert_eq!(frame[12], 0x08);
        assert_eq!(frame[13], 0x00);
    }
}
