//! Layer 2 ↔ Layer 3 packet translator
//! 
//! Handles conversion between Ethernet frames (L2) and IP packets (L3)
//! with gateway MAC learning for proper packet forwarding.

use std::time::{SystemTime, UNIX_EPOCH};

const ETHERNET_HEADER_SIZE: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_ARP: u16 = 0x0806;

#[derive(Debug, Clone)]
pub struct TranslatorConfig {
    pub our_mac: [u8; 6],
    pub verbose: bool,
}

#[derive(Debug)]
pub struct Translator {
    pub config: TranslatorConfig,  // Made public so VirtualTap can access verbose setting
    
    // Learned network configuration
    pub our_ip: Option<u32>,           // Our IP address (learned from DHCP)
    pub gateway_ip: Option<u32>,       // Gateway IP (learned from DHCP)
    pub gateway_mac: Option<[u8; 6]>,  // Gateway MAC (learned from incoming packets)
    
    last_gateway_learn: u64,
    
    // Statistics
    pub packets_l3_to_l2: u64,
    pub packets_l2_to_l3: u64,
}

impl Translator {
    pub fn new(config: TranslatorConfig) -> Self {
        Self {
            config,
            our_ip: None,
            gateway_ip: None,
            gateway_mac: None,
            last_gateway_learn: 0,
            packets_l3_to_l2: 0,
            packets_l2_to_l3: 0,
        }
    }
    
    /// Set our IP address (usually from DHCP)
    pub fn set_our_ip(&mut self, ip: u32) {
        self.our_ip = Some(ip);
        // Set our IP silently
    }
    
    /// Set gateway IP address (usually from DHCP)
    pub fn set_gateway_ip(&mut self, ip: u32) {
        self.gateway_ip = Some(ip);
        // Set gateway IP silently
    }
    
    /// Explicitly set the gateway MAC address (learned from ARP)
    /// This is critical for L3→L2 translation to work properly
    pub fn set_gateway_mac(&mut self, mac: [u8; 6]) {
        self.gateway_mac = Some(mac);
        // Gateway MAC set explicitly
    }
    
    /// Convert IP packet (L3) to Ethernet frame (L2)
    /// 
    /// This is called when sending packets from TUN to the VPN server.
    /// Uses the learned gateway MAC as destination, or broadcast if not learned yet.
    pub fn ip_to_ethernet(&mut self, ip_packet: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ip_packet.is_empty() {
            return Err("Empty IP packet");
        }
        
        // Detect IP version
        let version = (ip_packet[0] >> 4) & 0x0F;
        let ethertype = match version {
            4 => ETHERTYPE_IPV4,
            6 => ETHERTYPE_IPV6,
            _ => return Err("Invalid IP version"),
        };
        
        // Determine destination MAC
        let dest_mac = if let Some(gw_mac) = self.gateway_mac {
            // ✅ Use learned gateway MAC
            // Using learned gateway MAC
            gw_mac
        } else {
            // Gateway MAC not learned yet, use broadcast
            [0xFF; 6]
        };
        
        // Build Ethernet frame: [6 dest MAC][6 src MAC][2 EtherType][IP payload]
        let frame_size = ETHERNET_HEADER_SIZE + ip_packet.len();
        let mut frame = Vec::with_capacity(frame_size);
        
        frame.extend_from_slice(&dest_mac);              // Destination MAC
        frame.extend_from_slice(&self.config.our_mac);   // Source MAC (our MAC)
        frame.extend_from_slice(&ethertype.to_be_bytes()); // EtherType
        frame.extend_from_slice(ip_packet);              // IP packet
        
        self.packets_l3_to_l2 += 1;
        
        Ok(frame)
    }
    
    /// Convert Ethernet frame (L2) to IP packet (L3)
    /// 
    /// This is called when receiving packets from the VPN server to send to TUN.
    /// Also learns the gateway MAC from incoming packets.
    /// Returns None if the frame was ARP (handled elsewhere).
    pub fn ethernet_to_ip(&mut self, eth_frame: &[u8]) -> Result<Option<Vec<u8>>, &'static str> {
        if eth_frame.len() < ETHERNET_HEADER_SIZE {
            return Err("Frame too short");
        }
        
        // Extract EtherType
        let ethertype = u16::from_be_bytes([eth_frame[12], eth_frame[13]]);
        
        // Learn gateway MAC from incoming packets
        if let Some(gateway_ip) = self.gateway_ip {
            if ethertype == ETHERTYPE_IPV4 && eth_frame.len() >= ETHERNET_HEADER_SIZE + 20 {
                // Extract source IP from IPv4 header
                let ip_header = &eth_frame[ETHERNET_HEADER_SIZE..];
                let src_ip = u32::from_be_bytes([
                    ip_header[12], ip_header[13], ip_header[14], ip_header[15]
                ]);
                
                // If this packet is from the gateway, learn its MAC
                if src_ip == gateway_ip {
                    let src_mac = &eth_frame[6..12];
                    let new_mac: [u8; 6] = src_mac.try_into().unwrap();
                    
                    // Only update if different
                    let should_update = self.gateway_mac
                        .map(|old| old != new_mac)
                        .unwrap_or(true);
                    
                    if should_update {
                        self.gateway_mac = Some(new_mac);
                        self.last_gateway_learn = current_time_ms();
                        // Gateway MAC learned silently
                    }
                }
            }
        }
        
        // Handle different EtherTypes
        match ethertype {
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => {
                // Extract IP packet (strip Ethernet header)
                let ip_packet = eth_frame[ETHERNET_HEADER_SIZE..].to_vec();
                self.packets_l2_to_l3 += 1;
                
                // L2→L3 translation
                
                Ok(Some(ip_packet))
            }
            ETHERTYPE_ARP => {
                // ARP packets should be handled by ARP handler
                Ok(None)
            }
            _ => {
                // Unknown EtherType, ignore silently
                Ok(None)
            }
        }
    }
}

// Helper functions

fn ip_to_string(ip: u32) -> String {
    format!("{}.{}.{}.{}",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF)
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ip_to_ethernet_with_gateway_mac() {
        let config = TranslatorConfig {
            our_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            verbose: false,
        };
        
        let mut translator = Translator::new(config);
        translator.gateway_mac = Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        
        // IPv4 packet (version 4, minimal header)
        let ip_packet = vec![0x45, 0x00, 0x00, 0x14]; // Version 4, header length 5
        
        let frame = translator.ip_to_ethernet(&ip_packet).unwrap();
        
        // Check Ethernet header
        assert_eq!(&frame[0..6], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // Dest = gateway
        assert_eq!(&frame[6..12], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // Src = our MAC
        assert_eq!(&frame[12..14], &[0x08, 0x00]); // EtherType = IPv4
        assert_eq!(&frame[14..], &ip_packet[..]); // Payload
    }
    
    #[test]
    fn test_ip_to_ethernet_without_gateway_mac() {
        let config = TranslatorConfig {
            our_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            verbose: false,
        };
        
        let mut translator = Translator::new(config);
        // No gateway MAC set
        
        let ip_packet = vec![0x45, 0x00, 0x00, 0x14];
        let frame = translator.ip_to_ethernet(&ip_packet).unwrap();
        
        // Should use broadcast
        assert_eq!(&frame[0..6], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }
    
    #[test]
    fn test_ethernet_to_ip_learns_gateway_mac() {
        let config = TranslatorConfig {
            our_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            verbose: false,
        };
        
        let mut translator = Translator::new(config);
        translator.gateway_ip = Some(0x0A150001); // 10.21.0.1
        
        // Ethernet frame with IPv4 packet from gateway
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // Dest
        frame.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // Src (gateway MAC)
        frame.extend_from_slice(&[0x08, 0x00]); // IPv4
        
        // IPv4 header with source IP = 10.21.0.1
        let mut ip_header = vec![0x45, 0x00, 0x00, 0x14]; // Version, IHL, TOS, Total Length
        ip_header.extend_from_slice(&[0x00, 0x00]); // ID
        ip_header.extend_from_slice(&[0x00, 0x00]); // Flags, Fragment Offset
        ip_header.extend_from_slice(&[0x40, 0x11]); // TTL, Protocol (UDP)
        ip_header.extend_from_slice(&[0x00, 0x00]); // Checksum
        ip_header.extend_from_slice(&[0x0A, 0x15, 0x00, 0x01]); // Source IP = 10.21.0.1
        ip_header.extend_from_slice(&[0x0A, 0x15, 0xF8, 0xA4]); // Dest IP
        
        frame.extend_from_slice(&ip_header);
        
        translator.ethernet_to_ip(&frame).unwrap();
        
        // Should have learned gateway MAC
        assert_eq!(translator.gateway_mac, Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    }
}
