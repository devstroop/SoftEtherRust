//! Pure Rust VirtualTap implementation
//! 
//! L2↔L3 packet translation with gateway MAC learning and DHCP support

mod translator;
mod dhcp;
mod arp;
mod tun_device;
mod route_manager;

pub use translator::{Translator, TranslatorConfig};
pub use dhcp::{DhcpInfo, parse_dhcp, build_dhcp_discover, build_dhcp_request};
pub use arp::{ArpInfo, parse_arp, build_arp_reply, build_arp_gratuitous};
pub use tun_device::TunDevice;
pub use route_manager::RouteManager;

use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct VirtualTapConfig {
    pub our_mac: [u8; 6],
    pub verbose: bool,
}

#[derive(Debug)]
pub struct VirtualTap {
    translator: Arc<Mutex<Translator>>,
    verbose: bool,
}

impl VirtualTap {
    pub fn new(config: VirtualTapConfig) -> Self {
        let translator_config = TranslatorConfig {
            our_mac: config.our_mac,
            verbose: config.verbose,
        };
        
        // VirtualTap initialized
        
        Self {
            translator: Arc::new(Mutex::new(Translator::new(translator_config))),
            verbose: config.verbose,
        }
    }
    
    /// Convert IP packet to Ethernet frame
    pub fn ip_to_ethernet(&self, ip_packet: &[u8]) -> Result<Vec<u8>, String> {
        self.translator
            .lock()
            .unwrap()
            .ip_to_ethernet(ip_packet)
            .map_err(|e| e.to_string())
    }
    
    /// Convert Ethernet frame to IP packet
    /// Returns None if frame was ARP (handled internally)
    pub fn ethernet_to_ip(&self, eth_frame: &[u8]) -> Result<Option<Vec<u8>>, String> {
        // RX Ethernet frame
        
        let mut translator = self.translator.lock().unwrap();
        
        // Check if this is a DHCP packet and parse it
        let dhcp_attempt = self.try_parse_dhcp(eth_frame);
        if dhcp_attempt.is_some() {
            // DHCP packet detected
        }
        if let Some(dhcp_info) = dhcp_attempt {
            if dhcp_info.message_type == 2 || dhcp_info.message_type == 5 {
                // OFFER or ACK - learn network configuration
                if dhcp_info.offered_ip != [0, 0, 0, 0] {
                    let ip = u32::from_be_bytes(dhcp_info.offered_ip);
                    translator.set_our_ip(ip);
                }
                
                if dhcp_info.gateway != [0, 0, 0, 0] {
                    let gateway = u32::from_be_bytes(dhcp_info.gateway);
                    translator.set_gateway_ip(gateway);
                    
                    if self.verbose {
                        // Learned gateway from DHCP
                    }
                }
            }
        }
        
        translator
            .ethernet_to_ip(eth_frame)
            .map_err(|e| e.to_string())
    }
    
    /// Try to parse DHCP information from an Ethernet frame
    fn try_parse_dhcp(&self, eth_frame: &[u8]) -> Option<DhcpInfo> {
        const ETHERNET_HEADER_SIZE: usize = 14;
        
        if eth_frame.len() < ETHERNET_HEADER_SIZE + 20 {
            return None;
        }
        
        // Check EtherType (IPv4)
        let ethertype = u16::from_be_bytes([eth_frame[12], eth_frame[13]]);
        if ethertype != 0x0800 {
            return None;
        }
        
        let ip_header = &eth_frame[ETHERNET_HEADER_SIZE..];
        
        // Check protocol (UDP)
        if ip_header.len() < 20 || ip_header[9] != 17 {
            return None;
        }
        
        let ihl = ((ip_header[0] & 0x0F) * 4) as usize;
        if ip_header.len() < ihl + 8 {
            return None;
        }
        
        let udp_header = &ip_header[ihl..];
        
        // Check UDP ports (DHCP: 67→68 or 68→67)
        let src_port = u16::from_be_bytes([udp_header[0], udp_header[1]]);
        let dst_port = u16::from_be_bytes([udp_header[2], udp_header[3]]);
        
        if !((src_port == 67 && dst_port == 68) || (src_port == 68 && dst_port == 67)) {
            return None;
        }
        
        // Parse DHCP
        let udp_payload = &udp_header[8..];
        parse_dhcp(udp_payload)
    }
    
    /// Get learned IP address
    pub fn get_learned_ip(&self) -> Option<u32> {
        self.translator.lock().unwrap().our_ip
    }
    
    /// Get learned gateway MAC
    pub fn get_gateway_mac(&self) -> Option<[u8; 6]> {
        self.translator.lock().unwrap().gateway_mac
    }
    
    /// Set gateway IP (allows external setting)
    pub fn set_gateway_ip(&self, ip: u32) {
        self.translator.lock().unwrap().set_gateway_ip(ip);
    }
    
    /// Explicitly set the gateway MAC address (critical for L3→L2 translation)
    pub fn set_gateway_mac(&self, mac: [u8; 6]) {
        self.translator.lock().unwrap().set_gateway_mac(mac);
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> (u64, u64) {
        let translator = self.translator.lock().unwrap();
        (translator.packets_l3_to_l2, translator.packets_l2_to_l3)
    }
}

impl Clone for VirtualTap {
    fn clone(&self) -> Self {
        Self {
            translator: Arc::clone(&self.translator),
            verbose: self.verbose,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_virtual_tap_basic() {
        let config = VirtualTapConfig {
            our_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            verbose: false,
        };
        
        let vtap = VirtualTap::new(config);
        
        // Test IP to Ethernet conversion
        let ip_packet = vec![0x45, 0x00, 0x00, 0x14]; // IPv4 minimal
        let eth_frame = vtap.ip_to_ethernet(&ip_packet).unwrap();
        
        assert_eq!(eth_frame.len(), 14 + ip_packet.len());
        assert_eq!(&eth_frame[12..14], &[0x08, 0x00]); // IPv4 EtherType
    }
    
    #[test]
    fn test_gateway_mac_learning() {
        let config = VirtualTapConfig {
            our_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            verbose: false,
        };
        
        let vtap = VirtualTap::new(config);
        vtap.set_gateway_ip(0x0A150001); // 10.21.0.1
        
        // Create Ethernet frame with packet from gateway
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // Dest
        frame.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // Src (gateway)
        frame.extend_from_slice(&[0x08, 0x00]); // IPv4
        
        // IPv4 header from gateway
        let mut ip_header = vec![0x45, 0x00, 0x00, 0x14];
        ip_header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00]);
        ip_header.extend_from_slice(&[0x0A, 0x15, 0x00, 0x01]); // Src: 10.21.0.1
        ip_header.extend_from_slice(&[0x0A, 0x15, 0xF8, 0xA4]); // Dst
        
        frame.extend_from_slice(&ip_header);
        
        vtap.ethernet_to_ip(&frame).unwrap();
        
        // Gateway MAC should be learned
        assert_eq!(vtap.get_gateway_mac(), Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    }
}
