//! ARP (Address Resolution Protocol) Handler
//!
//! Provides functionality for building and processing ARP packets.
//! ARP is used to discover the MAC address associated with an IP address.

use anyhow::Result;
use std::net::Ipv4Addr;

/// ARP packet builder and handler
pub struct ArpHandler {
    our_mac: [u8; 6],
}

impl ArpHandler {
    /// Create a new ARP handler
    pub fn new(our_mac: [u8; 6]) -> Self {
        Self { our_mac }
    }
    
    /// Build an ARP reply packet
    ///
    /// Creates a complete Ethernet frame containing an ARP reply.
    /// Format: "our_ip is at our_mac" (telling target_ip at target_mac)
    ///
    /// # Arguments
    /// * `our_ip` - Our IP address (the one being asked about)
    /// * `target_mac` - MAC address of the requester
    /// * `target_ip` - IP address of the requester
    ///
    /// # Returns
    /// Complete 42-byte Ethernet frame with ARP reply
    pub fn build_arp_reply(
        &self,
        our_ip: Ipv4Addr,
        target_mac: [u8; 6],
        target_ip: Ipv4Addr,
    ) -> Result<Vec<u8>> {
        let mut packet = vec![0u8; 42]; // Ethernet (14) + ARP (28) = 42 bytes
        
        // ===== Ethernet Header (14 bytes) =====
        // Destination MAC (6 bytes)
        packet[0..6].copy_from_slice(&target_mac);
        
        // Source MAC (6 bytes)
        packet[6..12].copy_from_slice(&self.our_mac);
        
        // EtherType: ARP (0x0806)
        packet[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        
        // ===== ARP Header (28 bytes) =====
        // Hardware Type: Ethernet (0x0001)
        packet[14..16].copy_from_slice(&0x0001u16.to_be_bytes());
        
        // Protocol Type: IPv4 (0x0800)
        packet[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        
        // Hardware Address Length: 6 (MAC address)
        packet[18] = 6;
        
        // Protocol Address Length: 4 (IPv4 address)
        packet[19] = 4;
        
        // Operation: Reply (0x0002)
        packet[20..22].copy_from_slice(&0x0002u16.to_be_bytes());
        
        // Sender Hardware Address (our MAC)
        packet[22..28].copy_from_slice(&self.our_mac);
        
        // Sender Protocol Address (our IP)
        packet[28..32].copy_from_slice(&our_ip.octets());
        
        // Target Hardware Address (requester's MAC)
        packet[32..38].copy_from_slice(&target_mac);
        
        // Target Protocol Address (requester's IP)
        packet[38..42].copy_from_slice(&target_ip.octets());
        
        Ok(packet)
    }
    
    /// Build an ARP request packet
    ///
    /// Creates a complete Ethernet frame containing an ARP request.
    /// Format: "Who has target_ip? Tell our_ip (at our_mac)"
    ///
    /// # Arguments
    /// * `our_ip` - Our IP address
    /// * `target_ip` - IP address we're looking for
    ///
    /// # Returns
    /// Complete 42-byte Ethernet frame with ARP request
    pub fn build_arp_request(
        &self,
        our_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    ) -> Result<Vec<u8>> {
        let mut packet = vec![0u8; 42]; // Ethernet (14) + ARP (28) = 42 bytes
        
        // ===== Ethernet Header (14 bytes) =====
        // Destination MAC: Broadcast (ff:ff:ff:ff:ff:ff)
        packet[0..6].copy_from_slice(&[0xFF; 6]);
        
        // Source MAC (our MAC)
        packet[6..12].copy_from_slice(&self.our_mac);
        
        // EtherType: ARP (0x0806)
        packet[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        
        // ===== ARP Header (28 bytes) =====
        // Hardware Type: Ethernet (0x0001)
        packet[14..16].copy_from_slice(&0x0001u16.to_be_bytes());
        
        // Protocol Type: IPv4 (0x0800)
        packet[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        
        // Hardware Address Length: 6 (MAC address)
        packet[18] = 6;
        
        // Protocol Address Length: 4 (IPv4 address)
        packet[19] = 4;
        
        // Operation: Request (0x0001)
        packet[20..22].copy_from_slice(&0x0001u16.to_be_bytes());
        
        // Sender Hardware Address (our MAC)
        packet[22..28].copy_from_slice(&self.our_mac);
        
        // Sender Protocol Address (our IP)
        packet[28..32].copy_from_slice(&our_ip.octets());
        
        // Target Hardware Address (unknown, set to 00:00:00:00:00:00)
        packet[32..38].copy_from_slice(&[0x00; 6]);
        
        // Target Protocol Address (IP we're looking for)
        packet[38..42].copy_from_slice(&target_ip.octets());
        
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_reply_format() {
        let handler = ArpHandler::new([0x5E, 0x00, 0x53, 0x01, 0x02, 0x03]);
        let our_ip = Ipv4Addr::new(192, 168, 1, 100);
        let target_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        
        let result = handler.build_arp_reply(our_ip, target_mac, target_ip);
        assert!(result.is_ok());
        
        let packet = result.unwrap();
        assert_eq!(packet.len(), 42);
        
        // Verify EtherType (ARP = 0x0806)
        assert_eq!(packet[12], 0x08);
        assert_eq!(packet[13], 0x06);
        
        // Verify operation (Reply = 0x0002)
        assert_eq!(packet[20], 0x00);
        assert_eq!(packet[21], 0x02);
    }
    
    #[test]
    fn test_arp_request_format() {
        let handler = ArpHandler::new([0x5E, 0x00, 0x53, 0x01, 0x02, 0x03]);
        let our_ip = Ipv4Addr::new(192, 168, 1, 100);
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        
        let result = handler.build_arp_request(our_ip, target_ip);
        assert!(result.is_ok());
        
        let packet = result.unwrap();
        assert_eq!(packet.len(), 42);
        
        // Verify destination is broadcast
        assert_eq!(&packet[0..6], &[0xFF; 6]);
        
        // Verify operation (Request = 0x0001)
        assert_eq!(packet[20], 0x00);
        assert_eq!(packet[21], 0x01);
        
        // Verify target MAC is zero (unknown)
        assert_eq!(&packet[32..38], &[0x00; 6]);
    }
}
