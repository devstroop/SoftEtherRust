//! Ethernet frame and packet structures

use crate::error::VTapError;
use anyhow::Result;

/// Ethernet frame
///
/// Represents a complete Layer 2 Ethernet frame with:
/// - Destination MAC (6 bytes)
/// - Source MAC (6 bytes)  
/// - EtherType (2 bytes)
/// - Payload (46-1500 bytes)
/// - FCS (4 bytes, usually handled by hardware)
#[derive(Clone, Debug)]
pub struct EthernetFrame {
    data: Vec<u8>,
}

impl EthernetFrame {
    /// Minimum Ethernet frame size (without FCS)
    pub const MIN_SIZE: usize = 14; // Header only
    
    /// Maximum Ethernet frame size (without FCS)
    pub const MAX_SIZE: usize = 1518; // Header + 1500 MTU + 4 FCS
    
    /// Create from raw bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::MIN_SIZE {
            return Err(VTapError::InvalidPacket(
                format!("Frame too short: {} < {}", data.len(), Self::MIN_SIZE)
            ).into());
        }
        
        if data.len() > Self::MAX_SIZE {
            return Err(VTapError::InvalidPacket(
                format!("Frame too long: {} > {}", data.len(), Self::MAX_SIZE)
            ).into());
        }
        
        Ok(Self {
            data: data.to_vec(),
        })
    }
    
    /// Create from IP packet (for utun)
    ///
    /// iOS utun devices work with IP packets, not Ethernet frames.
    /// This wraps an IP packet in a minimal Ethernet frame with:
    /// - Dummy destination/source MACs
    /// - EtherType based on IP version
    pub fn from_ip_packet(ip_data: Vec<u8>) -> Result<Self> {
        if ip_data.is_empty() {
            return Err(VTapError::InvalidPacket("Empty IP packet".to_string()).into());
        }
        
        let version = ip_data[0] >> 4;
        let ethertype = match version {
            4 => 0x0800u16, // IPv4
            6 => 0x86DDu16, // IPv6
            _ => return Err(VTapError::InvalidPacket(format!("Unknown IP version: {}", version)).into()),
        };
        
        let mut frame = Vec::with_capacity(14 + ip_data.len());
        
        // Destination MAC (broadcast)
        frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        
        // Source MAC (dummy)
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        
        // EtherType
        frame.extend_from_slice(&ethertype.to_be_bytes());
        
        // Payload (IP packet)
        frame.extend_from_slice(&ip_data);
        
        Ok(Self { data: frame })
    }
    
    /// Get destination MAC address
    pub fn dst_mac(&self) -> &[u8] {
        &self.data[0..6]
    }
    
    /// Get source MAC address
    pub fn src_mac(&self) -> &[u8] {
        &self.data[6..12]
    }
    
    /// Get EtherType
    pub fn ethertype(&self) -> u16 {
        u16::from_be_bytes([self.data[12], self.data[13]])
    }
    
    /// Get payload (everything after header)
    pub fn payload(&self) -> &[u8] {
        &self.data[14..]
    }
    
    /// Extract IP packet from Ethernet frame
    ///
    /// Returns the IP packet data, stripping the Ethernet header
    pub fn ip_payload(&self) -> Result<Vec<u8>> {
        let ethertype = self.ethertype();
        
        // Verify it's an IP packet
        if ethertype != 0x0800 && ethertype != 0x86DD {
            return Err(VTapError::InvalidPacket(
                format!("Not an IP packet, ethertype: 0x{:04x}", ethertype)
            ).into());
        }
        
        Ok(self.payload().to_vec())
    }
    
    /// Get raw frame data
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    
    /// Get frame length
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if frame is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_frame_min_size() {
        let data = vec![0u8; 14];
        let frame = EthernetFrame::from_bytes(&data).unwrap();
        assert_eq!(frame.len(), 14);
    }

    #[test]
    fn test_ethernet_frame_too_short() {
        let data = vec![0u8; 13];
        assert!(EthernetFrame::from_bytes(&data).is_err());
    }

    #[test]
    fn test_ethernet_frame_too_long() {
        let data = vec![0u8; 1519];
        assert!(EthernetFrame::from_bytes(&data).is_err());
    }

    #[test]
    fn test_mac_addresses() {
        let mut data = vec![0u8; 14];
        data[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        data[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        
        let frame = EthernetFrame::from_bytes(&data).unwrap();
        assert_eq!(frame.dst_mac(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(frame.src_mac(), &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn test_ethertype() {
        let mut data = vec![0u8; 14];
        data[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4
        
        let frame = EthernetFrame::from_bytes(&data).unwrap();
        assert_eq!(frame.ethertype(), 0x0800);
    }

    #[test]
    fn test_from_ip_packet_v4() {
        let ip_packet = vec![0x45, 0x00, 0x00, 0x54]; // IPv4 header start
        let frame = EthernetFrame::from_ip_packet(ip_packet.clone()).unwrap();
        
        assert_eq!(frame.ethertype(), 0x0800); // IPv4
        assert_eq!(frame.payload(), &ip_packet[..]);
    }

    #[test]
    fn test_from_ip_packet_v6() {
        let ip_packet = vec![0x60, 0x00, 0x00, 0x00]; // IPv6 header start
        let frame = EthernetFrame::from_ip_packet(ip_packet.clone()).unwrap();
        
        assert_eq!(frame.ethertype(), 0x86DD); // IPv6
        assert_eq!(frame.payload(), &ip_packet[..]);
    }
}
