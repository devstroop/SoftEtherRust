//! Ethernet frame utilities with zero-copy helpers.
//!
//! Key design principle from SoftEtherZig: minimize allocations by using
//! slice references and pre-allocated buffers. The wrap/unwrap functions
//! return slices into the provided buffer rather than allocating.

#![allow(dead_code)]

/// Ethernet frame types (EtherType).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EtherType {
    /// IPv4
    Ipv4 = 0x0800,
    /// ARP
    Arp = 0x0806,
    /// VLAN-tagged frame
    Vlan = 0x8100,
    /// IPv6
    Ipv6 = 0x86DD,
}

impl EtherType {
    /// Parse EtherType from a 16-bit value.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0800 => Some(Self::Ipv4),
            0x0806 => Some(Self::Arp),
            0x8100 => Some(Self::Vlan),
            0x86DD => Some(Self::Ipv6),
            _ => None,
        }
    }

    /// Extract EtherType from an Ethernet frame.
    pub fn from_frame(frame: &[u8]) -> Option<Self> {
        if frame.len() < 14 {
            return None;
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        Self::from_u16(ethertype)
    }
}

/// Minimum Ethernet frame size (without FCS).
pub const MIN_FRAME_SIZE: usize = 60;

/// Maximum Ethernet frame size (without FCS).
pub const MAX_FRAME_SIZE: usize = 1514;

/// Ethernet header size.
pub const HEADER_SIZE: usize = 14;

/// Format a MAC address as a string.
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parse a MAC address from a string.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

/// Broadcast MAC address.
pub const BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

/// Zero MAC address.
pub const ZERO_MAC: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

/// Check if a MAC address is broadcast.
pub fn is_broadcast(mac: &[u8; 6]) -> bool {
    mac == &BROADCAST_MAC
}

/// Check if a MAC address is multicast.
pub fn is_multicast(mac: &[u8; 6]) -> bool {
    mac[0] & 0x01 != 0
}

// =============================================================================
// Zero-copy Ethernet frame helpers (inspired by SoftEtherZig)
// =============================================================================

/// Wrap an IP packet in an Ethernet frame (zero-copy).
///
/// Writes the Ethernet header + IP packet into `buffer` and returns
/// a slice of the written data. No allocations.
///
/// # Arguments
/// * `ip_packet` - The IP packet data (IPv4 or IPv6)
/// * `dst_mac` - Destination MAC address
/// * `src_mac` - Source MAC address
/// * `buffer` - Pre-allocated buffer to write into (must be at least 14 + ip_packet.len())
///
/// # Returns
/// * `Some(&[u8])` - Slice of the Ethernet frame in buffer
/// * `None` - If buffer is too small or IP version is invalid
#[inline]
pub fn wrap_ip_in_ethernet<'a>(
    ip_packet: &[u8],
    dst_mac: &[u8; 6],
    src_mac: &[u8; 6],
    buffer: &'a mut [u8],
) -> Option<&'a [u8]> {
    if ip_packet.is_empty() || ip_packet.len() > MAX_MTU {
        return None;
    }
    
    let total_len = HEADER_SIZE + ip_packet.len();
    if buffer.len() < total_len {
        return None;
    }
    
    // Determine IP version from first nibble
    let ip_version = (ip_packet[0] >> 4) & 0x0F;
    
    // Write destination MAC (bytes 0-5)
    buffer[0..6].copy_from_slice(dst_mac);
    
    // Write source MAC (bytes 6-11)
    buffer[6..12].copy_from_slice(src_mac);
    
    // Write EtherType (bytes 12-13)
    match ip_version {
        4 => {
            buffer[12] = 0x08;
            buffer[13] = 0x00;
        }
        6 => {
            buffer[12] = 0x86;
            buffer[13] = 0xDD;
        }
        _ => return None,
    }
    
    // Copy IP packet (bytes 14+)
    buffer[14..total_len].copy_from_slice(ip_packet);
    
    Some(&buffer[..total_len])
}

/// Unwrap an Ethernet frame to get the IP packet (zero-copy).
///
/// Returns a slice pointing directly into the original frame data.
/// No allocations.
///
/// # Arguments
/// * `eth_frame` - The complete Ethernet frame
///
/// # Returns
/// * `Some(&[u8])` - Slice of the IP packet within the frame
/// * `None` - If frame is too small or EtherType is not IP
#[inline]
pub fn unwrap_ethernet_to_ip(eth_frame: &[u8]) -> Option<&[u8]> {
    if eth_frame.len() <= HEADER_SIZE {
        return None;
    }
    
    let ethertype_hi = eth_frame[12];
    let ethertype_lo = eth_frame[13];
    
    // Check for IPv4 (0x0800) or IPv6 (0x86DD)
    if (ethertype_hi == 0x08 && ethertype_lo == 0x00)
        || (ethertype_hi == 0x86 && ethertype_lo == 0xDD)
    {
        Some(&eth_frame[14..])
    } else {
        None
    }
}

/// Check if an Ethernet frame is an ARP packet.
#[inline]
pub fn is_arp_packet(eth_frame: &[u8]) -> bool {
    eth_frame.len() >= HEADER_SIZE
        && eth_frame[12] == 0x08
        && eth_frame[13] == 0x06
}

/// Check if an Ethernet frame is an IPv4 packet.
#[inline]
pub fn is_ipv4_packet(eth_frame: &[u8]) -> bool {
    eth_frame.len() >= HEADER_SIZE
        && eth_frame[12] == 0x08
        && eth_frame[13] == 0x00
}

/// Check if an Ethernet frame is an IPv6 packet.
#[inline]
pub fn is_ipv6_packet(eth_frame: &[u8]) -> bool {
    eth_frame.len() >= HEADER_SIZE
        && eth_frame[12] == 0x86
        && eth_frame[13] == 0xDD
}

/// Get ARP operation from frame (1=request, 2=reply).
#[inline]
pub fn get_arp_operation(eth_frame: &[u8]) -> Option<u16> {
    if eth_frame.len() < 22 || !is_arp_packet(eth_frame) {
        return None;
    }
    Some(u16::from_be_bytes([eth_frame[20], eth_frame[21]]))
}

/// Extract sender IP from ARP packet (bytes 28-31).
#[inline]
pub fn get_arp_sender_ip(eth_frame: &[u8]) -> Option<u32> {
    if eth_frame.len() < 32 || !is_arp_packet(eth_frame) {
        return None;
    }
    Some(u32::from_be_bytes([
        eth_frame[28],
        eth_frame[29],
        eth_frame[30],
        eth_frame[31],
    ]))
}

/// Extract sender MAC from ARP packet (bytes 22-27).
#[inline]
pub fn get_arp_sender_mac(eth_frame: &[u8]) -> Option<[u8; 6]> {
    if eth_frame.len() < 28 || !is_arp_packet(eth_frame) {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&eth_frame[22..28]);
    Some(mac)
}

/// Extract target IP from ARP packet (bytes 38-41).
#[inline]
pub fn get_arp_target_ip(eth_frame: &[u8]) -> Option<u32> {
    if eth_frame.len() < 42 || !is_arp_packet(eth_frame) {
        return None;
    }
    Some(u32::from_be_bytes([
        eth_frame[38],
        eth_frame[39],
        eth_frame[40],
        eth_frame[41],
    ]))
}

/// Maximum MTU for IP packets.
pub const MAX_MTU: usize = 1500;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethertype_from_frame() {
        // IPv4 frame
        let frame = [0u8; 14];
        let mut ipv4_frame = frame;
        ipv4_frame[12] = 0x08;
        ipv4_frame[13] = 0x00;
        assert_eq!(EtherType::from_frame(&ipv4_frame), Some(EtherType::Ipv4));

        // ARP frame
        let mut arp_frame = frame;
        arp_frame[12] = 0x08;
        arp_frame[13] = 0x06;
        assert_eq!(EtherType::from_frame(&arp_frame), Some(EtherType::Arp));
    }

    #[test]
    fn test_format_mac() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        assert_eq!(format_mac(&mac), "5E:12:34:56:78:9A");
    }

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac("5E:12:34:56:78:9A").unwrap();
        assert_eq!(mac, [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A]);
    }

    #[test]
    fn test_is_broadcast() {
        assert!(is_broadcast(&BROADCAST_MAC));
        assert!(!is_broadcast(&[0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A]));
    }

    #[test]
    fn test_is_multicast() {
        assert!(is_multicast(&[0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]));
        assert!(!is_multicast(&[0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A]));
    }

    // =============================================================================
    // Zero-copy helper tests
    // =============================================================================

    #[test]
    fn test_wrap_ip_in_ethernet_ipv4() {
        // Minimal IPv4 header (version 4)
        let ip_packet: [u8; 20] = [
            0x45, 0x00, 0x00, 0x14, // version=4, IHL=5, total_len=20
            0x00, 0x00, 0x00, 0x00, // ID, flags, fragment
            0x40, 0x06, 0x00, 0x00, // TTL=64, proto=TCP
            0xC0, 0xA8, 0x01, 0x64, // src: 192.168.1.100
            0xC0, 0xA8, 0x01, 0x01, // dst: 192.168.1.1
        ];
        let dst_mac = BROADCAST_MAC;
        let src_mac = [0x02, 0x00, 0x5E, 0x00, 0x00, 0x01];
        let mut buffer = [0u8; 2048];

        let result = wrap_ip_in_ethernet(&ip_packet, &dst_mac, &src_mac, &mut buffer);
        assert!(result.is_some());

        let frame = result.unwrap();
        assert_eq!(frame.len(), 14 + 20);

        // Check EtherType is IPv4
        assert_eq!(frame[12], 0x08);
        assert_eq!(frame[13], 0x00);

        // Check MACs
        assert_eq!(&frame[0..6], &dst_mac);
        assert_eq!(&frame[6..12], &src_mac);

        // Check IP packet is intact
        assert_eq!(&frame[14..], &ip_packet);
    }

    #[test]
    fn test_wrap_ip_in_ethernet_ipv6() {
        // Minimal IPv6 header (version 6)
        let mut ip_packet = [0u8; 40];
        ip_packet[0] = 0x60; // version=6

        let dst_mac = BROADCAST_MAC;
        let src_mac = [0x02, 0x00, 0x5E, 0x00, 0x00, 0x01];
        let mut buffer = [0u8; 2048];

        let result = wrap_ip_in_ethernet(&ip_packet, &dst_mac, &src_mac, &mut buffer);
        assert!(result.is_some());

        let frame = result.unwrap();

        // Check EtherType is IPv6
        assert_eq!(frame[12], 0x86);
        assert_eq!(frame[13], 0xDD);
    }

    #[test]
    fn test_wrap_ip_in_ethernet_invalid_version() {
        // Invalid IP version (0)
        let ip_packet = [0x00u8; 20];
        let dst_mac = BROADCAST_MAC;
        let src_mac = [0x02, 0x00, 0x5E, 0x00, 0x00, 0x01];
        let mut buffer = [0u8; 2048];

        let result = wrap_ip_in_ethernet(&ip_packet, &dst_mac, &src_mac, &mut buffer);
        assert!(result.is_none());
    }

    #[test]
    fn test_wrap_ip_in_ethernet_buffer_too_small() {
        let ip_packet = [0x45u8; 20];
        let dst_mac = BROADCAST_MAC;
        let src_mac = [0x02, 0x00, 0x5E, 0x00, 0x00, 0x01];
        let mut buffer = [0u8; 20]; // Too small

        let result = wrap_ip_in_ethernet(&ip_packet, &dst_mac, &src_mac, &mut buffer);
        assert!(result.is_none());
    }

    #[test]
    fn test_unwrap_ethernet_to_ip() {
        // Build a fake Ethernet frame with IPv4
        let mut frame = [0u8; 34];
        frame[12] = 0x08; // EtherType IPv4
        frame[13] = 0x00;
        frame[14] = 0x45; // IP version 4

        let ip_packet = unwrap_ethernet_to_ip(&frame);
        assert!(ip_packet.is_some());
        assert_eq!(ip_packet.unwrap().len(), 20);
        assert_eq!(ip_packet.unwrap()[0], 0x45);
    }

    #[test]
    fn test_unwrap_ethernet_to_ip_ipv6() {
        let mut frame = [0u8; 54];
        frame[12] = 0x86; // EtherType IPv6
        frame[13] = 0xDD;
        frame[14] = 0x60; // IP version 6

        let ip_packet = unwrap_ethernet_to_ip(&frame);
        assert!(ip_packet.is_some());
        assert_eq!(ip_packet.unwrap()[0], 0x60);
    }

    #[test]
    fn test_unwrap_ethernet_to_ip_arp() {
        // ARP frame should not unwrap to IP
        let mut frame = [0u8; 42];
        frame[12] = 0x08;
        frame[13] = 0x06;

        let ip_packet = unwrap_ethernet_to_ip(&frame);
        assert!(ip_packet.is_none());
    }

    #[test]
    fn test_is_arp_packet() {
        let mut arp_frame = [0u8; 42];
        arp_frame[12] = 0x08;
        arp_frame[13] = 0x06;
        assert!(is_arp_packet(&arp_frame));

        let mut ip_frame = [0u8; 34];
        ip_frame[12] = 0x08;
        ip_frame[13] = 0x00;
        assert!(!is_arp_packet(&ip_frame));
    }

    #[test]
    fn test_get_arp_operation() {
        let mut arp_request = [0u8; 42];
        arp_request[12] = 0x08;
        arp_request[13] = 0x06;
        arp_request[20] = 0x00;
        arp_request[21] = 0x01; // ARP Request
        assert_eq!(get_arp_operation(&arp_request), Some(1));

        let mut arp_reply = [0u8; 42];
        arp_reply[12] = 0x08;
        arp_reply[13] = 0x06;
        arp_reply[20] = 0x00;
        arp_reply[21] = 0x02; // ARP Reply
        assert_eq!(get_arp_operation(&arp_reply), Some(2));
    }

    #[test]
    fn test_get_arp_sender_ip() {
        let mut arp_frame = [0u8; 42];
        arp_frame[12] = 0x08;
        arp_frame[13] = 0x06;
        // Sender IP at bytes 28-31: 192.168.1.1
        arp_frame[28] = 192;
        arp_frame[29] = 168;
        arp_frame[30] = 1;
        arp_frame[31] = 1;

        let ip = get_arp_sender_ip(&arp_frame);
        assert_eq!(ip, Some(0xC0A80101));
    }

    #[test]
    fn test_get_arp_sender_mac() {
        let mut arp_frame = [0u8; 42];
        arp_frame[12] = 0x08;
        arp_frame[13] = 0x06;
        // Sender MAC at bytes 22-27
        arp_frame[22..28].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let mac = get_arp_sender_mac(&arp_frame);
        assert_eq!(mac, Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    }

    #[test]
    fn test_get_arp_target_ip() {
        let mut arp_frame = [0u8; 42];
        arp_frame[12] = 0x08;
        arp_frame[13] = 0x06;
        // Target IP at bytes 38-41: 10.0.0.1
        arp_frame[38] = 10;
        arp_frame[39] = 0;
        arp_frame[40] = 0;
        arp_frame[41] = 1;

        let ip = get_arp_target_ip(&arp_frame);
        assert_eq!(ip, Some(0x0A000001));
    }
}
