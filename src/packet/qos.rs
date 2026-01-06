//! QoS (Quality of Service) packet classification for VoIP prioritization.
//!
//! This module provides functionality to identify high-priority packets
//! that should be processed before regular traffic. The logic matches
//! the official SoftEther VPN implementation.
//!
//! Priority packets include:
//! - IPv4 packets with non-zero ToS (Type of Service) field
//! - ICMPv4 packets (ping, traceroute, etc.)
//! - Small real-time packets (VoIP, gaming)

/// EtherType values
const ETHERTYPE_IPV4: u16 = 0x0800;
#[allow(dead_code)]
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// IP protocol numbers
const IPPROTO_ICMP: u8 = 1;
#[allow(dead_code)]
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Common VoIP/RTP port ranges
const RTP_PORT_MIN: u16 = 16384;
const RTP_PORT_MAX: u16 = 32767;

/// SIP signaling port
const SIP_PORT: u16 = 5060;
const SIP_TLS_PORT: u16 = 5061;

/// Maximum size for small real-time packets (voice frames are typically small)
const SMALL_PACKET_THRESHOLD: usize = 256;

/// Determines if an Ethernet frame contains a high-priority packet for QoS.
///
/// This function checks if the packet should be prioritized for transmission.
/// Priority is given to:
/// 1. IPv4 packets with non-zero ToS/DSCP field (indicates QoS marking)
/// 2. ICMPv4 packets (important for network diagnostics)
/// 3. Small UDP packets to RTP port ranges (likely VoIP audio)
///
/// This matches the official SoftEther VPN `IsPriorityHighestPacketForQoS` function.
///
/// # Arguments
/// * `frame` - Raw Ethernet frame bytes
///
/// # Returns
/// `true` if the packet should be prioritized, `false` otherwise
pub fn is_priority_packet(frame: &[u8]) -> bool {
    // Minimum Ethernet header (14 bytes) + IPv4 header (20 bytes)
    if frame.len() < 34 {
        return false;
    }

    // Extract EtherType (bytes 12-13)
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    match ethertype {
        ETHERTYPE_IPV4 => is_priority_ipv4(&frame[14..]),
        ETHERTYPE_IPV6 => is_priority_ipv6(&frame[14..]),
        _ => false,
    }
}

/// Check if an IPv4 packet is high priority.
fn is_priority_ipv4(ip_packet: &[u8]) -> bool {
    if ip_packet.len() < 20 {
        return false;
    }

    // Check IP version
    let version = (ip_packet[0] >> 4) & 0x0F;
    if version != 4 {
        return false;
    }

    // ToS field (byte 1) - if non-zero, packet has QoS marking
    // This matches official C: buf[15] != 0x00 && buf[15] != 0x08
    // buf[15] is ToS field (offset 1 in IP header, offset 15 from start of Ethernet frame)
    let tos = ip_packet[1];
    if tos != 0x00 && tos != 0x08 {
        return true;
    }

    // Protocol field (byte 9)
    let protocol = ip_packet[9];

    // ICMPv4 packets are always priority (network diagnostics)
    // Official C: size >= 34 && size <= 128 && buf[23] == 0x01
    if protocol == IPPROTO_ICMP {
        // Small ICMP packets (ping, etc.) - matches size check in official C
        let total_len = ip_packet.len() + 14; // Add Ethernet header size
        if total_len <= 128 {
            return true;
        }
    }

    // Check for small UDP packets to VoIP ports
    if protocol == IPPROTO_UDP && ip_packet.len() >= 28 {
        let ihl = (ip_packet[0] & 0x0F) as usize * 4;
        if ip_packet.len() >= ihl + 8 {
            let udp_start = ihl;
            let dst_port = u16::from_be_bytes([ip_packet[udp_start + 2], ip_packet[udp_start + 3]]);
            let src_port = u16::from_be_bytes([ip_packet[udp_start], ip_packet[udp_start + 1]]);

            // RTP port range (common for VoIP)
            if (RTP_PORT_MIN..=RTP_PORT_MAX).contains(&dst_port)
                || (RTP_PORT_MIN..=RTP_PORT_MAX).contains(&src_port)
            {
                // Small packet likely to be voice frame
                if ip_packet.len() <= SMALL_PACKET_THRESHOLD {
                    return true;
                }
            }

            // SIP signaling
            if dst_port == SIP_PORT
                || dst_port == SIP_TLS_PORT
                || src_port == SIP_PORT
                || src_port == SIP_TLS_PORT
            {
                return true;
            }
        }
    }

    false
}

/// Check if an IPv6 packet is high priority.
fn is_priority_ipv6(ip_packet: &[u8]) -> bool {
    if ip_packet.len() < 40 {
        return false;
    }

    // Check IP version
    let version = (ip_packet[0] >> 4) & 0x0F;
    if version != 6 {
        return false;
    }

    // Traffic Class (bits 4-11 of first two bytes) contains DSCP
    // Extract from version/traffic class/flow label field
    let traffic_class = ((ip_packet[0] & 0x0F) << 4) | ((ip_packet[1] & 0xF0) >> 4);
    if traffic_class != 0 {
        return true;
    }

    // Next Header (protocol) field - byte 6
    let next_header = ip_packet[6];

    // ICMPv6 (protocol 58) - important for IPv6 operation
    if next_header == 58 {
        return true;
    }

    // Check for UDP with VoIP ports
    if next_header == IPPROTO_UDP && ip_packet.len() >= 48 {
        let udp_start = 40; // Fixed IPv6 header size
        let dst_port = u16::from_be_bytes([ip_packet[udp_start + 2], ip_packet[udp_start + 3]]);
        let src_port = u16::from_be_bytes([ip_packet[udp_start], ip_packet[udp_start + 1]]);

        // RTP port range - small packets likely voice frames
        if ((RTP_PORT_MIN..=RTP_PORT_MAX).contains(&dst_port)
            || (RTP_PORT_MIN..=RTP_PORT_MAX).contains(&src_port))
            && ip_packet.len() <= SMALL_PACKET_THRESHOLD
        {
            return true;
        }

        // SIP signaling
        if dst_port == SIP_PORT
            || dst_port == SIP_TLS_PORT
            || src_port == SIP_PORT
            || src_port == SIP_TLS_PORT
        {
            return true;
        }
    }

    false
}

/// Extract DSCP value from an Ethernet frame.
///
/// Returns the 6-bit DSCP value from the IPv4 ToS or IPv6 Traffic Class field.
/// Returns 0 if the packet is not IP or is malformed.
pub fn get_dscp(frame: &[u8]) -> u8 {
    if frame.len() < 15 {
        return 0;
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    match ethertype {
        ETHERTYPE_IPV4 if frame.len() >= 15 => {
            // DSCP is upper 6 bits of ToS field
            (frame[15] >> 2) & 0x3F
        }
        ETHERTYPE_IPV6 if frame.len() >= 16 => {
            // Traffic Class extraction, then DSCP is upper 6 bits
            let traffic_class = ((frame[14] & 0x0F) << 4) | ((frame[15] & 0xF0) >> 4);
            (traffic_class >> 2) & 0x3F
        }
        _ => 0,
    }
}

/// DSCP values for common traffic classes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DscpClass {
    /// Best Effort (default)
    BestEffort = 0,
    /// Expedited Forwarding (VoIP)
    ExpeditedForwarding = 46,
    /// Assured Forwarding class 4, high drop probability
    Af41 = 34,
    /// Assured Forwarding class 4, medium drop probability
    Af42 = 36,
    /// Assured Forwarding class 4, low drop probability
    Af43 = 38,
    /// Class Selector 6 (network control)
    Cs6 = 48,
    /// Class Selector 7 (network control)
    Cs7 = 56,
}

impl From<u8> for DscpClass {
    fn from(value: u8) -> Self {
        match value {
            46 => DscpClass::ExpeditedForwarding,
            34 => DscpClass::Af41,
            36 => DscpClass::Af42,
            38 => DscpClass::Af43,
            48 => DscpClass::Cs6,
            56 => DscpClass::Cs7,
            _ => DscpClass::BestEffort,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv4_frame(tos: u8, protocol: u8, payload_len: usize) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + payload_len];
        // Ethernet header
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4

        // IPv4 header
        frame[14] = 0x45; // Version 4, IHL 5
        frame[15] = tos; // ToS
        let total_len = (20 + payload_len) as u16;
        frame[16..18].copy_from_slice(&total_len.to_be_bytes());
        frame[23] = protocol; // Protocol

        frame
    }

    fn make_ipv6_frame(traffic_class: u8, next_header: u8, payload_len: usize) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 40 + payload_len];
        // Ethernet header
        frame[12] = 0x86;
        frame[13] = 0xDD; // IPv6

        // IPv6 header - version and traffic class
        frame[14] = 0x60 | ((traffic_class >> 4) & 0x0F);
        frame[15] = (traffic_class << 4) & 0xF0;
        frame[20] = next_header;

        frame
    }

    #[test]
    fn test_ipv4_tos_priority() {
        // Non-zero ToS should be priority
        let frame = make_ipv4_frame(0x10, 6, 100); // DSCP 4
        assert!(is_priority_packet(&frame));

        // Zero ToS should not be priority (unless ICMP)
        let frame = make_ipv4_frame(0x00, 6, 100);
        assert!(!is_priority_packet(&frame));

        // ToS 0x08 should not be priority (explicit exception in official C)
        let frame = make_ipv4_frame(0x08, 6, 100);
        assert!(!is_priority_packet(&frame));
    }

    #[test]
    fn test_icmp_priority() {
        // Small ICMP should be priority
        let frame = make_ipv4_frame(0x00, 1, 50); // ICMP, small packet
        assert!(is_priority_packet(&frame));

        // Large ICMP should not be priority
        let frame = make_ipv4_frame(0x00, 1, 200);
        assert!(!is_priority_packet(&frame));
    }

    #[test]
    fn test_ipv6_traffic_class_priority() {
        // Non-zero traffic class should be priority
        let frame = make_ipv6_frame(0xB8, 6, 100); // EF DSCP
        assert!(is_priority_packet(&frame));

        // Zero traffic class should not be priority
        let frame = make_ipv6_frame(0x00, 6, 100);
        assert!(!is_priority_packet(&frame));
    }

    #[test]
    fn test_icmpv6_priority() {
        // ICMPv6 should be priority
        let frame = make_ipv6_frame(0x00, 58, 50);
        assert!(is_priority_packet(&frame));
    }

    #[test]
    fn test_dscp_extraction() {
        // IPv4 with DSCP 46 (EF)
        let frame = make_ipv4_frame(0xB8, 6, 100); // 0xB8 >> 2 = 46
        assert_eq!(get_dscp(&frame), 46);

        // IPv4 with DSCP 0
        let frame = make_ipv4_frame(0x00, 6, 100);
        assert_eq!(get_dscp(&frame), 0);
    }

    #[test]
    fn test_too_small_frame() {
        let frame = vec![0u8; 10];
        assert!(!is_priority_packet(&frame));
        assert_eq!(get_dscp(&frame), 0);
    }

    #[test]
    fn test_udp_voip_ports() {
        // Create UDP packet to RTP port range
        let mut frame = vec![0u8; 14 + 20 + 8 + 100]; // Eth + IP + UDP + payload
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4
        frame[14] = 0x45; // Version 4, IHL 5
        frame[23] = 17; // UDP

        // UDP header at offset 34
        let dst_port: u16 = 20000; // In RTP range
        frame[36..38].copy_from_slice(&dst_port.to_be_bytes());

        // Small packet should be priority
        let small_frame = &frame[..14 + 20 + 8 + 50];
        assert!(is_priority_packet(small_frame));
    }
}
