//! Packet handling utilities for Ethernet, ARP, DHCP, DHCPv6, QoS, and IP fragmentation.
//!
//! This module contains:
//! - Ethernet frame utilities with zero-copy helpers
//! - ARP handler for gateway MAC discovery  
//! - DHCP client for IPv4 address configuration
//! - DHCPv6 client for IPv6 address configuration
//! - QoS packet classification for VoIP prioritization
//! - IP packet fragmentation and reassembly

pub mod arp;
pub mod dhcp;
pub mod dhcpv6;
pub mod ethernet;
pub mod fragment;
pub mod qos;

pub use ethernet::{
    // MAC utilities
    format_mac,
    get_arp_operation,
    get_arp_sender_ip,
    get_arp_sender_mac,
    get_arp_target_ip,
    is_arp_packet,
    is_broadcast,
    is_ipv4_packet,
    is_ipv6_packet,
    is_multicast,
    parse_mac,
    unwrap_ethernet_to_ip,
    // Zero-copy helpers
    wrap_ip_in_ethernet,
    EtherType,
    BROADCAST_MAC,
    // Constants
    HEADER_SIZE,
    MAX_FRAME_SIZE,
    MAX_MTU,
    MIN_FRAME_SIZE,
    ZERO_MAC,
};

pub use arp::{ArpHandler, ArpOperation, PendingArpReply};
pub use dhcp::{DhcpClient, DhcpConfig, DhcpHandler, DhcpMessageType, DhcpOption, DhcpState};
pub use dhcpv6::{
    mac_to_link_local, solicited_node_multicast, Dhcpv6Client, Dhcpv6Config, Dhcpv6Handler,
    Dhcpv6MessageType, Dhcpv6Option, Dhcpv6State, Dhcpv6StatusCode, ALL_DHCP_SERVERS,
    DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT,
};
pub use fragment::{
    fragment_ipv4_packet, FragmentKey, FragmentReassembler, FragmentResult, DEFAULT_FRAGMENT_MTU,
    MIN_MTU,
};

pub use qos::{get_dscp, is_priority_packet, DscpClass};

/// DHCP client UDP port (destination port for DHCP responses).
pub const DHCP_CLIENT_PORT: u16 = 68;

/// Check if an Ethernet frame is a DHCP response (UDP dst port 68).
///
/// Returns `true` if the frame is an IPv4/UDP packet with destination port 68.
#[inline]
pub fn is_dhcp_response(frame: &[u8]) -> bool {
    // Minimum: Ethernet(14) + IP(20) + UDP(8)
    if frame.len() < 42 {
        return false;
    }
    // Check EtherType is IPv4 (0x0800)
    if frame[12] != 0x08 || frame[13] != 0x00 {
        return false;
    }
    // Check IP protocol is UDP (17)
    if frame[23] != 17 {
        return false;
    }
    // Check UDP destination port is 68 (DHCP client)
    let dst_port = u16::from_be_bytes([frame[36], frame[37]]);
    dst_port == DHCP_CLIENT_PORT
}

/// Check if an Ethernet frame is a DHCPv6 response (UDP dst port 546).
///
/// Returns `true` if the frame is an IPv6/UDP packet with destination port 546.
#[inline]
pub fn is_dhcpv6_response(frame: &[u8]) -> bool {
    // Minimum: Ethernet(14) + IPv6(40) + UDP(8)
    if frame.len() < 62 {
        return false;
    }
    // Check EtherType is IPv6 (0x86DD)
    if frame[12] != 0x86 || frame[13] != 0xDD {
        return false;
    }
    // Check IPv6 Next Header is UDP (17)
    if frame[20] != 17 {
        return false;
    }
    // Check UDP destination port is 546 (DHCPv6 client)
    let dst_port = u16::from_be_bytes([frame[54], frame[55]]);
    dst_port == DHCPV6_CLIENT_PORT
}
