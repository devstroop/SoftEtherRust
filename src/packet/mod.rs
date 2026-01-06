//! Packet handling utilities for Ethernet, ARP, DHCP, and IP fragmentation.
//!
//! This module contains:
//! - Ethernet frame utilities with zero-copy helpers
//! - ARP handler for gateway MAC discovery  
//! - DHCP client for IP address configuration
//! - IP packet fragmentation and reassembly

pub mod arp;
pub mod dhcp;
pub mod ethernet;
pub mod fragment;

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
pub use fragment::{
    fragment_ipv4_packet, FragmentKey, FragmentReassembler, FragmentResult, DEFAULT_FRAGMENT_MTU,
    MIN_MTU,
};
