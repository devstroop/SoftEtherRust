//! Packet handling utilities for Ethernet, ARP, and DHCP.
//!
//! This module contains:
//! - Ethernet frame utilities with zero-copy helpers
//! - ARP handler for gateway MAC discovery  
//! - DHCP client for IP address configuration

pub mod ethernet;
pub mod arp;
pub mod dhcp;

pub use ethernet::{
    EtherType,
    // Zero-copy helpers
    wrap_ip_in_ethernet,
    unwrap_ethernet_to_ip,
    is_arp_packet,
    is_ipv4_packet,
    is_ipv6_packet,
    get_arp_operation,
    get_arp_sender_ip,
    get_arp_sender_mac,
    get_arp_target_ip,
    // Constants
    HEADER_SIZE,
    MIN_FRAME_SIZE,
    MAX_FRAME_SIZE,
    MAX_MTU,
    BROADCAST_MAC,
    ZERO_MAC,
    // MAC utilities
    format_mac,
    parse_mac,
    is_broadcast,
    is_multicast,
};

pub use arp::{ArpHandler, ArpOperation, PendingArpReply};
pub use dhcp::{DhcpClient, DhcpConfig, DhcpState, DhcpHandler};
