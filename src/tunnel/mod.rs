//! Tunnel utilities for the VPN client.
//!
//! This module contains:
//! - DHCP client for IP address configuration
//! - ARP handler for gateway MAC discovery
//! - Ethernet frame utilities with zero-copy helpers
//! - Data loop state machine for tunnel operations
//! - Tunnel runner for the main data loop

mod dhcp;
mod arp;
mod ethernet;
mod data_loop;
mod runner;

pub use dhcp::{DhcpClient, DhcpConfig, DhcpState, DhcpHandler};
pub use arp::{ArpHandler, ArpOperation, PendingArpReply};
pub use runner::{TunnelRunner, TunnelConfig, RouteConfig};
pub use data_loop::{
    DataLoopState, DataLoopConfig, TimingState, LoopResult, Ipv4Info, format_ip,
};
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
