// DHCP Module - Consolidated DHCP implementation
// Based on Go implementation's clean architecture
//
// This module consolidates the fragmented DHCP functionality from:
// - dhcp.rs (534 lines)  
// - dhcp_localbridge.rs (337 lines)
// - dhcpv6.rs (296 lines)
//
// Following the Go pattern from:
// - cedar/dhcp_client.go
// - cedar/dhcp_packet_handler.go
// - cedar/session_dhcp.go

pub mod client;
pub mod packet_handler;
pub mod types;
pub mod v6;

pub use client::DhcpClient;
pub use packet_handler::DhcpPacketHandler;
pub use types::{Lease, LeaseV6, DhcpState, DhcpMetrics, DhcpOptions};
pub use v6::DhcpV6Client;

/// DHCP Constants from Go implementation
pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_REQUEST: u8 = 3;
pub const DHCP_ACK: u8 = 5;
pub const DHCP_NACK: u8 = 6;
pub const DHCP_RELEASE: u8 = 7;
pub const DHCP_INFORM: u8 = 8;

pub const DHCP_MAGIC_COOKIE: u32 = 0x63825363;

// DHCP Option IDs (matching Go implementation)
pub const DHCP_ID_MESSAGE_TYPE: u8 = 53;
pub const DHCP_ID_SERVER_ADDRESS: u8 = 54;
pub const DHCP_ID_CLIENT_ID: u8 = 61;
pub const DHCP_ID_REQUEST_IP: u8 = 50;
pub const DHCP_ID_HOSTNAME: u8 = 12;
pub const DHCP_ID_SUBNET_MASK: u8 = 1;
pub const DHCP_ID_GATEWAY: u8 = 3;
pub const DHCP_ID_DNS_SERVER: u8 = 6;
pub const DHCP_ID_LEASE_TIME: u8 = 51;
pub const DHCP_ID_DOMAIN_NAME: u8 = 15;
pub const DHCP_ID_PARAMETER_REQUEST_LIST: u8 = 55;
pub const DHCP_ID_END: u8 = 255;

pub const IPC_DHCP_TIMEOUT: u32 = 5000; // 5 seconds timeout

/// Unified DHCP interface inspired by Go's clean architecture
pub trait DhcpInterface {
    fn allocate_ip(&mut self) -> Result<DhcpOptions, Box<dyn std::error::Error>>;
    fn renew_lease(&mut self, lease: &Lease) -> Result<DhcpOptions, Box<dyn std::error::Error>>;
    fn release_lease(&mut self, lease: &Lease) -> Result<(), Box<dyn std::error::Error>>;
    fn get_network_config(&self) -> Option<(std::net::Ipv4Addr, std::net::Ipv4Addr, Option<std::net::Ipv4Addr>, Vec<std::net::Ipv4Addr>)>;
}