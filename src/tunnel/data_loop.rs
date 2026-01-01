//! Data Loop State Machine
//!
//! Main packet processing state for VPN tunnel.
//! Combines DHCP, ARP, and timing into a unified state struct.
//!
//! Inspired by SoftEtherZig's data_loop.zig pattern.

use std::net::Ipv4Addr;
use std::time::Instant;

use crate::packet::arp::ArpHandler;
use crate::packet::dhcp::{DhcpConfig, DhcpHandler};
use crate::packet::ethernet::{
    get_arp_operation, get_arp_sender_ip, get_arp_sender_mac, get_arp_target_ip,
    is_arp_packet, BROADCAST_MAC,
};

/// Configuration for the data loop.
#[derive(Debug, Clone)]
pub struct DataLoopConfig {
    /// Keepalive interval in milliseconds.
    pub keepalive_interval_ms: u64,
    /// Gratuitous ARP interval in milliseconds.
    pub garp_interval_ms: u64,
    /// DHCP retry interval in milliseconds.
    pub dhcp_retry_interval_ms: u64,
    /// Maximum DHCP retries.
    pub max_dhcp_retries: u32,
    /// Enable full tunnel routing.
    pub default_route: bool,
    /// Initial delay before DHCP discover (ms).
    pub initial_delay_ms: u32,
}

impl Default for DataLoopConfig {
    fn default() -> Self {
        Self {
            keepalive_interval_ms: 5_000,
            garp_interval_ms: 10_000,
            dhcp_retry_interval_ms: 3_000,
            max_dhcp_retries: 5,
            default_route: true,
            initial_delay_ms: 300,
        }
    }
}

/// Timing state for the data loop.
#[derive(Debug)]
pub struct TimingState {
    /// Last keepalive send time.
    pub last_keepalive: Instant,
    /// Last gratuitous ARP send time.
    pub last_garp_time: Option<Instant>,
    /// Last DHCP send time.
    pub last_dhcp_time: Option<Instant>,
}

impl TimingState {
    /// Create new timing state.
    pub fn new() -> Self {
        Self {
            last_keepalive: Instant::now(),
            last_garp_time: None,
            last_dhcp_time: None,
        }
    }

    /// Check if we should send keepalive.
    pub fn should_send_keepalive(&self, interval_ms: u64) -> bool {
        self.last_keepalive.elapsed().as_millis() as u64 >= interval_ms
    }

    /// Check if we should send gratuitous ARP.
    pub fn should_send_garp(&self, interval_ms: u64) -> bool {
        match self.last_garp_time {
            Some(last) => last.elapsed().as_millis() as u64 >= interval_ms,
            None => true,
        }
    }

    /// Mark keepalive sent.
    pub fn mark_keepalive_sent(&mut self) {
        self.last_keepalive = Instant::now();
    }

    /// Mark GARP sent.
    pub fn mark_garp_sent(&mut self) {
        self.last_garp_time = Some(Instant::now());
    }
}

impl Default for TimingState {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of processing a single iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopResult {
    /// Continue processing.
    Continue,
    /// Stop requested.
    StopRequested,
    /// Connection closed by server.
    ConnectionClosed,
    /// Error occurred.
    Error,
}

/// Combined state for the data loop.
///
/// This struct holds all the state needed for the tunnel data loop:
/// - DHCP handler for IP configuration
/// - ARP handler for gateway MAC discovery
/// - Timing state for periodic operations
/// - Configured addresses
#[derive(Debug)]
pub struct DataLoopState {
    /// DHCP handler.
    pub dhcp: DhcpHandler,
    
    /// ARP handler.
    pub arp: ArpHandler,
    
    /// Timing state.
    pub timing: TimingState,
    
    /// Our MAC address.
    pub mac: [u8; 6],
    
    /// Our IP address (set after DHCP).
    pub our_ip: Ipv4Addr,
    
    /// Gateway IP address.
    pub gateway_ip: Ipv4Addr,
    
    /// Gateway MAC address.
    pub gateway_mac: [u8; 6],
    
    /// Whether we're fully configured.
    pub is_configured: bool,
}

impl DataLoopState {
    /// Create a new data loop state.
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            dhcp: DhcpHandler::new(),
            arp: ArpHandler::new(mac),
            timing: TimingState::new(),
            mac,
            our_ip: Ipv4Addr::UNSPECIFIED,
            gateway_ip: Ipv4Addr::UNSPECIFIED,
            gateway_mac: BROADCAST_MAC,
            is_configured: false,
        }
    }

    /// Check if DHCP is configured.
    pub fn is_dhcp_configured(&self) -> bool {
        self.dhcp.is_configured()
    }

    /// Configure addresses after DHCP completes.
    pub fn configure(&mut self, ip: Ipv4Addr, gateway: Ipv4Addr) {
        self.our_ip = ip;
        self.gateway_ip = gateway;
        self.arp.configure(ip, gateway);
        self.is_configured = true;
    }

    /// Apply DHCP configuration.
    pub fn apply_dhcp_config(&mut self, config: &DhcpConfig) {
        self.our_ip = config.ip;
        self.gateway_ip = config.gateway.unwrap_or(config.ip);
        self.arp.configure(self.our_ip, self.gateway_ip);
        self.is_configured = true;
    }

    /// Process an ARP reply - learn MAC if it's from gateway.
    pub fn process_arp_reply(&mut self, eth_frame: &[u8]) {
        if eth_frame.len() < 42 || !is_arp_packet(eth_frame) {
            return;
        }

        // Check it's a reply (operation = 2)
        if get_arp_operation(eth_frame) != Some(2) {
            return;
        }

        // Extract sender IP
        let sender_ip = match get_arp_sender_ip(eth_frame) {
            Some(ip) => Ipv4Addr::from(ip),
            None => return,
        };

        // If from gateway, learn its MAC
        if !self.gateway_ip.is_unspecified() && sender_ip == self.gateway_ip {
            if let Some(sender_mac) = get_arp_sender_mac(eth_frame) {
                self.gateway_mac = sender_mac;
                tracing::debug!(
                    "Learned gateway MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    sender_mac[0], sender_mac[1], sender_mac[2],
                    sender_mac[3], sender_mac[4], sender_mac[5]
                );
            }
        }
        
        // Also update ARP handler
        self.arp.process_arp_reply(eth_frame);
    }

    /// Process an ARP request - queue reply if asking for our IP.
    pub fn process_arp_request(&mut self, eth_frame: &[u8]) {
        if eth_frame.len() < 42 || !is_arp_packet(eth_frame) {
            return;
        }

        // Check it's a request (operation = 1)
        if get_arp_operation(eth_frame) != Some(1) {
            return;
        }

        // Extract target IP
        let target_ip = match get_arp_target_ip(eth_frame) {
            Some(ip) => Ipv4Addr::from(ip),
            None => return,
        };

        // If asking for our IP, delegate to ARP handler
        if target_ip == self.our_ip && !self.our_ip.is_unspecified() {
            self.arp.process_arp_request(eth_frame);
        }
    }

    /// Process any incoming ARP packet.
    pub fn process_arp(&mut self, eth_frame: &[u8]) {
        match get_arp_operation(eth_frame) {
            Some(1) => self.process_arp_request(eth_frame),
            Some(2) => self.process_arp_reply(eth_frame),
            _ => {}
        }
    }

    /// Get gateway MAC (defaults to broadcast if not learned).
    pub fn get_gateway_mac(&self) -> [u8; 6] {
        if self.arp.has_gateway_mac() {
            *self.arp.gateway_mac().unwrap()
        } else {
            self.gateway_mac
        }
    }

    /// Check if gateway MAC is known.
    pub fn is_gateway_mac_known(&self) -> bool {
        self.arp.has_gateway_mac()
    }

    /// Reset for reconnection.
    pub fn reset(&mut self) {
        self.dhcp.reset();
        self.our_ip = Ipv4Addr::UNSPECIFIED;
        self.gateway_ip = Ipv4Addr::UNSPECIFIED;
        self.gateway_mac = BROADCAST_MAC;
        self.is_configured = false;
        self.timing = TimingState::new();
    }
}

/// Parsed IPv4 header info for logging.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Info {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: u8,
    pub total_len: u16,
}

impl Ipv4Info {
    /// Parse IPv4 header from packet.
    pub fn parse(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 {
            return None;
        }

        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        Some(Self {
            src_ip: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
            dst_ip: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
            protocol: packet[9],
            total_len: u16::from_be_bytes([packet[2], packet[3]]),
        })
    }
}

/// Format an IP address for logging.
pub fn format_ip(ip: Ipv4Addr) -> String {
    ip.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_loop_state_new() {
        let mac = [0x02, 0x00, 0x5E, 0x00, 0x00, 0x01];
        let state = DataLoopState::new(mac);

        assert!(!state.is_configured);
        assert!(!state.is_dhcp_configured());
        assert_eq!(state.our_ip, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_data_loop_state_configure() {
        let mac = [0x02, 0x00, 0x5E, 0x00, 0x00, 0x01];
        let mut state = DataLoopState::new(mac);

        state.configure(
            Ipv4Addr::new(10, 21, 0, 100),
            Ipv4Addr::new(10, 21, 0, 1),
        );

        assert!(state.is_configured);
        assert_eq!(state.our_ip, Ipv4Addr::new(10, 21, 0, 100));
        assert_eq!(state.gateway_ip, Ipv4Addr::new(10, 21, 0, 1));
    }

    #[test]
    fn test_timing_state() {
        let timing = TimingState::new();

        // Should not immediately need keepalive
        assert!(!timing.should_send_keepalive(5000));

        // Should need GARP (first time)
        assert!(timing.should_send_garp(10000));
    }

    #[test]
    fn test_ipv4_info_parse() {
        // Minimal valid IPv4 header
        let mut packet = [0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[2] = 0x00;
        packet[3] = 0x28; // Total length 40
        packet[9] = 6;    // TCP
        packet[12..16].copy_from_slice(&[192, 168, 1, 100]); // src
        packet[16..20].copy_from_slice(&[192, 168, 1, 1]);   // dst

        let info = Ipv4Info::parse(&packet);
        assert!(info.is_some());

        let info = info.unwrap();
        assert_eq!(info.src_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(info.dst_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(info.protocol, 6);
        assert_eq!(info.total_len, 40);
    }

    #[test]
    fn test_ipv4_info_parse_ipv6() {
        // IPv6 header should fail
        let mut packet = [0u8; 40];
        packet[0] = 0x60; // Version 6

        let info = Ipv4Info::parse(&packet);
        assert!(info.is_none());
    }

    #[test]
    fn test_data_loop_state_reset() {
        let mac = [0x02, 0x00, 0x5E, 0x00, 0x00, 0x01];
        let mut state = DataLoopState::new(mac);

        state.configure(
            Ipv4Addr::new(10, 21, 0, 100),
            Ipv4Addr::new(10, 21, 0, 1),
        );
        assert!(state.is_configured);

        state.reset();
        assert!(!state.is_configured);
        assert_eq!(state.our_ip, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_get_gateway_mac() {
        let mac = [0x02, 0x00, 0x5E, 0x00, 0x00, 0x01];
        let state = DataLoopState::new(mac);

        // Before learning, should be broadcast
        assert_eq!(state.get_gateway_mac(), BROADCAST_MAC);
        assert!(!state.is_gateway_mac_known());
    }
    
    #[test]
    fn test_data_loop_config_default() {
        let config = DataLoopConfig::default();
        assert_eq!(config.keepalive_interval_ms, 5000);
        assert_eq!(config.garp_interval_ms, 10000);
        assert_eq!(config.dhcp_retry_interval_ms, 3000);
        assert_eq!(config.max_dhcp_retries, 5);
        assert!(config.default_route);
    }
}
