//! DHCP client for virtual adapter IP configuration.
//!
//! This module implements a minimal DHCP client that obtains
//! IP address configuration from the VPN's DHCP server.
//!
//! Design follows SoftEtherZig with:
//! - DhcpHandler: State machine with timing/retry logic
//! - DhcpClient: Packet building and parsing
//! - Zero-copy parsing where possible

use bytes::{BufMut, Bytes, BytesMut};
use std::net::Ipv4Addr;
use std::time::Instant;
use tracing::{debug, info, warn};

use crate::crypto::generate_transaction_id;

/// DHCP message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl TryFrom<u8> for DhcpMessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Discover),
            2 => Ok(Self::Offer),
            3 => Ok(Self::Request),
            4 => Ok(Self::Decline),
            5 => Ok(Self::Ack),
            6 => Ok(Self::Nak),
            7 => Ok(Self::Release),
            8 => Ok(Self::Inform),
            _ => Err(()),
        }
    }
}

/// DHCP option codes.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpOption {
    Pad = 0,
    SubnetMask = 1,
    Router = 3,
    DnsServer = 6,
    Hostname = 12,
    DomainName = 15,
    RequestedIp = 50,
    LeaseTime = 51,
    MessageType = 53,
    ServerIdentifier = 54,
    ParameterRequest = 55,
    RenewalTime = 58,
    RebindingTime = 59,
    End = 255,
}

/// DHCP configuration obtained from the server.
#[derive(Debug, Clone)]
pub struct DhcpConfig {
    /// Assigned IP address.
    pub ip: Ipv4Addr,
    /// Subnet mask.
    pub netmask: Ipv4Addr,
    /// Default gateway.
    pub gateway: Option<Ipv4Addr>,
    /// Primary DNS server.
    pub dns1: Option<Ipv4Addr>,
    /// Secondary DNS server.
    pub dns2: Option<Ipv4Addr>,
    /// DHCP server IP.
    pub server_id: Option<Ipv4Addr>,
    /// Lease time in seconds.
    pub lease_time: u32,
    /// Renewal time (T1) in seconds - time to renew with original server.
    /// Default: lease_time / 2
    pub renewal_time: u32,
    /// Rebinding time (T2) in seconds - time to rebind with any server.
    /// Default: lease_time * 7 / 8
    pub rebinding_time: u32,
    /// Domain name.
    pub domain_name: String,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            ip: Ipv4Addr::UNSPECIFIED,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: None,
            dns1: None,
            dns2: None,
            server_id: None,
            lease_time: 0,
            renewal_time: 0,
            rebinding_time: 0,
            domain_name: String::new(),
        }
    }
}

impl DhcpConfig {
    /// Check if the configuration is valid (has an IP address).
    pub fn is_valid(&self) -> bool {
        !self.ip.is_unspecified()
    }
}

/// DHCP client state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DhcpState {
    /// Initial state.
    #[default]
    Idle,
    /// DISCOVER sent, waiting for OFFER.
    DiscoverSent,
    /// REQUEST sent, waiting for ACK.
    RequestSent,
    /// Successfully bound to an IP.
    Bound,
    /// Renewing lease (unicast to server).
    Renewing,
    /// Rebinding lease (broadcast to any server).
    Rebinding,
    /// DHCP failed.
    Failed,
}

/// DHCP magic cookie.
const DHCP_MAGIC: u32 = 0x63825363;

/// DHCP client.
#[derive(Debug)]
pub struct DhcpClient {
    /// Client state.
    state: DhcpState,
    /// Obtained configuration.
    config: DhcpConfig,
    /// Client MAC address.
    mac: [u8; 6],
    /// Transaction ID.
    xid: u32,
    /// Offered IP (from OFFER).
    offered_ip: Ipv4Addr,
    /// Server ID (from OFFER).
    server_id: Ipv4Addr,
}

impl DhcpClient {
    /// Create a new DHCP client.
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            state: DhcpState::Idle,
            config: DhcpConfig::default(),
            mac,
            xid: generate_transaction_id(),
            offered_ip: Ipv4Addr::UNSPECIFIED,
            server_id: Ipv4Addr::UNSPECIFIED,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> DhcpState {
        self.state
    }

    /// Get the obtained configuration.
    pub fn config(&self) -> &DhcpConfig {
        &self.config
    }

    /// Build a DHCP DISCOVER packet (full Ethernet frame).
    pub fn build_discover(&mut self) -> Bytes {
        self.state = DhcpState::DiscoverSent;
        self.build_dhcp_packet(DhcpMessageType::Discover, None, None)
    }

    /// Build a DHCP REQUEST packet (full Ethernet frame).
    pub fn build_request(&mut self) -> Option<Bytes> {
        if self.offered_ip.is_unspecified() || self.server_id.is_unspecified() {
            return None;
        }

        self.state = DhcpState::RequestSent;
        Some(self.build_dhcp_packet(
            DhcpMessageType::Request,
            Some(self.offered_ip),
            Some(self.server_id),
        ))
    }

    /// Build a DHCP renewal REQUEST packet (unicast to server).
    /// For renewal, we use our current IP as source and send directly to server.
    pub fn build_renewal_request(
        &self,
        client_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        gateway_mac: [u8; 6],
    ) -> Bytes {
        self.build_dhcp_packet_unicast(
            DhcpMessageType::Request,
            client_ip,
            server_ip,
            gateway_mac,
        )
    }

    /// Build a DHCP rebinding REQUEST packet (broadcast).
    /// For rebinding, we broadcast to any server.
    pub fn build_rebinding_request(&self, client_ip: Ipv4Addr) -> Bytes {
        // Rebinding uses broadcast like initial request, but ciaddr is set
        self.build_dhcp_packet_rebind(DhcpMessageType::Request, client_ip)
    }

    /// Build a DHCP RELEASE packet to release the lease.
    pub fn build_release(&self, client_ip: Ipv4Addr, server_ip: Ipv4Addr, gateway_mac: [u8; 6]) -> Bytes {
        self.build_dhcp_packet_unicast(DhcpMessageType::Release, client_ip, server_ip, gateway_mac)
    }

    /// Process a DHCP response packet.
    ///
    /// Returns `true` if DHCP is complete (ACK received).
    pub fn process_response(&mut self, frame: &[u8]) -> bool {
        // Minimum frame size: Ethernet(14) + IP(20) + UDP(8) + DHCP(240)
        if frame.len() < 282 {
            debug!("DHCP frame too small: {}", frame.len());
            return false;
        }

        // Check EtherType (IPv4)
        if frame[12] != 0x08 || frame[13] != 0x00 {
            debug!("Not IPv4");
            return false;
        }

        // Check IP protocol (UDP)
        if frame[23] != 17 {
            debug!("Not UDP");
            return false;
        }

        // Check UDP ports (67 -> 68)
        let src_port = u16::from_be_bytes([frame[34], frame[35]]);
        let dst_port = u16::from_be_bytes([frame[36], frame[37]]);
        if src_port != 67 || dst_port != 68 {
            debug!("Wrong ports: {} -> {}", src_port, dst_port);
            return false;
        }

        // DHCP starts at offset 42
        let dhcp_start = 42;

        // Check transaction ID
        let xid = u32::from_be_bytes([
            frame[dhcp_start + 4],
            frame[dhcp_start + 5],
            frame[dhcp_start + 6],
            frame[dhcp_start + 7],
        ]);
        if xid != self.xid {
            debug!("XID mismatch: got {:08x}, expected {:08x}", xid, self.xid);
            return false;
        }

        // Check magic cookie
        let magic = u32::from_be_bytes([
            frame[dhcp_start + 236],
            frame[dhcp_start + 237],
            frame[dhcp_start + 238],
            frame[dhcp_start + 239],
        ]);
        if magic != DHCP_MAGIC {
            debug!("Bad magic cookie: {:08x}", magic);
            return false;
        }

        // Get offered IP from yiaddr field
        let yiaddr = Ipv4Addr::new(
            frame[dhcp_start + 16],
            frame[dhcp_start + 17],
            frame[dhcp_start + 18],
            frame[dhcp_start + 19],
        );

        // Parse options
        let mut option_start = dhcp_start + 240;
        let mut message_type = None;
        let mut config = DhcpConfig {
            ip: yiaddr,
            ..Default::default()
        };

        while option_start < frame.len() {
            let opt_code = frame[option_start];

            if opt_code == DhcpOption::End as u8 {
                break;
            }

            if opt_code == DhcpOption::Pad as u8 {
                option_start += 1;
                continue;
            }

            if option_start + 1 >= frame.len() {
                break;
            }

            let opt_len = frame[option_start + 1] as usize;
            if option_start + 2 + opt_len > frame.len() {
                break;
            }

            let opt_data = &frame[option_start + 2..option_start + 2 + opt_len];

            match opt_code {
                c if c == DhcpOption::MessageType as u8 && opt_len >= 1 => {
                    message_type = DhcpMessageType::try_from(opt_data[0]).ok();
                }
                c if c == DhcpOption::SubnetMask as u8 && opt_len >= 4 => {
                    config.netmask =
                        Ipv4Addr::new(opt_data[0], opt_data[1], opt_data[2], opt_data[3]);
                }
                c if c == DhcpOption::Router as u8 && opt_len >= 4 => {
                    config.gateway = Some(Ipv4Addr::new(
                        opt_data[0],
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                    ));
                }
                c if c == DhcpOption::DnsServer as u8 && opt_len >= 4 => {
                    config.dns1 = Some(Ipv4Addr::new(
                        opt_data[0],
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                    ));
                    if opt_len >= 8 {
                        config.dns2 = Some(Ipv4Addr::new(
                            opt_data[4],
                            opt_data[5],
                            opt_data[6],
                            opt_data[7],
                        ));
                    }
                }
                c if c == DhcpOption::ServerIdentifier as u8 && opt_len >= 4 => {
                    config.server_id = Some(Ipv4Addr::new(
                        opt_data[0],
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                    ));
                }
                c if c == DhcpOption::LeaseTime as u8 && opt_len >= 4 => {
                    config.lease_time =
                        u32::from_be_bytes([opt_data[0], opt_data[1], opt_data[2], opt_data[3]]);
                }
                c if c == DhcpOption::RenewalTime as u8 && opt_len >= 4 => {
                    config.renewal_time =
                        u32::from_be_bytes([opt_data[0], opt_data[1], opt_data[2], opt_data[3]]);
                }
                c if c == DhcpOption::RebindingTime as u8 && opt_len >= 4 => {
                    config.rebinding_time =
                        u32::from_be_bytes([opt_data[0], opt_data[1], opt_data[2], opt_data[3]]);
                }
                c if c == DhcpOption::DomainName as u8 => {
                    config.domain_name = String::from_utf8_lossy(opt_data).into_owned();
                }
                _ => {}
            }

            option_start += 2 + opt_len;
        }

        match message_type {
            Some(DhcpMessageType::Offer) => {
                self.offered_ip = config.ip;
                self.server_id = config.server_id.unwrap_or(Ipv4Addr::UNSPECIFIED);
                info!("DHCP OFFER: {}", config.ip);
                false
            }
            Some(DhcpMessageType::Ack) => {
                // Compute default T1/T2 if not provided by server
                if config.renewal_time == 0 && config.lease_time > 0 {
                    config.renewal_time = config.lease_time / 2;
                }
                if config.rebinding_time == 0 && config.lease_time > 0 {
                    config.rebinding_time = config.lease_time * 7 / 8;
                }
                self.config = config;
                self.state = DhcpState::Bound;
                info!(
                    "DHCP ACK: IP={}, Gateway={:?}, DNS={:?}, Lease={}s, T1={}s, T2={}s",
                    self.config.ip, self.config.gateway, self.config.dns1,
                    self.config.lease_time, self.config.renewal_time, self.config.rebinding_time
                );
                true
            }
            Some(DhcpMessageType::Nak) => {
                warn!("DHCP NAK received");
                self.state = DhcpState::Failed;
                false
            }
            _ => {
                debug!("Unknown DHCP message type: {:?}", message_type);
                false
            }
        }
    }

    /// Build a DHCP packet.
    fn build_dhcp_packet(
        &self,
        msg_type: DhcpMessageType,
        requested_ip: Option<Ipv4Addr>,
        server_id: Option<Ipv4Addr>,
    ) -> Bytes {
        let dhcp_payload = self.build_dhcp_payload(msg_type, requested_ip, server_id);
        let udp_len = 8 + dhcp_payload.len();
        let ip_len = 20 + udp_len;

        let mut packet = BytesMut::with_capacity(14 + ip_len);

        // === Ethernet Header (14 bytes) ===
        packet.put_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Destination: broadcast
        packet.put_slice(&self.mac); // Source: our MAC
        packet.put_u16(0x0800); // EtherType: IPv4

        // === IPv4 Header (20 bytes) ===
        packet.put_u8(0x45); // Version 4, IHL 5
        packet.put_u8(0x00); // DSCP/ECN
        packet.put_u16(ip_len as u16);
        packet.put_u32(0x00000000); // ID, flags, fragment
        packet.put_u8(64); // TTL
        packet.put_u8(17); // Protocol: UDP
        packet.put_u16(0x0000); // Checksum placeholder
        packet.put_u32(0x00000000); // Source: 0.0.0.0
        packet.put_u32(0xFFFFFFFF); // Dest: broadcast

        // Calculate IP checksum
        let ip_start = 14;
        let checksum = Self::calculate_ip_checksum(&packet[ip_start..ip_start + 20]);
        packet[ip_start + 10] = (checksum >> 8) as u8;
        packet[ip_start + 11] = checksum as u8;

        // === UDP Header (8 bytes) ===
        packet.put_u16(68); // Source port: DHCP client
        packet.put_u16(67); // Dest port: DHCP server
        packet.put_u16(udp_len as u16);
        packet.put_u16(0x0000); // Checksum (optional)

        // === DHCP Payload ===
        packet.put_slice(&dhcp_payload);

        packet.freeze()
    }

    /// Build the DHCP payload.
    fn build_dhcp_payload(
        &self,
        msg_type: DhcpMessageType,
        requested_ip: Option<Ipv4Addr>,
        server_id: Option<Ipv4Addr>,
    ) -> Bytes {
        let mut payload = BytesMut::with_capacity(300);

        // DHCP fixed header (236 bytes)
        payload.put_u8(0x01); // op: BOOTREQUEST
        payload.put_u8(0x01); // htype: Ethernet
        payload.put_u8(0x06); // hlen: 6
        payload.put_u8(0x00); // hops: 0

        // Transaction ID
        payload.put_u32(self.xid);

        // secs (2 bytes) + flags (2 bytes)
        // Set BROADCAST flag (0x8000) so server broadcasts reply
        payload.put_u16(0x0000); // secs: 0
        payload.put_u16(0x8000); // flags: BROADCAST

        // ciaddr, yiaddr, siaddr, giaddr (all zeros)
        payload.put_slice(&[0u8; 16]);

        // chaddr (client hardware address) - 16 bytes
        payload.put_slice(&self.mac);
        payload.put_slice(&[0u8; 10]); // padding

        // sname (64 bytes) + file (128 bytes) - zeros
        payload.put_slice(&[0u8; 192]);

        // Magic cookie
        payload.put_u32(DHCP_MAGIC);

        // Options
        // Message type
        payload.put_u8(DhcpOption::MessageType as u8);
        payload.put_u8(1);
        payload.put_u8(msg_type as u8);

        // Requested IP (for REQUEST)
        if let Some(ip) = requested_ip {
            payload.put_u8(DhcpOption::RequestedIp as u8);
            payload.put_u8(4);
            payload.put_slice(&ip.octets());
        }

        // Server ID (for REQUEST)
        if let Some(ip) = server_id {
            payload.put_u8(DhcpOption::ServerIdentifier as u8);
            payload.put_u8(4);
            payload.put_slice(&ip.octets());
        }

        // Parameter request list
        payload.put_u8(DhcpOption::ParameterRequest as u8);
        payload.put_u8(4);
        payload.put_u8(DhcpOption::SubnetMask as u8);
        payload.put_u8(DhcpOption::Router as u8);
        payload.put_u8(DhcpOption::DnsServer as u8);
        payload.put_u8(DhcpOption::DomainName as u8);

        // End option
        payload.put_u8(DhcpOption::End as u8);

        // Pad to minimum size
        while payload.len() < 300 - 14 - 20 - 8 {
            payload.put_u8(0x00);
        }

        payload.freeze()
    }

    /// Build a unicast DHCP packet (for renewal/release to server).
    fn build_dhcp_packet_unicast(
        &self,
        msg_type: DhcpMessageType,
        client_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        gateway_mac: [u8; 6],
    ) -> Bytes {
        let dhcp_payload = self.build_dhcp_payload_renewal(msg_type, client_ip, Some(server_ip));
        let udp_len = 8 + dhcp_payload.len();
        let ip_len = 20 + udp_len;

        let mut packet = BytesMut::with_capacity(14 + ip_len);

        // === Ethernet Header (14 bytes) ===
        // For unicast, send to gateway MAC (server is on different subnet)
        packet.put_slice(&gateway_mac); // Destination: gateway MAC
        packet.put_slice(&self.mac); // Source: our MAC
        packet.put_u16(0x0800); // EtherType: IPv4

        // === IPv4 Header (20 bytes) ===
        packet.put_u8(0x45); // Version 4, IHL 5
        packet.put_u8(0x00); // DSCP/ECN
        packet.put_u16(ip_len as u16);
        packet.put_u32(0x00000000); // ID, flags, fragment
        packet.put_u8(64); // TTL
        packet.put_u8(17); // Protocol: UDP
        packet.put_u16(0x0000); // Checksum placeholder
        packet.put_slice(&client_ip.octets()); // Source: our IP
        packet.put_slice(&server_ip.octets()); // Dest: server IP

        // Calculate IP checksum
        let ip_start = 14;
        let checksum = Self::calculate_ip_checksum(&packet[ip_start..ip_start + 20]);
        packet[ip_start + 10] = (checksum >> 8) as u8;
        packet[ip_start + 11] = checksum as u8;

        // === UDP Header (8 bytes) ===
        packet.put_u16(68); // Source port: DHCP client
        packet.put_u16(67); // Dest port: DHCP server
        packet.put_u16(udp_len as u16);
        packet.put_u16(0x0000); // Checksum (optional)

        // === DHCP Payload ===
        packet.put_slice(&dhcp_payload);

        packet.freeze()
    }

    /// Build a broadcast DHCP packet for rebinding.
    fn build_dhcp_packet_rebind(&self, msg_type: DhcpMessageType, client_ip: Ipv4Addr) -> Bytes {
        let dhcp_payload = self.build_dhcp_payload_renewal(msg_type, client_ip, None);
        let udp_len = 8 + dhcp_payload.len();
        let ip_len = 20 + udp_len;

        let mut packet = BytesMut::with_capacity(14 + ip_len);

        // === Ethernet Header (14 bytes) ===
        packet.put_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Destination: broadcast
        packet.put_slice(&self.mac); // Source: our MAC
        packet.put_u16(0x0800); // EtherType: IPv4

        // === IPv4 Header (20 bytes) ===
        packet.put_u8(0x45); // Version 4, IHL 5
        packet.put_u8(0x00); // DSCP/ECN
        packet.put_u16(ip_len as u16);
        packet.put_u32(0x00000000); // ID, flags, fragment
        packet.put_u8(64); // TTL
        packet.put_u8(17); // Protocol: UDP
        packet.put_u16(0x0000); // Checksum placeholder
        packet.put_slice(&client_ip.octets()); // Source: our IP
        packet.put_u32(0xFFFFFFFF); // Dest: broadcast

        // Calculate IP checksum
        let ip_start = 14;
        let checksum = Self::calculate_ip_checksum(&packet[ip_start..ip_start + 20]);
        packet[ip_start + 10] = (checksum >> 8) as u8;
        packet[ip_start + 11] = checksum as u8;

        // === UDP Header (8 bytes) ===
        packet.put_u16(68); // Source port: DHCP client
        packet.put_u16(67); // Dest port: DHCP server
        packet.put_u16(udp_len as u16);
        packet.put_u16(0x0000); // Checksum (optional)

        // === DHCP Payload ===
        packet.put_slice(&dhcp_payload);

        packet.freeze()
    }

    /// Build DHCP payload for renewal/rebinding/release.
    /// For renewal, ciaddr is set to our current IP.
    fn build_dhcp_payload_renewal(
        &self,
        msg_type: DhcpMessageType,
        client_ip: Ipv4Addr,
        server_id: Option<Ipv4Addr>,
    ) -> Bytes {
        let mut payload = BytesMut::with_capacity(300);

        // DHCP fixed header (236 bytes)
        payload.put_u8(0x01); // op: BOOTREQUEST
        payload.put_u8(0x01); // htype: Ethernet
        payload.put_u8(0x06); // hlen: 6
        payload.put_u8(0x00); // hops: 0

        // Transaction ID
        payload.put_u32(self.xid);

        // secs (2 bytes) + flags (2 bytes)
        // For renewal, don't set BROADCAST flag - we want unicast reply
        payload.put_u16(0x0000); // secs: 0
        payload.put_u16(0x0000); // flags: 0 (unicast)

        // ciaddr: our current IP (required for renewal)
        payload.put_slice(&client_ip.octets());
        // yiaddr, siaddr, giaddr (zeros)
        payload.put_slice(&[0u8; 12]);

        // chaddr (client hardware address) - 16 bytes
        payload.put_slice(&self.mac);
        payload.put_slice(&[0u8; 10]); // padding

        // sname (64 bytes) + file (128 bytes) - zeros
        payload.put_slice(&[0u8; 192]);

        // Magic cookie
        payload.put_u32(DHCP_MAGIC);

        // Options
        // Message type
        payload.put_u8(DhcpOption::MessageType as u8);
        payload.put_u8(1);
        payload.put_u8(msg_type as u8);

        // Server ID (for renewal, not for rebinding)
        if let Some(ip) = server_id {
            payload.put_u8(DhcpOption::ServerIdentifier as u8);
            payload.put_u8(4);
            payload.put_slice(&ip.octets());
        }

        // Parameter request list
        payload.put_u8(DhcpOption::ParameterRequest as u8);
        payload.put_u8(4);
        payload.put_u8(DhcpOption::SubnetMask as u8);
        payload.put_u8(DhcpOption::Router as u8);
        payload.put_u8(DhcpOption::DnsServer as u8);
        payload.put_u8(DhcpOption::DomainName as u8);

        // End option
        payload.put_u8(DhcpOption::End as u8);

        // Pad to minimum size
        while payload.len() < 300 - 14 - 20 - 8 {
            payload.put_u8(0x00);
        }

        payload.freeze()
    }

    /// Calculate IP header checksum.
    fn calculate_ip_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        for i in (0..header.len()).step_by(2) {
            let word = (header[i] as u32) << 8 | (header[i + 1] as u32);
            sum += word;
        }

        // Fold 32-bit sum to 16 bits
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }
}

// =============================================================================
// DhcpHandler - State machine with timing (like SoftEtherZig)
// =============================================================================

/// DHCP retry interval (3 seconds).
const DHCP_RETRY_INTERVAL_MS: u64 = 3_000;

/// Maximum DHCP retries.
const MAX_DHCP_RETRIES: u32 = 5;

/// DHCP handler state machine.
///
/// This separates the timing/retry logic from the packet building.
/// Inspired by SoftEtherZig's DhcpHandler.
#[derive(Debug)]
pub struct DhcpHandler {
    /// Current state.
    state: DhcpState,
    /// Transaction ID for this DHCP session.
    xid: u32,
    /// Last send time.
    last_send_time: Option<Instant>,
    /// Retry count.
    retry_count: u32,
    /// Configuration once complete.
    config: Option<DhcpConfig>,
    /// Offered IP (from OFFER).
    offered_ip: Option<Ipv4Addr>,
    /// Server ID (from OFFER).
    server_id: Option<Ipv4Addr>,
    /// Time when lease was obtained (for renewal timing).
    lease_obtained_at: Option<Instant>,
}

impl Default for DhcpHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl DhcpHandler {
    /// Create a new DHCP handler.
    pub fn new() -> Self {
        Self {
            state: DhcpState::Idle,
            xid: generate_transaction_id(),
            last_send_time: None,
            retry_count: 0,
            config: None,
            offered_ip: None,
            server_id: None,
            lease_obtained_at: None,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> DhcpState {
        self.state
    }

    /// Get the transaction ID.
    pub fn xid(&self) -> u32 {
        self.xid
    }

    /// Get the configuration if configured.
    pub fn config(&self) -> Option<&DhcpConfig> {
        self.config.as_ref()
    }

    /// Check if DHCP is fully configured.
    pub fn is_configured(&self) -> bool {
        self.state == DhcpState::Bound
    }

    /// Check if DHCP is in progress.
    pub fn is_in_progress(&self) -> bool {
        matches!(
            self.state,
            DhcpState::DiscoverSent | DhcpState::RequestSent | DhcpState::Renewing | DhcpState::Rebinding
        )
    }

    /// Check if lease needs renewal (T1 elapsed).
    /// Returns true if we're in Bound state and T1 time has elapsed.
    pub fn needs_renewal(&self) -> bool {
        if self.state != DhcpState::Bound {
            return false;
        }
        if let (Some(config), Some(obtained_at)) = (&self.config, self.lease_obtained_at) {
            if config.renewal_time > 0 {
                let elapsed = obtained_at.elapsed().as_secs() as u32;
                return elapsed >= config.renewal_time;
            }
        }
        false
    }

    /// Check if lease needs rebinding (T2 elapsed).
    /// Returns true if we're in Bound or Renewing state and T2 time has elapsed.
    pub fn needs_rebinding(&self) -> bool {
        if !matches!(self.state, DhcpState::Bound | DhcpState::Renewing) {
            return false;
        }
        if let (Some(config), Some(obtained_at)) = (&self.config, self.lease_obtained_at) {
            if config.rebinding_time > 0 {
                let elapsed = obtained_at.elapsed().as_secs() as u32;
                return elapsed >= config.rebinding_time;
            }
        }
        false
    }

    /// Check if lease has expired.
    /// Returns true if lease_time has fully elapsed.
    pub fn is_lease_expired(&self) -> bool {
        if let (Some(config), Some(obtained_at)) = (&self.config, self.lease_obtained_at) {
            if config.lease_time > 0 {
                let elapsed = obtained_at.elapsed().as_secs() as u32;
                return elapsed >= config.lease_time;
            }
        }
        false
    }

    /// Get time remaining until renewal (T1) in seconds.
    pub fn time_until_renewal(&self) -> Option<u32> {
        if let (Some(config), Some(obtained_at)) = (&self.config, self.lease_obtained_at) {
            if config.renewal_time > 0 {
                let elapsed = obtained_at.elapsed().as_secs() as u32;
                return Some(config.renewal_time.saturating_sub(elapsed));
            }
        }
        None
    }

    /// Check if we should send/retry DHCP discover.
    pub fn should_send_discover(&self) -> bool {
        if self.state == DhcpState::Idle {
            return true;
        }
        if self.state == DhcpState::DiscoverSent && self.retry_count < MAX_DHCP_RETRIES {
            match self.last_send_time {
                Some(last) => last.elapsed().as_millis() as u64 >= DHCP_RETRY_INTERVAL_MS,
                None => true,
            }
        } else {
            false
        }
    }

    /// Check if we should send/retry DHCP request.
    pub fn should_send_request(&self) -> bool {
        if self.state != DhcpState::RequestSent {
            return false;
        }
        if self.retry_count >= MAX_DHCP_RETRIES {
            return false;
        }
        match self.last_send_time {
            Some(last) => last.elapsed().as_millis() as u64 >= DHCP_RETRY_INTERVAL_MS,
            None => true,
        }
    }

    /// Mark that DISCOVER was sent.
    pub fn mark_discover_sent(&mut self) {
        if self.state == DhcpState::DiscoverSent {
            self.retry_count += 1;
        } else {
            self.state = DhcpState::DiscoverSent;
            self.retry_count = 0;
        }
        self.last_send_time = Some(Instant::now());
    }

    /// Mark that REQUEST was sent.
    pub fn mark_request_sent(&mut self) {
        if self.state == DhcpState::RequestSent {
            self.retry_count += 1;
        } else {
            self.state = DhcpState::RequestSent;
            self.retry_count = 0;
        }
        self.last_send_time = Some(Instant::now());
    }

    /// Record an OFFER was received.
    pub fn record_offer(&mut self, offered_ip: Ipv4Addr, server_id: Ipv4Addr) {
        self.offered_ip = Some(offered_ip);
        self.server_id = Some(server_id);
    }

    /// Get offered IP and server ID for REQUEST.
    pub fn get_offer(&self) -> Option<(Ipv4Addr, Ipv4Addr)> {
        match (self.offered_ip, self.server_id) {
            (Some(ip), Some(server)) => Some((ip, server)),
            _ => None,
        }
    }

    /// Mark that configuration is complete.
    pub fn mark_configured(&mut self, config: DhcpConfig) {
        self.state = DhcpState::Bound;
        self.config = Some(config);
        self.lease_obtained_at = Some(Instant::now());
    }

    /// Start renewal process (unicast to original server).
    pub fn start_renewal(&mut self) {
        if self.state == DhcpState::Bound {
            self.state = DhcpState::Renewing;
            self.retry_count = 0;
            self.last_send_time = None;
            // Generate new XID for renewal
            self.xid = generate_transaction_id();
            info!("Starting DHCP lease renewal");
        }
    }

    /// Start rebinding process (broadcast to any server).
    pub fn start_rebinding(&mut self) {
        if matches!(self.state, DhcpState::Bound | DhcpState::Renewing) {
            self.state = DhcpState::Rebinding;
            self.retry_count = 0;
            self.last_send_time = None;
            // Generate new XID for rebinding
            self.xid = generate_transaction_id();
            info!("Starting DHCP lease rebinding");
        }
    }

    /// Check if we should send renewal request (unicast).
    pub fn should_send_renewal(&self) -> bool {
        if self.state != DhcpState::Renewing {
            return false;
        }
        if self.retry_count >= MAX_DHCP_RETRIES {
            return false;
        }
        match self.last_send_time {
            Some(last) => last.elapsed().as_millis() as u64 >= DHCP_RETRY_INTERVAL_MS,
            None => true,
        }
    }

    /// Check if we should send rebinding request (broadcast).
    pub fn should_send_rebinding(&self) -> bool {
        if self.state != DhcpState::Rebinding {
            return false;
        }
        if self.retry_count >= MAX_DHCP_RETRIES {
            return false;
        }
        match self.last_send_time {
            Some(last) => last.elapsed().as_millis() as u64 >= DHCP_RETRY_INTERVAL_MS,
            None => true,
        }
    }

    /// Mark that renewal/rebind REQUEST was sent.
    pub fn mark_renewal_sent(&mut self) {
        self.retry_count += 1;
        self.last_send_time = Some(Instant::now());
    }

    /// Handle renewal ACK - reset lease timers.
    pub fn handle_renewal_ack(&mut self, config: DhcpConfig) {
        info!(
            "DHCP renewal ACK: Lease renewed for {}s (T1={}s, T2={}s)",
            config.lease_time, config.renewal_time, config.rebinding_time
        );
        self.state = DhcpState::Bound;
        self.config = Some(config);
        self.lease_obtained_at = Some(Instant::now());
        self.retry_count = 0;
    }

    /// Mark that DHCP failed.
    pub fn mark_failed(&mut self) {
        self.state = DhcpState::Failed;
    }

    /// Reset to initial state for retry.
    pub fn reset(&mut self) {
        self.state = DhcpState::Idle;
        self.retry_count = 0;
        self.last_send_time = None;
        self.config = None;
        self.offered_ip = None;
        self.server_id = None;
        self.lease_obtained_at = None;
        // Generate new XID for next attempt
        self.xid = generate_transaction_id();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_client_new() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let client = DhcpClient::new(mac);
        assert_eq!(client.state(), DhcpState::Idle);
        assert!(!client.config().is_valid());
    }

    #[test]
    fn test_build_discover() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let mut client = DhcpClient::new(mac);
        let discover = client.build_discover();

        // Should have Ethernet header
        assert!(discover.len() >= 14);
        // Should be broadcast
        assert_eq!(&discover[..6], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // EtherType should be IPv4
        assert_eq!(&discover[12..14], &[0x08, 0x00]);

        assert_eq!(client.state(), DhcpState::DiscoverSent);
    }

    #[test]
    fn test_dhcp_config_valid() {
        let mut config = DhcpConfig::default();
        assert!(!config.is_valid());

        config.ip = Ipv4Addr::new(192, 168, 1, 100);
        assert!(config.is_valid());
    }

    // =============================================================================
    // DhcpHandler tests
    // =============================================================================

    #[test]
    fn test_dhcp_handler_new() {
        let handler = DhcpHandler::new();
        assert_eq!(handler.state(), DhcpState::Idle);
        assert!(handler.xid() != 0);
        assert!(!handler.is_configured());
        assert!(!handler.is_in_progress());
    }

    #[test]
    fn test_dhcp_handler_should_send_discover() {
        let handler = DhcpHandler::new();

        // Initial state should send
        assert!(handler.should_send_discover());
    }

    #[test]
    fn test_dhcp_handler_mark_discover_sent() {
        let mut handler = DhcpHandler::new();

        handler.mark_discover_sent();
        assert_eq!(handler.state(), DhcpState::DiscoverSent);
        assert!(handler.is_in_progress());

        // Shouldn't send immediately after
        assert!(!handler.should_send_discover());
    }

    #[test]
    fn test_dhcp_handler_configuration_flow() {
        let mut handler = DhcpHandler::new();

        // DISCOVER
        handler.mark_discover_sent();
        assert_eq!(handler.state(), DhcpState::DiscoverSent);

        // Record OFFER
        handler.record_offer(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        let offer = handler.get_offer();
        assert!(offer.is_some());
        let (ip, server) = offer.unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(server, Ipv4Addr::new(192, 168, 1, 1));

        // REQUEST
        handler.mark_request_sent();
        assert_eq!(handler.state(), DhcpState::RequestSent);

        // ACK
        let config = DhcpConfig {
            ip: Ipv4Addr::new(192, 168, 1, 100),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            ..Default::default()
        };
        handler.mark_configured(config);

        assert_eq!(handler.state(), DhcpState::Bound);
        assert!(handler.is_configured());
        assert!(!handler.is_in_progress());
        assert!(handler.config().is_some());
        assert_eq!(
            handler.config().unwrap().ip,
            Ipv4Addr::new(192, 168, 1, 100)
        );
    }

    #[test]
    fn test_dhcp_handler_reset() {
        let mut handler = DhcpHandler::new();
        let original_xid = handler.xid();

        handler.mark_discover_sent();
        handler.reset();

        assert_eq!(handler.state(), DhcpState::Idle);
        // XID should change after reset
        assert_ne!(handler.xid(), original_xid);
        assert!(handler.config().is_none());
    }
}
