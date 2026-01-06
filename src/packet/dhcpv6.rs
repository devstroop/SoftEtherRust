//! DHCPv6 client for virtual adapter IPv6 configuration.
//!
//! This module implements a minimal DHCPv6 client that obtains
//! IPv6 address configuration from the VPN's DHCPv6 server.
//!
//! DHCPv6 differs significantly from DHCPv4:
//! - Uses UDP ports 546 (client) and 547 (server)
//! - Uses link-local addresses and multicast
//! - Uses DUID (DHCP Unique Identifier) instead of just MAC
//! - Supports stateful (full address) and stateless (just options) modes
//!
//! Message flow:
//! - Stateful: SOLICIT -> ADVERTISE -> REQUEST -> REPLY
//! - Stateless: INFORMATION-REQUEST -> REPLY

use bytes::{BufMut, Bytes, BytesMut};
use std::net::Ipv6Addr;
use std::time::Instant;
use tracing::{debug, info, warn};

use crate::crypto::generate_transaction_id;

/// DHCPv6 message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dhcpv6MessageType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Confirm = 4,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
    Decline = 9,
    Reconfigure = 10,
    InformationRequest = 11,
    RelayForw = 12,
    RelayRepl = 13,
}

impl TryFrom<u8> for Dhcpv6MessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Solicit),
            2 => Ok(Self::Advertise),
            3 => Ok(Self::Request),
            4 => Ok(Self::Confirm),
            5 => Ok(Self::Renew),
            6 => Ok(Self::Rebind),
            7 => Ok(Self::Reply),
            8 => Ok(Self::Release),
            9 => Ok(Self::Decline),
            10 => Ok(Self::Reconfigure),
            11 => Ok(Self::InformationRequest),
            12 => Ok(Self::RelayForw),
            13 => Ok(Self::RelayRepl),
            _ => Err(()),
        }
    }
}

/// DHCPv6 option codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Dhcpv6Option {
    ClientId = 1,
    ServerId = 2,
    IaNa = 3,        // Identity Association for Non-temporary Addresses
    IaTa = 4,        // Identity Association for Temporary Addresses
    IaAddr = 5,      // IA Address
    OptionRequest = 6,
    Preference = 7,
    ElapsedTime = 8,
    RelayMessage = 9,
    Auth = 11,
    ServerUnicast = 12,
    StatusCode = 13,
    RapidCommit = 14,
    UserClass = 15,
    VendorClass = 16,
    VendorOpts = 17,
    InterfaceId = 18,
    ReconfMsg = 19,
    ReconfAccept = 20,
    DnsServers = 23,
    DomainList = 24,
    IaPd = 25,       // Identity Association for Prefix Delegation
    IaPrefix = 26,
    InformationRefreshTime = 32,
    SolMaxRt = 82,   // SOL_MAX_RT
    InfMaxRt = 83,   // INF_MAX_RT
}

/// DHCPv6 status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Dhcpv6StatusCode {
    Success = 0,
    UnspecFail = 1,
    NoAddrsAvail = 2,
    NoBinding = 3,
    NotOnLink = 4,
    UseMulticast = 5,
    NoPrefixAvail = 6,
}

impl TryFrom<u16> for Dhcpv6StatusCode {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Success),
            1 => Ok(Self::UnspecFail),
            2 => Ok(Self::NoAddrsAvail),
            3 => Ok(Self::NoBinding),
            4 => Ok(Self::NotOnLink),
            5 => Ok(Self::UseMulticast),
            6 => Ok(Self::NoPrefixAvail),
            _ => Err(()),
        }
    }
}

/// DHCPv6 configuration obtained from the server.
#[derive(Debug, Clone)]
pub struct Dhcpv6Config {
    /// Assigned IPv6 address.
    pub ip: Ipv6Addr,
    /// Prefix length (typically 128 for single address, or 64 for prefix).
    pub prefix_len: u8,
    /// Primary DNS server.
    pub dns1: Option<Ipv6Addr>,
    /// Secondary DNS server.
    pub dns2: Option<Ipv6Addr>,
    /// Preferred lifetime in seconds.
    pub preferred_lifetime: u32,
    /// Valid lifetime in seconds.
    pub valid_lifetime: u32,
    /// T1 (renewal time) in seconds.
    pub t1: u32,
    /// T2 (rebind time) in seconds.
    pub t2: u32,
    /// Domain search list.
    pub domain_list: Vec<String>,
    /// Server DUID.
    pub server_duid: Vec<u8>,
}

impl Default for Dhcpv6Config {
    fn default() -> Self {
        Self {
            ip: Ipv6Addr::UNSPECIFIED,
            prefix_len: 128,
            dns1: None,
            dns2: None,
            preferred_lifetime: 0,
            valid_lifetime: 0,
            t1: 0,
            t2: 0,
            domain_list: Vec::new(),
            server_duid: Vec::new(),
        }
    }
}

impl Dhcpv6Config {
    /// Check if the configuration is valid (has an IP address).
    pub fn is_valid(&self) -> bool {
        !self.ip.is_unspecified()
    }
}

/// DHCPv6 client state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Dhcpv6State {
    /// Initial state.
    #[default]
    Idle,
    /// SOLICIT sent, waiting for ADVERTISE.
    SolicitSent,
    /// REQUEST sent, waiting for REPLY.
    RequestSent,
    /// Successfully bound to an IPv6 address.
    Bound,
    /// Renewing lease.
    Renewing,
    /// Rebinding lease.
    Rebinding,
    /// DHCPv6 failed.
    Failed,
}

/// DUID type: Link-layer address plus time (DUID-LLT).
const DUID_TYPE_LLT: u16 = 1;
/// DUID type: Vendor-assigned unique ID (DUID-EN).
const _DUID_TYPE_EN: u16 = 2;
/// DUID type: Link-layer address (DUID-LL).
const DUID_TYPE_LL: u16 = 3;

/// Hardware type: Ethernet.
const HW_TYPE_ETHERNET: u16 = 1;

/// DHCPv6 multicast address: All DHCP Relay Agents and Servers.
pub const ALL_DHCP_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// DHCPv6 client port.
pub const DHCPV6_CLIENT_PORT: u16 = 546;
/// DHCPv6 server port.
pub const DHCPV6_SERVER_PORT: u16 = 547;

/// Identity Association ID (IAID) - we use a fixed value derived from MAC.
fn generate_iaid(mac: &[u8; 6]) -> u32 {
    // Use last 4 bytes of MAC as IAID
    u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]])
}

/// Generate DUID-LL (Link-Layer) from MAC address.
fn generate_duid_ll(mac: &[u8; 6]) -> Vec<u8> {
    let mut duid = Vec::with_capacity(10);
    duid.extend_from_slice(&DUID_TYPE_LL.to_be_bytes());
    duid.extend_from_slice(&HW_TYPE_ETHERNET.to_be_bytes());
    duid.extend_from_slice(mac);
    duid
}

/// Generate link-local IPv6 address from MAC (EUI-64).
pub fn mac_to_link_local(mac: &[u8; 6]) -> Ipv6Addr {
    // EUI-64: insert ff:fe in the middle, flip universal/local bit
    let eui64 = [
        mac[0] ^ 0x02, // flip U/L bit
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ];
    Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        u16::from_be_bytes([eui64[0], eui64[1]]),
        u16::from_be_bytes([eui64[2], eui64[3]]),
        u16::from_be_bytes([eui64[4], eui64[5]]),
        u16::from_be_bytes([eui64[6], eui64[7]]),
    )
}

/// Generate solicited-node multicast address for an IPv6 address.
pub fn solicited_node_multicast(ip: &Ipv6Addr) -> Ipv6Addr {
    let octets = ip.octets();
    Ipv6Addr::new(
        0xff02, 0, 0, 0, 0, 1,
        0xff00 | (octets[13] as u16),
        u16::from_be_bytes([octets[14], octets[15]]),
    )
}

/// DHCPv6 client.
#[derive(Debug)]
pub struct Dhcpv6Client {
    /// Client state.
    state: Dhcpv6State,
    /// Obtained configuration.
    config: Dhcpv6Config,
    /// Client MAC address.
    mac: [u8; 6],
    /// Client DUID.
    client_duid: Vec<u8>,
    /// Transaction ID (24 bits).
    xid: u32,
    /// Identity Association ID.
    iaid: u32,
    /// Advertised address (from ADVERTISE).
    advertised_ip: Ipv6Addr,
    /// Server DUID (from ADVERTISE).
    server_duid: Vec<u8>,
    /// Elapsed time counter start.
    start_time: Instant,
}

impl Dhcpv6Client {
    /// Create a new DHCPv6 client.
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            state: Dhcpv6State::Idle,
            config: Dhcpv6Config::default(),
            mac,
            client_duid: generate_duid_ll(&mac),
            xid: generate_transaction_id() & 0x00FFFFFF, // 24-bit XID
            iaid: generate_iaid(&mac),
            advertised_ip: Ipv6Addr::UNSPECIFIED,
            server_duid: Vec::new(),
            start_time: Instant::now(),
        }
    }

    /// Get the current state.
    pub fn state(&self) -> Dhcpv6State {
        self.state
    }

    /// Get the obtained configuration.
    pub fn config(&self) -> &Dhcpv6Config {
        &self.config
    }

    /// Get client's link-local address.
    pub fn link_local(&self) -> Ipv6Addr {
        mac_to_link_local(&self.mac)
    }

    /// Build a DHCPv6 SOLICIT packet (full Ethernet frame).
    pub fn build_solicit(&mut self) -> Bytes {
        self.state = Dhcpv6State::SolicitSent;
        self.start_time = Instant::now();
        self.build_dhcpv6_packet(Dhcpv6MessageType::Solicit, None)
    }

    /// Build a DHCPv6 REQUEST packet (full Ethernet frame).
    pub fn build_request(&mut self) -> Option<Bytes> {
        if self.advertised_ip.is_unspecified() || self.server_duid.is_empty() {
            return None;
        }

        self.state = Dhcpv6State::RequestSent;
        Some(self.build_dhcpv6_packet(Dhcpv6MessageType::Request, Some(&self.advertised_ip)))
    }

    /// Build a DHCPv6 RENEW packet.
    pub fn build_renew(&self) -> Option<Bytes> {
        if !self.config.is_valid() {
            return None;
        }
        Some(self.build_dhcpv6_packet(Dhcpv6MessageType::Renew, Some(&self.config.ip)))
    }

    /// Build a DHCPv6 REBIND packet.
    pub fn build_rebind(&self) -> Option<Bytes> {
        if !self.config.is_valid() {
            return None;
        }
        // Rebind doesn't include server DUID
        Some(self.build_dhcpv6_packet_no_server(Dhcpv6MessageType::Rebind, Some(&self.config.ip)))
    }

    /// Build a DHCPv6 RELEASE packet.
    pub fn build_release(&self) -> Option<Bytes> {
        if !self.config.is_valid() {
            return None;
        }
        Some(self.build_dhcpv6_packet(Dhcpv6MessageType::Release, Some(&self.config.ip)))
    }

    /// Build a DHCPv6 INFORMATION-REQUEST packet (stateless).
    pub fn build_information_request(&mut self) -> Bytes {
        self.start_time = Instant::now();
        self.build_dhcpv6_packet_stateless(Dhcpv6MessageType::InformationRequest)
    }

    /// Process a DHCPv6 response packet.
    ///
    /// Returns `true` if DHCPv6 is complete (REPLY with address received).
    pub fn process_response(&mut self, frame: &[u8]) -> bool {
        // Minimum frame size: Ethernet(14) + IPv6(40) + UDP(8) + DHCPv6(4)
        if frame.len() < 66 {
            debug!("DHCPv6 frame too small: {}", frame.len());
            return false;
        }

        // Check EtherType (IPv6)
        if frame[12] != 0x86 || frame[13] != 0xDD {
            debug!("Not IPv6");
            return false;
        }

        // Check IPv6 Next Header (UDP = 17)
        if frame[20] != 17 {
            debug!("Not UDP");
            return false;
        }

        // Check UDP ports (547 -> 546)
        let src_port = u16::from_be_bytes([frame[54], frame[55]]);
        let dst_port = u16::from_be_bytes([frame[56], frame[57]]);
        if src_port != DHCPV6_SERVER_PORT || dst_port != DHCPV6_CLIENT_PORT {
            debug!("Wrong ports: {} -> {}", src_port, dst_port);
            return false;
        }

        // DHCPv6 starts at offset 62
        let dhcp_start = 62;
        if frame.len() < dhcp_start + 4 {
            return false;
        }

        // Parse message type and transaction ID
        let msg_type_byte = frame[dhcp_start];
        let xid = u32::from_be_bytes([0, frame[dhcp_start + 1], frame[dhcp_start + 2], frame[dhcp_start + 3]]);

        if xid != self.xid {
            debug!("XID mismatch: got {:06x}, expected {:06x}", xid, self.xid);
            return false;
        }

        let msg_type = match Dhcpv6MessageType::try_from(msg_type_byte) {
            Ok(t) => t,
            Err(_) => {
                debug!("Unknown DHCPv6 message type: {}", msg_type_byte);
                return false;
            }
        };

        // Parse options
        let mut config = Dhcpv6Config::default();
        let mut option_start = dhcp_start + 4;
        let mut status_code = Dhcpv6StatusCode::Success;

        while option_start + 4 <= frame.len() {
            let opt_code = u16::from_be_bytes([frame[option_start], frame[option_start + 1]]);
            let opt_len = u16::from_be_bytes([frame[option_start + 2], frame[option_start + 3]]) as usize;

            if option_start + 4 + opt_len > frame.len() {
                break;
            }

            let opt_data = &frame[option_start + 4..option_start + 4 + opt_len];

            match opt_code {
                c if c == Dhcpv6Option::ServerId as u16 => {
                    config.server_duid = opt_data.to_vec();
                }
                c if c == Dhcpv6Option::IaNa as u16 => {
                    // Parse IA_NA: IAID(4) + T1(4) + T2(4) + IA_ADDR options
                    if opt_len >= 12 {
                        config.t1 = u32::from_be_bytes([opt_data[4], opt_data[5], opt_data[6], opt_data[7]]);
                        config.t2 = u32::from_be_bytes([opt_data[8], opt_data[9], opt_data[10], opt_data[11]]);
                        
                        // Parse nested IA_ADDR options
                        let mut ia_offset = 12;
                        while ia_offset + 4 <= opt_len {
                            let ia_opt_code = u16::from_be_bytes([opt_data[ia_offset], opt_data[ia_offset + 1]]);
                            let ia_opt_len = u16::from_be_bytes([opt_data[ia_offset + 2], opt_data[ia_offset + 3]]) as usize;
                            
                            if ia_opt_code == Dhcpv6Option::IaAddr as u16 && ia_opt_len >= 24 {
                                let ia_addr_data = &opt_data[ia_offset + 4..ia_offset + 4 + ia_opt_len];
                                // IPv6 address (16 bytes) + preferred_lifetime (4) + valid_lifetime (4)
                                let addr_bytes: [u8; 16] = ia_addr_data[0..16].try_into().unwrap_or([0; 16]);
                                config.ip = Ipv6Addr::from(addr_bytes);
                                config.preferred_lifetime = u32::from_be_bytes([
                                    ia_addr_data[16], ia_addr_data[17], ia_addr_data[18], ia_addr_data[19]
                                ]);
                                config.valid_lifetime = u32::from_be_bytes([
                                    ia_addr_data[20], ia_addr_data[21], ia_addr_data[22], ia_addr_data[23]
                                ]);
                            }
                            
                            ia_offset += 4 + ia_opt_len;
                        }
                    }
                }
                c if c == Dhcpv6Option::DnsServers as u16 => {
                    // DNS servers are 16 bytes each
                    if opt_len >= 16 {
                        let addr_bytes: [u8; 16] = opt_data[0..16].try_into().unwrap_or([0; 16]);
                        config.dns1 = Some(Ipv6Addr::from(addr_bytes));
                    }
                    if opt_len >= 32 {
                        let addr_bytes: [u8; 16] = opt_data[16..32].try_into().unwrap_or([0; 16]);
                        config.dns2 = Some(Ipv6Addr::from(addr_bytes));
                    }
                }
                c if c == Dhcpv6Option::DomainList as u16 => {
                    // Parse DNS-encoded domain names
                    config.domain_list = parse_domain_list(opt_data);
                }
                c if c == Dhcpv6Option::StatusCode as u16 => {
                    if opt_len >= 2 {
                        let code = u16::from_be_bytes([opt_data[0], opt_data[1]]);
                        status_code = Dhcpv6StatusCode::try_from(code).unwrap_or(Dhcpv6StatusCode::UnspecFail);
                    }
                }
                _ => {}
            }

            option_start += 4 + opt_len;
        }

        // Handle status code
        if status_code != Dhcpv6StatusCode::Success {
            warn!("DHCPv6 error status: {:?}", status_code);
            if matches!(status_code, Dhcpv6StatusCode::NoAddrsAvail | Dhcpv6StatusCode::NoBinding) {
                self.state = Dhcpv6State::Failed;
            }
            return false;
        }

        match msg_type {
            Dhcpv6MessageType::Advertise => {
                if config.ip.is_unspecified() {
                    debug!("ADVERTISE without address");
                    return false;
                }
                self.advertised_ip = config.ip;
                self.server_duid = config.server_duid.clone();
                info!("DHCPv6 ADVERTISE: {}", config.ip);
                false
            }
            Dhcpv6MessageType::Reply => {
                // For stateful, we need an address
                if self.state == Dhcpv6State::RequestSent || 
                   self.state == Dhcpv6State::Renewing ||
                   self.state == Dhcpv6State::Rebinding {
                    if config.ip.is_unspecified() {
                        debug!("REPLY without address for stateful request");
                        return false;
                    }
                    
                    // Compute default T1/T2 if not provided
                    if config.t1 == 0 && config.valid_lifetime > 0 {
                        config.t1 = config.valid_lifetime / 2;
                    }
                    if config.t2 == 0 && config.valid_lifetime > 0 {
                        config.t2 = config.valid_lifetime * 4 / 5;
                    }
                    
                    self.config = config;
                    self.state = Dhcpv6State::Bound;
                    info!(
                        "DHCPv6 REPLY: IP={}, DNS={:?}, Preferred={}s, Valid={}s, T1={}s, T2={}s",
                        self.config.ip, self.config.dns1,
                        self.config.preferred_lifetime, self.config.valid_lifetime,
                        self.config.t1, self.config.t2
                    );
                    true
                } else {
                    // Stateless - just got DNS/domain info
                    self.config.dns1 = config.dns1;
                    self.config.dns2 = config.dns2;
                    self.config.domain_list = config.domain_list;
                    info!("DHCPv6 REPLY (stateless): DNS={:?}", self.config.dns1);
                    true
                }
            }
            _ => {
                debug!("Unexpected DHCPv6 message type: {:?}", msg_type);
                false
            }
        }
    }

    /// Build a DHCPv6 packet (full Ethernet frame).
    fn build_dhcpv6_packet(&self, msg_type: Dhcpv6MessageType, requested_ip: Option<&Ipv6Addr>) -> Bytes {
        let dhcp_payload = self.build_dhcpv6_payload(msg_type, requested_ip, true);
        self.wrap_in_frame(&dhcp_payload)
    }

    /// Build a DHCPv6 packet without server DUID (for REBIND).
    fn build_dhcpv6_packet_no_server(&self, msg_type: Dhcpv6MessageType, requested_ip: Option<&Ipv6Addr>) -> Bytes {
        let dhcp_payload = self.build_dhcpv6_payload(msg_type, requested_ip, false);
        self.wrap_in_frame(&dhcp_payload)
    }

    /// Build a stateless DHCPv6 packet (INFORMATION-REQUEST).
    fn build_dhcpv6_packet_stateless(&self, msg_type: Dhcpv6MessageType) -> Bytes {
        let dhcp_payload = self.build_dhcpv6_payload_stateless(msg_type);
        self.wrap_in_frame(&dhcp_payload)
    }

    /// Wrap DHCPv6 payload in Ethernet + IPv6 + UDP.
    fn wrap_in_frame(&self, dhcp_payload: &[u8]) -> Bytes {
        let udp_len = 8 + dhcp_payload.len();
        let ipv6_payload_len = udp_len;

        let mut packet = BytesMut::with_capacity(14 + 40 + udp_len);

        // === Ethernet Header (14 bytes) ===
        // Destination: IPv6 multicast MAC for ff02::1:2
        // 33:33:00:01:00:02
        packet.put_slice(&[0x33, 0x33, 0x00, 0x01, 0x00, 0x02]);
        packet.put_slice(&self.mac); // Source: our MAC
        packet.put_u16(0x86DD); // EtherType: IPv6

        // === IPv6 Header (40 bytes) ===
        packet.put_u32(0x60000000); // Version 6, Traffic Class 0, Flow Label 0
        packet.put_u16(ipv6_payload_len as u16); // Payload Length
        packet.put_u8(17); // Next Header: UDP
        packet.put_u8(64); // Hop Limit

        // Source: link-local address
        let src_ip = self.link_local();
        packet.put_slice(&src_ip.octets());

        // Destination: All DHCP Servers (ff02::1:2)
        packet.put_slice(&ALL_DHCP_SERVERS.octets());

        // === UDP Header (8 bytes) ===
        packet.put_u16(DHCPV6_CLIENT_PORT);
        packet.put_u16(DHCPV6_SERVER_PORT);
        packet.put_u16(udp_len as u16);
        packet.put_u16(0x0000); // Checksum placeholder (optional for IPv6)

        // === DHCPv6 Payload ===
        packet.put_slice(dhcp_payload);

        packet.freeze()
    }

    /// Build the DHCPv6 payload for stateful requests.
    fn build_dhcpv6_payload(
        &self,
        msg_type: Dhcpv6MessageType,
        requested_ip: Option<&Ipv6Addr>,
        include_server_id: bool,
    ) -> Vec<u8> {
        let mut payload = Vec::with_capacity(200);

        // Message type (1 byte) + Transaction ID (3 bytes)
        payload.push(msg_type as u8);
        payload.push(((self.xid >> 16) & 0xFF) as u8);
        payload.push(((self.xid >> 8) & 0xFF) as u8);
        payload.push((self.xid & 0xFF) as u8);

        // Option: Client ID (DUID)
        payload.extend_from_slice(&(Dhcpv6Option::ClientId as u16).to_be_bytes());
        payload.extend_from_slice(&(self.client_duid.len() as u16).to_be_bytes());
        payload.extend_from_slice(&self.client_duid);

        // Option: Server ID (if we have one and should include it)
        if include_server_id && !self.server_duid.is_empty() {
            payload.extend_from_slice(&(Dhcpv6Option::ServerId as u16).to_be_bytes());
            payload.extend_from_slice(&(self.server_duid.len() as u16).to_be_bytes());
            payload.extend_from_slice(&self.server_duid);
        }

        // Option: IA_NA (Identity Association for Non-temporary Addresses)
        let ia_na = self.build_ia_na(requested_ip);
        payload.extend_from_slice(&(Dhcpv6Option::IaNa as u16).to_be_bytes());
        payload.extend_from_slice(&(ia_na.len() as u16).to_be_bytes());
        payload.extend_from_slice(&ia_na);

        // Option: Elapsed Time
        let elapsed = self.start_time.elapsed().as_millis().min(65535) as u16 / 10;
        payload.extend_from_slice(&(Dhcpv6Option::ElapsedTime as u16).to_be_bytes());
        payload.extend_from_slice(&2u16.to_be_bytes());
        payload.extend_from_slice(&elapsed.to_be_bytes());

        // Option: Option Request (request DNS servers and domain list)
        payload.extend_from_slice(&(Dhcpv6Option::OptionRequest as u16).to_be_bytes());
        payload.extend_from_slice(&4u16.to_be_bytes()); // 2 options * 2 bytes each
        payload.extend_from_slice(&(Dhcpv6Option::DnsServers as u16).to_be_bytes());
        payload.extend_from_slice(&(Dhcpv6Option::DomainList as u16).to_be_bytes());

        payload
    }

    /// Build the DHCPv6 payload for stateless requests (INFORMATION-REQUEST).
    fn build_dhcpv6_payload_stateless(&self, msg_type: Dhcpv6MessageType) -> Vec<u8> {
        let mut payload = Vec::with_capacity(100);

        // Message type (1 byte) + Transaction ID (3 bytes)
        payload.push(msg_type as u8);
        payload.push(((self.xid >> 16) & 0xFF) as u8);
        payload.push(((self.xid >> 8) & 0xFF) as u8);
        payload.push((self.xid & 0xFF) as u8);

        // Option: Client ID (DUID)
        payload.extend_from_slice(&(Dhcpv6Option::ClientId as u16).to_be_bytes());
        payload.extend_from_slice(&(self.client_duid.len() as u16).to_be_bytes());
        payload.extend_from_slice(&self.client_duid);

        // Option: Elapsed Time
        let elapsed = self.start_time.elapsed().as_millis().min(65535) as u16 / 10;
        payload.extend_from_slice(&(Dhcpv6Option::ElapsedTime as u16).to_be_bytes());
        payload.extend_from_slice(&2u16.to_be_bytes());
        payload.extend_from_slice(&elapsed.to_be_bytes());

        // Option: Option Request (request DNS servers and domain list)
        payload.extend_from_slice(&(Dhcpv6Option::OptionRequest as u16).to_be_bytes());
        payload.extend_from_slice(&4u16.to_be_bytes());
        payload.extend_from_slice(&(Dhcpv6Option::DnsServers as u16).to_be_bytes());
        payload.extend_from_slice(&(Dhcpv6Option::DomainList as u16).to_be_bytes());

        payload
    }

    /// Build IA_NA (Identity Association for Non-temporary Addresses) option data.
    fn build_ia_na(&self, requested_ip: Option<&Ipv6Addr>) -> Vec<u8> {
        let mut ia_na = Vec::with_capacity(40);

        // IAID (4 bytes)
        ia_na.extend_from_slice(&self.iaid.to_be_bytes());

        // T1 (4 bytes) - 0 means server decides
        ia_na.extend_from_slice(&0u32.to_be_bytes());

        // T2 (4 bytes) - 0 means server decides
        ia_na.extend_from_slice(&0u32.to_be_bytes());

        // If we have a requested IP, include IA_ADDR option
        if let Some(ip) = requested_ip {
            // Option: IA_ADDR
            ia_na.extend_from_slice(&(Dhcpv6Option::IaAddr as u16).to_be_bytes());
            ia_na.extend_from_slice(&24u16.to_be_bytes()); // IPv6(16) + preferred(4) + valid(4)
            ia_na.extend_from_slice(&ip.octets());
            ia_na.extend_from_slice(&0u32.to_be_bytes()); // Preferred lifetime (server decides)
            ia_na.extend_from_slice(&0u32.to_be_bytes()); // Valid lifetime (server decides)
        }

        ia_na
    }
}

/// Parse DNS-encoded domain list.
fn parse_domain_list(data: &[u8]) -> Vec<String> {
    let mut domains = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let mut domain_parts = Vec::new();
        
        loop {
            if offset >= data.len() {
                break;
            }
            
            let len = data[offset] as usize;
            offset += 1;
            
            if len == 0 {
                break;
            }
            
            if offset + len > data.len() {
                break;
            }
            
            if let Ok(part) = std::str::from_utf8(&data[offset..offset + len]) {
                domain_parts.push(part.to_string());
            }
            offset += len;
        }
        
        if !domain_parts.is_empty() {
            domains.push(domain_parts.join("."));
        }
    }

    domains
}

// =============================================================================
// Dhcpv6Handler - State machine with timing
// =============================================================================

/// DHCPv6 retry interval (1 second initial, exponential backoff).
const DHCPV6_INITIAL_RT_MS: u64 = 1_000;

/// Maximum DHCPv6 retransmission time (30 seconds).
const DHCPV6_MAX_RT_MS: u64 = 30_000;

/// Maximum DHCPv6 retries.
const MAX_DHCPV6_RETRIES: u32 = 5;

/// DHCPv6 handler state machine.
#[derive(Debug)]
pub struct Dhcpv6Handler {
    /// Current state.
    state: Dhcpv6State,
    /// Transaction ID for this DHCPv6 session.
    xid: u32,
    /// Last send time.
    last_send_time: Option<Instant>,
    /// Retry count.
    retry_count: u32,
    /// Current retransmission timeout (exponential backoff).
    current_rt_ms: u64,
    /// Configuration once complete.
    config: Option<Dhcpv6Config>,
    /// Advertised IP (from ADVERTISE).
    advertised_ip: Option<Ipv6Addr>,
    /// Server DUID (from ADVERTISE).
    server_duid: Vec<u8>,
    /// Time when lease was obtained.
    lease_obtained_at: Option<Instant>,
}

impl Default for Dhcpv6Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl Dhcpv6Handler {
    /// Create a new DHCPv6 handler.
    pub fn new() -> Self {
        Self {
            state: Dhcpv6State::Idle,
            xid: generate_transaction_id() & 0x00FFFFFF,
            last_send_time: None,
            retry_count: 0,
            current_rt_ms: DHCPV6_INITIAL_RT_MS,
            config: None,
            advertised_ip: None,
            server_duid: Vec::new(),
            lease_obtained_at: None,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> Dhcpv6State {
        self.state
    }

    /// Get the transaction ID.
    pub fn xid(&self) -> u32 {
        self.xid
    }

    /// Get the configuration if configured.
    pub fn config(&self) -> Option<&Dhcpv6Config> {
        self.config.as_ref()
    }

    /// Check if DHCPv6 is fully configured.
    pub fn is_configured(&self) -> bool {
        self.state == Dhcpv6State::Bound
    }

    /// Check if DHCPv6 is in progress.
    pub fn is_in_progress(&self) -> bool {
        matches!(
            self.state,
            Dhcpv6State::SolicitSent | Dhcpv6State::RequestSent | Dhcpv6State::Renewing | Dhcpv6State::Rebinding
        )
    }

    /// Check if lease needs renewal (T1 elapsed).
    pub fn needs_renewal(&self) -> bool {
        if self.state != Dhcpv6State::Bound {
            return false;
        }
        if let (Some(config), Some(obtained_at)) = (&self.config, self.lease_obtained_at) {
            if config.t1 > 0 {
                let elapsed = obtained_at.elapsed().as_secs() as u32;
                return elapsed >= config.t1;
            }
        }
        false
    }

    /// Check if lease needs rebinding (T2 elapsed).
    pub fn needs_rebinding(&self) -> bool {
        if !matches!(self.state, Dhcpv6State::Bound | Dhcpv6State::Renewing) {
            return false;
        }
        if let (Some(config), Some(obtained_at)) = (&self.config, self.lease_obtained_at) {
            if config.t2 > 0 {
                let elapsed = obtained_at.elapsed().as_secs() as u32;
                return elapsed >= config.t2;
            }
        }
        false
    }

    /// Check if lease has expired.
    pub fn is_lease_expired(&self) -> bool {
        if let (Some(config), Some(obtained_at)) = (&self.config, self.lease_obtained_at) {
            if config.valid_lifetime > 0 {
                let elapsed = obtained_at.elapsed().as_secs() as u32;
                return elapsed >= config.valid_lifetime;
            }
        }
        false
    }

    /// Check if we should send/retry SOLICIT.
    pub fn should_send_solicit(&self) -> bool {
        if self.state == Dhcpv6State::Idle {
            return true;
        }
        if self.state == Dhcpv6State::SolicitSent && self.retry_count < MAX_DHCPV6_RETRIES {
            match self.last_send_time {
                Some(last) => last.elapsed().as_millis() as u64 >= self.current_rt_ms,
                None => true,
            }
        } else {
            false
        }
    }

    /// Check if we should send/retry REQUEST.
    pub fn should_send_request(&self) -> bool {
        if self.state != Dhcpv6State::RequestSent {
            return false;
        }
        if self.retry_count >= MAX_DHCPV6_RETRIES {
            return false;
        }
        match self.last_send_time {
            Some(last) => last.elapsed().as_millis() as u64 >= self.current_rt_ms,
            None => true,
        }
    }

    /// Mark that SOLICIT was sent.
    pub fn mark_solicit_sent(&mut self) {
        if self.state == Dhcpv6State::SolicitSent {
            self.retry_count += 1;
            // Exponential backoff with jitter
            self.current_rt_ms = (self.current_rt_ms * 2).min(DHCPV6_MAX_RT_MS);
        } else {
            self.state = Dhcpv6State::SolicitSent;
            self.retry_count = 0;
            self.current_rt_ms = DHCPV6_INITIAL_RT_MS;
        }
        self.last_send_time = Some(Instant::now());
    }

    /// Mark that REQUEST was sent.
    pub fn mark_request_sent(&mut self) {
        if self.state == Dhcpv6State::RequestSent {
            self.retry_count += 1;
            self.current_rt_ms = (self.current_rt_ms * 2).min(DHCPV6_MAX_RT_MS);
        } else {
            self.state = Dhcpv6State::RequestSent;
            self.retry_count = 0;
            self.current_rt_ms = DHCPV6_INITIAL_RT_MS;
        }
        self.last_send_time = Some(Instant::now());
    }

    /// Record an ADVERTISE was received.
    pub fn record_advertise(&mut self, advertised_ip: Ipv6Addr, server_duid: Vec<u8>) {
        self.advertised_ip = Some(advertised_ip);
        self.server_duid = server_duid;
    }

    /// Get advertised IP and server DUID for REQUEST.
    pub fn get_advertise(&self) -> Option<(Ipv6Addr, &[u8])> {
        match &self.advertised_ip {
            Some(ip) if !self.server_duid.is_empty() => Some((*ip, &self.server_duid)),
            _ => None,
        }
    }

    /// Mark that configuration is complete.
    pub fn mark_configured(&mut self, config: Dhcpv6Config) {
        self.state = Dhcpv6State::Bound;
        self.config = Some(config);
        self.lease_obtained_at = Some(Instant::now());
    }

    /// Start renewal process.
    pub fn start_renewal(&mut self) {
        if self.state == Dhcpv6State::Bound {
            self.state = Dhcpv6State::Renewing;
            self.retry_count = 0;
            self.current_rt_ms = DHCPV6_INITIAL_RT_MS;
            self.last_send_time = None;
            self.xid = generate_transaction_id() & 0x00FFFFFF;
            info!("Starting DHCPv6 lease renewal");
        }
    }

    /// Start rebinding process.
    pub fn start_rebinding(&mut self) {
        if matches!(self.state, Dhcpv6State::Bound | Dhcpv6State::Renewing) {
            self.state = Dhcpv6State::Rebinding;
            self.retry_count = 0;
            self.current_rt_ms = DHCPV6_INITIAL_RT_MS;
            self.last_send_time = None;
            self.xid = generate_transaction_id() & 0x00FFFFFF;
            info!("Starting DHCPv6 lease rebinding");
        }
    }

    /// Handle renewal/rebind REPLY - reset lease timers.
    pub fn handle_reply(&mut self, config: Dhcpv6Config) {
        info!(
            "DHCPv6 REPLY: Lease renewed, Valid={}s, T1={}s, T2={}s",
            config.valid_lifetime, config.t1, config.t2
        );
        self.state = Dhcpv6State::Bound;
        self.config = Some(config);
        self.lease_obtained_at = Some(Instant::now());
        self.retry_count = 0;
    }

    /// Mark that DHCPv6 failed.
    pub fn mark_failed(&mut self) {
        self.state = Dhcpv6State::Failed;
    }

    /// Reset to initial state.
    pub fn reset(&mut self) {
        self.state = Dhcpv6State::Idle;
        self.retry_count = 0;
        self.current_rt_ms = DHCPV6_INITIAL_RT_MS;
        self.last_send_time = None;
        self.config = None;
        self.advertised_ip = None;
        self.server_duid.clear();
        self.lease_obtained_at = None;
        self.xid = generate_transaction_id() & 0x00FFFFFF;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcpv6_client_new() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let client = Dhcpv6Client::new(mac);
        assert_eq!(client.state(), Dhcpv6State::Idle);
        assert!(!client.config().is_valid());
    }

    #[test]
    fn test_mac_to_link_local() {
        let mac = [0x00, 0x16, 0x3e, 0x12, 0x34, 0x56];
        let ll = mac_to_link_local(&mac);
        
        // Should be fe80::216:3eff:fe12:3456
        assert!(ll.segments()[0] == 0xfe80);
        assert!(ll.segments()[1] == 0);
        assert!(ll.segments()[2] == 0);
        assert!(ll.segments()[3] == 0);
        // EUI-64: 02:16:3e:ff:fe:12:34:56
        assert_eq!(ll.segments()[4], 0x0216);
        assert_eq!(ll.segments()[5], 0x3eff);
        assert_eq!(ll.segments()[6], 0xfe12);
        assert_eq!(ll.segments()[7], 0x3456);
    }

    #[test]
    fn test_generate_duid_ll() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let duid = generate_duid_ll(&mac);
        
        // DUID-LL: type(2) + hw_type(2) + link_layer_addr(6) = 10 bytes
        assert_eq!(duid.len(), 10);
        assert_eq!(&duid[0..2], &DUID_TYPE_LL.to_be_bytes());
        assert_eq!(&duid[2..4], &HW_TYPE_ETHERNET.to_be_bytes());
        assert_eq!(&duid[4..10], &mac);
    }

    #[test]
    fn test_build_solicit() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let mut client = Dhcpv6Client::new(mac);
        let solicit = client.build_solicit();

        // Should have Ethernet header
        assert!(solicit.len() >= 14);
        // Should be multicast MAC for ff02::1:2
        assert_eq!(&solicit[..6], &[0x33, 0x33, 0x00, 0x01, 0x00, 0x02]);
        // EtherType should be IPv6
        assert_eq!(&solicit[12..14], &[0x86, 0xDD]);

        assert_eq!(client.state(), Dhcpv6State::SolicitSent);
    }

    #[test]
    fn test_dhcpv6_config_valid() {
        let mut config = Dhcpv6Config::default();
        assert!(!config.is_valid());

        config.ip = "2001:db8::1".parse().unwrap();
        assert!(config.is_valid());
    }

    #[test]
    fn test_dhcpv6_handler_new() {
        let handler = Dhcpv6Handler::new();
        assert_eq!(handler.state(), Dhcpv6State::Idle);
        assert!(!handler.is_configured());
        assert!(!handler.is_in_progress());
    }

    #[test]
    fn test_dhcpv6_handler_should_send_solicit() {
        let handler = Dhcpv6Handler::new();
        assert!(handler.should_send_solicit());
    }

    #[test]
    fn test_dhcpv6_handler_mark_solicit_sent() {
        let mut handler = Dhcpv6Handler::new();

        handler.mark_solicit_sent();
        assert_eq!(handler.state(), Dhcpv6State::SolicitSent);
        assert!(handler.is_in_progress());
        assert!(!handler.should_send_solicit());
    }

    #[test]
    fn test_solicited_node_multicast() {
        let ip: Ipv6Addr = "2001:db8::1234:5678".parse().unwrap();
        let snm = solicited_node_multicast(&ip);
        
        // Should be ff02::1:ff34:5678
        assert_eq!(snm.segments()[0], 0xff02);
        assert_eq!(snm.segments()[5], 0x01);
        assert_eq!(snm.segments()[6], 0xff34);
        assert_eq!(snm.segments()[7], 0x5678);
    }
}
