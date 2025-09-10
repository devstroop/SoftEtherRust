// DHCP client implementation - inspired by Go's cedar/dhcp_client.go
// This consolidates and cleans up the scattered DHCP client functionality

use super::types::{Lease, DhcpOptions, DhcpState, DhcpMetrics};
use super::*;
use cedar::dataplane::DataPlane;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// Unified DHCP client (consolidating multiple implementations)
pub struct DhcpClient {
    dataplane: DataPlane,
    mac_address: [u8; 6],
    hostname: String,
    transaction_id: u32,
    state: DhcpState,
    current_lease: Option<Lease>,
    metrics: Arc<DhcpMetrics>,
    packet_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    
    // Network adapter L2/L3 mode
    adapter_is_l2: bool,
    
    // Server discovery
    server_mac: Option<[u8; 6]>,
    server_ip_observed: Option<Ipv4Addr>,
}

impl DhcpClient {
    /// Create a new DHCP client (consolidating constructor logic)
    pub fn new(
        dataplane: DataPlane,
        mac_address: [u8; 6],
        hostname: String,
        adapter_is_l2: bool,
    ) -> (Self, mpsc::UnboundedSender<Vec<u8>>) {
        let (packet_tx, packet_rx) = mpsc::unbounded_channel();
        
        let client = Self {
            dataplane,
            mac_address,
            hostname,
            transaction_id: rand::random(),
            state: DhcpState::Idle,
            current_lease: None,
            metrics: Arc::new(DhcpMetrics::new()),
            packet_rx,
            adapter_is_l2,
            server_mac: None,
            server_ip_observed: None,
        };
        
        (client, packet_tx)
    }

    /// Allocate IP address via DHCP (main entry point)
    pub async fn allocate_ip(&mut self) -> Result<DhcpOptions, Box<dyn std::error::Error>> {
        info!("Starting DHCP IP allocation");
        
        self.state = DhcpState::Discovering;
        
        // Generate new transaction ID
        self.transaction_id = rand::random();
        
        // Send DHCP Discover
        let discover_packet = self.build_dhcp_discover()?;
        if !self.dataplane.send_frame(discover_packet) {
            return Err("Failed to send DHCP Discover".into());
        }
        debug!("Sent DHCP Discover (XID: {:08x})", self.transaction_id);
        
        // Wait for DHCP Offer
        let offer = self.wait_for_dhcp_response(DHCP_OFFER).await?;
        debug!("Received DHCP Offer: IP={}", self.uint32_to_ip(offer.client_address));
        
        self.state = DhcpState::Requesting;
        
        // Send DHCP Request
        let request_packet = self.build_dhcp_request(&offer)?;
        if !self.dataplane.send_frame(request_packet) {
            return Err("Failed to send DHCP Request".into());
        }
        debug!("Sent DHCP Request (XID: {:08x})", self.transaction_id);
        
        // Wait for DHCP ACK
        let ack = self.wait_for_dhcp_response(DHCP_ACK).await?;
        info!("Received DHCP ACK: IP={} Server={}", 
             self.uint32_to_ip(ack.client_address),
             self.uint32_to_ip(ack.server_address));
        
        self.state = DhcpState::Bound;
        
        // Create lease from ACK
        self.current_lease = Some(self.options_to_lease(&ack));
        
        Ok(ack)
    }

    /// Build DHCP Discover packet (based on Go implementation)
    fn build_dhcp_discover(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let options = DhcpOptions {
            opcode: DHCP_DISCOVER,
            hostname: self.hostname.clone(),
            ..Default::default()
        };
        
        self.build_dhcp_packet(&options)
    }

    /// Build DHCP Request packet
    fn build_dhcp_request(&self, offer: &DhcpOptions) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let options = DhcpOptions {
            opcode: DHCP_REQUEST,
            server_address: offer.server_address,
            requested_ip: offer.client_address,
            hostname: self.hostname.clone(),
            ..Default::default()
        };
        
        self.build_dhcp_packet(&options)
    }

    /// Build DHCP packet (core packet construction)
    fn build_dhcp_packet(&self, options: &DhcpOptions) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut packet = Vec::new();
        
        if self.adapter_is_l2 {
            // Ethernet header (for TAP adapters)
            packet.extend_from_slice(&[0xff; 6]); // Broadcast MAC
            packet.extend_from_slice(&self.mac_address); // Source MAC
            packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4
        }
        
        // IPv4 header
        let ip_header = self.build_ipv4_header()?;
        packet.extend(ip_header);
        
        // UDP header
        let udp_header = self.build_udp_header()?;
        packet.extend(udp_header);
        
        // DHCP payload (BOOTP header + options)
        let dhcp_payload = self.build_dhcp_payload(options)?;
        packet.extend(dhcp_payload);
        
        Ok(packet)
    }

    /// Build IPv4 header for DHCP packet
    fn build_ipv4_header(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut header = vec![0u8; 20];
        
        header[0] = 0x45; // Version 4, Header length 5*4=20 bytes
        header[1] = 0x00; // DSCP + ECN
        
        let total_length = 20 + 8 + 236 + 4 + self.estimate_options_length(); // IP + UDP + BOOTP + magic + options
        header[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        
        header[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes()); // ID
        header[6..8].copy_from_slice(&[0x40, 0x00]); // Flags: Don't fragment
        header[8] = 64; // TTL
        header[9] = 17; // Protocol: UDP
        // header[10..12] = checksum (calculated later)
        header[12..16].copy_from_slice(&[0, 0, 0, 0]); // Source IP: 0.0.0.0
        header[16..20].copy_from_slice(&[255, 255, 255, 255]); // Dest IP: 255.255.255.255
        
        // Calculate checksum
        let checksum = self.calculate_ipv4_checksum(&header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());
        
        Ok(header)
    }

    /// Build UDP header for DHCP packet
    fn build_udp_header(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut header = vec![0u8; 8];
        
        header[0..2].copy_from_slice(&68u16.to_be_bytes()); // Source port: DHCP client
        header[2..4].copy_from_slice(&67u16.to_be_bytes()); // Dest port: DHCP server
        
        let udp_length = 8 + 236 + 4 + self.estimate_options_length(); // UDP + BOOTP + magic + options
        header[4..6].copy_from_slice(&(udp_length as u16).to_be_bytes());
        
        // header[6..8] = checksum (0 for simplicity in DHCP)
        
        Ok(header)
    }

    /// Build DHCP payload (BOOTP header + options)
    fn build_dhcp_payload(&self, options: &DhcpOptions) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut payload = vec![0u8; 236]; // BOOTP fixed header
        
        payload[0] = 1; // op = BOOTREQUEST
        payload[1] = 1; // htype = Ethernet
        payload[2] = 6; // hlen = 6 bytes
        payload[3] = 0; // hops = 0
        
        payload[4..8].copy_from_slice(&self.transaction_id.to_be_bytes());
        
        // secs (8:10) = 0, flags (10:12) = broadcast
        if options.opcode == DHCP_DISCOVER || options.opcode == DHCP_REQUEST {
            payload[10] = 0x80; // Set broadcast flag
        }
        
        // Client IP, Your IP, Server IP, Relay IP all zero for discover/request
        
        // Client MAC address
        payload[28..34].copy_from_slice(&self.mac_address);
        
        // Magic cookie
        payload.extend_from_slice(&DHCP_MAGIC_COOKIE.to_be_bytes());
        
        // DHCP options
        let opts = self.build_dhcp_options(options)?;
        payload.extend(opts);
        
        Ok(payload)
    }

    /// Build DHCP options (based on Go implementation)
    fn build_dhcp_options(&self, options: &DhcpOptions) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut opts = Vec::new();
        
        // Message type option
        opts.push(DHCP_ID_MESSAGE_TYPE);
        opts.push(1);
        opts.push(options.opcode);
        
        // Client ID option (MAC address)
        opts.push(DHCP_ID_CLIENT_ID);
        opts.push(7);
        opts.push(1); // Ethernet
        opts.extend_from_slice(&self.mac_address);
        
        // Server address (if specified)
        if options.server_address != 0 {
            opts.push(DHCP_ID_SERVER_ADDRESS);
            opts.push(4);
            opts.extend_from_slice(&options.server_address.to_be_bytes());
        }
        
        // Requested IP (if specified)
        if options.requested_ip != 0 {
            opts.push(DHCP_ID_REQUEST_IP);
            opts.push(4);
            opts.extend_from_slice(&options.requested_ip.to_be_bytes());
        }
        
        // Hostname (if specified)
        if !options.hostname.is_empty() {
            let hostname_bytes = options.hostname.as_bytes();
            if hostname_bytes.len() <= 255 {
                opts.push(DHCP_ID_HOSTNAME);
                opts.push(hostname_bytes.len() as u8);
                opts.extend_from_slice(hostname_bytes);
            }
        }
        
        // Parameter Request List
        opts.push(DHCP_ID_PARAMETER_REQUEST_LIST);
        opts.push(6);
        opts.push(DHCP_ID_SUBNET_MASK);
        opts.push(DHCP_ID_GATEWAY);
        opts.push(DHCP_ID_DNS_SERVER);
        opts.push(DHCP_ID_DOMAIN_NAME);
        opts.push(DHCP_ID_LEASE_TIME);
        opts.push(DHCP_ID_SERVER_ADDRESS);
        
        // End option
        opts.push(DHCP_ID_END);
        
        Ok(opts)
    }

    /// Wait for DHCP response with specific message type
    async fn wait_for_dhcp_response(&mut self, expected_type: u8) -> Result<DhcpOptions, Box<dyn std::error::Error>> {
        let timeout = tokio::time::Duration::from_millis(IPC_DHCP_TIMEOUT as u64);
        
        while let Ok(packet) = tokio::time::timeout(timeout, self.packet_rx.recv()).await {
            if let Some(packet) = packet {
                if let Ok(options) = self.parse_dhcp_packet(&packet) {
                    if options.opcode == expected_type {
                        return Ok(options);
                    }
                }
            }
        }
        
        Err("DHCP timeout".into())
    }

    /// Parse DHCP packet and extract options
    fn parse_dhcp_packet(&self, packet: &[u8]) -> Result<DhcpOptions, Box<dyn std::error::Error>> {
        // This is a simplified parser - in real implementation you'd need full packet parsing
        // For now, we'll parse the essential fields
        
        let mut options = DhcpOptions::default();
        
        // Find DHCP payload start (skip Ethernet + IP + UDP headers if present)
        let dhcp_start = if self.adapter_is_l2 { 14 + 20 + 8 } else { 20 + 8 };
        
        if packet.len() < dhcp_start + 240 {
            return Err("Packet too short".into());
        }
        
        let dhcp_data = &packet[dhcp_start..];
        
        // Check magic cookie
        if dhcp_data.len() < 240 {
            return Err("DHCP packet too short".into());
        }
        
        let magic = u32::from_be_bytes([dhcp_data[236], dhcp_data[237], dhcp_data[238], dhcp_data[239]]);
        if magic != DHCP_MAGIC_COOKIE {
            return Err("Invalid DHCP magic cookie".into());
        }
        
        // Parse basic fields
        let transaction_id = u32::from_be_bytes([dhcp_data[4], dhcp_data[5], dhcp_data[6], dhcp_data[7]]);
        if transaction_id != self.transaction_id {
            return Err("Transaction ID mismatch".into());
        }
        
        // Your IP address (assigned by server)
        options.client_address = u32::from_be_bytes([dhcp_data[16], dhcp_data[17], dhcp_data[18], dhcp_data[19]]);
        
        // Parse options
        let options_data = &dhcp_data[240..];
        self.parse_dhcp_options(options_data, &mut options)?;
        
        Ok(options)
    }

    /// Parse DHCP options from options section
    fn parse_dhcp_options(&self, data: &[u8], options: &mut DhcpOptions) -> Result<(), Box<dyn std::error::Error>> {
        let mut i = 0;
        
        while i < data.len() {
            let option_type = data[i];
            i += 1;
            
            if option_type == DHCP_ID_END {
                break;
            }
            
            if i >= data.len() {
                break;
            }
            
            let option_len = data[i] as usize;
            i += 1;
            
            if i + option_len > data.len() {
                break;
            }
            
            let option_data = &data[i..i + option_len];
            
            match option_type {
                DHCP_ID_MESSAGE_TYPE if option_len == 1 => {
                    options.opcode = option_data[0];
                }
                DHCP_ID_SUBNET_MASK if option_len == 4 => {
                    options.subnet_mask = u32::from_be_bytes([option_data[0], option_data[1], option_data[2], option_data[3]]);
                }
                DHCP_ID_GATEWAY if option_len >= 4 => {
                    options.gateway = u32::from_be_bytes([option_data[0], option_data[1], option_data[2], option_data[3]]);
                }
                DHCP_ID_DNS_SERVER if option_len >= 4 => {
                    options.dns_server = u32::from_be_bytes([option_data[0], option_data[1], option_data[2], option_data[3]]);
                    if option_len >= 8 {
                        options.dns_server2 = u32::from_be_bytes([option_data[4], option_data[5], option_data[6], option_data[7]]);
                    }
                }
                DHCP_ID_LEASE_TIME if option_len == 4 => {
                    options.lease_time = u32::from_be_bytes([option_data[0], option_data[1], option_data[2], option_data[3]]);
                }
                DHCP_ID_SERVER_ADDRESS if option_len == 4 => {
                    options.server_address = u32::from_be_bytes([option_data[0], option_data[1], option_data[2], option_data[3]]);
                }
                _ => {
                    debug!("Unhandled DHCP option: {}", option_type);
                }
            }
            
            i += option_len;
        }
        
        Ok(())
    }

    /// Convert DHCP options to lease structure
    fn options_to_lease(&self, options: &DhcpOptions) -> Lease {
        Lease {
            client_ip: self.uint32_to_ip(options.client_address),
            server_ip: if options.server_address != 0 { Some(self.uint32_to_ip(options.server_address)) } else { None },
            gateway: if options.gateway != 0 { Some(self.uint32_to_ip(options.gateway)) } else { None },
            subnet_mask: if options.subnet_mask != 0 { Some(self.uint32_to_ip(options.subnet_mask)) } else { None },
            dns_servers: {
                let mut dns = Vec::new();
                if options.dns_server != 0 {
                    dns.push(self.uint32_to_ip(options.dns_server));
                }
                if options.dns_server2 != 0 {
                    dns.push(self.uint32_to_ip(options.dns_server2));
                }
                dns
            },
            lease_time: if options.lease_time != 0 { Some(std::time::Duration::from_secs(options.lease_time as u64)) } else { None },
            ..Default::default()
        }
    }

    /// Helper functions
    fn uint32_to_ip(&self, ip: u32) -> Ipv4Addr {
        Ipv4Addr::from(ip.to_be_bytes())
    }

    fn estimate_options_length(&self) -> usize {
        100 // Rough estimate for DHCP options
    }

    fn calculate_ipv4_checksum(&self, header: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in header.chunks(2) {
            if chunk.len() == 2 {
                let word = u16::from_be_bytes([chunk[0], chunk[1]]);
                sum += word as u32;
            }
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

impl super::DhcpInterface for DhcpClient {
    fn allocate_ip(&mut self) -> Result<DhcpOptions, Box<dyn std::error::Error>> {
        // This would need to be made async or use a runtime
        Err("Use allocate_ip async method instead".into())
    }

    fn renew_lease(&mut self, _lease: &Lease) -> Result<DhcpOptions, Box<dyn std::error::Error>> {
        todo!("Implement lease renewal")
    }

    fn release_lease(&mut self, _lease: &Lease) -> Result<(), Box<dyn std::error::Error>> {
        todo!("Implement lease release")
    }

    fn get_network_config(&self) -> Option<(Ipv4Addr, Ipv4Addr, Option<Ipv4Addr>, Vec<Ipv4Addr>)> {
        if let Some(lease) = &self.current_lease {
            Some((
                lease.client_ip,
                lease.subnet_mask.unwrap_or(Ipv4Addr::new(255, 255, 255, 0)),
                lease.gateway,
                lease.dns_servers.clone(),
            ))
        } else {
            None
        }
    }
}