/// Packet generation functions for adapter bridge
/// Matches Zig implementation in packet_adapter_macos.c

use super::adapter_bridge::{DhcpState, PacketGeneratorState};
use std::time::{Duration, Instant};
use tracing::{info, debug, trace};

/// DHCP response types
#[derive(Debug, Clone)]
pub enum DhcpResponse {
    Offer {
        yiaddr: [u8; 4],
        server_id: [u8; 4],
    },
    Ack {
        yiaddr: [u8; 4],
        mask: [u8; 4],
        router: [u8; 4],
        dns1: [u8; 4],
        dns2: [u8; 4],
    },
}

/// Parse DHCP response from Ethernet frame
/// Returns Some(DhcpResponse) if this is a DHCP OFFER or ACK
pub fn parse_dhcp_response(eth_frame: &[u8]) -> Option<DhcpResponse> {
    // Must be at least: Ethernet(14) + IPv4(20) + UDP(8) + BOOTP(236) + Magic(4) = 282 bytes
    if eth_frame.len() < 282 {
        return None;
    }
    
    // Check EtherType: 0x0800 (IPv4)
    if eth_frame[12] != 0x08 || eth_frame[13] != 0x00 {
        return None;
    }
    
    // Check IP protocol: 17 (UDP)
    if eth_frame[23] != 17 {
        return None;
    }
    
    // Check UDP ports: src=67 (DHCP server), dst=68 (DHCP client)
    let udp_offset = 14 + 20; // After Ethernet + IPv4 headers
    let src_port = u16::from_be_bytes([eth_frame[udp_offset], eth_frame[udp_offset + 1]]);
    let dst_port = u16::from_be_bytes([eth_frame[udp_offset + 2], eth_frame[udp_offset + 3]]);
    
    if src_port != 67 || dst_port != 68 {
        return None;
    }
    
    // Parse BOOTP header
    let bootp_offset = udp_offset + 8;
    let op = eth_frame[bootp_offset]; // Should be 2 (BOOTREPLY)
    if op != 2 {
        return None;
    }
    
    // Extract yiaddr (your IP address)
    let yiaddr = [
        eth_frame[bootp_offset + 16],
        eth_frame[bootp_offset + 17],
        eth_frame[bootp_offset + 18],
        eth_frame[bootp_offset + 19],
    ];
    
    // Check DHCP magic cookie: 0x63825363
    let magic_offset = bootp_offset + 236;
    if eth_frame[magic_offset] != 0x63 || eth_frame[magic_offset + 1] != 0x82 
        || eth_frame[magic_offset + 2] != 0x53 || eth_frame[magic_offset + 3] != 0x63 {
        return None;
    }
    
    // Parse DHCP options
    let mut msg_type: Option<u8> = None;
    let mut server_id: Option<[u8; 4]> = None;
    let mut mask: Option<[u8; 4]> = None;
    let mut router: Option<[u8; 4]> = None;
    let mut dns1: Option<[u8; 4]> = None;
    let mut dns2: Option<[u8; 4]> = None;
    
    let options_start = magic_offset + 4;
    let mut pos = options_start;
    
    while pos < eth_frame.len() {
        let opt_type = eth_frame[pos];
        if opt_type == 0xff { // End option
            break;
        }
        if opt_type == 0x00 { // Pad option
            pos += 1;
            continue;
        }
        
        if pos + 1 >= eth_frame.len() {
            break;
        }
        let opt_len = eth_frame[pos + 1] as usize;
        if pos + 2 + opt_len > eth_frame.len() {
            break;
        }
        
        match opt_type {
            53 => { // DHCP Message Type
                if opt_len >= 1 {
                    msg_type = Some(eth_frame[pos + 2]);
                }
            }
            54 => { // Server Identifier
                if opt_len >= 4 {
                    server_id = Some([
                        eth_frame[pos + 2],
                        eth_frame[pos + 3],
                        eth_frame[pos + 4],
                        eth_frame[pos + 5],
                    ]);
                }
            }
            1 => { // Subnet Mask
                if opt_len >= 4 {
                    mask = Some([
                        eth_frame[pos + 2],
                        eth_frame[pos + 3],
                        eth_frame[pos + 4],
                        eth_frame[pos + 5],
                    ]);
                }
            }
            3 => { // Router
                if opt_len >= 4 {
                    router = Some([
                        eth_frame[pos + 2],
                        eth_frame[pos + 3],
                        eth_frame[pos + 4],
                        eth_frame[pos + 5],
                    ]);
                }
            }
            6 => { // DNS
                if opt_len >= 4 {
                    dns1 = Some([
                        eth_frame[pos + 2],
                        eth_frame[pos + 3],
                        eth_frame[pos + 4],
                        eth_frame[pos + 5],
                    ]);
                }
                if opt_len >= 8 {
                    dns2 = Some([
                        eth_frame[pos + 6],
                        eth_frame[pos + 7],
                        eth_frame[pos + 8],
                        eth_frame[pos + 9],
                    ]);
                }
            }
            _ => {}
        }
        
        pos += 2 + opt_len;
    }
    
    match msg_type {
        Some(2) => { // DHCP OFFER
            Some(DhcpResponse::Offer {
                yiaddr,
                server_id: server_id.unwrap_or([0, 0, 0, 0]),
            })
        }
        Some(5) => { // DHCP ACK
            Some(DhcpResponse::Ack {
                yiaddr,
                mask: mask.unwrap_or([255, 255, 0, 0]),
                router: router.unwrap_or([0, 0, 0, 0]),
                dns1: dns1.unwrap_or([0, 0, 0, 0]),
                dns2: dns2.unwrap_or([0, 0, 0, 0]),
            })
        }
        _ => None,
    }
}

/// Generate the next packet based on DHCP state machine
/// Mimics Zig's MacOsTunGetNextPacket() behavior
pub async fn generate_next_packet(state: &mut PacketGeneratorState) -> Option<Vec<u8>> {
    let now = Instant::now();
    let time_since_start = now.duration_since(state.connection_start);
    let time_since_state_change = now.duration_since(state.last_state_change);
    
    trace!("generate_next_packet: state={:?}, time_since_start={:?}, time_since_state_change={:?}", 
        state.dhcp_state, time_since_start, time_since_state_change);
    
    // Stage 1: Send DHCP DISCOVER INSTANTLY (matches Zig's "Triggered session" behavior)
    // Critical: Bridge needs to learn MAC immediately after session establishment!
    // Zig sends: DHCP → IPv6 NA → IPv6 RS → GARP all instantly to populate bridge MAC table
    if state.dhcp_state == DhcpState::Init {
        info!("📡 Sending DHCP DISCOVER #1 (xid={:#x}) - INSTANT to trigger bridge learning", state.dhcp_xid);
        state.dhcp_state = DhcpState::DiscoverSent;
        state.last_state_change = now;
        state.last_dhcp_send = now;
        state.dhcp_retry_count = 0;
        return Some(build_dhcp_discover(state.our_mac, state.dhcp_xid));
    }
    
    // Retry DHCP DISCOVER every 3 seconds (up to 5 times)
    if state.dhcp_state == DhcpState::DiscoverSent {
        if state.dhcp_retry_count < 5 && now.duration_since(state.last_dhcp_send) >= Duration::from_secs(3) {
            state.dhcp_retry_count += 1;
            state.last_dhcp_send = now;
            info!("🔄 DHCP DISCOVER retry #{} (no response after {:?})", 
                state.dhcp_retry_count, time_since_start);
            return Some(build_dhcp_discover(state.our_mac, state.dhcp_xid));
        }
    }
    
    // Stage 2: Send IPv6 Neighbor Advertisement INSTANTLY after DHCP
    // Bridge learning: All packets must be sent instantly to populate MAC table
    if state.dhcp_state == DhcpState::DiscoverSent && state.dhcp_retry_count == 0 {
        debug!("📡 Sending IPv6 Neighbor Advertisement - INSTANT");
        state.dhcp_state = DhcpState::Ipv6NaSent;
        state.last_state_change = now;
        return Some(build_neighbor_advertisement(state.our_mac));
    }
    
    // Stage 3: Send IPv6 Router Solicitation INSTANTLY
    if state.dhcp_state == DhcpState::Ipv6NaSent {
        debug!("📡 Sending IPv6 Router Solicitation - INSTANT");
        state.dhcp_state = DhcpState::Ipv6RsSent;
        state.last_state_change = now;
        return Some(build_router_solicitation(state.our_mac));
    }
    
    // Stage 4: Send Gratuitous ARP INSTANTLY to complete MAC learning
    if state.dhcp_state == DhcpState::Ipv6RsSent {
        info!("📡 Sending Gratuitous ARP with 0.0.0.0 - INSTANT to complete bridge MAC learning");
        state.dhcp_state = DhcpState::ArpAnnounceSent;
        state.last_state_change = now;
        return Some(build_gratuitous_arp(state.our_mac, [0, 0, 0, 0]));
    }
    
    // After completing initial sequence, retry DHCP DISCOVER every 3 seconds (up to 5 times)
    if state.dhcp_state == DhcpState::ArpAnnounceSent {
        if state.dhcp_retry_count < 5 && now.duration_since(state.last_dhcp_send) >= Duration::from_secs(3) {
            state.dhcp_retry_count += 1;
            state.last_dhcp_send = now;
            info!("🔄 DHCP DISCOVER retry #{} (no response after {:?})", 
                state.dhcp_retry_count, time_since_start);
            return Some(build_dhcp_discover(state.our_mac, state.dhcp_xid));
        }
    }
    
    // Send DHCP REQUEST after receiving OFFER
    if state.dhcp_state == DhcpState::OfferReceived {
        if let (Some(offered_ip), Some(server_ip)) = (state.offered_ip, state.dhcp_server_ip) {
            info!("📤 Sending DHCP REQUEST for {}.{}.{}.{}", 
                offered_ip[0], offered_ip[1], offered_ip[2], offered_ip[3]);
            state.dhcp_state = DhcpState::RequestSent;
            return Some(build_dhcp_request(state.our_mac, state.dhcp_xid, offered_ip, server_ip));
        }
    }
    
    // Send ARP request for gateway after DHCP configuration
    if state.need_gateway_arp {
        if let (Some(our_ip), Some(gateway_ip)) = (state.our_ip, state.gateway_ip) {
            info!("🔍 Resolving gateway MAC address for {}.{}.{}.{}", 
                gateway_ip[0], gateway_ip[1], gateway_ip[2], gateway_ip[3]);
            state.need_gateway_arp = false;
            return Some(build_arp_request(state.our_mac, our_ip, gateway_ip));
        }
    }
    
    // Send keep-alive Gratuitous ARP every 30 seconds when configured
    if state.dhcp_state == DhcpState::Configured {
        if let Some(our_ip) = state.our_ip {
            if now.duration_since(state.last_keepalive) >= Duration::from_secs(30) {
                trace!("💓 Sending keep-alive Gratuitous ARP");
                state.last_keepalive = now;
                return Some(build_gratuitous_arp(state.our_mac, our_ip));
            }
        }
    }
    
    None
}

/// Build Gratuitous ARP packet (announces our IP)
fn build_gratuitous_arp(src_mac: [u8; 6], src_ip: [u8; 4]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(42);
    
    // Ethernet header (14 bytes)
    packet.extend_from_slice(&[0xff; 6]); // Destination: broadcast
    packet.extend_from_slice(&src_mac);    // Source MAC
    packet.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP
    
    // ARP header (28 bytes)
    packet.extend_from_slice(&[0x00, 0x01]); // Hardware type: Ethernet
    packet.extend_from_slice(&[0x08, 0x00]); // Protocol type: IPv4
    packet.push(6); // Hardware size
    packet.push(4); // Protocol size
    packet.extend_from_slice(&[0x00, 0x01]); // Opcode: Request (GARP uses request)
    packet.extend_from_slice(&src_mac);      // Sender MAC
    packet.extend_from_slice(&src_ip);       // Sender IP
    packet.extend_from_slice(&[0x00; 6]);    // Target MAC: 00:00:00:00:00:00
    packet.extend_from_slice(&src_ip);       // Target IP: same as sender (GARP)
    
    packet
}

/// Build ARP request packet
fn build_arp_request(src_mac: [u8; 6], src_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(42);
    
    // Ethernet header
    packet.extend_from_slice(&[0xff; 6]); // Broadcast
    packet.extend_from_slice(&src_mac);
    packet.extend_from_slice(&[0x08, 0x06]);
    
    // ARP header
    packet.extend_from_slice(&[0x00, 0x01]); // Hardware: Ethernet
    packet.extend_from_slice(&[0x08, 0x00]); // Protocol: IPv4
    packet.push(6);
    packet.push(4);
    packet.extend_from_slice(&[0x00, 0x01]); // Opcode: Request
    packet.extend_from_slice(&src_mac);
    packet.extend_from_slice(&src_ip);
    packet.extend_from_slice(&[0x00; 6]); // Target MAC unknown
    packet.extend_from_slice(&target_ip);
    
    packet
}

/// Build DHCP DISCOVER packet
fn build_dhcp_discover(src_mac: [u8; 6], xid: u32) -> Vec<u8> {
    let mut packet = Vec::with_capacity(342);
    
    // Ethernet header (14 bytes)
    packet.extend_from_slice(&[0xff; 6]); // Broadcast
    packet.extend_from_slice(&src_mac);
    packet.extend_from_slice(&[0x08, 0x00]); // IPv4
    
    // IPv4 header (20 bytes)
    packet.push(0x45); // Version 4, Header length 5
    packet.push(0x00); // DSCP/ECN
    let total_len = 20 + 8 + 240 + 64; // IP + UDP + BOOTP + options
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]); // Identification
    packet.extend_from_slice(&[0x00, 0x00]); // Flags + Fragment offset
    packet.push(64); // TTL
    packet.push(17); // Protocol: UDP
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum (calculate later)
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Source IP: 0.0.0.0
    packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // Dest IP: broadcast
    
    // Calculate IP checksum
    let ip_start = 14;
    let checksum = calculate_ip_checksum(&packet[ip_start..ip_start+20]);
    packet[ip_start+10] = (checksum >> 8) as u8;
    packet[ip_start+11] = (checksum & 0xff) as u8;
    
    // UDP header (8 bytes)
    packet.extend_from_slice(&[0x00, 0x44]); // Source port: 68
    packet.extend_from_slice(&[0x00, 0x43]); // Dest port: 67
    let udp_len = 8 + 240 + 64;
    packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum (optional)
    
    // BOOTP header (240 bytes)
    packet.push(0x01); // op: BOOTREQUEST
    packet.push(0x01); // htype: Ethernet
    packet.push(0x06); // hlen
    packet.push(0x00); // hops
    packet.extend_from_slice(&xid.to_be_bytes()); // Transaction ID
    packet.extend_from_slice(&[0x00, 0x00]); // secs
    packet.extend_from_slice(&[0x80, 0x00]); // flags: broadcast
    packet.extend_from_slice(&[0x00; 4]); // ciaddr
    packet.extend_from_slice(&[0x00; 4]); // yiaddr
    packet.extend_from_slice(&[0x00; 4]); // siaddr
    packet.extend_from_slice(&[0x00; 4]); // giaddr
    packet.extend_from_slice(&src_mac); // chaddr (client MAC)
    packet.extend_from_slice(&[0x00; 10]); // chaddr padding
    packet.extend_from_slice(&[0x00; 64]); // sname
    packet.extend_from_slice(&[0x00; 128]); // file
    
    // DHCP options
    packet.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]); // Magic cookie
    
    // Option 53: DHCP Message Type = DISCOVER (1)
    packet.extend_from_slice(&[53, 1, 1]);
    
    // Option 55: Parameter Request List
    packet.extend_from_slice(&[55, 4, 1, 3, 6, 15]); // Subnet, Router, DNS, Domain
    
    // Option 255: End
    packet.push(255);
    
    packet
}

/// Build DHCP REQUEST packet
fn build_dhcp_request(src_mac: [u8; 6], xid: u32, requested_ip: [u8; 4], server_ip: [u8; 4]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(342);
    
    // Ethernet header
    packet.extend_from_slice(&[0xff; 6]);
    packet.extend_from_slice(&src_mac);
    packet.extend_from_slice(&[0x08, 0x00]);
    
    // IPv4 header
    packet.push(0x45);
    packet.push(0x00);
    let total_len = 20 + 8 + 240 + 80;
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.push(64);
    packet.push(17);
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum
    packet.extend_from_slice(&[0x00; 4]); // Source
    packet.extend_from_slice(&[0xff; 4]); // Dest
    
    let ip_start = 14;
    let checksum = calculate_ip_checksum(&packet[ip_start..ip_start+20]);
    packet[ip_start+10] = (checksum >> 8) as u8;
    packet[ip_start+11] = (checksum & 0xff) as u8;
    
    // UDP header
    packet.extend_from_slice(&[0x00, 0x44]);
    packet.extend_from_slice(&[0x00, 0x43]);
    let udp_len = 8 + 240 + 80;
    packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    
    // BOOTP header
    packet.push(0x01);
    packet.push(0x01);
    packet.push(0x06);
    packet.push(0x00);
    packet.extend_from_slice(&xid.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x80, 0x00]);
    packet.extend_from_slice(&[0x00; 16]);
    packet.extend_from_slice(&src_mac);
    packet.extend_from_slice(&[0x00; 10]);
    packet.extend_from_slice(&[0x00; 192]);
    
    // DHCP options
    packet.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    packet.extend_from_slice(&[53, 1, 3]); // DHCP REQUEST
    packet.extend_from_slice(&[50, 4]); // Requested IP
    packet.extend_from_slice(&requested_ip);
    packet.extend_from_slice(&[54, 4]); // Server identifier
    packet.extend_from_slice(&server_ip);
    packet.extend_from_slice(&[55, 4, 1, 3, 6, 15]);
    packet.push(255);
    
    packet
}

/// Build IPv6 Neighbor Advertisement
fn build_neighbor_advertisement(src_mac: [u8; 6]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(86);
    
    // Ethernet header
    packet.extend_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]); // IPv6 multicast
    packet.extend_from_slice(&src_mac);
    packet.extend_from_slice(&[0x86, 0xdd]); // IPv6
    
    // IPv6 header (40 bytes)
    packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Version, traffic class, flow label
    packet.extend_from_slice(&[0x00, 0x20]); // Payload length: 32
    packet.push(58); // Next header: ICMPv6
    packet.push(255); // Hop limit
    
    // Source: link-local fe80::MAC
    packet.extend_from_slice(&[0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    packet.push(src_mac[0] ^ 0x02);
    packet.push(src_mac[1]);
    packet.push(src_mac[2]);
    packet.push(0xff);
    packet.push(0xfe);
    packet.push(src_mac[3]);
    packet.push(src_mac[4]);
    packet.push(src_mac[5]);
    
    // Destination: all-nodes ff02::1
    packet.extend_from_slice(&[0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    
    // ICMPv6 Neighbor Advertisement
    packet.push(136); // Type: Neighbor Advertisement
    packet.push(0); // Code
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum (calculate)
    packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Flags: Router, Solicited, Override
    
    // Target address (same as source)
    packet.extend_from_slice(&[0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    packet.push(src_mac[0] ^ 0x02);
    packet.push(src_mac[1]);
    packet.push(src_mac[2]);
    packet.push(0xff);
    packet.push(0xfe);
    packet.push(src_mac[3]);
    packet.push(src_mac[4]);
    packet.push(src_mac[5]);
    
    // Option: Target link-layer address
    packet.push(2); // Type
    packet.push(1); // Length (1 * 8 bytes)
    packet.extend_from_slice(&src_mac);
    
    packet
}

/// Build IPv6 Router Solicitation
fn build_router_solicitation(src_mac: [u8; 6]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(70);
    
    // Ethernet header
    packet.extend_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x02]); // All routers
    packet.extend_from_slice(&src_mac);
    packet.extend_from_slice(&[0x86, 0xdd]);
    
    // IPv6 header
    packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x10]); // Payload: 16
    packet.push(58);
    packet.push(255);
    
    // Source: link-local
    packet.extend_from_slice(&[0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    packet.push(src_mac[0] ^ 0x02);
    packet.push(src_mac[1]);
    packet.push(src_mac[2]);
    packet.push(0xff);
    packet.push(0xfe);
    packet.push(src_mac[3]);
    packet.push(src_mac[4]);
    packet.push(src_mac[5]);
    
    // Dest: all-routers ff02::2
    packet.extend_from_slice(&[0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
    
    // ICMPv6 Router Solicitation
    packet.push(133); // Type
    packet.push(0);
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved
    
    // Option: Source link-layer address
    packet.push(1); // Type
    packet.push(1); // Length
    packet.extend_from_slice(&src_mac);
    
    packet
}

/// Calculate IP checksum
fn calculate_ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    
    while i < data.len() - 1 {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum += word;
        i += 2;
    }
    
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    !sum as u16
}
