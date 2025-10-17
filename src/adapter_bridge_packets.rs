/// Packet generation functions for adapter bridge
/// Matches Zig implementation in packet_adapter_macos.c
use super::adapter_bridge::{DhcpState, PacketGeneratorState};
use std::time::{Duration, Instant};
use tracing::{debug, info, trace};

/// DHCP response types
#[derive(Debug, Clone)]
pub enum DhcpResponse {
    Offer {
        yiaddr: [u8; 4],
        server_id: [u8; 4],
        gateway_mac: [u8; 6], // ✅ Extract gateway MAC from Ethernet source (Zig does this!)
    },
    Ack {
        yiaddr: [u8; 4],
        mask: [u8; 4],
        router: [u8; 4],
        dns1: [u8; 4],
        dns2: [u8; 4],
        gateway_mac: [u8; 6], // ✅ Extract gateway MAC from Ethernet source (Zig does this!)
    },
}

/// Parse DHCP response from Ethernet frame
/// Returns Some(DhcpResponse) if this is a DHCP OFFER or ACK
pub fn parse_dhcp_response(eth_frame: &[u8]) -> Option<DhcpResponse> {
    debug!("🔍 parse_dhcp_response: checking frame len={}", eth_frame.len());
    
    // Must be at least: Ethernet(14) + IPv4 min(20) + UDP(8) + BOOTP min(236) + Magic(4) = 282 bytes
    // BUT: IP header can have options, so we need to check IHL (Internet Header Length)
    if eth_frame.len() < 14 + 20 {
        debug!(
            "🚫 DHCP parse: too short for Ethernet+IP (len={}, need ≥34)",
            eth_frame.len()
        );
        return None;
    }

    // Check EtherType: 0x0800 (IPv4)
    if eth_frame[12] != 0x08 || eth_frame[13] != 0x00 {
        trace!(
            "🚫 DHCP parse: not IPv4 (ethertype={:02x}{:02x})",
            eth_frame[12],
            eth_frame[13]
        );
        return None;
    }

    // Get IP header length from IHL field (lower 4 bits of first byte, in 32-bit words)
    let ip_header_start = 14;
    let ihl = (eth_frame[ip_header_start] & 0x0f) as usize * 4; // IHL is in 32-bit words
    debug!("🔍 IP header length (IHL): {} bytes", ihl);

    if ihl < 20 || ihl > 60 {
        trace!("🚫 DHCP parse: invalid IHL={} (must be 20-60)", ihl);
        return None;
    }

    // Check IP protocol: 17 (UDP)
    let ip_proto_offset = ip_header_start + 9;
    if eth_frame.len() <= ip_proto_offset || eth_frame[ip_proto_offset] != 17 {
        trace!(
            "🚫 DHCP parse: not UDP (protocol={:?})",
            eth_frame.get(ip_proto_offset)
        );
        return None;
    }

    // Check UDP ports: src=67 (DHCP server), dst=68 (DHCP client)
    let udp_offset = 14 + ihl; // After Ethernet + IPv4 headers (with variable length)
    if eth_frame.len() < udp_offset + 8 {
        trace!(
            "🚫 DHCP parse: too short for UDP header (len={}, need ≥{})",
            eth_frame.len(),
            udp_offset + 8
        );
        return None;
    }

    let src_port = u16::from_be_bytes([eth_frame[udp_offset], eth_frame[udp_offset + 1]]);
    let dst_port = u16::from_be_bytes([eth_frame[udp_offset + 2], eth_frame[udp_offset + 3]]);

    if src_port != 67 || dst_port != 68 {
        trace!(
            "🚫 DHCP parse: wrong ports (src={}, dst={}, expected 67→68)",
            src_port,
            dst_port
        );
        return None;
    }

    debug!(
        "✅ DHCP packet detected: UDP 67→68, IHL={}, len={}",
        ihl,
        eth_frame.len()
    );

    // Parse BOOTP header (minimum 236 bytes)
    let bootp_offset = udp_offset + 8;
    if eth_frame.len() < bootp_offset + 236 {
        debug!(
            "🚫 DHCP parse: too short for BOOTP header (len={}, need ≥{})",
            eth_frame.len(),
            bootp_offset + 236
        );
        return None;
    }

    let op = eth_frame[bootp_offset]; // Should be 2 (BOOTREPLY)
    if op != 2 {
        debug!("🚫 DHCP parse: not BOOTREPLY (op={}, expected 2)", op);
        return None;
    }

    // Extract yiaddr (your IP address)
    let yiaddr = [
        eth_frame[bootp_offset + 16],
        eth_frame[bootp_offset + 17],
        eth_frame[bootp_offset + 18],
        eth_frame[bootp_offset + 19],
    ];
    debug!(
        "✅ BOOTP REPLY found, yiaddr={}.{}.{}.{}",
        yiaddr[0], yiaddr[1], yiaddr[2], yiaddr[3]
    );

    // Check DHCP magic cookie: 0x63825363
    let magic_offset = bootp_offset + 236;
    if eth_frame.len() < magic_offset + 4 {
        debug!(
            "🚫 DHCP parse: too short for magic cookie (len={}, need ≥{})",
            eth_frame.len(),
            magic_offset + 4
        );
        return None;
    }

    if eth_frame[magic_offset] != 0x63
        || eth_frame[magic_offset + 1] != 0x82
        || eth_frame[magic_offset + 2] != 0x53
        || eth_frame[magic_offset + 3] != 0x63
    {
        debug!(
            "🚫 DHCP parse: bad magic cookie ({:02x}{:02x}{:02x}{:02x})",
            eth_frame[magic_offset],
            eth_frame[magic_offset + 1],
            eth_frame[magic_offset + 2],
            eth_frame[magic_offset + 3]
        );
        return None;
    }
    debug!("✅ DHCP magic cookie verified");

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
        if opt_type == 0xff {
            // End option
            break;
        }
        if opt_type == 0x00 {
            // Pad option
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
            53 => {
                // DHCP Message Type
                if opt_len >= 1 {
                    msg_type = Some(eth_frame[pos + 2]);
                }
            }
            54 => {
                // Server Identifier
                if opt_len >= 4 {
                    server_id = Some([
                        eth_frame[pos + 2],
                        eth_frame[pos + 3],
                        eth_frame[pos + 4],
                        eth_frame[pos + 5],
                    ]);
                }
            }
            1 => {
                // Subnet Mask
                if opt_len >= 4 {
                    mask = Some([
                        eth_frame[pos + 2],
                        eth_frame[pos + 3],
                        eth_frame[pos + 4],
                        eth_frame[pos + 5],
                    ]);
                }
            }
            3 => {
                // Router
                if opt_len >= 4 {
                    router = Some([
                        eth_frame[pos + 2],
                        eth_frame[pos + 3],
                        eth_frame[pos + 4],
                        eth_frame[pos + 5],
                    ]);
                }
            }
            6 => {
                // DNS
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

    // ✅ CRITICAL FIX: Extract gateway MAC from Ethernet source MAC (bytes 6-11)
    // This is what Zig does: memcpy(gateway_mac, eth_frame + 6, 6)
    // The DHCP response comes from the gateway, so its source MAC IS the gateway MAC!
    let gateway_mac = [
        eth_frame[6],
        eth_frame[7],
        eth_frame[8],
        eth_frame[9],
        eth_frame[10],
        eth_frame[11],
    ];

    match msg_type {
        Some(2) => {
            // DHCP OFFER
            info!("🎉 DHCP OFFER parsed! IP={}.{}.{}.{}, server={:?}, gateway_mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                yiaddr[0], yiaddr[1], yiaddr[2], yiaddr[3], server_id,
                gateway_mac[0], gateway_mac[1], gateway_mac[2], gateway_mac[3], gateway_mac[4], gateway_mac[5]);
            Some(DhcpResponse::Offer {
                yiaddr,
                server_id: server_id.unwrap_or([0, 0, 0, 0]),
                gateway_mac,
            })
        }
        Some(5) => {
            // DHCP ACK
            info!("🎉 DHCP ACK parsed! IP={}.{}.{}.{}, mask={:?}, router={:?}, gateway_mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                yiaddr[0], yiaddr[1], yiaddr[2], yiaddr[3], mask, router,
                gateway_mac[0], gateway_mac[1], gateway_mac[2], gateway_mac[3], gateway_mac[4], gateway_mac[5]);
            Some(DhcpResponse::Ack {
                yiaddr,
                mask: mask.unwrap_or([255, 255, 0, 0]),
                router: router.unwrap_or([0, 0, 0, 0]),
                dns1: dns1.unwrap_or([0, 0, 0, 0]),
                dns2: dns2.unwrap_or([0, 0, 0, 0]),
                gateway_mac,
            })
        }
        _ => {
            debug!(
                "🚫 DHCP parse: unsupported msg_type={:?} (expected 2=OFFER or 5=ACK)",
                msg_type
            );
            None
        }
    }
}

/// Generate the next packet based on DHCP state machine
/// Mimics Zig's MacOsTunGetNextPacket() behavior
pub async fn generate_next_packet(state: &mut PacketGeneratorState) -> Option<Vec<u8>> {
    let now = Instant::now();
    let time_since_start = now.duration_since(state.connection_start);
    let time_since_state_change = now.duration_since(state.last_state_change);

    trace!(
        "generate_next_packet: state={:?}, time_since_start={:?}, time_since_state_change={:?}",
        state.dhcp_state,
        time_since_start,
        time_since_state_change
    );

    // Stage 1: Send DHCP DISCOVER INSTANTLY (matches Zig's "Triggered session" behavior)
    // Critical: Bridge needs to learn MAC immediately after session establishment!
    // Zig sends: DHCP → IPv6 NA → IPv6 RS → GARP all instantly to populate bridge MAC table
    if state.dhcp_state == DhcpState::Init {
        info!(
            "📡 Sending DHCP DISCOVER #1 (xid={:#x}) - INSTANT to trigger bridge learning",
            state.dhcp_xid
        );
        state.dhcp_state = DhcpState::DiscoverSent;
        state.last_state_change = now;
        state.last_dhcp_send = now;
        state.dhcp_retry_count = 0;
        return Some(build_dhcp_discover(state.our_mac, state.dhcp_xid));
    }

    // Retry DHCP DISCOVER every 3 seconds (up to 5 times) - ONLY if we haven't received OFFER yet
    if state.dhcp_state == DhcpState::DiscoverSent {
        // First, check if we should send IPv6 NA immediately after first DISCOVER
        if state.dhcp_retry_count == 0 {
            debug!("📡 Sending IPv6 Neighbor Advertisement - INSTANT");
            state.dhcp_state = DhcpState::Ipv6NaSent;
            state.last_state_change = now;
            return Some(build_neighbor_advertisement(state.our_mac));
        }
        
        // Then retry DISCOVER if no response
        if state.dhcp_retry_count < 5
            && now.duration_since(state.last_dhcp_send) >= Duration::from_secs(3)
        {
            state.dhcp_retry_count += 1;
            state.last_dhcp_send = now;
            info!(
                "🔄 DHCP DISCOVER retry #{} (no response after {:?})",
                state.dhcp_retry_count, time_since_start
            );
            return Some(build_dhcp_discover(state.our_mac, state.dhcp_xid));
        }
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
    // BUT STOP if we've received an OFFER (state transitions to OfferReceived)
    if state.dhcp_state == DhcpState::ArpAnnounceSent {
        if state.dhcp_retry_count < 5
            && now.duration_since(state.last_dhcp_send) >= Duration::from_secs(3)
        {
            state.dhcp_retry_count += 1;
            state.last_dhcp_send = now;
            info!(
                "🔄 DHCP DISCOVER retry #{} (no response after {:?})",
                state.dhcp_retry_count, time_since_start
            );
            return Some(build_dhcp_discover(state.our_mac, state.dhcp_xid));
        }
        // If we've exceeded retries but still no OFFER, stay in this state (will timeout eventually)
    }

    // Send DHCP REQUEST after receiving OFFER
    if state.dhcp_state == DhcpState::OfferReceived {
        if let (Some(offered_ip), Some(server_ip)) = (state.offered_ip, state.dhcp_server_ip) {
            info!(
                "📤 Sending DHCP REQUEST for {}.{}.{}.{}",
                offered_ip[0], offered_ip[1], offered_ip[2], offered_ip[3]
            );
            state.dhcp_state = DhcpState::RequestSent;
            state.last_state_change = now;
            state.last_dhcp_send = now; // Track timestamp for retries
            state.dhcp_retry_count = 0; // Reset retry counter for REQUEST phase
            return Some(build_dhcp_request(
                state.our_mac,
                state.dhcp_xid,
                offered_ip,
                server_ip,
            ));
        }
    }

    // Retry DHCP REQUEST every 3 seconds (up to 5 times) if no ACK received
    if state.dhcp_state == DhcpState::RequestSent {
        if state.dhcp_retry_count < 5
            && now.duration_since(state.last_dhcp_send) >= Duration::from_secs(3)
        {
            if let (Some(offered_ip), Some(server_ip)) = (state.offered_ip, state.dhcp_server_ip) {
                state.dhcp_retry_count += 1;
                state.last_dhcp_send = now;
                info!(
                    "🔄 DHCP REQUEST retry #{} (no ACK after {:?})",
                    state.dhcp_retry_count, time_since_state_change
                );
                return Some(build_dhcp_request(
                    state.our_mac,
                    state.dhcp_xid,
                    offered_ip,
                    server_ip,
                ));
            }
        }
    }

    // Send ARP request for gateway after DHCP configuration
    if state.need_gateway_arp {
        if let (Some(our_ip), Some(gateway_ip)) = (state.our_ip, state.gateway_ip) {
            info!(
                "🔍 Resolving gateway MAC address for {}.{}.{}.{}",
                gateway_ip[0], gateway_ip[1], gateway_ip[2], gateway_ip[3]
            );
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
    packet.extend_from_slice(&src_mac); // Source MAC
    packet.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP

    // ARP header (28 bytes)
    packet.extend_from_slice(&[0x00, 0x01]); // Hardware type: Ethernet
    packet.extend_from_slice(&[0x08, 0x00]); // Protocol type: IPv4
    packet.push(6); // Hardware size
    packet.push(4); // Protocol size
    packet.extend_from_slice(&[0x00, 0x01]); // Opcode: Request (GARP uses request)
    packet.extend_from_slice(&src_mac); // Sender MAC
    packet.extend_from_slice(&src_ip); // Sender IP
    packet.extend_from_slice(&[0x00; 6]); // Target MAC: 00:00:00:00:00:00
    packet.extend_from_slice(&src_ip); // Target IP: same as sender (GARP)

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
/// ⚠️ CRITICAL: Must match Zig's BuildDhcpDiscover() structure EXACTLY (292 bytes)!
/// SoftEther server is picky about DHCP packet structure.
fn build_dhcp_discover(src_mac: [u8; 6], xid: u32) -> Vec<u8> {
    let mut packet = Vec::with_capacity(1024);

    // Ethernet header (14 bytes)
    packet.extend_from_slice(&[0xff; 6]); // Broadcast
    packet.extend_from_slice(&src_mac);
    packet.extend_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 header (20 bytes) - will set total length later
    let ip_header_start = packet.len();
    packet.push(0x45); // Version 4, Header length 5
    packet.push(0x00); // DSCP/ECN
    let ip_total_len_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]); // Placeholder for total length
    packet.extend_from_slice(&[0x00, 0x00]); // Identification
    packet.extend_from_slice(&[0x00, 0x00]); // Flags + Fragment offset
    packet.push(64); // TTL
    packet.push(17); // Protocol: UDP
    let ip_checksum_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum (calculate later)
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Source IP: 0.0.0.0
    packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // Dest IP: broadcast

    // UDP header (8 bytes) - will set length later
    let udp_header_start = packet.len();
    packet.extend_from_slice(&[0x00, 0x44]); // Source port: 68 (DHCP client)
    packet.extend_from_slice(&[0x00, 0x43]); // Dest port: 67 (DHCP server)
    let udp_len_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]); // Placeholder for UDP length
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum (optional)

    // BOOTP/DHCP header (240 bytes minimum)
    packet.push(0x01); // op: BOOTREQUEST
    packet.push(0x01); // htype: Ethernet
    packet.push(0x06); // hlen: 6
    packet.push(0x00); // hops: 0
    packet.extend_from_slice(&xid.to_be_bytes()); // Transaction ID (4 bytes)
    packet.extend_from_slice(&[0x00, 0x00]); // secs
    packet.extend_from_slice(&[0x80, 0x00]); // flags: broadcast
    packet.extend_from_slice(&[0x00; 4]); // ciaddr
    packet.extend_from_slice(&[0x00; 4]); // yiaddr
    packet.extend_from_slice(&[0x00; 4]); // siaddr
    packet.extend_from_slice(&[0x00; 4]); // giaddr
    packet.extend_from_slice(&src_mac); // chaddr (client MAC, 6 bytes)
    packet.extend_from_slice(&[0x00; 10]); // chaddr padding (10 bytes)
    packet.extend_from_slice(&[0x00; 64]); // sname (64 bytes)
    packet.extend_from_slice(&[0x00; 128]); // file (128 bytes)

    // DHCP options (magic cookie + options)
    packet.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]); // Magic cookie

    // Option 53: DHCP Message Type = DISCOVER (1)
    packet.extend_from_slice(&[53, 1, 1]);

    // Option 55: Parameter Request List (match Zig ordering)
    packet.extend_from_slice(&[55, 4, 1, 3, 6, 15]);

    // Option 255: End
    packet.push(255);

    // Update lengths
    let total_packet_size = packet.len();
    let ip_total_len = (total_packet_size - ip_header_start) as u16;
    let udp_len = (total_packet_size - udp_header_start) as u16;

    packet[ip_total_len_pos..ip_total_len_pos + 2].copy_from_slice(&ip_total_len.to_be_bytes());
    packet[udp_len_pos..udp_len_pos + 2].copy_from_slice(&udp_len.to_be_bytes());

    // Calculate IP checksum
    let checksum = calculate_ip_checksum(&packet[ip_header_start..ip_header_start + 20]);
    packet[ip_checksum_pos..ip_checksum_pos + 2].copy_from_slice(&checksum.to_be_bytes());

    debug!("🔧 Built DHCP DISCOVER: {} bytes total", packet.len());
    packet
}

/// Build DHCP REQUEST packet (must match Zig's C code structure)
fn build_dhcp_request(
    src_mac: [u8; 6],
    xid: u32,
    requested_ip: [u8; 4],
    server_ip: [u8; 4],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(512);

    // Ethernet header (14 bytes)
    packet.extend_from_slice(&[0xff; 6]); // Broadcast dst
    packet.extend_from_slice(&src_mac);
    packet.extend_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 header (20 bytes)
    let ip_header_start = 14;
    packet.push(0x45); // Version 4, IHL 5
    packet.push(0x00); // DSCP/ECN
    let ip_total_len_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]); // Placeholder for total length
    packet.extend_from_slice(&[0x00, 0x00]); // Identification
    packet.extend_from_slice(&[0x00, 0x00]); // Flags + Fragment offset
    packet.push(64); // TTL
    packet.push(17); // Protocol: UDP
    let ip_checksum_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum (calculate later)
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Source IP: 0.0.0.0
    packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // Dest IP: broadcast

    // UDP header (8 bytes)
    let udp_header_start = packet.len();
    packet.extend_from_slice(&[0x00, 0x44]); // Source port 68
    packet.extend_from_slice(&[0x00, 0x43]); // Dest port 67
    let udp_len_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]); // Placeholder for UDP length
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum (optional for UDP)

    // BOOTP header (236 bytes)
    packet.push(0x01); // op: BOOTREQUEST
    packet.push(0x01); // htype: Ethernet
    packet.push(0x06); // hlen: 6
    packet.push(0x00); // hops: 0
    packet.extend_from_slice(&xid.to_be_bytes()); // Transaction ID (4 bytes)
    packet.extend_from_slice(&[0x00, 0x00]); // secs
    packet.extend_from_slice(&[0x80, 0x00]); // flags: broadcast
    packet.extend_from_slice(&[0x00; 4]); // ciaddr
    packet.extend_from_slice(&[0x00; 4]); // yiaddr
    packet.extend_from_slice(&[0x00; 4]); // siaddr
    packet.extend_from_slice(&[0x00; 4]); // giaddr
    packet.extend_from_slice(&src_mac); // chaddr (client MAC, 6 bytes)
    packet.extend_from_slice(&[0x00; 10]); // chaddr padding (10 bytes)
    packet.extend_from_slice(&[0x00; 64]); // sname (64 bytes)
    packet.extend_from_slice(&[0x00; 128]); // file (128 bytes)

    // DHCP options
    packet.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]); // Magic cookie
    packet.extend_from_slice(&[53, 1, 3]); // Option 53: DHCP REQUEST (Message Type = 3)
    packet.extend_from_slice(&[50, 4]); // Option 50: Requested IP Address
    packet.extend_from_slice(&requested_ip);
    packet.extend_from_slice(&[54, 4]); // Option 54: Server Identifier
    packet.extend_from_slice(&server_ip);
    // Option 55: Parameter Request List (match Zig: 1=subnet, 3=router, 6=DNS, 15=domain)
    packet.extend_from_slice(&[55, 4, 1, 3, 6, 15]);
    packet.push(255); // Option 255: End

    // Update lengths
    let total_packet_size = packet.len();
    let ip_total_len = (total_packet_size - ip_header_start) as u16;
    let udp_len = (total_packet_size - udp_header_start) as u16;

    packet[ip_total_len_pos..ip_total_len_pos + 2].copy_from_slice(&ip_total_len.to_be_bytes());
    packet[udp_len_pos..udp_len_pos + 2].copy_from_slice(&udp_len.to_be_bytes());

    // Calculate IP checksum
    let checksum = calculate_ip_checksum(&packet[ip_header_start..ip_header_start + 20]);
    packet[ip_checksum_pos..ip_checksum_pos + 2].copy_from_slice(&checksum.to_be_bytes());

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
