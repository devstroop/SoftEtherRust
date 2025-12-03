//! DHCP packet parsing and building

const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

#[derive(Debug, Clone)]
pub struct DhcpInfo {
    pub message_type: u8, // 1=DISCOVER, 2=OFFER, 3=REQUEST, 4=DECLINE, 5=ACK, 6=NAK, 7=RELEASE, 8=INFORM
    pub offered_ip: [u8; 4],
    pub server_ip: [u8; 4],
    pub gateway: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub dns_servers: Vec<[u8; 4]>,
}

/// Parse DHCP packet from IPv4/UDP payload
pub fn parse_dhcp(udp_payload: &[u8]) -> Option<DhcpInfo> {
    if udp_payload.len() < 240 {
        return None;
    }
    
    // DHCP header offsets:
    // 0: op (1=request, 2=reply)
    // 1: htype (1=Ethernet)
    // 2: hlen (6 for MAC)
    // 3: hops
    // 4-7: xid (transaction ID)
    // 8-9: secs
    // 10-11: flags
    // 12-15: ciaddr (client IP)
    // 16-19: yiaddr (your IP - offered)
    // 20-23: siaddr (server IP)
    // 24-27: giaddr (gateway/relay IP)
    // 28-43: chaddr (client hardware address)
    // 44-235: sname + file (server name and boot filename)
    // 236-239: magic cookie
    // 240+: options
    
    let op = udp_payload[0];
    if op != 2 {
        // Not a reply
        return None;
    }
    
    // Check magic cookie
    if &udp_payload[236..240] != &DHCP_MAGIC_COOKIE {
        return None;
    }
    
    let offered_ip = [
        udp_payload[16], udp_payload[17], udp_payload[18], udp_payload[19]
    ];
    
    let siaddr = [
        udp_payload[20], udp_payload[21], udp_payload[22], udp_payload[23]
    ];
    
    // Parse options
    let mut message_type = 0;
    let mut server_ip = siaddr;
    let mut gateway = [0u8; 4];
    let mut subnet_mask = [0u8; 4];
    let mut dns_servers = Vec::new();
    
    let mut i = 240;
    while i < udp_payload.len() {
        let option_type = udp_payload[i];
        
        if option_type == 0xFF {
            // End of options
            break;
        }
        
        if option_type == 0x00 {
            // Padding
            i += 1;
            continue;
        }
        
        if i + 1 >= udp_payload.len() {
            break;
        }
        
        let option_len = udp_payload[i + 1] as usize;
        
        if i + 2 + option_len > udp_payload.len() {
            break;
        }
        
        let option_data = &udp_payload[i + 2..i + 2 + option_len];
        
        match option_type {
            53 => {
                // DHCP Message Type
                if option_len >= 1 {
                    message_type = option_data[0];
                }
            }
            54 => {
                // Server Identifier
                if option_len >= 4 {
                    server_ip.copy_from_slice(&option_data[0..4]);
                }
            }
            3 => {
                // Router (Gateway)
                if option_len >= 4 {
                    gateway.copy_from_slice(&option_data[0..4]);
                }
            }
            1 => {
                // Subnet Mask
                if option_len >= 4 {
                    subnet_mask.copy_from_slice(&option_data[0..4]);
                }
            }
            6 => {
                // DNS Servers
                for chunk in option_data.chunks_exact(4) {
                    if let Ok(dns) = <[u8; 4]>::try_from(chunk) {
                        dns_servers.push(dns);
                    }
                }
            }
            _ => {}
        }
        
        i += 2 + option_len;
    }
    
    Some(DhcpInfo {
        message_type,
        offered_ip,
        server_ip,
        gateway,
        subnet_mask,
        dns_servers,
    })
}

/// Build DHCP DISCOVER packet (Ethernet frame)
pub fn build_dhcp_discover(client_mac: [u8; 6], transaction_id: u32) -> Vec<u8> {
    let mut frame = Vec::new();
    
    // Ethernet header (14 bytes)
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Broadcast dest
    frame.extend_from_slice(&client_mac); // Source MAC
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4
    
    // IPv4 header (20 bytes) - we'll update length and checksum later
    let ip_header_start = frame.len();
    frame.push(0x45); // Version 4, IHL 5
    frame.push(0x00); // DSCP/ECN
    frame.extend_from_slice(&0u16.to_be_bytes()); // Total length (PLACEHOLDER - will update)
    frame.extend_from_slice(&0u16.to_be_bytes()); // ID
    frame.extend_from_slice(&0x4000u16.to_be_bytes()); // Flags: Don't Fragment
    frame.push(64); // TTL
    frame.push(17); // Protocol: UDP
    frame.extend_from_slice(&0u16.to_be_bytes()); // Checksum (PLACEHOLDER - will calculate)
    frame.extend_from_slice(&[0, 0, 0, 0]); // Source IP: 0.0.0.0
    frame.extend_from_slice(&[255, 255, 255, 255]); // Dest IP: 255.255.255.255
    
    // UDP header (8 bytes) - we'll update length later
    let udp_header_start = frame.len();
    frame.extend_from_slice(&68u16.to_be_bytes()); // Source port (DHCP client)
    frame.extend_from_slice(&67u16.to_be_bytes()); // Dest port (DHCP server)
    frame.extend_from_slice(&0u16.to_be_bytes()); // Length (PLACEHOLDER - will update)
    frame.extend_from_slice(&0u16.to_be_bytes()); // Checksum (optional for IPv4)
    
    // DHCP header (236 bytes base)
    frame.push(1); // op: BOOTREQUEST
    frame.push(1); // htype: Ethernet
    frame.push(6); // hlen: MAC address length
    frame.push(0); // hops
    frame.extend_from_slice(&transaction_id.to_be_bytes()); // xid
    frame.extend_from_slice(&0u16.to_be_bytes()); // secs
    frame.extend_from_slice(&0x8000u16.to_be_bytes()); // flags: broadcast
    frame.extend_from_slice(&[0; 4]); // ciaddr
    frame.extend_from_slice(&[0; 4]); // yiaddr
    frame.extend_from_slice(&[0; 4]); // siaddr
    frame.extend_from_slice(&[0; 4]); // giaddr
    frame.extend_from_slice(&client_mac); // chaddr
    frame.extend_from_slice(&[0; 10]); // chaddr padding
    frame.extend_from_slice(&[0; 192]); // sname + file (192 bytes)
    frame.extend_from_slice(&DHCP_MAGIC_COOKIE); // magic cookie
    
    // DHCP options
    frame.push(53); // Option: DHCP Message Type
    frame.push(1); // Length
    frame.push(1); // DISCOVER
    
    // Option 55: Parameter Request List (CRITICAL for SoftEther DHCP server)
    frame.push(55); // Option code
    frame.push(4);  // Length: 4 parameters
    frame.push(1);  // Subnet Mask
    frame.push(3);  // Router
    frame.push(6);  // DNS Server
    frame.push(15); // Domain Name
    
    frame.push(255); // End option
    
    // NOW update IP and UDP length fields with actual packet size
    let total_len = frame.len();
    let ip_total_len = (total_len - 14) as u16; // Total packet minus Ethernet header
    let udp_len = (total_len - 14 - 20) as u16; // Total minus Eth and IP headers
    
    // Update IP total length (offset 16-17 from start, or ip_header_start+2)
    frame[ip_header_start + 2] = (ip_total_len >> 8) as u8;
    frame[ip_header_start + 3] = (ip_total_len & 0xFF) as u8;
    
    // Update UDP length (offset udp_header_start+4)
    frame[udp_header_start + 4] = (udp_len >> 8) as u8;
    frame[udp_header_start + 5] = (udp_len & 0xFF) as u8;
    
    // Calculate and update IP checksum
    let mut ip_sum: u32 = 0;
    for i in (ip_header_start..ip_header_start + 20).step_by(2) {
        ip_sum += ((frame[i] as u32) << 8) | (frame[i + 1] as u32);
    }
    while ip_sum >> 16 != 0 {
        ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
    }
    let ip_checksum = !ip_sum as u16;
    frame[ip_header_start + 10] = (ip_checksum >> 8) as u8;
    frame[ip_header_start + 11] = (ip_checksum & 0xFF) as u8;
    
    frame
}

/// Build DHCP REQUEST packet (Ethernet frame)
pub fn build_dhcp_request(
    client_mac: [u8; 6],
    transaction_id: u32,
    requested_ip: [u8; 4],
    server_ip: [u8; 4],
) -> Vec<u8> {
    let mut frame = Vec::new();
    
    // Ethernet header (14 bytes)
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Broadcast
    frame.extend_from_slice(&client_mac);
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4
    
    // IPv4 header (20 bytes) - we'll update length and checksum later
    let ip_header_start = frame.len();
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&0u16.to_be_bytes()); // Total length (PLACEHOLDER)
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&0x4000u16.to_be_bytes()); // Flags: Don't Fragment
    frame.push(64);
    frame.push(17);
    frame.extend_from_slice(&0u16.to_be_bytes()); // Checksum (PLACEHOLDER)
    frame.extend_from_slice(&[0, 0, 0, 0]);
    frame.extend_from_slice(&[255, 255, 255, 255]);
    
    // UDP header (8 bytes) - we'll update length later
    let udp_header_start = frame.len();
    frame.extend_from_slice(&68u16.to_be_bytes());
    frame.extend_from_slice(&67u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes()); // Length (PLACEHOLDER)
    frame.extend_from_slice(&0u16.to_be_bytes());
    
    // DHCP header (236 bytes base)
    frame.push(1);
    frame.push(1);
    frame.push(6);
    frame.push(0);
    frame.extend_from_slice(&transaction_id.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&0x8000u16.to_be_bytes());
    frame.extend_from_slice(&[0; 4]); // ciaddr
    frame.extend_from_slice(&[0; 4]); // yiaddr
    frame.extend_from_slice(&[0; 4]); // siaddr
    frame.extend_from_slice(&[0; 4]); // giaddr
    frame.extend_from_slice(&client_mac);
    frame.extend_from_slice(&[0; 10]);
    frame.extend_from_slice(&[0; 192]);
    frame.extend_from_slice(&DHCP_MAGIC_COOKIE);
    
    // DHCP options
    frame.push(53); // Message Type
    frame.push(1);
    frame.push(3); // REQUEST
    
    frame.push(50); // Requested IP Address
    frame.push(4);
    frame.extend_from_slice(&requested_ip);
    
    frame.push(54); // Server Identifier
    frame.push(4);
    frame.extend_from_slice(&server_ip);
    
    frame.push(255); // End
    
    // NOW update IP and UDP length fields with actual packet size
    let total_len = frame.len();
    let ip_total_len = (total_len - 14) as u16;
    let udp_len = (total_len - 14 - 20) as u16;
    
    frame[ip_header_start + 2] = (ip_total_len >> 8) as u8;
    frame[ip_header_start + 3] = (ip_total_len & 0xFF) as u8;
    
    frame[udp_header_start + 4] = (udp_len >> 8) as u8;
    frame[udp_header_start + 5] = (udp_len & 0xFF) as u8;
    
    // Calculate and update IP checksum
    let mut ip_sum: u32 = 0;
    for i in (ip_header_start..ip_header_start + 20).step_by(2) {
        ip_sum += ((frame[i] as u32) << 8) | (frame[i + 1] as u32);
    }
    while ip_sum >> 16 != 0 {
        ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
    }
    let ip_checksum = !ip_sum as u16;
    frame[ip_header_start + 10] = (ip_checksum >> 8) as u8;
    frame[ip_header_start + 11] = (ip_checksum & 0xFF) as u8;
    
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_build_dhcp_discover() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let xid = 0x12345678;
        
        let frame = build_dhcp_discover(mac, xid);
        
        // Check Ethernet header
        assert_eq!(&frame[0..6], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Broadcast
        assert_eq!(&frame[6..12], &mac); // Source MAC
        assert_eq!(&frame[12..14], &[0x08, 0x00]); // IPv4
        
        // Check DHCP op
        assert_eq!(frame[42], 1); // BOOTREQUEST
        
        // Check transaction ID
        assert_eq!(&frame[46..50], &xid.to_be_bytes());
        
        // Check magic cookie
        assert_eq!(&frame[278..282], &DHCP_MAGIC_COOKIE);
        
        // Check message type option
        assert_eq!(frame[282], 53); // Option type
        assert_eq!(frame[283], 1); // Length
        assert_eq!(frame[284], 1); // DISCOVER
    }
}
