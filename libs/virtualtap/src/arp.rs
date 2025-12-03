//! ARP packet parsing and building

/// Parse ARP packet and extract information
pub fn parse_arp(eth_frame: &[u8]) -> Option<ArpInfo> {
    if eth_frame.len() < 42 {
        return None;
    }
    
    // Check EtherType = ARP (0x0806)
    let ethertype = u16::from_be_bytes([eth_frame[12], eth_frame[13]]);
    if ethertype != 0x0806 {
        return None;
    }
    
    let arp = &eth_frame[14..];
    
    // Check hardware type (Ethernet = 1) and protocol type (IPv4 = 0x0800)
    let hw_type = u16::from_be_bytes([arp[0], arp[1]]);
    let proto_type = u16::from_be_bytes([arp[2], arp[3]]);
    
    if hw_type != 1 || proto_type != 0x0800 {
        return None;
    }
    
    let hw_len = arp[4];
    let proto_len = arp[5];
    let operation = u16::from_be_bytes([arp[6], arp[7]]);
    
    if hw_len != 6 || proto_len != 4 {
        return None;
    }
    
    // Extract fields
    let sender_mac = [arp[8], arp[9], arp[10], arp[11], arp[12], arp[13]];
    let sender_ip = [arp[14], arp[15], arp[16], arp[17]];
    let target_mac = [arp[18], arp[19], arp[20], arp[21], arp[22], arp[23]];
    let target_ip = [arp[24], arp[25], arp[26], arp[27]];
    
    Some(ArpInfo {
        operation,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}

/// Build ARP reply packet (Ethernet frame)
pub fn build_arp_reply(
    our_mac: [u8; 6],
    our_ip: [u8; 4],
    target_mac: [u8; 6],
    target_ip: [u8; 4],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);
    
    // Ethernet header
    frame.extend_from_slice(&target_mac);  // Destination MAC (who asked)
    frame.extend_from_slice(&our_mac);     // Source MAC (us)
    frame.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP
    
    // ARP packet
    frame.extend_from_slice(&[0x00, 0x01]); // Hardware type: Ethernet
    frame.extend_from_slice(&[0x08, 0x00]); // Protocol type: IPv4
    frame.push(6); // Hardware address length
    frame.push(4); // Protocol address length
    frame.extend_from_slice(&[0x00, 0x02]); // Operation: Reply (2)
    
    // Sender (us)
    frame.extend_from_slice(&our_mac);
    frame.extend_from_slice(&our_ip);
    
    // Target (who asked)
    frame.extend_from_slice(&target_mac);
    frame.extend_from_slice(&target_ip);
    
    frame
}

/// Build ARP gratuitous announcement (broadcast our IP/MAC binding)
pub fn build_arp_gratuitous(our_mac: [u8; 6], our_ip: [u8; 4]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);
    
    // Ethernet header (broadcast)
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Broadcast
    frame.extend_from_slice(&our_mac);     // Source MAC
    frame.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP
    
    // ARP packet
    frame.extend_from_slice(&[0x00, 0x01]); // Hardware type: Ethernet
    frame.extend_from_slice(&[0x08, 0x00]); // Protocol type: IPv4
    frame.push(6); // Hardware address length
    frame.push(4); // Protocol address length
    frame.extend_from_slice(&[0x00, 0x02]); // Operation: Reply (gratuitous)
    
    // Sender (us) = Target (us) for gratuitous ARP
    frame.extend_from_slice(&our_mac);
    frame.extend_from_slice(&our_ip);
    frame.extend_from_slice(&our_mac);  // Target MAC = our MAC
    frame.extend_from_slice(&our_ip);   // Target IP = our IP
    
    frame
}

/// Build ARP request to discover MAC address for an IP
pub fn build_arp_request(
    our_mac: [u8; 6],
    our_ip: [u8; 4],
    target_ip: [u8; 4],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);
    
    // Ethernet header (broadcast to reach target)
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Broadcast
    frame.extend_from_slice(&our_mac);     // Source MAC
    frame.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP
    
    // ARP packet
    frame.extend_from_slice(&[0x00, 0x01]); // Hardware type: Ethernet
    frame.extend_from_slice(&[0x08, 0x00]); // Protocol type: IPv4
    frame.push(6); // Hardware address length
    frame.push(4); // Protocol address length
    frame.extend_from_slice(&[0x00, 0x01]); // Operation: Request (1)
    
    // Sender (us)
    frame.extend_from_slice(&our_mac);
    frame.extend_from_slice(&our_ip);
    
    // Target (unknown MAC, we're asking for it)
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&target_ip);
    
    frame
}

#[derive(Debug, Clone)]
pub struct ArpInfo {
    pub operation: u16,     // 1=request, 2=reply
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}
