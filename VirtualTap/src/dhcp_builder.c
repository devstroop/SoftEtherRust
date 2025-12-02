#include "../include/virtual_tap_internal.h"
#include <string.h>

// ============================================================================
// DHCP Packet Building
// ============================================================================

// Build DHCP DISCOVER packet (client broadcasts to find DHCP servers)
int32_t dhcp_build_discover(
    const uint8_t* client_mac,
    uint32_t transaction_id,
    uint8_t* eth_frame_out,
    uint32_t out_capacity
) {
    if (!client_mac || !eth_frame_out || out_capacity < 342) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    uint32_t pos = 0;
    
    // ====================================================================
    // Ethernet Header (14 bytes)
    // ====================================================================
    // Destination: Broadcast
    eth_frame_out[pos++] = 0xFF;
    eth_frame_out[pos++] = 0xFF;
    eth_frame_out[pos++] = 0xFF;
    eth_frame_out[pos++] = 0xFF;
    eth_frame_out[pos++] = 0xFF;
    eth_frame_out[pos++] = 0xFF;
    // Source: Client MAC
    memcpy(eth_frame_out + pos, client_mac, 6);
    pos += 6;
    // EtherType: IPv4 (0x0800)
    eth_frame_out[pos++] = 0x08;
    eth_frame_out[pos++] = 0x00;
    
    // ====================================================================
    // IPv4 Header (20 bytes)
    // ====================================================================
    uint32_t ip_header_start = pos;
    eth_frame_out[pos++] = 0x45;  // Version 4, IHL 5
    eth_frame_out[pos++] = 0x00;  // DSCP/ECN
    // Total Length (will update later)
    uint32_t ip_total_len_pos = pos;
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x00;  // ID
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x00;  // Flags/Fragment
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 64;    // TTL
    eth_frame_out[pos++] = 17;    // Protocol: UDP
    // Checksum (will calculate later)
    uint32_t ip_checksum_pos = pos;
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x00;
    // Source IP: 0.0.0.0
    eth_frame_out[pos++] = 0;
    eth_frame_out[pos++] = 0;
    eth_frame_out[pos++] = 0;
    eth_frame_out[pos++] = 0;
    // Dest IP: 255.255.255.255
    eth_frame_out[pos++] = 255;
    eth_frame_out[pos++] = 255;
    eth_frame_out[pos++] = 255;
    eth_frame_out[pos++] = 255;
    
    // ====================================================================
    // UDP Header (8 bytes)
    // ====================================================================
    uint32_t udp_header_start = pos;
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 68;    // Source port: 68 (DHCP client)
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 67;    // Dest port: 67 (DHCP server)
    // UDP Length (will update later)
    uint32_t udp_len_pos = pos;
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x00;  // Checksum (optional for IPv4)
    eth_frame_out[pos++] = 0x00;
    
    // ====================================================================
    // DHCP Header (240 bytes minimum)
    // ====================================================================
    eth_frame_out[pos++] = 0x01;  // op: BOOTREQUEST
    eth_frame_out[pos++] = 0x01;  // htype: Ethernet
    eth_frame_out[pos++] = 0x06;  // hlen: 6
    eth_frame_out[pos++] = 0x00;  // hops: 0
    
    // Transaction ID (XID) - 4 bytes
    write_u32_be(eth_frame_out + pos, transaction_id);
    pos += 4;
    
    // secs, flags
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x80;  // Broadcast flag
    eth_frame_out[pos++] = 0x00;
    
    // ciaddr, yiaddr, siaddr, giaddr (all zeros)
    for (int i = 0; i < 16; i++) {
        eth_frame_out[pos++] = 0x00;
    }
    
    // chaddr (client hardware address)
    memcpy(eth_frame_out + pos, client_mac, 6);
    pos += 6;
    // Padding
    for (int i = 0; i < 10; i++) {
        eth_frame_out[pos++] = 0x00;
    }
    
    // sname, file (zeros)
    for (int i = 0; i < 192; i++) {
        eth_frame_out[pos++] = 0x00;
    }
    
    // ====================================================================
    // DHCP Options
    // ====================================================================
    // Magic cookie (0x63825363)
    eth_frame_out[pos++] = 0x63;
    eth_frame_out[pos++] = 0x82;
    eth_frame_out[pos++] = 0x53;
    eth_frame_out[pos++] = 0x63;
    
    // Option 53: DHCP Message Type = DISCOVER (1)
    eth_frame_out[pos++] = 53;
    eth_frame_out[pos++] = 1;
    eth_frame_out[pos++] = 1;
    
    // Option 55: Parameter Request List
    eth_frame_out[pos++] = 55;
    eth_frame_out[pos++] = 4;
    eth_frame_out[pos++] = 1;   // Subnet Mask
    eth_frame_out[pos++] = 3;   // Router
    eth_frame_out[pos++] = 6;   // DNS
    eth_frame_out[pos++] = 15;  // Domain Name
    
    // Option 255: End
    eth_frame_out[pos++] = 255;
    
    // ====================================================================
    // Update Lengths and Checksums
    // ====================================================================
    uint32_t total_size = pos;
    uint16_t ip_total_len = total_size - 14;  // Exclude Ethernet header
    uint16_t udp_len = total_size - udp_header_start;
    
    // Update IP total length
    write_u16_be(eth_frame_out + ip_total_len_pos, ip_total_len);
    
    // Update UDP length
    write_u16_be(eth_frame_out + udp_len_pos, udp_len);
    
    // Calculate IP checksum
    uint32_t checksum = 0;
    for (uint32_t i = 0; i < 20; i += 2) {
        checksum += read_u16_be(eth_frame_out + ip_header_start + i);
    }
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum = ~checksum & 0xFFFF;
    write_u16_be(eth_frame_out + ip_checksum_pos, checksum);
    
    return (int32_t)total_size;
}

// Build DHCP REQUEST packet (client requests specific IP after receiving OFFER)
int32_t dhcp_build_request(
    const uint8_t* client_mac,
    uint32_t transaction_id,
    uint32_t requested_ip,
    uint32_t server_ip,
    uint8_t* eth_frame_out,
    uint32_t out_capacity
) {
    if (!client_mac || !eth_frame_out || out_capacity < 362) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    uint32_t pos = 0;
    
    // ====================================================================
    // Ethernet Header (14 bytes)
    // ====================================================================
    // Destination: Broadcast
    eth_frame_out[pos++] = 0xFF;
    eth_frame_out[pos++] = 0xFF;
    eth_frame_out[pos++] = 0xFF;
    eth_frame_out[pos++] = 0xFF;
    eth_frame_out[pos++] = 0xFF;
    eth_frame_out[pos++] = 0xFF;
    // Source: Client MAC
    memcpy(eth_frame_out + pos, client_mac, 6);
    pos += 6;
    // EtherType: IPv4 (0x0800)
    eth_frame_out[pos++] = 0x08;
    eth_frame_out[pos++] = 0x00;
    
    // ====================================================================
    // IPv4 Header (20 bytes)
    // ====================================================================
    uint32_t ip_header_start = pos;
    eth_frame_out[pos++] = 0x45;  // Version 4, IHL 5
    eth_frame_out[pos++] = 0x00;  // DSCP/ECN
    // Total Length (will update later)
    uint32_t ip_total_len_pos = pos;
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x00;  // ID
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x00;  // Flags/Fragment
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 64;    // TTL
    eth_frame_out[pos++] = 17;    // Protocol: UDP
    // Checksum (will calculate later)
    uint32_t ip_checksum_pos = pos;
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x00;
    // Source IP: 0.0.0.0
    eth_frame_out[pos++] = 0;
    eth_frame_out[pos++] = 0;
    eth_frame_out[pos++] = 0;
    eth_frame_out[pos++] = 0;
    // Dest IP: 255.255.255.255
    eth_frame_out[pos++] = 255;
    eth_frame_out[pos++] = 255;
    eth_frame_out[pos++] = 255;
    eth_frame_out[pos++] = 255;
    
    // ====================================================================
    // UDP Header (8 bytes)
    // ====================================================================
    uint32_t udp_header_start = pos;
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 68;    // Source port: 68 (DHCP client)
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 67;    // Dest port: 67 (DHCP server)
    // UDP Length (will update later)
    uint32_t udp_len_pos = pos;
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x00;  // Checksum (optional for IPv4)
    eth_frame_out[pos++] = 0x00;
    
    // ====================================================================
    // DHCP Header (240 bytes minimum)
    // ====================================================================
    eth_frame_out[pos++] = 0x01;  // op: BOOTREQUEST
    eth_frame_out[pos++] = 0x01;  // htype: Ethernet
    eth_frame_out[pos++] = 0x06;  // hlen: 6
    eth_frame_out[pos++] = 0x00;  // hops: 0
    
    // Transaction ID (XID) - 4 bytes
    write_u32_be(eth_frame_out + pos, transaction_id);
    pos += 4;
    
    // secs, flags
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x00;
    eth_frame_out[pos++] = 0x80;  // Broadcast flag
    eth_frame_out[pos++] = 0x00;
    
    // ciaddr, yiaddr, siaddr, giaddr (all zeros)
    for (int i = 0; i < 16; i++) {
        eth_frame_out[pos++] = 0x00;
    }
    
    // chaddr (client hardware address)
    memcpy(eth_frame_out + pos, client_mac, 6);
    pos += 6;
    // Padding
    for (int i = 0; i < 10; i++) {
        eth_frame_out[pos++] = 0x00;
    }
    
    // sname, file (zeros)
    for (int i = 0; i < 192; i++) {
        eth_frame_out[pos++] = 0x00;
    }
    
    // ====================================================================
    // DHCP Options
    // ====================================================================
    // Magic cookie (0x63825363)
    eth_frame_out[pos++] = 0x63;
    eth_frame_out[pos++] = 0x82;
    eth_frame_out[pos++] = 0x53;
    eth_frame_out[pos++] = 0x63;
    
    // Option 53: DHCP Message Type = REQUEST (3)
    eth_frame_out[pos++] = 53;
    eth_frame_out[pos++] = 1;
    eth_frame_out[pos++] = 3;
    
    // Option 50: Requested IP Address
    eth_frame_out[pos++] = 50;
    eth_frame_out[pos++] = 4;
    write_u32_be(eth_frame_out + pos, requested_ip);
    pos += 4;
    
    // Option 54: DHCP Server Identifier
    eth_frame_out[pos++] = 54;
    eth_frame_out[pos++] = 4;
    write_u32_be(eth_frame_out + pos, server_ip);
    pos += 4;
    
    // Option 55: Parameter Request List
    eth_frame_out[pos++] = 55;
    eth_frame_out[pos++] = 4;
    eth_frame_out[pos++] = 1;   // Subnet Mask
    eth_frame_out[pos++] = 3;   // Router
    eth_frame_out[pos++] = 6;   // DNS
    eth_frame_out[pos++] = 15;  // Domain Name
    
    // Option 255: End
    eth_frame_out[pos++] = 255;
    
    // ====================================================================
    // Update Lengths and Checksums
    // ====================================================================
    uint32_t total_size = pos;
    uint16_t ip_total_len = total_size - 14;  // Exclude Ethernet header
    uint16_t udp_len = total_size - udp_header_start;
    
    // Update IP total length
    write_u16_be(eth_frame_out + ip_total_len_pos, ip_total_len);
    
    // Update UDP length
    write_u16_be(eth_frame_out + udp_len_pos, udp_len);
    
    // Calculate IP checksum
    uint32_t checksum = 0;
    for (uint32_t i = 0; i < 20; i += 2) {
        checksum += read_u16_be(eth_frame_out + ip_header_start + i);
    }
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum = ~checksum & 0xFFFF;
    write_u16_be(eth_frame_out + ip_checksum_pos, checksum);
    
    return (int32_t)total_size;
}
