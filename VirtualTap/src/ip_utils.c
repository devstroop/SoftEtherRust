#include "../include/virtual_tap_internal.h"

// ============================================================================
// IP Utility Functions
// ============================================================================

uint32_t ipv4_to_u32(const uint8_t ip[4]) {
    if (!ip) return 0;
    return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) |
           ((uint32_t)ip[2] << 8) | ip[3];
}

void u32_to_ipv4(uint32_t ip, uint8_t out[4]) {
    if (!out) return;
    out[0] = (ip >> 24) & 0xFF;
    out[1] = (ip >> 16) & 0xFF;
    out[2] = (ip >> 8) & 0xFF;
    out[3] = ip & 0xFF;
}

uint32_t extract_dest_ip_from_packet(const uint8_t* ip_packet, uint32_t len) {
    if (!ip_packet || len < 20) return 0;
    
    // Check IPv4
    uint8_t version = (ip_packet[0] >> 4) & 0x0F;
    if (version != 4) return 0;
    
    // Destination IP at bytes 16-19
    return read_u32_be(ip_packet + 16);
}

// ============================================================================
// IPv6 Utility Functions
// ============================================================================

void extract_ipv6_address(const uint8_t* ipv6_packet, uint32_t offset, uint8_t out[16]) {
    if (!ipv6_packet || !out) return;
    memcpy(out, ipv6_packet + offset, 16);
}

bool is_ipv6_link_local(const uint8_t ipv6[16]) {
    if (!ipv6) return false;
    // Link-local addresses: fe80::/10
    return (ipv6[0] == 0xfe) && ((ipv6[1] & 0xc0) == 0x80);
}

bool is_icmpv6_ndp(const uint8_t* ipv6_packet, uint32_t len) {
    if (!ipv6_packet || len < 40) return false;
    
    // Check IPv6 version
    uint8_t version = (ipv6_packet[0] >> 4) & 0x0F;
    if (version != 6) return false;
    
    // Check Next Header (protocol) at byte 6
    uint8_t next_header = ipv6_packet[6];
    
    // ICMPv6 protocol number is 58
    if (next_header != ICMPV6_PROTOCOL) return false;
    
    // Need at least ICMPv6 header (40 IPv6 + 8 ICMPv6)
    if (len < 48) return false;
    
    // Check ICMPv6 type (NDP types: 133-137)
    uint8_t icmpv6_type = ipv6_packet[40];
    return (icmpv6_type >= 133 && icmpv6_type <= 137);
}
