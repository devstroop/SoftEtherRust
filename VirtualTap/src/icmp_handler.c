#include "../include/icmp_handler.h"
#include <string.h>

bool icmp_is_error(const uint8_t* icmp_packet, uint32_t len) {
    if (!icmp_packet || len < 8) {
        return false;
    }
    
    uint8_t type = icmp_packet[0];
    
    // Error message types: 3, 4, 5, 11, 12
    return (type == ICMP_TYPE_DEST_UNREACHABLE ||
            type == ICMP_TYPE_SOURCE_QUENCH ||
            type == ICMP_TYPE_REDIRECT ||
            type == ICMP_TYPE_TIME_EXCEEDED ||
            type == ICMP_TYPE_PARAMETER_PROBLEM);
}

bool icmpv6_is_error(const uint8_t* icmpv6_packet, uint32_t len) {
    if (!icmpv6_packet || len < 8) {
        return false;
    }
    
    uint8_t type = icmpv6_packet[0];
    
    // Error message types: 1, 2, 3, 4 (all < 128)
    return (type == ICMPV6_TYPE_DEST_UNREACHABLE ||
            type == ICMPV6_TYPE_PACKET_TOO_BIG ||
            type == ICMPV6_TYPE_TIME_EXCEEDED ||
            type == ICMPV6_TYPE_PARAMETER_PROBLEM);
}

int icmp_parse_error(const uint8_t* icmp_packet, uint32_t len,
                     ICMPErrorInfo* info) {
    if (!icmp_packet || !info || len < 8) {
        return -1;
    }
    
    memset(info, 0, sizeof(ICMPErrorInfo));
    
    info->type = icmp_packet[0];
    info->code = icmp_packet[1];
    info->is_error = icmp_is_error(icmp_packet, len);
    
    if (!info->is_error) {
        return 0;  // Not an error, but still valid
    }
    
    // Extract MTU for fragmentation needed (type 3, code 4)
    if (info->type == ICMP_TYPE_DEST_UNREACHABLE &&
        info->code == ICMP_CODE_FRAGMENTATION_NEEDED) {
        // MTU is in bytes 6-7 of ICMP header
        info->mtu = (icmp_packet[6] << 8) | icmp_packet[7];
    }
    
    // Parse embedded IP packet (starts at offset 8)
    if (len < 8 + 20) {
        return -1;  // Not enough data for embedded IPv4 header
    }
    
    const uint8_t* embedded_ip = icmp_packet + 8;
    
    // Verify IPv4 header
    if ((embedded_ip[0] >> 4) != 4) {
        return -1;  // Not IPv4
    }
    
    info->embedded_protocol = embedded_ip[9];
    
    // Extract source and dest IPs (in network order, convert to host order)
    info->embedded_src_ip = (embedded_ip[12] << 24) | (embedded_ip[13] << 16) |
                            (embedded_ip[14] << 8) | embedded_ip[15];
    info->embedded_dst_ip = (embedded_ip[16] << 24) | (embedded_ip[17] << 16) |
                            (embedded_ip[18] << 8) | embedded_ip[19];
    
    // Extract ports if TCP/UDP
    if ((info->embedded_protocol == 6 || info->embedded_protocol == 17) &&
        len >= 8 + 20 + 4) {
        const uint8_t* transport = embedded_ip + 20;
        info->embedded_src_port = (transport[0] << 8) | transport[1];
        info->embedded_dst_port = (transport[2] << 8) | transport[3];
    }
    
    return 0;
}

int icmpv6_parse_error(const uint8_t* icmpv6_packet, uint32_t len,
                       ICMPErrorInfo* info) {
    if (!icmpv6_packet || !info || len < 8) {
        return -1;
    }
    
    memset(info, 0, sizeof(ICMPErrorInfo));
    
    info->type = icmpv6_packet[0];
    info->code = icmpv6_packet[1];
    info->is_error = icmpv6_is_error(icmpv6_packet, len);
    
    if (!info->is_error) {
        return 0;  // Not an error, but still valid
    }
    
    // Extract MTU for packet too big (type 2)
    if (info->type == ICMPV6_TYPE_PACKET_TOO_BIG) {
        // MTU is in bytes 4-7 of ICMPv6 header
        info->mtu = (icmpv6_packet[4] << 24) | (icmpv6_packet[5] << 16) |
                    (icmpv6_packet[6] << 8) | icmpv6_packet[7];
    }
    
    // Parse embedded IPv6 packet (starts at offset 8)
    if (len < 8 + 40) {
        return -1;  // Not enough data for embedded IPv6 header
    }
    
    const uint8_t* embedded_ip = icmpv6_packet + 8;
    
    // Verify IPv6 header
    if ((embedded_ip[0] >> 4) != 6) {
        return -1;  // Not IPv6
    }
    
    info->embedded_protocol = embedded_ip[6];  // Next header
    
    // Extract source and dest IPv6 addresses
    memcpy(info->embedded_src_ipv6, embedded_ip + 8, 16);
    memcpy(info->embedded_dst_ipv6, embedded_ip + 24, 16);
    
    // Extract ports if TCP/UDP
    if ((info->embedded_protocol == 6 || info->embedded_protocol == 17) &&
        len >= 8 + 40 + 4) {
        const uint8_t* transport = embedded_ip + 40;
        info->embedded_src_port = (transport[0] << 8) | transport[1];
        info->embedded_dst_port = (transport[2] << 8) | transport[3];
    }
    
    return 0;
}
