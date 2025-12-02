/**
 * VirtualTap - ICMPv6 Handler Implementation
 * 
 * Handles ICMPv6 Neighbor Discovery Protocol (NDP):
 * - Router Advertisement (RA) parsing for IPv6 auto-configuration
 * - Neighbor Advertisement (NA) responses for address resolution
 * 
 * Copyright (c) 2025 SoftEtherUnofficial at GitHub
 */

#include "icmpv6_handler.h"
#include <string.h>
#include <stdio.h>

// ICMPv6 Types
#define ICMPV6_ROUTER_ADVERTISEMENT 134
#define ICMPV6_NEIGHBOR_SOLICITATION 135
#define ICMPV6_NEIGHBOR_ADVERTISEMENT 136

// ICMPv6 NA Flags
#define NA_FLAG_ROUTER 0x80000000     // R flag
#define NA_FLAG_SOLICITED 0x40000000  // S flag
#define NA_FLAG_OVERRIDE 0x20000000   // O flag

// NDP Options
#define NDP_OPT_SOURCE_LINK_ADDR 1
#define NDP_OPT_TARGET_LINK_ADDR 2
#define NDP_OPT_PREFIX_INFO 3
#define NDP_OPT_MTU 5
#define NDP_OPT_RDNSS 25  // Recursive DNS Server

bool parse_router_advertisement(const uint8_t* ipv6_packet, uint32_t len, IPv6RAInfo* out) {
    if (!ipv6_packet || !out || len < 56) {
        return false;  // Minimum: 40 (IPv6) + 16 (RA header) = 56
    }
    
    // Verify IPv6 header
    uint8_t version = (ipv6_packet[0] >> 4) & 0x0F;
    uint8_t next_header = ipv6_packet[6];
    if (version != 6 || next_header != 58) {  // 58 = ICMPv6
        return false;
    }
    
    // Get ICMPv6 payload
    const uint8_t* icmpv6 = ipv6_packet + 40;
    uint32_t icmpv6_len = len - 40;
    
    // Verify RA type
    uint8_t type = icmpv6[0];
    if (type != ICMPV6_ROUTER_ADVERTISEMENT) {
        return false;
    }
    
    // Initialize output
    memset(out, 0, sizeof(IPv6RAInfo));
    
    // Extract RA header fields
    out->hop_limit = icmpv6[4];
    out->managed_flag = (icmpv6[5] & 0x80) != 0;
    out->other_config_flag = (icmpv6[5] & 0x40) != 0;
    
    // Router lifetime (bytes 6-7) - use as gateway indicator
    uint16_t router_lifetime = (icmpv6[6] << 8) | icmpv6[7];
    
    // Extract source IPv6 as gateway (from IPv6 header)
    if (router_lifetime > 0) {
        memcpy(out->gateway, ipv6_packet + 8, 16);
        out->has_gateway = true;
    }
    
    // Parse NDP options (start at byte 16)
    uint32_t offset = 16;
    while (offset + 8 <= icmpv6_len) {
        uint8_t opt_type = icmpv6[offset];
        uint8_t opt_len = icmpv6[offset + 1];  // In units of 8 bytes
        
        if (opt_len == 0 || offset + (opt_len * 8) > icmpv6_len) {
            break;  // Invalid option
        }
        
        switch (opt_type) {
            case NDP_OPT_PREFIX_INFO:
                if (opt_len == 4 && !out->has_prefix) {  // 32 bytes
                    out->prefix_length = icmpv6[offset + 2];
                    out->valid_lifetime = (icmpv6[offset + 4] << 24) |
                                         (icmpv6[offset + 5] << 16) |
                                         (icmpv6[offset + 6] << 8) |
                                         icmpv6[offset + 7];
                    out->preferred_lifetime = (icmpv6[offset + 8] << 24) |
                                             (icmpv6[offset + 9] << 16) |
                                             (icmpv6[offset + 10] << 8) |
                                             icmpv6[offset + 11];
                    memcpy(out->prefix, icmpv6 + offset + 16, 16);
                    out->has_prefix = true;
                }
                break;
                
            case NDP_OPT_MTU:
                if (opt_len == 1) {  // 8 bytes
                    out->mtu = (icmpv6[offset + 4] << 24) |
                              (icmpv6[offset + 5] << 16) |
                              (icmpv6[offset + 6] << 8) |
                              icmpv6[offset + 7];
                }
                break;
                
            case NDP_OPT_RDNSS:
                if (opt_len >= 3 && out->dns_count < 3) {  // At least 24 bytes
                    // Each DNS server is 16 bytes, starts at offset+8
                    uint32_t dns_offset = offset + 8;
                    while (dns_offset + 16 <= offset + (opt_len * 8) && out->dns_count < 3) {
                        memcpy(out->dns_servers[out->dns_count], icmpv6 + dns_offset, 16);
                        out->dns_count++;
                        dns_offset += 16;
                    }
                }
                break;
        }
        
        offset += opt_len * 8;
    }
    
    return out->has_prefix || out->has_gateway;
}

uint16_t calculate_icmpv6_checksum(
    const uint8_t src_ipv6[16],
    const uint8_t dst_ipv6[16],
    const uint8_t* icmpv6_msg,
    uint32_t icmpv6_len
) {
    uint32_t sum = 0;
    
    // Add pseudo-header: source IPv6
    for (int i = 0; i < 16; i += 2) {
        sum += (src_ipv6[i] << 8) | src_ipv6[i + 1];
    }
    
    // Add pseudo-header: destination IPv6
    for (int i = 0; i < 16; i += 2) {
        sum += (dst_ipv6[i] << 8) | dst_ipv6[i + 1];
    }
    
    // Add pseudo-header: ICMPv6 length (32-bit)
    sum += (icmpv6_len >> 16) & 0xFFFF;
    sum += icmpv6_len & 0xFFFF;
    
    // Add pseudo-header: next header (58 = ICMPv6)
    sum += 58;
    
    // Add ICMPv6 message
    for (uint32_t i = 0; i < icmpv6_len; i += 2) {
        if (i + 1 < icmpv6_len) {
            sum += (icmpv6_msg[i] << 8) | icmpv6_msg[i + 1];
        } else {
            sum += icmpv6_msg[i] << 8;  // Odd byte
        }
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

bool is_neighbor_solicitation(const uint8_t* ipv6_packet, uint32_t len, uint8_t out_target[16]) {
    if (!ipv6_packet || len < 64) {
        return false;  // Minimum: 40 (IPv6) + 24 (NS) = 64
    }
    
    // Verify IPv6 header
    uint8_t version = (ipv6_packet[0] >> 4) & 0x0F;
    uint8_t next_header = ipv6_packet[6];
    if (version != 6 || next_header != 58) {
        return false;
    }
    
    // Get ICMPv6 payload
    const uint8_t* icmpv6 = ipv6_packet + 40;
    uint8_t type = icmpv6[0];
    
    if (type != ICMPV6_NEIGHBOR_SOLICITATION) {
        return false;
    }
    
    // Extract target address (bytes 8-23 of ICMPv6)
    if (out_target) {
        memcpy(out_target, icmpv6 + 8, 16);
    }
    
    return true;
}

int32_t build_neighbor_advertisement(
    const uint8_t target_ipv6[16],
    const uint8_t target_mac[6],
    const uint8_t solicitor_ipv6[16],
    uint8_t* out_packet,
    uint32_t out_max_len
) {
    // NA packet size: 40 (IPv6) + 32 (ICMPv6 NA with target link-layer option)
    const uint32_t packet_len = 72;
    
    if (!target_ipv6 || !target_mac || !solicitor_ipv6 || !out_packet || out_max_len < packet_len) {
        return -1;
    }
    
    memset(out_packet, 0, packet_len);
    
    // Build IPv6 header
    out_packet[0] = 0x60;  // Version 6, traffic class 0
    // Payload length: 32 bytes
    out_packet[4] = 0;
    out_packet[5] = 32;
    out_packet[6] = 58;    // Next header: ICMPv6
    out_packet[7] = 255;   // Hop limit
    
    // Source: our IPv6 (target)
    memcpy(out_packet + 8, target_ipv6, 16);
    
    // Destination: solicitor's IPv6
    memcpy(out_packet + 24, solicitor_ipv6, 16);
    
    // Build ICMPv6 NA message
    uint8_t* icmpv6 = out_packet + 40;
    
    icmpv6[0] = ICMPV6_NEIGHBOR_ADVERTISEMENT;  // Type
    icmpv6[1] = 0;  // Code
    icmpv6[2] = 0;  // Checksum (calculated later)
    icmpv6[3] = 0;
    
    // Flags: S (solicited) and O (override)
    uint32_t flags = NA_FLAG_SOLICITED | NA_FLAG_OVERRIDE;
    icmpv6[4] = (flags >> 24) & 0xFF;
    icmpv6[5] = (flags >> 16) & 0xFF;
    icmpv6[6] = (flags >> 8) & 0xFF;
    icmpv6[7] = flags & 0xFF;
    
    // Target address (our IPv6)
    memcpy(icmpv6 + 8, target_ipv6, 16);
    
    // Option: Target link-layer address (type 2)
    icmpv6[24] = NDP_OPT_TARGET_LINK_ADDR;  // Type
    icmpv6[25] = 1;                         // Length (1 unit of 8 bytes)
    memcpy(icmpv6 + 26, target_mac, 6);     // MAC address
    
    // Calculate checksum
    uint16_t checksum = calculate_icmpv6_checksum(target_ipv6, solicitor_ipv6, icmpv6, 32);
    icmpv6[2] = (checksum >> 8) & 0xFF;
    icmpv6[3] = checksum & 0xFF;
    
    return packet_len;
}
