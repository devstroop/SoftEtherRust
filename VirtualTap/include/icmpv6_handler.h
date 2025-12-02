/**
 * VirtualTap - ICMPv6 Handler
 * 
 * Handles ICMPv6 Neighbor Discovery Protocol (NDP):
 * - Router Advertisement (RA) parsing for IPv6 auto-configuration
 * - Neighbor Advertisement (NA) responses for address resolution
 * 
 * Copyright (c) 2025 SoftEtherUnofficial at GitHub
 */

#ifndef ICMPV6_HANDLER_H
#define ICMPV6_HANDLER_H

#include <stdint.h>
#include <stdbool.h>

/**
 * IPv6 Router Advertisement (RA) Information
 * Extracted from ICMPv6 type 134 packets
 */
typedef struct {
    uint8_t prefix[16];              // IPv6 prefix (e.g., 2001:db8::)
    uint8_t prefix_length;           // Prefix length in bits (e.g., 64)
    uint8_t gateway[16];             // Default gateway IPv6 address
    uint8_t dns_servers[3][16];      // Up to 3 DNS servers (RDNSS option)
    uint32_t mtu;                    // Path MTU (option 5)
    uint32_t valid_lifetime;         // Prefix valid lifetime (seconds)
    uint32_t preferred_lifetime;     // Prefix preferred lifetime (seconds)
    uint8_t hop_limit;               // Suggested hop limit
    bool has_prefix;                 // True if prefix extracted
    bool has_gateway;                // True if gateway extracted
    bool managed_flag;               // M flag (use DHCPv6 for addresses)
    bool other_config_flag;          // O flag (use DHCPv6 for other config)
    uint8_t dns_count;               // Number of DNS servers (0-3)
} IPv6RAInfo;

/**
 * Parse IPv6 Router Advertisement (ICMPv6 type 134)
 * 
 * @param icmpv6_packet Pointer to ICMPv6 packet (starting at IPv6 header)
 * @param len Length of ICMPv6 packet
 * @param out Pointer to IPv6RAInfo structure to fill
 * @return true if RA parsed successfully, false otherwise
 */
bool parse_router_advertisement(const uint8_t* icmpv6_packet, uint32_t len, IPv6RAInfo* out);

/**
 * Build ICMPv6 Neighbor Advertisement (type 136) response
 * 
 * Called when we receive a Neighbor Solicitation (type 135) asking for our IPv6 address.
 * Builds a complete IPv6 packet with ICMPv6 NA payload.
 * 
 * @param target_ipv6 Our IPv6 address (the one being solicited)
 * @param target_mac Our MAC address
 * @param solicitor_ipv6 IPv6 address of the device asking (source of NS)
 * @param out_packet Buffer to write IPv6 packet (needs at least 86 bytes)
 * @param out_max_len Maximum length of out_packet buffer
 * @return Length of IPv6 packet written, or -1 on error
 */
int32_t build_neighbor_advertisement(
    const uint8_t target_ipv6[16],
    const uint8_t target_mac[6],
    const uint8_t solicitor_ipv6[16],
    uint8_t* out_packet,
    uint32_t out_max_len
);

/**
 * Check if an ICMPv6 packet is a Neighbor Solicitation (type 135)
 * 
 * @param icmpv6_packet Pointer to ICMPv6 packet (starting at IPv6 header)
 * @param len Length of packet
 * @param out_target If not NULL, writes the solicited IPv6 address here
 * @return true if this is an NS packet
 */
bool is_neighbor_solicitation(const uint8_t* icmpv6_packet, uint32_t len, uint8_t out_target[16]);

/**
 * Calculate ICMPv6 checksum
 * 
 * ICMPv6 checksum includes IPv6 pseudo-header:
 * - Source IPv6 (16 bytes)
 * - Destination IPv6 (16 bytes)
 * - ICMPv6 length (4 bytes)
 * - Next header = 58 (4 bytes)
 * - ICMPv6 message
 * 
 * @param src_ipv6 Source IPv6 address
 * @param dst_ipv6 Destination IPv6 address
 * @param icmpv6_msg ICMPv6 message (without IPv6 header)
 * @param icmpv6_len Length of ICMPv6 message
 * @return 16-bit checksum
 */
uint16_t calculate_icmpv6_checksum(
    const uint8_t src_ipv6[16],
    const uint8_t dst_ipv6[16],
    const uint8_t* icmpv6_msg,
    uint32_t icmpv6_len
);

#endif // ICMPV6_HANDLER_H
