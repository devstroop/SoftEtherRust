#ifndef ICMP_HANDLER_H
#define ICMP_HANDLER_H

#include <stdint.h>
#include <stdbool.h>

// ICMP Type codes
#define ICMP_TYPE_ECHO_REPLY            0
#define ICMP_TYPE_DEST_UNREACHABLE      3
#define ICMP_TYPE_SOURCE_QUENCH         4
#define ICMP_TYPE_REDIRECT              5
#define ICMP_TYPE_ECHO_REQUEST          8
#define ICMP_TYPE_TIME_EXCEEDED         11
#define ICMP_TYPE_PARAMETER_PROBLEM     12

// ICMP Destination Unreachable codes
#define ICMP_CODE_NET_UNREACHABLE       0
#define ICMP_CODE_HOST_UNREACHABLE      1
#define ICMP_CODE_PROTOCOL_UNREACHABLE  2
#define ICMP_CODE_PORT_UNREACHABLE      3
#define ICMP_CODE_FRAGMENTATION_NEEDED  4  // Path MTU Discovery
#define ICMP_CODE_SOURCE_ROUTE_FAILED   5

// ICMP Time Exceeded codes
#define ICMP_CODE_TTL_EXCEEDED          0
#define ICMP_CODE_FRAGMENT_TIMEOUT      1

// ICMPv6 Type codes
#define ICMPV6_TYPE_DEST_UNREACHABLE    1
#define ICMPV6_TYPE_PACKET_TOO_BIG      2
#define ICMPV6_TYPE_TIME_EXCEEDED       3
#define ICMPV6_TYPE_PARAMETER_PROBLEM   4

// ICMPv6 Destination Unreachable codes
#define ICMPV6_CODE_NO_ROUTE            0
#define ICMPV6_CODE_ADMIN_PROHIBITED    1
#define ICMPV6_CODE_BEYOND_SCOPE        2
#define ICMPV6_CODE_ADDR_UNREACHABLE    3
#define ICMPV6_CODE_PORT_UNREACHABLE    4

/**
 * Parsed ICMP error information
 */
typedef struct {
    bool is_error;
    uint8_t type;
    uint8_t code;
    uint16_t mtu;  // For fragmentation needed / packet too big
    
    // Embedded packet info (from error message payload)
    uint8_t embedded_protocol;  // IPv4: protocol, IPv6: next header
    uint32_t embedded_src_ip;   // For IPv4 (host order)
    uint32_t embedded_dst_ip;   // For IPv4 (host order)
    uint8_t embedded_src_ipv6[16];  // For IPv6
    uint8_t embedded_dst_ipv6[16];  // For IPv6
    uint16_t embedded_src_port;
    uint16_t embedded_dst_port;
} ICMPErrorInfo;

/**
 * Check if ICMP packet is an error message
 * 
 * @param icmp_packet ICMP packet (starting at ICMP header)
 * @param len Length of ICMP packet
 * @return true if error message, false otherwise
 */
bool icmp_is_error(const uint8_t* icmp_packet, uint32_t len);

/**
 * Check if ICMPv6 packet is an error message
 * 
 * @param icmpv6_packet ICMPv6 packet (starting at ICMPv6 header)
 * @param len Length of ICMPv6 packet
 * @return true if error message, false otherwise
 */
bool icmpv6_is_error(const uint8_t* icmpv6_packet, uint32_t len);

/**
 * Parse ICMP error message
 * 
 * @param icmp_packet ICMP packet (starting at ICMP header)
 * @param len Length of ICMP packet
 * @param info Output: parsed error information
 * @return 0 on success, -1 on error
 */
int icmp_parse_error(const uint8_t* icmp_packet, uint32_t len,
                     ICMPErrorInfo* info);

/**
 * Parse ICMPv6 error message
 * 
 * @param icmpv6_packet ICMPv6 packet (starting at ICMPv6 header)
 * @param len Length of ICMPv6 packet
 * @param info Output: parsed error information
 * @return 0 on success, -1 on error
 */
int icmpv6_parse_error(const uint8_t* icmpv6_packet, uint32_t len,
                       ICMPErrorInfo* info);

#endif // ICMP_HANDLER_H
