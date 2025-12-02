#ifndef VIRTUAL_TAP_INTERNAL_H
#define VIRTUAL_TAP_INTERNAL_H

#include "virtual_tap.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>

// Error codes
#define VTAP_ERROR_INVALID_PARAMS -1
#define VTAP_ERROR_PARSE_FAILED -2
#define VTAP_ERROR_BUFFER_TOO_SMALL -3
#define VTAP_ERROR_ALLOC_FAILED -4

// Constants
#define ARP_TABLE_SIZE 64
#define MAX_PACKET_SIZE 2048
#define ETHERNET_HEADER_SIZE 14
#define ARP_PACKET_SIZE 42
#define ARP_REPLY_QUEUE_MAX 16
#define ARP_TIMEOUT_MS 300000  // 5 minutes

// EtherTypes
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD

// ARP
#define ARP_HARDWARE_ETHERNET 0x0001
#define ARP_PROTOCOL_IPV4 0x0800
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

// ICMPv6 / NDP (Neighbor Discovery Protocol)
#define ICMPV6_PROTOCOL 58
#define ICMPV6_NEIGHBOR_SOLICITATION 135
#define ICMPV6_NEIGHBOR_ADVERTISEMENT 136
#define ICMPV6_ROUTER_SOLICITATION 133
#define ICMPV6_ROUTER_ADVERTISEMENT 134

// Utility macros
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// Byte order conversion
static inline uint16_t read_u16_be(const uint8_t* p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

static inline uint32_t read_u32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static inline void write_u16_be(uint8_t* p, uint16_t val) {
    p[0] = (val >> 8) & 0xFF;
    p[1] = val & 0xFF;
}

static inline void write_u32_be(uint8_t* p, uint32_t val) {
    p[0] = (val >> 24) & 0xFF;
    p[1] = (val >> 16) & 0xFF;
    p[2] = (val >> 8) & 0xFF;
    p[3] = val & 0xFF;
}

// Time utilities
static inline int64_t get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// ARP structures
typedef struct {
    uint32_t ip;           // 0 = empty slot
    uint8_t mac[6];
    int64_t timestamp_ms;
    bool is_static;
} ArpEntry;

typedef struct {
    ArpEntry entries[ARP_TABLE_SIZE];
    int64_t timeout_ms;
} ArpTable;

typedef struct {
    uint16_t operation;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
} ArpInfo;

// ARP reply queue
typedef struct ArpReplyNode {
    uint8_t* packet;
    uint32_t length;
    struct ArpReplyNode* next;
} ArpReplyNode;

// Translator structure
typedef struct {
    uint8_t our_mac[6];
    uint32_t our_ip;                // IPv4 address
    uint32_t gateway_ip;            // IPv4 gateway
    uint8_t gateway_mac[6];
    
    // IPv6 support
    uint8_t our_ipv6[16];           // IPv6 address
    uint8_t gateway_ipv6[16];       // IPv6 gateway
    bool has_ipv6;
    bool has_ipv6_gateway;
    
    int64_t last_gateway_learn_ms;
    bool handle_arp;
    bool learn_gateway_mac;
    bool verbose;
    uint64_t packets_l2_to_l3;
    uint64_t packets_l3_to_l2;
    uint64_t arp_replies_learned;
} Translator;

// DHCP info
typedef struct {
    uint8_t offered_ip[4];
    uint8_t gateway[4];
    uint8_t subnet_mask[4];
    uint8_t dns1[4];
    uint8_t dns2[4];
    uint8_t message_type;
    bool valid;
} DhcpInfo;

// Main VirtualTap structure
struct VirtualTap {
    VirtualTapConfig config;
    ArpTable* arp_table;
    Translator* translator;
    void* dns_cache;  // DnsCache* (forward declared to avoid circular dependency)
    void* fragment_handler;  // FragmentHandler* (forward declared)
    ArpReplyNode* arp_reply_head;
    ArpReplyNode* arp_reply_tail;
    VirtualTapStats stats;
};

// Forward declarations - ARP handler (arp_handler.c)
ArpTable* arp_table_create(int64_t timeout_ms);
void arp_table_destroy(ArpTable* table);
bool arp_table_lookup(ArpTable* table, uint32_t ip, uint8_t mac_out[6]);
void arp_table_insert(ArpTable* table, uint32_t ip, const uint8_t mac[6], bool is_static);
void arp_table_cleanup(ArpTable* table);
uint32_t arp_table_count(ArpTable* table);
int arp_parse_packet(const uint8_t* arp_packet, uint32_t len, ArpInfo* info);
int arp_build_reply(const uint8_t our_mac[6], uint32_t our_ip,
                    const uint8_t target_mac[6], uint32_t target_ip,
                    uint8_t* packet_out, uint32_t out_capacity);

int arp_build_request(const uint8_t our_mac[6], uint32_t our_ip,
                      uint32_t target_ip,
                      uint8_t* packet_out, uint32_t out_capacity);

// Forward declarations - Translator (translator.c)
Translator* translator_create(const uint8_t our_mac[6], bool handle_arp,
                              bool learn_gateway_mac, bool verbose);
void translator_destroy(Translator* t);
int translator_ip_to_ethernet(Translator* t, const uint8_t* ip_packet, uint32_t ip_len,
                              const uint8_t* dest_mac, uint8_t* eth_out, uint32_t out_capacity);
int translator_ethernet_to_ip(Translator* t, const uint8_t* eth_frame, uint32_t eth_len,
                              uint8_t* ip_out, uint32_t out_capacity);
uint32_t translator_get_our_ip(Translator* t);
void translator_set_our_ip(Translator* t, uint32_t ip);
uint32_t translator_get_gateway_ip(Translator* t);
void translator_set_gateway_ip(Translator* t, uint32_t ip);
bool translator_get_gateway_mac(Translator* t, uint8_t mac_out[6]);
void translator_set_gateway_mac(Translator* t, const uint8_t mac[6]);

// Forward declarations - DHCP parser (dhcp_parser.c)
bool dhcp_is_dhcp_packet(const uint8_t* ip_packet, uint32_t len);
int dhcp_parse_packet(const uint8_t* ip_packet, uint32_t len, DhcpInfo* info);

// Forward declarations - IP utilities (ip_utils.c)
uint32_t ipv4_to_u32(const uint8_t ip[4]);
void u32_to_ipv4(uint32_t ip, uint8_t out[4]);
uint32_t extract_dest_ip_from_packet(const uint8_t* ip_packet, uint32_t len);
void extract_ipv6_address(const uint8_t* ipv6_packet, uint32_t offset, uint8_t out[16]);
bool is_ipv6_link_local(const uint8_t ipv6[16]);
bool is_icmpv6_ndp(const uint8_t* ipv6_packet, uint32_t len);

#endif // VIRTUAL_TAP_INTERNAL_H
