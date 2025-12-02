/**
 * VirtualTap - DNS Handler
 * 
 * DNS query/response interception and caching for VPN clients.
 * Apps won't work without DNS resolution.
 * 
 * Features:
 * - Intercept DNS queries (UDP port 53)
 * - Simple LRU cache (256 entries)
 * - Support A, AAAA, CNAME record types
 * - 5-minute cache TTL (respects actual TTL if lower)
 * - Thread-safe operations
 * 
 * Copyright (c) 2025 SoftEtherUnofficial at GitHub
 */

#ifndef DNS_HANDLER_H
#define DNS_HANDLER_H

#include <stdint.h>
#include <stdbool.h>

// DNS record types
#define DNS_TYPE_A     1   // IPv4 address
#define DNS_TYPE_AAAA  28  // IPv6 address
#define DNS_TYPE_CNAME 5   // Canonical name

// DNS classes
#define DNS_CLASS_IN   1   // Internet

// DNS response codes
#define DNS_RCODE_NOERROR  0
#define DNS_RCODE_NXDOMAIN 3

// Cache configuration
#define DNS_CACHE_SIZE 256
#define DNS_MAX_NAME_LEN 255
#define DNS_MAX_RESPONSE_SIZE 512
#define DNS_DEFAULT_TTL 300  // 5 minutes

/**
 * DNS cache entry
 */
typedef struct {
    char name[DNS_MAX_NAME_LEN + 1];  // Domain name (null-terminated)
    uint16_t type;                     // DNS_TYPE_A or DNS_TYPE_AAAA
    uint8_t response[DNS_MAX_RESPONSE_SIZE];  // Cached DNS response
    uint32_t response_len;             // Length of cached response
    int64_t expires_ms;                // Expiration timestamp
    bool valid;                        // Entry is valid
} DnsCacheEntry;

/**
 * DNS cache (LRU)
 */
typedef struct {
    DnsCacheEntry entries[DNS_CACHE_SIZE];
    uint32_t next_evict_index;  // Simple round-robin for LRU
} DnsCache;

/**
 * DNS query information (parsed from DNS packet)
 */
typedef struct {
    char name[DNS_MAX_NAME_LEN + 1];
    uint16_t type;
    uint16_t qclass;
    uint16_t transaction_id;
    bool valid;
} DnsQuery;

/**
 * Create DNS cache
 * 
 * @return Pointer to DNS cache, or NULL on allocation failure
 */
DnsCache* dns_cache_create(void);

/**
 * Destroy DNS cache
 * 
 * @param cache DNS cache to destroy
 */
void dns_cache_destroy(DnsCache* cache);

/**
 * Check if a UDP packet is a DNS query (dest port 53)
 * 
 * @param udp_packet Pointer to UDP packet (after IP header)
 * @param len Length of UDP packet
 * @return true if this is a DNS query
 */
bool dns_is_query(const uint8_t* udp_packet, uint32_t len);

/**
 * Parse DNS query from UDP packet
 * 
 * @param udp_packet Pointer to UDP packet (after IP header)
 * @param len Length of UDP packet
 * @param query Output: parsed query information
 * @return true if parsed successfully
 */
bool dns_parse_query(const uint8_t* udp_packet, uint32_t len, DnsQuery* query);

/**
 * Look up DNS query in cache
 * 
 * @param cache DNS cache
 * @param name Domain name to look up
 * @param type DNS record type (A, AAAA, etc.)
 * @param response_out Output buffer for cached response
 * @param out_capacity Maximum size of response_out
 * @return Length of response written, or 0 if not found/expired
 */
int32_t dns_cache_lookup(DnsCache* cache, const char* name, uint16_t type,
                         uint8_t* response_out, uint32_t out_capacity);

/**
 * Insert DNS response into cache
 * 
 * @param cache DNS cache
 * @param name Domain name
 * @param type DNS record type
 * @param response DNS response packet
 * @param response_len Length of response
 * @param ttl_seconds TTL in seconds (0 = use default)
 */
void dns_cache_insert(DnsCache* cache, const char* name, uint16_t type,
                     const uint8_t* response, uint32_t response_len,
                     uint32_t ttl_seconds);

/**
 * Build DNS response from cache or error
 * 
 * Helper function to construct a DNS response packet for a query.
 * 
 * @param query Original DNS query
 * @param answer_data Answer data (IP address bytes)
 * @param answer_len Length of answer data (4 for A, 16 for AAAA)
 * @param ttl TTL in seconds
 * @param rcode Response code (0 = success, 3 = NXDOMAIN)
 * @param response_out Output buffer for DNS response
 * @param out_capacity Maximum size of response_out
 * @return Length of response written, or -1 on error
 */
int32_t dns_build_response(const DnsQuery* query,
                          const uint8_t* answer_data, uint32_t answer_len,
                          uint32_t ttl, uint8_t rcode,
                          uint8_t* response_out, uint32_t out_capacity);

/**
 * Clean up expired cache entries
 * 
 * @param cache DNS cache
 * @return Number of entries cleaned up
 */
uint32_t dns_cache_cleanup(DnsCache* cache);

/**
 * Get cache statistics
 * 
 * @param cache DNS cache
 * @param valid_entries Output: number of valid entries
 * @param expired_entries Output: number of expired entries
 */
void dns_cache_stats(DnsCache* cache, uint32_t* valid_entries, uint32_t* expired_entries);

#endif // DNS_HANDLER_H
