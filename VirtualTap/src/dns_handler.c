/**
 * VirtualTap - DNS Handler Implementation
 * 
 * DNS query/response interception and caching for VPN clients.
 * 
 * Copyright (c) 2025 SoftEtherUnofficial at GitHub
 */

#include "dns_handler.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <ctype.h>

// DNS header size
#define DNS_HEADER_SIZE 12
#define UDP_HEADER_SIZE 8

// Get current time in milliseconds
static int64_t get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

DnsCache* dns_cache_create(void) {
    DnsCache* cache = (DnsCache*)calloc(1, sizeof(DnsCache));
    if (!cache) {
        return NULL;
    }
    
    // All entries initialized to invalid (valid = false) by calloc
    return cache;
}

void dns_cache_destroy(DnsCache* cache) {
    free(cache);
}

bool dns_is_query(const uint8_t* udp_packet, uint32_t len) {
    if (!udp_packet || len < UDP_HEADER_SIZE + DNS_HEADER_SIZE) {
        return false;
    }
    
    // Check destination port = 53
    uint16_t dest_port = (udp_packet[2] << 8) | udp_packet[3];
    if (dest_port != 53) {
        return false;
    }
    
    // Check DNS header: QR bit should be 0 (query)
    const uint8_t* dns = udp_packet + UDP_HEADER_SIZE;
    uint8_t flags_high = dns[2];
    bool is_query = (flags_high & 0x80) == 0;
    
    return is_query;
}

// Parse DNS name from packet (handles compression)
static int parse_dns_name(const uint8_t* packet, uint32_t packet_len, uint32_t offset,
                         char* name_out, uint32_t name_capacity) {
    uint32_t pos = offset;
    uint32_t out_pos = 0;
    bool first_label = true;
    uint32_t jumps = 0;
    const uint32_t MAX_JUMPS = 10;  // Prevent infinite loops
    
    while (pos < packet_len && jumps < MAX_JUMPS) {
        uint8_t len = packet[pos];
        
        // End of name
        if (len == 0) {
            name_out[out_pos] = '\0';
            return pos - offset + 1;
        }
        
        // Compression pointer
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= packet_len) return -1;
            uint16_t pointer = ((len & 0x3F) << 8) | packet[pos + 1];
            pos = pointer;
            jumps++;
            continue;
        }
        
        // Regular label
        if (len > 63) return -1;  // Invalid label length
        if (pos + 1 + len > packet_len) return -1;
        
        // Add dot separator
        if (!first_label) {
            if (out_pos + 1 >= name_capacity) return -1;
            name_out[out_pos++] = '.';
        }
        first_label = false;
        
        // Copy label
        if (out_pos + len >= name_capacity) return -1;
        for (uint32_t i = 0; i < len; i++) {
            name_out[out_pos++] = tolower(packet[pos + 1 + i]);
        }
        
        pos += len + 1;
    }
    
    return -1;  // Shouldn't reach here
}

bool dns_parse_query(const uint8_t* udp_packet, uint32_t len, DnsQuery* query) {
    if (!udp_packet || !query || len < UDP_HEADER_SIZE + DNS_HEADER_SIZE + 5) {
        return false;
    }
    
    memset(query, 0, sizeof(DnsQuery));
    
    const uint8_t* dns = udp_packet + UDP_HEADER_SIZE;
    uint32_t dns_len = len - UDP_HEADER_SIZE;
    
    // Parse DNS header
    query->transaction_id = (dns[0] << 8) | dns[1];
    
    // Check this is a query
    if (dns[2] & 0x80) {
        return false;  // Response, not query
    }
    
    // Get question count
    uint16_t qdcount = (dns[4] << 8) | dns[5];
    if (qdcount == 0) {
        return false;
    }
    
    // Parse first question
    int name_len = parse_dns_name(dns, dns_len, DNS_HEADER_SIZE, 
                                   query->name, sizeof(query->name));
    if (name_len < 0) {
        return false;
    }
    
    uint32_t offset = DNS_HEADER_SIZE + name_len;
    if (offset + 4 > dns_len) {
        return false;
    }
    
    query->type = (dns[offset] << 8) | dns[offset + 1];
    query->qclass = (dns[offset + 2] << 8) | dns[offset + 3];
    query->valid = true;
    
    return true;
}

int32_t dns_cache_lookup(DnsCache* cache, const char* name, uint16_t type,
                         uint8_t* response_out, uint32_t out_capacity) {
    if (!cache || !name || !response_out) {
        return 0;
    }
    
    int64_t now = get_time_ms();
    
    // Linear search (fast enough for 256 entries)
    for (uint32_t i = 0; i < DNS_CACHE_SIZE; i++) {
        DnsCacheEntry* entry = &cache->entries[i];
        
        if (!entry->valid) continue;
        
        // Check expiration
        if (now >= entry->expires_ms) {
            entry->valid = false;
            continue;
        }
        
        // Check name and type match
        if (entry->type == type && strcmp(entry->name, name) == 0) {
            // Cache hit!
            if (entry->response_len > out_capacity) {
                return 0;
            }
            
            memcpy(response_out, entry->response, entry->response_len);
            return entry->response_len;
        }
    }
    
    return 0;  // Cache miss
}

void dns_cache_insert(DnsCache* cache, const char* name, uint16_t type,
                     const uint8_t* response, uint32_t response_len,
                     uint32_t ttl_seconds) {
    if (!cache || !name || !response || response_len > DNS_MAX_RESPONSE_SIZE) {
        return;
    }
    
    if (ttl_seconds == 0) {
        ttl_seconds = DNS_DEFAULT_TTL;
    }
    
    // Use round-robin eviction (simple LRU approximation)
    uint32_t index = cache->next_evict_index;
    cache->next_evict_index = (index + 1) % DNS_CACHE_SIZE;
    
    DnsCacheEntry* entry = &cache->entries[index];
    
    strncpy(entry->name, name, DNS_MAX_NAME_LEN);
    entry->name[DNS_MAX_NAME_LEN] = '\0';
    entry->type = type;
    memcpy(entry->response, response, response_len);
    entry->response_len = response_len;
    entry->expires_ms = get_time_ms() + (ttl_seconds * 1000);
    entry->valid = true;
}

int32_t dns_build_response(const DnsQuery* query,
                          const uint8_t* answer_data, uint32_t answer_len,
                          uint32_t ttl, uint8_t rcode,
                          uint8_t* response_out, uint32_t out_capacity) {
    if (!query || !response_out || out_capacity < UDP_HEADER_SIZE + DNS_HEADER_SIZE) {
        return -1;
    }
    
    // Calculate response size
    uint32_t name_len = (uint32_t)strlen(query->name);
    uint32_t labels_size = name_len + 2;  // Labels + length bytes + null
    uint32_t question_size = labels_size + 4;  // + type + class
    uint32_t answer_size = (rcode == 0 && answer_data) ? 
                          (labels_size + 10 + answer_len) : 0;  // name + header + data
    uint32_t total_size = UDP_HEADER_SIZE + DNS_HEADER_SIZE + question_size + answer_size;
    
    if (total_size > out_capacity) {
        return -1;
    }
    
    memset(response_out, 0, total_size);
    
    // UDP header (source port 53, dest port from query)
    response_out[0] = 0;   // Source port high
    response_out[1] = 53;  // Source port low
    // Destination port copied from query later
    uint16_t udp_len = total_size - UDP_HEADER_SIZE;
    response_out[4] = (udp_len >> 8) & 0xFF;
    response_out[5] = udp_len & 0xFF;
    
    uint8_t* dns = response_out + UDP_HEADER_SIZE;
    
    // DNS header
    dns[0] = (query->transaction_id >> 8) & 0xFF;
    dns[1] = query->transaction_id & 0xFF;
    dns[2] = 0x81;  // QR=1 (response), Opcode=0, AA=0, TC=0, RD=1
    dns[3] = 0x80 | rcode;  // RA=1, Z=0, RCODE
    dns[4] = 0; dns[5] = 1;  // QDCOUNT = 1
    dns[6] = 0; dns[7] = (rcode == 0 && answer_data) ? 1 : 0;  // ANCOUNT
    dns[8] = 0; dns[9] = 0;  // NSCOUNT = 0
    dns[10] = 0; dns[11] = 0;  // ARCOUNT = 0
    
    // Question section
    uint32_t offset = DNS_HEADER_SIZE;
    const char* label_start = query->name;
    while (*label_start) {
        const char* dot = strchr(label_start, '.');
        uint32_t label_len = dot ? (uint32_t)(dot - label_start) : (uint32_t)strlen(label_start);
        
        dns[offset++] = label_len;
        memcpy(dns + offset, label_start, label_len);
        offset += label_len;
        
        if (dot) {
            label_start = dot + 1;
        } else {
            break;
        }
    }
    dns[offset++] = 0;  // End of name
    
    dns[offset++] = (query->type >> 8) & 0xFF;
    dns[offset++] = query->type & 0xFF;
    dns[offset++] = (query->qclass >> 8) & 0xFF;
    dns[offset++] = query->qclass & 0xFF;
    
    // Answer section (if success)
    if (rcode == 0 && answer_data && answer_len > 0) {
        // Name (compression pointer to question)
        dns[offset++] = 0xC0;
        dns[offset++] = DNS_HEADER_SIZE;
        
        // Type and class
        dns[offset++] = (query->type >> 8) & 0xFF;
        dns[offset++] = query->type & 0xFF;
        dns[offset++] = (query->qclass >> 8) & 0xFF;
        dns[offset++] = query->qclass & 0xFF;
        
        // TTL
        dns[offset++] = (ttl >> 24) & 0xFF;
        dns[offset++] = (ttl >> 16) & 0xFF;
        dns[offset++] = (ttl >> 8) & 0xFF;
        dns[offset++] = ttl & 0xFF;
        
        // RDLENGTH
        dns[offset++] = (answer_len >> 8) & 0xFF;
        dns[offset++] = answer_len & 0xFF;
        
        // RDATA
        memcpy(dns + offset, answer_data, answer_len);
        offset += answer_len;
    }
    
    return total_size;
}

uint32_t dns_cache_cleanup(DnsCache* cache) {
    if (!cache) return 0;
    
    int64_t now = get_time_ms();
    uint32_t cleaned = 0;
    
    for (uint32_t i = 0; i < DNS_CACHE_SIZE; i++) {
        DnsCacheEntry* entry = &cache->entries[i];
        if (entry->valid && now >= entry->expires_ms) {
            entry->valid = false;
            cleaned++;
        }
    }
    
    return cleaned;
}

void dns_cache_stats(DnsCache* cache, uint32_t* valid_entries, uint32_t* expired_entries) {
    if (!cache) return;
    
    int64_t now = get_time_ms();
    uint32_t valid = 0, expired = 0;
    
    for (uint32_t i = 0; i < DNS_CACHE_SIZE; i++) {
        DnsCacheEntry* entry = &cache->entries[i];
        if (entry->valid) {
            if (now >= entry->expires_ms) {
                expired++;
            } else {
                valid++;
            }
        }
    }
    
    if (valid_entries) *valid_entries = valid;
    if (expired_entries) *expired_entries = expired;
}
