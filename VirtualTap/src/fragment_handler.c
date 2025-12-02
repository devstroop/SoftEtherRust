/**
 * VirtualTap - IP Fragmentation Handler Implementation
 * 
 * Handles IPv4 and IPv6 packet fragmentation and reassembly.
 * 
 * Copyright (c) 2025 SoftEtherUnofficial at GitHub
 */

#include "fragment_handler.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>

// IPv4 fragment offset mask (in 8-byte units)
#define IPV4_FRAG_OFFSET_MASK 0x1FFF
#define IPV4_MORE_FRAGMENTS 0x2000
#define IPV4_DONT_FRAGMENT 0x4000

// Get current time in milliseconds
static int64_t get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

FragmentHandler* fragment_handler_create(void) {
    FragmentHandler* handler = (FragmentHandler*)calloc(1, sizeof(FragmentHandler));
    if (!handler) {
        return NULL;
    }
    
    // All chains initialized to invalid (valid = false) by calloc
    return handler;
}

void fragment_handler_destroy(FragmentHandler* handler) {
    free(handler);
}

bool is_ipv4_fragmented(const uint8_t* ip_packet, uint32_t len) {
    if (!ip_packet || len < 20) {
        return false;
    }
    
    // Check fragment offset and MF flag
    uint16_t frag_info = (ip_packet[6] << 8) | ip_packet[7];
    uint16_t offset = (frag_info & IPV4_FRAG_OFFSET_MASK) * 8;
    bool more_fragments = (frag_info & IPV4_MORE_FRAGMENTS) != 0;
    
    return (offset > 0 || more_fragments);
}

bool is_ipv6_fragmented(const uint8_t* ipv6_packet, uint32_t len) {
    if (!ipv6_packet || len < 40) {
        return false;
    }
    
    // Check for fragment extension header (next header = 44)
    uint8_t next_header = ipv6_packet[6];
    
    // Simple check: if next header is 44, it's fragmented
    // More complex: need to walk extension header chain
    if (next_header == 44) {
        return true;
    }
    
    // TODO: Walk extension header chain to find fragment header
    // For now, just check immediate next header
    
    return false;
}

int32_t fragment_process_ipv4(FragmentHandler* handler,
                              const uint8_t* ip_packet, uint32_t len,
                              uint8_t* reassembled_out, uint32_t out_capacity) {
    if (!handler || !ip_packet || !reassembled_out || len < 20) {
        return -1;
    }
    
    // Parse IPv4 header
    uint8_t ihl = (ip_packet[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > len) {
        return -1;
    }
    
    uint16_t id = (ip_packet[4] << 8) | ip_packet[5];
    uint16_t frag_info = (ip_packet[6] << 8) | ip_packet[7];
    uint16_t offset = (frag_info & IPV4_FRAG_OFFSET_MASK) * 8;
    bool more_fragments = (frag_info & IPV4_MORE_FRAGMENTS) != 0;
    uint8_t protocol = ip_packet[9];
    uint32_t src_ip = (ip_packet[12] << 24) | (ip_packet[13] << 16) |
                      (ip_packet[14] << 8) | ip_packet[15];
    uint32_t dst_ip = (ip_packet[16] << 24) | (ip_packet[17] << 16) |
                      (ip_packet[18] << 8) | ip_packet[19];
    
    // Find or create fragment chain
    IPv4FragmentChain* chain = NULL;
    int64_t now = get_time_ms();
    
    // Look for existing chain
    for (uint32_t i = 0; i < MAX_FRAGMENT_CHAINS; i++) {
        IPv4FragmentChain* c = &handler->ipv4_chains[i];
        if (c->valid && c->id == id && c->src_ip == src_ip && 
            c->dst_ip == dst_ip && c->protocol == protocol) {
            chain = c;
            break;
        }
    }
    
    // Create new chain if not found
    if (!chain) {
        uint32_t index = handler->next_ipv4_evict;
        handler->next_ipv4_evict = (index + 1) % MAX_FRAGMENT_CHAINS;
        
        chain = &handler->ipv4_chains[index];
        memset(chain, 0, sizeof(IPv4FragmentChain));
        chain->id = id;
        chain->src_ip = src_ip;
        chain->dst_ip = dst_ip;
        chain->protocol = protocol;
        chain->timestamp_ms = now;
        chain->valid = true;
    }
    
    // Copy fragment data to reassembly buffer
    uint32_t payload_offset = ihl;
    uint32_t payload_len = len - payload_offset;
    
    if (offset + payload_len > MAX_FRAGMENT_SIZE) {
        chain->valid = false;  // Fragment too large
        return -1;
    }
    
    // Copy IP header from first fragment (offset 0)
    if (offset == 0) {
        memcpy(chain->reassembly_buffer, ip_packet, ihl);
    }
    
    // Copy payload
    memcpy(chain->reassembly_buffer + ihl + offset, 
           ip_packet + payload_offset, payload_len);
    
    // Mark fragment as received
    uint32_t fragment_index = offset / 512;  // Assume 512-byte fragments
    if (fragment_index < 64) {
        chain->fragments_received[fragment_index] = true;
    }
    
    chain->received_bytes += payload_len;
    
    // If this is the last fragment, we know the total length
    if (!more_fragments) {
        chain->total_length = ihl + offset + payload_len;
    }
    
    // Check if reassembly is complete
    if (chain->total_length > 0 && chain->received_bytes >= (chain->total_length - ihl)) {
        // Reassembly complete!
        uint32_t total = chain->total_length;
        
        if (total > out_capacity) {
            chain->valid = false;
            return -1;
        }
        
        // Copy reassembled packet
        memcpy(reassembled_out, chain->reassembly_buffer, total);
        
        // Update total length in IP header
        reassembled_out[2] = (total >> 8) & 0xFF;
        reassembled_out[3] = total & 0xFF;
        
        // Clear fragment flags (MF flag is bit 5 = 0x20)
        reassembled_out[6] &= 0xDF;  // Clear MF flag (keep DF and reserved)
        reassembled_out[7] = 0;      // Clear offset
        
        // Recalculate checksum
        reassembled_out[10] = 0;
        reassembled_out[11] = 0;
        uint32_t sum = 0;
        for (uint32_t i = 0; i < ihl; i += 2) {
            sum += (reassembled_out[i] << 8) | reassembled_out[i + 1];
        }
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        uint16_t checksum = ~sum;
        reassembled_out[10] = (checksum >> 8) & 0xFF;
        reassembled_out[11] = checksum & 0xFF;
        
        // Invalidate chain
        chain->valid = false;
        
        return total;
    }
    
    return 0;  // More fragments needed
}

int32_t fragment_process_ipv6(FragmentHandler* handler,
                              const uint8_t* ipv6_packet, uint32_t len,
                              uint8_t* reassembled_out, uint32_t out_capacity) {
    if (!handler || !ipv6_packet || !reassembled_out || len < 48) {
        return -1;  // Min: 40 (IPv6) + 8 (fragment header)
    }
    
    // Parse IPv6 header
    uint8_t next_header = ipv6_packet[6];
    if (next_header != 44) {
        return -1;  // Not a fragment extension header
    }
    
    // Extract fragment header (at offset 40)
    const uint8_t* frag_header = ipv6_packet + 40;
    uint8_t final_next_header = frag_header[0];
    uint16_t frag_info = (frag_header[2] << 8) | frag_header[3];
    uint16_t offset = frag_info & 0xFFF8;  // Fragment offset in 8-byte units
    bool more_fragments = (frag_info & 0x0001) != 0;
    uint32_t id = (frag_header[4] << 24) | (frag_header[5] << 16) |
                  (frag_header[6] << 8) | frag_header[7];
    
    // Extract source and destination IPv6
    uint8_t src_ipv6[16], dst_ipv6[16];
    memcpy(src_ipv6, ipv6_packet + 8, 16);
    memcpy(dst_ipv6, ipv6_packet + 24, 16);
    
    // Find or create fragment chain
    IPv6FragmentChain* chain = NULL;
    int64_t now = get_time_ms();
    
    for (uint32_t i = 0; i < MAX_FRAGMENT_CHAINS; i++) {
        IPv6FragmentChain* c = &handler->ipv6_chains[i];
        if (c->valid && c->id == id &&
            memcmp(c->src_ipv6, src_ipv6, 16) == 0 &&
            memcmp(c->dst_ipv6, dst_ipv6, 16) == 0) {
            chain = c;
            break;
        }
    }
    
    if (!chain) {
        uint32_t index = handler->next_ipv6_evict;
        handler->next_ipv6_evict = (index + 1) % MAX_FRAGMENT_CHAINS;
        
        chain = &handler->ipv6_chains[index];
        memset(chain, 0, sizeof(IPv6FragmentChain));
        chain->id = id;
        memcpy(chain->src_ipv6, src_ipv6, 16);
        memcpy(chain->dst_ipv6, dst_ipv6, 16);
        chain->timestamp_ms = now;
        chain->valid = true;
    }
    
    // Copy fragment data
    uint32_t payload_offset = 48;  // 40 (IPv6) + 8 (fragment header)
    uint32_t payload_len = len - payload_offset;
    
    if (offset + payload_len > MAX_FRAGMENT_SIZE - 40) {
        chain->valid = false;
        return -1;
    }
    
    // Copy IPv6 header from first fragment
    if (offset == 0) {
        memcpy(chain->reassembly_buffer, ipv6_packet, 40);
        // Update next header to skip fragment extension
        chain->reassembly_buffer[6] = final_next_header;
    }
    
    // Copy payload
    memcpy(chain->reassembly_buffer + 40 + offset,
           ipv6_packet + payload_offset, payload_len);
    
    uint32_t fragment_index = offset / 512;
    if (fragment_index < 64) {
        chain->fragments_received[fragment_index] = true;
    }
    
    chain->received_bytes += payload_len;
    
    if (!more_fragments) {
        chain->total_length = 40 + offset + payload_len;
    }
    
    // Check if complete
    if (chain->total_length > 0 && chain->received_bytes >= (chain->total_length - 40)) {
        uint32_t total = chain->total_length;
        
        if (total > out_capacity) {
            chain->valid = false;
            return -1;
        }
        
        memcpy(reassembled_out, chain->reassembly_buffer, total);
        
        // Update payload length
        uint32_t payload_length = total - 40;
        reassembled_out[4] = (payload_length >> 8) & 0xFF;
        reassembled_out[5] = payload_length & 0xFF;
        
        chain->valid = false;
        
        return total;
    }
    
    return 0;
}

uint32_t fragment_cleanup_expired(FragmentHandler* handler) {
    if (!handler) return 0;
    
    int64_t now = get_time_ms();
    uint32_t cleaned = 0;
    
    for (uint32_t i = 0; i < MAX_FRAGMENT_CHAINS; i++) {
        IPv4FragmentChain* c4 = &handler->ipv4_chains[i];
        if (c4->valid && (now - c4->timestamp_ms) > FRAGMENT_TIMEOUT_MS) {
            c4->valid = false;
            cleaned++;
        }
        
        IPv6FragmentChain* c6 = &handler->ipv6_chains[i];
        if (c6->valid && (now - c6->timestamp_ms) > FRAGMENT_TIMEOUT_MS) {
            c6->valid = false;
            cleaned++;
        }
    }
    
    return cleaned;
}

void fragment_get_stats(FragmentHandler* handler,
                       uint32_t* ipv4_active, uint32_t* ipv6_active) {
    if (!handler) return;
    
    uint32_t v4 = 0, v6 = 0;
    
    for (uint32_t i = 0; i < MAX_FRAGMENT_CHAINS; i++) {
        if (handler->ipv4_chains[i].valid) v4++;
        if (handler->ipv6_chains[i].valid) v6++;
    }
    
    if (ipv4_active) *ipv4_active = v4;
    if (ipv6_active) *ipv6_active = v6;
}
