/**
 * VirtualTap - IP Fragmentation Handler
 * 
 * Handles IPv4 and IPv6 packet fragmentation and reassembly.
 * Large packets fail without this support.
 * 
 * Features:
 * - Track fragment IDs and offsets
 * - Reassembly buffer per fragment chain
 * - 30-second timeout for incomplete fragments
 * - Support IPv4 and IPv6 fragmentation
 * - Maximum 16 concurrent fragment chains
 * 
 * Copyright (c) 2025 SoftEtherUnofficial at GitHub
 */

#ifndef FRAGMENT_HANDLER_H
#define FRAGMENT_HANDLER_H

#include <stdint.h>
#include <stdbool.h>

// Fragment configuration
#define MAX_FRAGMENT_CHAINS 16
#define MAX_FRAGMENT_SIZE 65535
#define FRAGMENT_TIMEOUT_MS 30000  // 30 seconds

/**
 * IPv4 fragment chain
 */
typedef struct {
    uint32_t src_ip;               // Source IP
    uint32_t dst_ip;               // Destination IP
    uint16_t id;                   // Fragment ID
    uint8_t protocol;              // Protocol (TCP, UDP, etc.)
    uint8_t reassembly_buffer[MAX_FRAGMENT_SIZE];  // Reassembly buffer
    uint32_t total_length;         // Total packet length (0 if unknown)
    uint32_t received_bytes;       // Bytes received so far
    bool fragments_received[64];   // Bitmap of received fragments
    int64_t timestamp_ms;          // Creation time
    bool valid;                    // Chain is valid
} IPv4FragmentChain;

/**
 * IPv6 fragment chain
 */
typedef struct {
    uint8_t src_ipv6[16];          // Source IPv6
    uint8_t dst_ipv6[16];          // Destination IPv6
    uint32_t id;                   // Fragment ID
    uint8_t reassembly_buffer[MAX_FRAGMENT_SIZE];  // Reassembly buffer
    uint32_t total_length;         // Total packet length (0 if unknown)
    uint32_t received_bytes;       // Bytes received so far
    bool fragments_received[64];   // Bitmap of received fragments
    int64_t timestamp_ms;          // Creation time
    bool valid;                    // Chain is valid
} IPv6FragmentChain;

/**
 * Fragment handler (manages all fragment chains)
 */
typedef struct {
    IPv4FragmentChain ipv4_chains[MAX_FRAGMENT_CHAINS];
    IPv6FragmentChain ipv6_chains[MAX_FRAGMENT_CHAINS];
    uint32_t next_ipv4_evict;      // Round-robin eviction index
    uint32_t next_ipv6_evict;      // Round-robin eviction index
} FragmentHandler;

/**
 * Create fragment handler
 * 
 * @return Pointer to fragment handler, or NULL on allocation failure
 */
FragmentHandler* fragment_handler_create(void);

/**
 * Destroy fragment handler
 * 
 * @param handler Fragment handler to destroy
 */
void fragment_handler_destroy(FragmentHandler* handler);

/**
 * Check if IPv4 packet is fragmented
 * 
 * @param ip_packet IPv4 packet
 * @param len Packet length
 * @return true if packet is fragmented
 */
bool is_ipv4_fragmented(const uint8_t* ip_packet, uint32_t len);

/**
 * Check if IPv6 packet is fragmented
 * 
 * @param ipv6_packet IPv6 packet
 * @param len Packet length
 * @return true if packet has fragment extension header
 */
bool is_ipv6_fragmented(const uint8_t* ipv6_packet, uint32_t len);

/**
 * Process IPv4 fragment
 * 
 * If this completes a fragment chain, returns the reassembled packet.
 * Otherwise returns 0 (more fragments needed).
 * 
 * @param handler Fragment handler
 * @param ip_packet IPv4 fragment packet
 * @param len Fragment length
 * @param reassembled_out Output buffer for reassembled packet
 * @param out_capacity Maximum size of reassembled_out
 * @return Length of reassembled packet (> 0), 0 if incomplete, or -1 on error
 */
int32_t fragment_process_ipv4(FragmentHandler* handler,
                              const uint8_t* ip_packet, uint32_t len,
                              uint8_t* reassembled_out, uint32_t out_capacity);

/**
 * Process IPv6 fragment
 * 
 * If this completes a fragment chain, returns the reassembled packet.
 * Otherwise returns 0 (more fragments needed).
 * 
 * @param handler Fragment handler
 * @param ipv6_packet IPv6 fragment packet
 * @param len Fragment length
 * @param reassembled_out Output buffer for reassembled packet
 * @param out_capacity Maximum size of reassembled_out
 * @return Length of reassembled packet (> 0), 0 if incomplete, or -1 on error
 */
int32_t fragment_process_ipv6(FragmentHandler* handler,
                              const uint8_t* ipv6_packet, uint32_t len,
                              uint8_t* reassembled_out, uint32_t out_capacity);

/**
 * Clean up expired fragment chains
 * 
 * @param handler Fragment handler
 * @return Number of chains cleaned up
 */
uint32_t fragment_cleanup_expired(FragmentHandler* handler);

/**
 * Get fragment handler statistics
 * 
 * @param handler Fragment handler
 * @param ipv4_active Output: number of active IPv4 chains
 * @param ipv6_active Output: number of active IPv6 chains
 */
void fragment_get_stats(FragmentHandler* handler,
                       uint32_t* ipv4_active, uint32_t* ipv6_active);

#endif // FRAGMENT_HANDLER_H
