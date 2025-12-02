#include "../include/virtual_tap_internal.h"
#include "../include/icmpv6_handler.h"
#include "../include/dns_handler.h"
#include "../include/fragment_handler.h"
#include "../include/icmp_handler.h"

// ============================================================================
// Internal Helper Functions
// ============================================================================

static void arp_reply_queue_push(VirtualTap* tap, uint8_t* packet, uint32_t len) {
    if (!tap || !packet) return;
    
    ArpReplyNode* node = (ArpReplyNode*)malloc(sizeof(ArpReplyNode));
    if (!node) {
        free(packet);
        return;
    }
    
    node->packet = packet;
    node->length = len;
    node->next = NULL;
    
    if (tap->arp_reply_tail == NULL) {
        tap->arp_reply_head = tap->arp_reply_tail = node;
    } else {
        tap->arp_reply_tail->next = node;
        tap->arp_reply_tail = node;
    }
}

static int handle_arp(VirtualTap* tap, const uint8_t* eth_frame, uint32_t eth_len) {
    if (!tap || !eth_frame || eth_len < ETHERNET_HEADER_SIZE + 28) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    // Parse ARP packet (skip 14-byte Ethernet header)
    ArpInfo info;
    if (arp_parse_packet(eth_frame + ETHERNET_HEADER_SIZE, 
                        eth_len - ETHERNET_HEADER_SIZE, &info) != 0) {
        return VTAP_ERROR_PARSE_FAILED;
    }
    
    // Handle ARP Reply: learn MAC
    if (info.operation == ARP_OP_REPLY) {
        arp_table_insert(tap->arp_table, info.sender_ip, info.sender_mac, false);
        tap->stats.arp_table_entries = arp_table_count(tap->arp_table);
        
        // Learn gateway MAC if this is from gateway
        uint32_t our_ip = translator_get_our_ip(tap->translator);
        if (our_ip != 0 && tap->config.learn_gateway_mac) {
            // Simple heuristic: gateway is typically x.x.x.1
            uint32_t assumed_gateway = (our_ip & 0xFFFFFF00) | 0x01;
            if (info.sender_ip == assumed_gateway || info.sender_ip == tap->config.gateway_ip) {
                translator_set_gateway_mac(tap->translator, info.sender_mac);
                if (tap->config.verbose) {
                    printf("[VirtualTap] Learned gateway MAC from ARP reply\n");
                }
            }
        }
        
        return 0; // Handled internally
    }
    
    // Handle ARP Request: build reply if for us
    if (info.operation == ARP_OP_REQUEST) {
        tap->stats.arp_requests_handled++;
        
        uint32_t our_ip = translator_get_our_ip(tap->translator);
        if (our_ip == 0 || info.target_ip != our_ip) {
            return 0; // Not for us
        }
        
        // Build ARP reply
        uint8_t* reply = (uint8_t*)malloc(ARP_PACKET_SIZE);
        if (!reply) {
            return VTAP_ERROR_ALLOC_FAILED;
        }
        
        int result = arp_build_reply(tap->config.our_mac, our_ip,
                                     info.sender_mac, info.sender_ip,
                                     reply, ARP_PACKET_SIZE);
        
        if (result != ARP_PACKET_SIZE) {
            free(reply);
            return result;
        }
        
        // Queue reply
        arp_reply_queue_push(tap, reply, ARP_PACKET_SIZE);
        tap->stats.arp_replies_sent++;
        
        if (tap->config.verbose) {
            printf("[VirtualTap] Generated ARP reply\n");
        }
        
        return 0;
    }
    
    return 0;
}

static int handle_icmpv6_ndp(VirtualTap* tap, const uint8_t* eth_frame, uint32_t eth_len) {
    if (!tap || !eth_frame || eth_len < ETHERNET_HEADER_SIZE + 64) {
        return 0;  // Too small for NS
    }
    
    const uint8_t* ipv6_packet = eth_frame + ETHERNET_HEADER_SIZE;
    uint32_t ipv6_len = eth_len - ETHERNET_HEADER_SIZE;
    
    // Check for Neighbor Solicitation (asking for our IPv6)
    uint8_t target_ipv6[16];
    if (is_neighbor_solicitation(ipv6_packet, ipv6_len, target_ipv6)) {
        // Check if solicitation is for our IPv6
        uint8_t our_ipv6[16];
        memcpy(our_ipv6, tap->translator->our_ipv6, 16);
        
        if (tap->translator->has_ipv6 && memcmp(target_ipv6, our_ipv6, 16) == 0) {
            // Build Neighbor Advertisement response
            uint8_t solicitor_ipv6[16];
            memcpy(solicitor_ipv6, ipv6_packet + 8, 16);  // Source IPv6
            
            uint8_t* na_packet = (uint8_t*)malloc(72);  // IPv6 + NA
            if (!na_packet) {
                return VTAP_ERROR_ALLOC_FAILED;
            }
            
            int32_t result = build_neighbor_advertisement(
                our_ipv6,
                tap->config.our_mac,
                solicitor_ipv6,
                na_packet,
                72
            );
            
            if (result == 72) {
                // Queue NA response (needs Ethernet wrapping)
                uint8_t* eth_reply = (uint8_t*)malloc(86);  // 14 + 72
                if (eth_reply) {
                    // Build Ethernet header
                    memcpy(eth_reply, eth_frame + 6, 6);      // Dest: sender MAC
                    memcpy(eth_reply + 6, tap->config.our_mac, 6);  // Src: our MAC
                    eth_reply[12] = 0x86;  // EtherType IPv6
                    eth_reply[13] = 0xDD;
                    memcpy(eth_reply + 14, na_packet, 72);
                    
                    arp_reply_queue_push(tap, eth_reply, 86);
                    tap->stats.icmpv6_packets++;
                    
                    if (tap->config.verbose) {
                        printf("[VirtualTap] Sent Neighbor Advertisement response\n");
                    }
                }
                free(na_packet);
                return 0;
            }
            free(na_packet);
        }
    }
    
    // Check for Router Advertisement (IPv6 config)
    const uint8_t* icmpv6 = ipv6_packet + 40;
    if (ipv6_len >= 56 && icmpv6[0] == ICMPV6_ROUTER_ADVERTISEMENT) {
        IPv6RAInfo ra_info;
        if (parse_router_advertisement(ipv6_packet, ipv6_len, &ra_info)) {
            // Store gateway IPv6
            if (ra_info.has_gateway) {
                memcpy(tap->translator->gateway_ipv6, ra_info.gateway, 16);
                tap->translator->has_ipv6_gateway = true;
                
                if (tap->config.verbose) {
                    printf("[VirtualTap] Learned IPv6 gateway from RA\n");
                }
            }
            
            // Store prefix info if needed
            if (ra_info.has_prefix && tap->config.verbose) {
                printf("[VirtualTap] Received IPv6 prefix (length %d)\n", ra_info.prefix_length);
            }
            
            tap->stats.icmpv6_packets++;
        }
    }
    
    return 0;
}

static int handle_dns_query(VirtualTap* tap, const uint8_t* ip_packet, uint32_t ip_len) {
    if (!tap || !ip_packet || ip_len < 28) {  // Min: 20 (IP) + 8 (UDP)
        return 0;
    }
    
    // Check if UDP
    uint8_t protocol = ip_packet[9];
    if (protocol != 17) {  // UDP
        return 0;
    }
    
    // Extract UDP header
    uint8_t ip_header_len = (ip_packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || ip_header_len + 8 > ip_len) {
        return 0;
    }
    
    const uint8_t* udp_packet = ip_packet + ip_header_len;
    uint32_t udp_len = ip_len - ip_header_len;
    
    // Check if DNS query
    if (!dns_is_query(udp_packet, udp_len)) {
        return 0;
    }
    
    tap->stats.dns_queries++;
    
    // Parse DNS query
    DnsQuery query;
    if (!dns_parse_query(udp_packet, udp_len, &query)) {
        return 0;
    }
    
    // Check cache if enabled
    if (!tap->dns_cache) {
        tap->stats.dns_cache_misses++;
        return 0;  // Cache disabled, pass through
    }
    
    DnsCache* cache = (DnsCache*)tap->dns_cache;
    uint8_t cached_response[DNS_MAX_RESPONSE_SIZE];
    int32_t cached_len = dns_cache_lookup(cache, query.name, query.type,
                                          cached_response, sizeof(cached_response));
    
    if (cached_len > 0) {
        // Cache hit!
        tap->stats.dns_cache_hits++;
        
        if (tap->config.verbose) {
            printf("[VirtualTap] DNS cache hit: %s (type %d)\n", query.name, query.type);
        }
        
        // TODO: Build and queue DNS response
        // For now, just pass through to let server handle it
        // Full implementation would require UDP response construction
        
        return 0;
    }
    
    tap->stats.dns_cache_misses++;
    
    if (tap->config.verbose) {
        printf("[VirtualTap] DNS cache miss: %s (type %d)\n", query.name, query.type);
    }
    
    return 0;  // Pass through to server
}

// ============================================================================
// Public API Implementation
// ============================================================================

VirtualTap* virtual_tap_create(const VirtualTapConfig* config) {
    if (!config) return NULL;
    
    VirtualTap* tap = (VirtualTap*)calloc(1, sizeof(VirtualTap));
    if (!tap) return NULL;
    
    // Copy config
    memcpy(&tap->config, config, sizeof(VirtualTapConfig));
    
    // Create ARP table
    tap->arp_table = arp_table_create(ARP_TIMEOUT_MS);
    if (!tap->arp_table) {
        free(tap);
        return NULL;
    }
    
    // Create translator
    tap->translator = translator_create(config->our_mac, config->handle_arp,
                                        config->learn_gateway_mac, config->verbose);
    if (!tap->translator) {
        arp_table_destroy(tap->arp_table);
        free(tap);
        return NULL;
    }
    
    // Initialize translator with configured IPs/MACs
    if (config->our_ip != 0) {
        translator_set_our_ip(tap->translator, config->our_ip);
    }
    if (config->gateway_ip != 0) {
        translator_set_gateway_ip(tap->translator, config->gateway_ip);
    }
    
    // Check if gateway MAC is configured
    bool has_gateway_mac = false;
    for (int i = 0; i < 6; i++) {
        if (config->gateway_mac[i] != 0) {
            has_gateway_mac = true;
            break;
        }
    }
    if (has_gateway_mac) {
        translator_set_gateway_mac(tap->translator, config->gateway_mac);
    }
    
    // Create DNS cache if enabled
    if (config->enable_dns_cache) {
        tap->dns_cache = dns_cache_create();
        // Note: dns_cache can be NULL, we'll check before using
    } else {
        tap->dns_cache = NULL;
    }
    
    // Create fragment handler
    tap->fragment_handler = fragment_handler_create();
    // Note: fragment_handler can be NULL, we'll check before using
    
    // Initialize queue
    tap->arp_reply_head = NULL;
    tap->arp_reply_tail = NULL;
    
    // Initialize stats
    memset(&tap->stats, 0, sizeof(VirtualTapStats));
    
    if (config->verbose) {
        printf("[VirtualTap] Created successfully\n");
    }
    
    return tap;
}

void virtual_tap_destroy(VirtualTap* tap) {
    if (!tap) return;
    
    // Free DNS cache
    if (tap->dns_cache) {
        dns_cache_destroy((DnsCache*)tap->dns_cache);
    }
    
    // Free fragment handler
    if (tap->fragment_handler) {
        fragment_handler_destroy((FragmentHandler*)tap->fragment_handler);
    }
    
    // Free ARP reply queue
    ArpReplyNode* node = tap->arp_reply_head;
    while (node) {
        ArpReplyNode* next = node->next;
        free(node->packet);
        free(node);
        node = next;
    }
    
    // Free components
    if (tap->translator) {
        translator_destroy(tap->translator);
    }
    if (tap->arp_table) {
        arp_table_destroy(tap->arp_table);
    }
    
    free(tap);
}

int32_t virtual_tap_ip_to_ethernet(VirtualTap* tap, const uint8_t* ip_packet,
                                   uint32_t ip_len, uint8_t* eth_frame_out,
                                   uint32_t out_capacity) {
    if (!tap || !ip_packet || !eth_frame_out) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    // Use translator
    int result = translator_ip_to_ethernet(tap->translator, ip_packet, ip_len,
                                          NULL, eth_frame_out, out_capacity);
    
    if (result > 0) {
        tap->stats.ip_to_eth_packets++;
    }
    
    return result;
}

int32_t virtual_tap_ethernet_to_ip(VirtualTap* tap, const uint8_t* eth_frame,
                                   uint32_t eth_len, uint8_t* ip_packet_out,
                                   uint32_t out_capacity) {
    if (!tap || !eth_frame || !ip_packet_out || eth_len < ETHERNET_HEADER_SIZE) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    // Extract EtherType
    uint16_t ethertype = read_u16_be(eth_frame + 12);
    
    // Route by protocol
    switch (ethertype) {
        case ETHERTYPE_IPV4:
            tap->stats.ipv4_packets++;
            
            // Extract IP packet for inspection
            const uint8_t* ip_packet = eth_frame + ETHERNET_HEADER_SIZE;
            uint32_t ip_packet_len = eth_len - ETHERNET_HEADER_SIZE;
            
            // Check if DHCP
            if (ip_packet_len >= 20 &&
                dhcp_is_dhcp_packet(ip_packet, ip_packet_len)) {
                tap->stats.dhcp_packets++;
                
                // Parse DHCP to learn IP/gateway
                DhcpInfo dhcp;
                if (tap->config.verbose) {
                    printf("[VirtualTap] 🔍 DHCP packet detected (packet #%llu)\n", 
                           (unsigned long long)tap->stats.dhcp_packets);
                }
                if (dhcp_parse_packet(ip_packet, ip_packet_len, &dhcp) == 0) {
                    if (tap->config.verbose) {
                        const char* type_name = "UNKNOWN";
                        switch (dhcp.message_type) {
                            case 1: type_name = "DISCOVER"; break;
                            case 2: type_name = "OFFER"; break;
                            case 3: type_name = "REQUEST"; break;
                            case 4: type_name = "DECLINE"; break;
                            case 5: type_name = "ACK"; break;
                            case 6: type_name = "NAK"; break;
                            case 7: type_name = "RELEASE"; break;
                            case 8: type_name = "INFORM"; break;
                        }
                        printf("[VirtualTap] 📦 DHCP %s (type=%d): offered_ip=%d.%d.%d.%d\n",
                               type_name, dhcp.message_type, 
                               dhcp.offered_ip[0], dhcp.offered_ip[1],
                               dhcp.offered_ip[2], dhcp.offered_ip[3]);
                    }
                    if (tap->config.learn_ip && dhcp.offered_ip[0] != 0) {
                        uint32_t offered = ipv4_to_u32(dhcp.offered_ip);
                        translator_set_our_ip(tap->translator, offered);
                        if (tap->config.verbose) {
                            printf("[VirtualTap] Learned IP from DHCP: %d.%d.%d.%d\n",
                                   dhcp.offered_ip[0], dhcp.offered_ip[1],
                                   dhcp.offered_ip[2], dhcp.offered_ip[3]);
                        }
                    }
                    if (dhcp.gateway[0] != 0) {
                        uint32_t gateway = ipv4_to_u32(dhcp.gateway);
                        translator_set_gateway_ip(tap->translator, gateway);
                        if (tap->config.verbose) {
                            printf("[VirtualTap] Learned gateway from DHCP: %d.%d.%d.%d\n",
                                   dhcp.gateway[0], dhcp.gateway[1],
                                   dhcp.gateway[2], dhcp.gateway[3]);
                        }
                    }
                }
            }
            
            // Check if DNS query (for caching/stats)
            handle_dns_query(tap, ip_packet, ip_packet_len);
            
            // Translate to IP
            {
                int result = translator_ethernet_to_ip(tap->translator, eth_frame, eth_len,
                                                      ip_packet_out, out_capacity);
                if (result > 0) {
                    tap->stats.eth_to_ip_packets++;
                    
                    // Check if fragmented
                    if (tap->fragment_handler && is_ipv4_fragmented(ip_packet_out, result)) {
                        tap->stats.ipv4_fragments++;
                        
                        // Process fragment
                        uint8_t reassembled[MAX_PACKET_SIZE];
                        int32_t reassembled_len = fragment_process_ipv4(
                            (FragmentHandler*)tap->fragment_handler,
                            ip_packet_out, result,
                            reassembled, sizeof(reassembled)
                        );
                        
                        if (reassembled_len > 0) {
                            // Reassembly complete!
                            tap->stats.fragments_reassembled++;
                            
                            if (reassembled_len <= (int32_t)out_capacity) {
                                memcpy(ip_packet_out, reassembled, reassembled_len);
                                return reassembled_len;
                            }
                        } else if (reassembled_len == 0) {
                            // More fragments needed - don't return packet yet
                            return 0;
                        }
                        // reassembled_len < 0 means error, fall through to return original
                    }
                    
                    // Check for ICMP error messages
                    if (result >= 20) {
                        uint8_t protocol = ip_packet_out[9];
                        if (protocol == 1) {  // ICMP
                            uint8_t ihl = (ip_packet_out[0] & 0x0F) * 4;
                            if (result >= (int)(ihl + 8)) {
                                const uint8_t* icmp_packet = ip_packet_out + ihl;
                                uint32_t icmp_len = result - ihl;
                                
                                if (icmp_is_error(icmp_packet, icmp_len)) {
                                    tap->stats.icmp_errors_received++;
                                    
                                    // Parse error for logging/debugging
                                    if (tap->config.verbose) {
                                        ICMPErrorInfo info;
                                        if (icmp_parse_error(icmp_packet, icmp_len, &info) == 0) {
                                            printf("[VirtualTap] ICMP error: type=%d code=%d", 
                                                   info.type, info.code);
                                            if (info.mtu > 0) {
                                                printf(" MTU=%d", info.mtu);
                                            }
                                            printf("\n");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return result;
            }
            
        case ETHERTYPE_ARP:
            tap->stats.arp_packets++;
            if (!tap->config.handle_arp) {
                return 0;
            }
            return handle_arp(tap, eth_frame, eth_len);
            
        case ETHERTYPE_IPV6:
            tap->stats.ipv6_packets++;
            
            // Check if ICMPv6 NDP (Neighbor Discovery Protocol)
            if (eth_len >= ETHERNET_HEADER_SIZE + 40 &&
                is_icmpv6_ndp(eth_frame + ETHERNET_HEADER_SIZE, eth_len - ETHERNET_HEADER_SIZE)) {
                // Handle NS (respond) and RA (learn gateway)
                handle_icmpv6_ndp(tap, eth_frame, eth_len);
            }
            
            {
                int result = translator_ethernet_to_ip(tap->translator, eth_frame, eth_len,
                                                      ip_packet_out, out_capacity);
                if (result > 0) {
                    tap->stats.eth_to_ip_packets++;
                    
                    // Check if fragmented
                    if (tap->fragment_handler && is_ipv6_fragmented(ip_packet_out, result)) {
                        tap->stats.ipv6_fragments++;
                        
                        // Process fragment
                        uint8_t reassembled[MAX_PACKET_SIZE];
                        int32_t reassembled_len = fragment_process_ipv6(
                            (FragmentHandler*)tap->fragment_handler,
                            ip_packet_out, result,
                            reassembled, sizeof(reassembled)
                        );
                        
                        if (reassembled_len > 0) {
                            // Reassembly complete!
                            tap->stats.fragments_reassembled++;
                            
                            if (reassembled_len <= (int32_t)out_capacity) {
                                memcpy(ip_packet_out, reassembled, reassembled_len);
                                return reassembled_len;
                            }
                        } else if (reassembled_len == 0) {
                            // More fragments needed
                            return 0;
                        }
                    }
                    
                    // Check for ICMPv6 error messages
                    if (result >= 40) {
                        uint8_t next_header = ip_packet_out[6];
                        if (next_header == 58) {  // ICMPv6
                            if (result >= 40 + 8) {
                                const uint8_t* icmpv6_packet = ip_packet_out + 40;
                                uint32_t icmpv6_len = result - 40;
                                
                                if (icmpv6_is_error(icmpv6_packet, icmpv6_len)) {
                                    tap->stats.icmpv6_errors_received++;
                                    
                                    // Parse error for logging/debugging
                                    if (tap->config.verbose) {
                                        ICMPErrorInfo info;
                                        if (icmpv6_parse_error(icmpv6_packet, icmpv6_len, &info) == 0) {
                                            printf("[VirtualTap] ICMPv6 error: type=%d code=%d", 
                                                   info.type, info.code);
                                            if (info.mtu > 0) {
                                                printf(" MTU=%d", info.mtu);
                                            }
                                            printf("\n");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return result;
            }
            
        default:
            tap->stats.other_packets++;
            return 0;
    }
}

uint32_t virtual_tap_get_learned_ip(VirtualTap* tap) {
    if (!tap) return 0;
    return translator_get_our_ip(tap->translator);
}

bool virtual_tap_get_gateway_mac(VirtualTap* tap, uint8_t mac_out[6]) {
    if (!tap || !mac_out) return false;
    return translator_get_gateway_mac(tap->translator, mac_out);
}

// WORKAROUND: Expose translator for direct gateway MAC setting (ARP-less operation)
void* virtual_tap_get_translator(VirtualTap* tap) {
    return tap ? tap->translator : NULL;
}

void virtual_tap_get_stats(VirtualTap* tap, VirtualTapStats* stats) {
    if (!tap || !stats) return;
    memcpy(stats, &tap->stats, sizeof(VirtualTapStats));
}

bool virtual_tap_has_pending_arp_reply(VirtualTap* tap) {
    if (!tap) return false;
    return tap->arp_reply_head != NULL;
}

int32_t virtual_tap_pop_arp_reply(VirtualTap* tap, uint8_t* arp_reply_out,
                                  uint32_t out_capacity) {
    if (!tap || !arp_reply_out) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    if (tap->arp_reply_head == NULL) {
        return 0;
    }
    
    ArpReplyNode* node = tap->arp_reply_head;
    tap->arp_reply_head = node->next;
    if (tap->arp_reply_head == NULL) {
        tap->arp_reply_tail = NULL;
    }
    
    if (node->length > out_capacity) {
        free(node->packet);
        free(node);
        return VTAP_ERROR_BUFFER_TOO_SMALL;
    }
    
    memcpy(arp_reply_out, node->packet, node->length);
    uint32_t len = node->length;
    
    free(node->packet);
    free(node);
    
    return len;
}

int32_t virtual_tap_send_arp_request(VirtualTap* tap, uint32_t target_ip) {
    if (!tap || target_ip == 0) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    uint32_t our_ip = translator_get_our_ip(tap->translator);
    if (our_ip == 0) {
        // Can't send ARP request without knowing our own IP
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    // Build ARP request
    uint8_t* request = (uint8_t*)malloc(ARP_PACKET_SIZE);
    if (!request) {
        return VTAP_ERROR_ALLOC_FAILED;
    }
    
    int result = arp_build_request(tap->config.our_mac, our_ip, target_ip,
                                   request, ARP_PACKET_SIZE);
    
    if (result != ARP_PACKET_SIZE) {
        free(request);
        return result;
    }
    
    // Queue ARP request (use same queue as ARP replies)
    arp_reply_queue_push(tap, request, ARP_PACKET_SIZE);
    tap->stats.arp_requests_sent++;
    
    if (tap->config.verbose) {
        printf("[VirtualTap] 📡 Sent ARP request for %d.%d.%d.%d\n",
               (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF,
               (target_ip >> 8) & 0xFF, target_ip & 0xFF);
    }
    
    return 0;
}
