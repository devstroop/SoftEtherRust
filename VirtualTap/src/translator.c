#include "../include/virtual_tap_internal.h"

// ============================================================================
// Translator Implementation
// ============================================================================

Translator* translator_create(const uint8_t our_mac[6], bool handle_arp,
                              bool learn_gateway_mac, bool verbose) {
    if (!our_mac) return NULL;
    
    Translator* t = (Translator*)calloc(1, sizeof(Translator));
    if (!t) return NULL;
    
    memcpy(t->our_mac, our_mac, 6);
    t->our_ip = 0;
    t->gateway_ip = 0;
    memset(t->gateway_mac, 0, 6);
    memset(t->our_ipv6, 0, 16);
    memset(t->gateway_ipv6, 0, 16);
    t->has_ipv6 = false;
    t->has_ipv6_gateway = false;
    t->last_gateway_learn_ms = 0;
    t->handle_arp = handle_arp;
    t->learn_gateway_mac = learn_gateway_mac;
    t->verbose = verbose;
    t->packets_l2_to_l3 = 0;
    t->packets_l3_to_l2 = 0;
    t->arp_replies_learned = 0;
    
    return t;
}

void translator_destroy(Translator* t) {
    if (t) {
        free(t);
    }
}

// ============================================================================
// IP to Ethernet (L3 → L2)
// ============================================================================

int translator_ip_to_ethernet(Translator* t, const uint8_t* ip_packet, uint32_t ip_len,
                              const uint8_t* dest_mac, uint8_t* eth_out, uint32_t out_capacity) {
    if (!t || !ip_packet || !eth_out || ip_len == 0) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    if (out_capacity < ip_len + ETHERNET_HEADER_SIZE) {
        return VTAP_ERROR_BUFFER_TOO_SMALL;
    }
    
    // Detect IP version from first byte
    uint8_t version = (ip_packet[0] >> 4) & 0x0F;
    uint16_t ethertype;
    
    if (version == 4) {
        ethertype = ETHERTYPE_IPV4;
        
        // DO NOT learn IP from outgoing packets - wait for DHCP from server
        // Learning from outgoing would use the temporary tunnel IP (10.0.0.1)
        // instead of the real DHCP-assigned IP
    } else if (version == 6) {
        ethertype = ETHERTYPE_IPV6;
        
        // DO NOT learn IPv6 from outgoing packets - wait for server responses
        // Learning from outgoing would use temporary addresses instead of real ones
    } else {
        return VTAP_ERROR_PARSE_FAILED;
    }
    
    // Determine destination MAC
    uint8_t dest[6];
    if (dest_mac) {
        memcpy(dest, dest_mac, 6);
    } else {
        // Check if gateway MAC is known
        bool has_gateway = false;
        for (int i = 0; i < 6; i++) {
            if (t->gateway_mac[i] != 0) {
                has_gateway = true;
                break;
            }
        }
        
        if (has_gateway) {
            memcpy(dest, t->gateway_mac, 6);
        } else {
            // Use broadcast
            memset(dest, 0xFF, 6);
        }
    }
    
    // Build Ethernet frame: [6 dest][6 src][2 type][IP payload]
    memcpy(eth_out, dest, 6);
    memcpy(eth_out + 6, t->our_mac, 6);
    write_u16_be(eth_out + 12, ethertype);
    memcpy(eth_out + ETHERNET_HEADER_SIZE, ip_packet, ip_len);
    
    t->packets_l3_to_l2++;
    
    return ip_len + ETHERNET_HEADER_SIZE;
}

// ============================================================================
// Ethernet to IP (L2 → L3)
// ============================================================================

int translator_ethernet_to_ip(Translator* t, const uint8_t* eth_frame, uint32_t eth_len,
                              uint8_t* ip_out, uint32_t out_capacity) {
    if (!t || !eth_frame || !ip_out || eth_len < ETHERNET_HEADER_SIZE) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    // Extract EtherType
    uint16_t ethertype = read_u16_be(eth_frame + 12);
    
    // Learn our IP from INCOMING packets
    if (ethertype == ETHERTYPE_IPV4 && eth_len >= ETHERNET_HEADER_SIZE + 20) {
        const uint8_t* ip_header = eth_frame + ETHERNET_HEADER_SIZE;
        
        // Check if this is a DHCP packet (UDP ports 67/68)
        uint8_t protocol = ip_header[9];
        if (protocol == 17 && t->our_ip == 0) {  // UDP
            uint8_t ihl = (ip_header[0] & 0x0F) * 4;
            if (eth_len >= ETHERNET_HEADER_SIZE + ihl + 8) {
                const uint8_t* udp_header = ip_header + ihl;
                uint16_t src_port = read_u16_be(udp_header);
                uint16_t dst_port = read_u16_be(udp_header + 2);
                
                // DHCP server response (port 67 → 68)
                if (src_port == 67 && dst_port == 68) {
                    DhcpInfo dhcp;
                    if (dhcp_parse_packet(ip_header, eth_len - ETHERNET_HEADER_SIZE, &dhcp) == 0) {
                        // DHCP OFFER (2) or ACK (5) - learn offered IP
                        if ((dhcp.message_type == 2 || dhcp.message_type == 5) && 
                            dhcp.offered_ip[0] != 0) {
                            t->our_ip = read_u32_be(dhcp.offered_ip);
                            if (t->verbose) {
                                printf("[Translator] ✅ Learned IP from DHCP %s: %d.%d.%d.%d\n",
                                       dhcp.message_type == 2 ? "OFFER" : "ACK",
                                       dhcp.offered_ip[0], dhcp.offered_ip[1],
                                       dhcp.offered_ip[2], dhcp.offered_ip[3]);
                            }
                        }
                    }
                }
            }
        }
        
        // Fallback: learn from destination IP if not broadcast (for non-DHCP packets)
        if (t->our_ip == 0) {
            uint32_t dest_ip = read_u32_be(ip_header + 16);  // Destination IP
            if (dest_ip != 0xFFFFFFFF && dest_ip != 0) {  // Not broadcast, not zero
                t->our_ip = dest_ip;
                if (t->verbose) {
                    printf("[Translator] ✅ Learned our IPv4 from INCOMING packet: %d.%d.%d.%d\n",
                           (dest_ip >> 24) & 0xFF, (dest_ip >> 16) & 0xFF,
                           (dest_ip >> 8) & 0xFF, dest_ip & 0xFF);
                }
            }
        }
    }
    
    // Learn our IPv6 from INCOMING packets (destination IPv6 = our IPv6)
    if (ethertype == ETHERTYPE_IPV6 && eth_len >= ETHERNET_HEADER_SIZE + 40 && !t->has_ipv6) {
        uint8_t dest_ipv6[16];
        extract_ipv6_address(eth_frame + ETHERNET_HEADER_SIZE, 24, dest_ipv6);  // Dest at offset 24
        
        // Learn if not link-local and not multicast
        if (!is_ipv6_link_local(dest_ipv6) && (dest_ipv6[0] != 0xFF)) {
            memcpy(t->our_ipv6, dest_ipv6, 16);
            t->has_ipv6 = true;
            if (t->verbose) {
                printf("[Translator] ✅ Learned our IPv6 from INCOMING packet\n");
            }
        }
    }
    
    // Learn gateway MAC from source MAC if this is from gateway
    if (t->learn_gateway_mac && t->gateway_ip != 0) {
        // Check if source IP (for IPv4) matches gateway
        if (ethertype == ETHERTYPE_IPV4 && eth_len >= ETHERNET_HEADER_SIZE + 20) {
            uint32_t src_ip = read_u32_be(eth_frame + ETHERNET_HEADER_SIZE + 12);
            if (src_ip == t->gateway_ip) {
                const uint8_t* src_mac = eth_frame + 6;
                bool different = false;
                for (int i = 0; i < 6; i++) {
                    if (t->gateway_mac[i] != src_mac[i]) {
                        different = true;
                        break;
                    }
                }
                if (different) {
                    memcpy(t->gateway_mac, src_mac, 6);
                    t->last_gateway_learn_ms = get_time_ms();
                    if (t->verbose) {
                        printf("[Translator] Learned gateway MAC from incoming IPv4 packet\n");
                    }
                }
            }
        }
        
        // Check if source IPv6 matches gateway
        if (ethertype == ETHERTYPE_IPV6 && eth_len >= ETHERNET_HEADER_SIZE + 40 && t->has_ipv6_gateway) {
            uint8_t src_ipv6[16];
            extract_ipv6_address(eth_frame + ETHERNET_HEADER_SIZE, 8, src_ipv6);
            if (memcmp(src_ipv6, t->gateway_ipv6, 16) == 0) {
                const uint8_t* src_mac = eth_frame + 6;
                bool different = false;
                for (int i = 0; i < 6; i++) {
                    if (t->gateway_mac[i] != src_mac[i]) {
                        different = true;
                        break;
                    }
                }
                if (different) {
                    memcpy(t->gateway_mac, src_mac, 6);
                    t->last_gateway_learn_ms = get_time_ms();
                    if (t->verbose) {
                        printf("[Translator] Learned gateway MAC from incoming IPv6 packet\n");
                    }
                }
            }
        }
    }
    
    // Handle by EtherType
    if (ethertype == ETHERTYPE_IPV4 || ethertype == ETHERTYPE_IPV6) {
        uint32_t ip_len = eth_len - ETHERNET_HEADER_SIZE;
        
        if (out_capacity < ip_len) {
            return VTAP_ERROR_BUFFER_TOO_SMALL;
        }
        
        memcpy(ip_out, eth_frame + ETHERNET_HEADER_SIZE, ip_len);
        t->packets_l2_to_l3++;
        return ip_len;
    } else if (ethertype == ETHERTYPE_ARP) {
        // ARP handled separately
        return 0;
    } else {
        // Unknown protocol
        return 0;
    }
}

// ============================================================================
// Getters and Setters
// ============================================================================

uint32_t translator_get_our_ip(Translator* t) {
    return t ? t->our_ip : 0;
}

void translator_set_our_ip(Translator* t, uint32_t ip) {
    if (t) {
        t->our_ip = ip;
    }
}

uint32_t translator_get_gateway_ip(Translator* t) {
    return t ? t->gateway_ip : 0;
}

void translator_set_gateway_ip(Translator* t, uint32_t ip) {
    if (t) {
        t->gateway_ip = ip;
    }
}

bool translator_get_gateway_mac(Translator* t, uint8_t mac_out[6]) {
    if (!t || !mac_out) return false;
    
    bool has_mac = false;
    for (int i = 0; i < 6; i++) {
        if (t->gateway_mac[i] != 0) {
            has_mac = true;
            break;
        }
    }
    
    if (has_mac) {
        memcpy(mac_out, t->gateway_mac, 6);
    }
    
    return has_mac;
}

void translator_set_gateway_mac(Translator* t, const uint8_t mac[6]) {
    if (t && mac) {
        memcpy(t->gateway_mac, mac, 6);
        t->last_gateway_learn_ms = get_time_ms();
    }
}
