#include "../include/virtual_tap_internal.h"

// ============================================================================
// ARP Table Implementation
// ============================================================================

ArpTable* arp_table_create(int64_t timeout_ms) {
    ArpTable* table = (ArpTable*)calloc(1, sizeof(ArpTable));
    if (!table) return NULL;
    
    table->timeout_ms = timeout_ms;
    // All entries initialized to 0 by calloc (ip=0 means empty)
    
    return table;
}

void arp_table_destroy(ArpTable* table) {
    if (table) {
        free(table);
    }
}

bool arp_table_lookup(ArpTable* table, uint32_t ip, uint8_t mac_out[6]) {
    if (!table || ip == 0) return false;
    
    int64_t now = get_time_ms();
    
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        ArpEntry* entry = &table->entries[i];
        if (entry->ip == ip) {
            // Check if expired (unless static)
            if (!entry->is_static && (now - entry->timestamp_ms) > table->timeout_ms) {
                entry->ip = 0; // Mark as empty
                return false;
            }
            memcpy(mac_out, entry->mac, 6);
            return true;
        }
    }
    
    return false;
}

void arp_table_insert(ArpTable* table, uint32_t ip, const uint8_t mac[6], bool is_static) {
    if (!table || ip == 0) return;
    
    int64_t now = get_time_ms();
    
    // Try to find existing entry or empty slot
    int empty_slot = -1;
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        ArpEntry* entry = &table->entries[i];
        
        // Update existing entry
        if (entry->ip == ip) {
            memcpy(entry->mac, mac, 6);
            entry->timestamp_ms = now;
            entry->is_static = is_static;
            return;
        }
        
        // Remember first empty slot
        if (empty_slot == -1 && entry->ip == 0) {
            empty_slot = i;
        }
    }
    
    // Insert in empty slot
    if (empty_slot != -1) {
        ArpEntry* entry = &table->entries[empty_slot];
        entry->ip = ip;
        memcpy(entry->mac, mac, 6);
        entry->timestamp_ms = now;
        entry->is_static = is_static;
        return;
    }
    
    // Table full - replace oldest non-static entry
    int oldest_idx = -1;
    int64_t oldest_time = now;
    
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        ArpEntry* entry = &table->entries[i];
        if (!entry->is_static && entry->timestamp_ms < oldest_time) {
            oldest_time = entry->timestamp_ms;
            oldest_idx = i;
        }
    }
    
    if (oldest_idx != -1) {
        ArpEntry* entry = &table->entries[oldest_idx];
        entry->ip = ip;
        memcpy(entry->mac, mac, 6);
        entry->timestamp_ms = now;
        entry->is_static = is_static;
    }
}

void arp_table_cleanup(ArpTable* table) {
    if (!table) return;
    
    int64_t now = get_time_ms();
    
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        ArpEntry* entry = &table->entries[i];
        if (entry->ip != 0 && !entry->is_static) {
            if ((now - entry->timestamp_ms) > table->timeout_ms) {
                entry->ip = 0; // Mark as empty
            }
        }
    }
}

uint32_t arp_table_count(ArpTable* table) {
    if (!table) return 0;
    
    uint32_t count = 0;
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        if (table->entries[i].ip != 0) {
            count++;
        }
    }
    return count;
}

// ============================================================================
// ARP Packet Parsing
// ============================================================================

int arp_parse_packet(const uint8_t* arp_packet, uint32_t len, ArpInfo* info) {
    if (!arp_packet || !info || len < 28) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    // ARP packet structure (28 bytes):
    // [0-1]   Hardware type (0x0001 for Ethernet)
    // [2-3]   Protocol type (0x0800 for IPv4)
    // [4]     Hardware size (6 for MAC)
    // [5]     Protocol size (4 for IPv4)
    // [6-7]   Operation (1=request, 2=reply)
    // [8-13]  Sender MAC
    // [14-17] Sender IP
    // [18-23] Target MAC
    // [24-27] Target IP
    
    uint16_t hw_type = read_u16_be(arp_packet);
    uint16_t proto_type = read_u16_be(arp_packet + 2);
    uint8_t hw_size = arp_packet[4];
    uint8_t proto_size = arp_packet[5];
    
    if (hw_type != ARP_HARDWARE_ETHERNET || proto_type != ARP_PROTOCOL_IPV4 ||
        hw_size != 6 || proto_size != 4) {
        return VTAP_ERROR_PARSE_FAILED;
    }
    
    info->operation = read_u16_be(arp_packet + 6);
    memcpy(info->sender_mac, arp_packet + 8, 6);
    info->sender_ip = read_u32_be(arp_packet + 14);
    memcpy(info->target_mac, arp_packet + 18, 6);
    info->target_ip = read_u32_be(arp_packet + 24);
    
    return 0;
}

// ============================================================================
// ARP Reply Building
// ============================================================================

int arp_build_reply(const uint8_t our_mac[6], uint32_t our_ip,
                    const uint8_t target_mac[6], uint32_t target_ip,
                    uint8_t* packet_out, uint32_t out_capacity) {
    if (!our_mac || !target_mac || !packet_out || out_capacity < ARP_PACKET_SIZE) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    // Build 42-byte ARP reply frame:
    // [0-5]   Dest MAC (target)
    // [6-11]  Src MAC (us)
    // [12-13] EtherType: 0x0806 (ARP)
    // [14-15] Hardware type: 0x0001
    // [16-17] Protocol type: 0x0800
    // [18]    Hardware size: 6
    // [19]    Protocol size: 4
    // [20-21] Operation: 0x0002 (Reply)
    // [22-27] Sender MAC (us)
    // [28-31] Sender IP (us)
    // [32-37] Target MAC (them)
    // [38-41] Target IP (them)
    
    // Ethernet header
    memcpy(packet_out, target_mac, 6);
    memcpy(packet_out + 6, our_mac, 6);
    write_u16_be(packet_out + 12, ETHERTYPE_ARP);
    
    // ARP header
    write_u16_be(packet_out + 14, ARP_HARDWARE_ETHERNET);
    write_u16_be(packet_out + 16, ARP_PROTOCOL_IPV4);
    packet_out[18] = 6;
    packet_out[19] = 4;
    write_u16_be(packet_out + 20, ARP_OP_REPLY);
    
    // ARP payload
    memcpy(packet_out + 22, our_mac, 6);
    write_u32_be(packet_out + 28, our_ip);
    memcpy(packet_out + 32, target_mac, 6);
    write_u32_be(packet_out + 38, target_ip);
    
    return ARP_PACKET_SIZE;
}

int arp_build_request(const uint8_t our_mac[6], uint32_t our_ip,
                      uint32_t target_ip,
                      uint8_t* packet_out, uint32_t out_capacity) {
    if (!our_mac || !packet_out || out_capacity < ARP_PACKET_SIZE) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    // Build 42-byte ARP request frame:
    // [0-5]   Dest MAC (broadcast)
    // [6-11]  Src MAC (us)
    // [12-13] EtherType: 0x0806 (ARP)
    // [14-15] Hardware type: 0x0001
    // [16-17] Protocol type: 0x0800
    // [18]    Hardware size: 6
    // [19]    Protocol size: 4
    // [20-21] Operation: 0x0001 (Request)
    // [22-27] Sender MAC (us)
    // [28-31] Sender IP (us)
    // [32-37] Target MAC (00:00:00:00:00:00)
    // [38-41] Target IP (who we're looking for)
    
    // Ethernet header - broadcast destination
    memset(packet_out, 0xFF, 6);  // Broadcast MAC
    memcpy(packet_out + 6, our_mac, 6);
    write_u16_be(packet_out + 12, ETHERTYPE_ARP);
    
    // ARP header
    write_u16_be(packet_out + 14, ARP_HARDWARE_ETHERNET);
    write_u16_be(packet_out + 16, ARP_PROTOCOL_IPV4);
    packet_out[18] = 6;
    packet_out[19] = 4;
    write_u16_be(packet_out + 20, ARP_OP_REQUEST);
    
    // ARP payload
    memcpy(packet_out + 22, our_mac, 6);
    write_u32_be(packet_out + 28, our_ip);
    memset(packet_out + 32, 0, 6);  // Target MAC unknown
    write_u32_be(packet_out + 38, target_ip);
    
    return ARP_PACKET_SIZE;
}
