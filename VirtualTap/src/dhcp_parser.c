#include "../include/virtual_tap_internal.h"

// ============================================================================
// DHCP Detection and Parsing
// ============================================================================

bool dhcp_is_dhcp_packet(const uint8_t* ip_packet, uint32_t len) {
    if (!ip_packet || len < 20) return false;
    
    // Check IP version
    uint8_t version = (ip_packet[0] >> 4) & 0x0F;
    if (version != 4) return false;
    
    // Check protocol (17 = UDP)
    uint8_t protocol = ip_packet[9];
    if (protocol != 17) return false;
    
    // Get IP header length
    uint8_t ihl = (ip_packet[0] & 0x0F) * 4;
    if (len < ihl + 8) return false;  // Need UDP header
    
    // Check UDP ports (67=server, 68=client)
    const uint8_t* udp_header = ip_packet + ihl;
    uint16_t src_port = read_u16_be(udp_header);
    uint16_t dst_port = read_u16_be(udp_header + 2);
    
    return (src_port == 67 || src_port == 68) && 
           (dst_port == 67 || dst_port == 68);
}

int dhcp_parse_packet(const uint8_t* ip_packet, uint32_t len, DhcpInfo* info) {
    if (!ip_packet || !info || len < 20) {
        return VTAP_ERROR_INVALID_PARAMS;
    }
    
    memset(info, 0, sizeof(DhcpInfo));
    
    // Get IP header length
    uint8_t ihl = (ip_packet[0] & 0x0F) * 4;
    if (len < ihl + 8) {
        return VTAP_ERROR_PARSE_FAILED;
    }
    
    // Get UDP payload
    const uint8_t* udp_header = ip_packet + ihl;
    uint16_t udp_len = read_u16_be(udp_header + 4);
    
    if (len < ihl + udp_len) {
        return VTAP_ERROR_PARSE_FAILED;
    }
    
    const uint8_t* dhcp_data = udp_header + 8;
    uint32_t dhcp_len = udp_len - 8;
    
    // DHCP packet structure:
    // [0]     Op (1=request, 2=reply)
    // [1]     Hardware type
    // [2]     Hardware addr length
    // [3]     Hops
    // [4-7]   Transaction ID
    // [8-9]   Seconds
    // [10-11] Flags
    // [12-15] Client IP
    // [16-19] Your IP (offered IP)
    // [20-23] Server IP
    // [24-27] Gateway IP
    // [28-43] Client hardware address
    // [44-107] Server name
    // [108-235] Boot filename
    // [236-239] Magic cookie (0x63825363)
    // [240+]  Options
    
    if (dhcp_len < 240) {
        return VTAP_ERROR_PARSE_FAILED;
    }
    
    // Check magic cookie
    uint32_t magic = read_u32_be(dhcp_data + 236);
    if (magic != 0x63825363) {
        return VTAP_ERROR_PARSE_FAILED;
    }
    
    // Extract offered IP (Your IP field)
    memcpy(info->offered_ip, dhcp_data + 16, 4);
    
    // Parse options
    const uint8_t* options = dhcp_data + 240;
    uint32_t options_len = dhcp_len - 240;
    uint32_t pos = 0;
    
    while (pos < options_len) {
        uint8_t opt_type = options[pos++];
        
        // End option
        if (opt_type == 255) break;
        
        // Pad option
        if (opt_type == 0) continue;
        
        // Need length
        if (pos >= options_len) break;
        uint8_t opt_len = options[pos++];
        
        // Need data
        if (pos + opt_len > options_len) break;
        const uint8_t* opt_data = options + pos;
        pos += opt_len;
        
        switch (opt_type) {
            case 1:  // Subnet mask
                if (opt_len >= 4) {
                    memcpy(info->subnet_mask, opt_data, 4);
                }
                break;
                
            case 3:  // Router (gateway)
                if (opt_len >= 4) {
                    memcpy(info->gateway, opt_data, 4);
                }
                break;
                
            case 6:  // DNS servers
                if (opt_len >= 4) {
                    memcpy(info->dns1, opt_data, 4);
                }
                if (opt_len >= 8) {
                    memcpy(info->dns2, opt_data + 4, 4);
                }
                break;
                
            case 53:  // DHCP message type
                if (opt_len >= 1) {
                    info->message_type = opt_data[0];
                }
                break;
        }
    }
    
    // Valid if we got message type
    info->valid = (info->message_type != 0);
    
    return info->valid ? 0 : VTAP_ERROR_PARSE_FAILED;
}
