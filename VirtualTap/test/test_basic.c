#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/virtual_tap.h"
#include "../include/icmpv6_handler.h"
#include "../include/dns_handler.h"
#include "../include/fragment_handler.h"
#include "../include/icmp_handler.h"

void test_create_destroy() {
    printf("Test 1: Create and destroy... ");
    
    VirtualTapConfig config = {
        .our_mac = {0x02, 0x00, 0x5E, 0x10, 0x20, 0x30},
        .our_ip = 0,
        .gateway_ip = 0,
        .handle_arp = true,
        .learn_ip = true,
        .learn_gateway_mac = true,
        .verbose = false,
        .enable_dns_cache = true
    };
    memset(config.gateway_mac, 0, 6);
    
    VirtualTap* tap = virtual_tap_create(&config);
    assert(tap != NULL);
    
    virtual_tap_destroy(tap);
    printf("✅\n");
}

void test_ip_to_ethernet() {
    printf("Test 2: IP to Ethernet conversion... ");
    
    VirtualTapConfig config = {
        .our_mac = {0x02, 0x00, 0x5E, 0x10, 0x20, 0x30},
        .our_ip = 0,
        .gateway_ip = 0,
        .handle_arp = true,
        .learn_ip = true,
        .learn_gateway_mac = true,
        .verbose = false,
        .enable_dns_cache = true
    };
    memset(config.gateway_mac, 0, 6);
    
    VirtualTap* tap = virtual_tap_create(&config);
    assert(tap != NULL);
    
    // Simple IPv4 packet (20 bytes minimum header)
    uint8_t ip_packet[20] = {
        0x45, 0x00, 0x00, 0x14,  // Version, IHL, TOS, Total Length
        0x00, 0x00, 0x00, 0x00,  // ID, Flags, Fragment Offset
        0x40, 0x11, 0x00, 0x00,  // TTL, Protocol (UDP), Checksum
        0xC0, 0xA8, 0x01, 0x64,  // Source IP: 192.168.1.100
        0xC0, 0xA8, 0x01, 0x01   // Dest IP: 192.168.1.1
    };
    
    uint8_t eth_frame[2048];
    int32_t result = virtual_tap_ip_to_ethernet(tap, ip_packet, 20, eth_frame, sizeof(eth_frame));
    
    assert(result == 34);  // 20 + 14
    
    // Check Ethernet header
    assert(eth_frame[12] == 0x08 && eth_frame[13] == 0x00);  // EtherType IPv4
    assert(eth_frame[6] == 0x02 && eth_frame[11] == 0x30);   // Source MAC
    
    // Check IP packet is intact
    assert(memcmp(eth_frame + 14, ip_packet, 20) == 0);
    
    VirtualTapStats stats;
    virtual_tap_get_stats(tap, &stats);
    assert(stats.ip_to_eth_packets == 1);
    
    virtual_tap_destroy(tap);
    printf("✅\n");
}

void test_ethernet_to_ip() {
    printf("Test 3: Ethernet to IP conversion... ");
    
    VirtualTapConfig config = {
        .our_mac = {0x02, 0x00, 0x5E, 0x10, 0x20, 0x30},
        .our_ip = 0,
        .gateway_ip = 0,
        .handle_arp = true,
        .learn_ip = true,
        .learn_gateway_mac = true,
        .verbose = false,
        .enable_dns_cache = true
    };
    memset(config.gateway_mac, 0, 6);
    
    VirtualTap* tap = virtual_tap_create(&config);
    assert(tap != NULL);
    
    // Ethernet frame with IPv4 packet
    uint8_t eth_frame[34] = {
        // Ethernet header
        0x02, 0x00, 0x5E, 0x10, 0x20, 0x30,  // Dest MAC
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Src MAC
        0x08, 0x00,                          // EtherType IPv4
        // IP packet
        0x45, 0x00, 0x00, 0x14,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xC0, 0xA8, 0x01, 0x01,  // Source IP: 192.168.1.1
        0xC0, 0xA8, 0x01, 0x64   // Dest IP: 192.168.1.100
    };
    
    uint8_t ip_packet[2048];
    int32_t result = virtual_tap_ethernet_to_ip(tap, eth_frame, 34, ip_packet, sizeof(ip_packet));
    
    assert(result == 20);  // 34 - 14
    
    // Check IP packet
    assert(ip_packet[0] == 0x45);  // Version + IHL
    assert(memcmp(ip_packet, eth_frame + 14, 20) == 0);
    
    VirtualTapStats stats;
    virtual_tap_get_stats(tap, &stats);
    assert(stats.eth_to_ip_packets == 1);
    assert(stats.ipv4_packets == 1);
    
    virtual_tap_destroy(tap);
    printf("✅\n");
}

void test_arp_handling() {
    printf("Test 4: ARP request handling... ");
    
    VirtualTapConfig config = {
        .our_mac = {0x02, 0x00, 0x5E, 0x10, 0x20, 0x30},
        .our_ip = 0xC0A80164,  // 192.168.1.100 in network byte order
        .gateway_ip = 0,
        .handle_arp = true,
        .learn_ip = false,
        .learn_gateway_mac = true,
        .verbose = false,
        .enable_dns_cache = true
    };
    memset(config.gateway_mac, 0, 6);
    
    VirtualTap* tap = virtual_tap_create(&config);
    assert(tap != NULL);
    
    // ARP request: Who has 192.168.1.100?
    uint8_t arp_request[42] = {
        // Ethernet header
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Dest MAC (broadcast)
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Src MAC
        0x08, 0x06,                          // EtherType ARP
        // ARP packet
        0x00, 0x01,                          // Hardware type: Ethernet
        0x08, 0x00,                          // Protocol type: IPv4
        0x06,                                // Hardware size: 6
        0x04,                                // Protocol size: 4
        0x00, 0x01,                          // Operation: Request
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Sender MAC
        0xC0, 0xA8, 0x01, 0x01,              // Sender IP: 192.168.1.1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Target MAC (unknown)
        0xC0, 0xA8, 0x01, 0x64               // Target IP: 192.168.1.100
    };
    
    uint8_t ip_packet[2048];
    int32_t result = virtual_tap_ethernet_to_ip(tap, arp_request, 42, ip_packet, sizeof(ip_packet));
    
    // ARP should be handled internally (return 0)
    assert(result == 0);
    
    // Should have pending ARP reply
    assert(virtual_tap_has_pending_arp_reply(tap));
    
    // Pop the reply
    uint8_t arp_reply[2048];
    result = virtual_tap_pop_arp_reply(tap, arp_reply, sizeof(arp_reply));
    assert(result == 42);
    
    // Check reply
    assert(arp_reply[12] == 0x08 && arp_reply[13] == 0x06);  // EtherType ARP
    assert(arp_reply[20] == 0x00 && arp_reply[21] == 0x02);  // Operation: Reply
    
    // Check sender is us
    assert(memcmp(arp_reply + 22, config.our_mac, 6) == 0);
    assert(arp_reply[28] == 0xC0 && arp_reply[31] == 0x64);  // Our IP
    
    VirtualTapStats stats;
    virtual_tap_get_stats(tap, &stats);
    assert(stats.arp_packets == 1);
    assert(stats.arp_requests_handled == 1);
    assert(stats.arp_replies_sent == 1);
    
    virtual_tap_destroy(tap);
    printf("✅\n");
}

void test_ipv6_to_ethernet() {
    printf("Test 5: IPv6 to Ethernet conversion... ");
    
    VirtualTapConfig config = {
        .our_mac = {0x02, 0x00, 0x5E, 0x10, 0x20, 0x30},
        .our_ip = 0,
        .gateway_ip = 0,
        .handle_arp = true,
        .learn_ip = true,
        .learn_gateway_mac = true,
        .verbose = false,
        .enable_dns_cache = true
    };
    memset(config.gateway_mac, 0, 6);
    
    VirtualTap* tap = virtual_tap_create(&config);
    assert(tap != NULL);
    
    // Simple IPv6 packet (40 bytes minimum header)
    uint8_t ipv6_packet[40] = {
        0x60, 0x00, 0x00, 0x00,  // Version, Traffic Class, Flow Label
        0x00, 0x00, 0x3B, 0x40,  // Payload Length, Next Header (no next), Hop Limit
        // Source IPv6: 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Dest IPv6: 2001:db8::2
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    };
    
    uint8_t eth_frame[2048];
    int32_t result = virtual_tap_ip_to_ethernet(tap, ipv6_packet, 40, eth_frame, sizeof(eth_frame));
    
    assert(result == 54);  // 40 + 14
    
    // Check Ethernet header
    assert(eth_frame[12] == 0x86 && eth_frame[13] == 0xDD);  // EtherType IPv6
    assert(eth_frame[6] == 0x02 && eth_frame[11] == 0x30);   // Source MAC
    
    // Check IPv6 packet is intact
    assert(memcmp(eth_frame + 14, ipv6_packet, 40) == 0);
    
    VirtualTapStats stats;
    virtual_tap_get_stats(tap, &stats);
    assert(stats.ip_to_eth_packets == 1);
    
    virtual_tap_destroy(tap);
    printf("✅\n");
}

void test_ipv6_from_ethernet() {
    printf("Test 6: IPv6 from Ethernet extraction... ");
    
    VirtualTapConfig config = {
        .our_mac = {0x02, 0x00, 0x5E, 0x10, 0x20, 0x30},
        .our_ip = 0,
        .gateway_ip = 0,
        .handle_arp = true,
        .learn_ip = true,
        .learn_gateway_mac = true,
        .verbose = false,
        .enable_dns_cache = true
    };
    memset(config.gateway_mac, 0, 6);
    
    VirtualTap* tap = virtual_tap_create(&config);
    assert(tap != NULL);
    
    // Ethernet frame with IPv6 packet
    uint8_t eth_frame[54] = {
        // Ethernet header
        0x02, 0x00, 0x5E, 0x10, 0x20, 0x30,  // Dest MAC
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Src MAC
        0x86, 0xDD,                          // EtherType IPv6
        // IPv6 packet
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x3B, 0x40,
        // Source IPv6
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Dest IPv6
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    };
    
    uint8_t ip_packet[2048];
    int32_t result = virtual_tap_ethernet_to_ip(tap, eth_frame, 54, ip_packet, sizeof(ip_packet));
    
    assert(result == 40);  // 54 - 14
    
    // Check IPv6 packet
    assert(ip_packet[0] == 0x60);  // Version 6
    assert(memcmp(ip_packet, eth_frame + 14, 40) == 0);
    
    VirtualTapStats stats;
    virtual_tap_get_stats(tap, &stats);
    assert(stats.eth_to_ip_packets == 1);
    assert(stats.ipv6_packets == 1);
    
    virtual_tap_destroy(tap);
    printf("✅\n");
}

void test_icmpv6_ra_parsing() {
    printf("Test 7: ICMPv6 Router Advertisement parsing... ");
    
    // Build minimal RA packet
    uint8_t ipv6_packet[88] = {0};  // 40 (IPv6) + 48 (RA with prefix option)
    
    // IPv6 header
    ipv6_packet[0] = 0x60;  // Version 6
    ipv6_packet[4] = 0;     // Payload length high
    ipv6_packet[5] = 48;    // Payload length low
    ipv6_packet[6] = 58;    // Next header: ICMPv6
    ipv6_packet[7] = 255;   // Hop limit
    
    // Source: fe80::1 (link-local gateway)
    ipv6_packet[8] = 0xfe;
    ipv6_packet[9] = 0x80;
    ipv6_packet[23] = 0x01;
    
    // Dest: ff02::1 (all nodes)
    ipv6_packet[24] = 0xff;
    ipv6_packet[25] = 0x02;
    ipv6_packet[39] = 0x01;
    
    // ICMPv6 RA header
    ipv6_packet[40] = 134;  // Type: Router Advertisement
    ipv6_packet[41] = 0;    // Code
    ipv6_packet[42] = 0;    // Checksum (not validated in test)
    ipv6_packet[43] = 0;
    ipv6_packet[44] = 64;   // Cur hop limit
    ipv6_packet[45] = 0;    // Flags (M=0, O=0)
    ipv6_packet[46] = 0x04; // Router lifetime high (1024 seconds)
    ipv6_packet[47] = 0x00; // Router lifetime low
    
    // Prefix Information Option (type 3, length 4)
    ipv6_packet[56] = 3;    // Type
    ipv6_packet[57] = 4;    // Length (32 bytes)
    ipv6_packet[58] = 64;   // Prefix length
    ipv6_packet[59] = 0xC0; // Flags (L=1, A=1)
    // Valid lifetime: 86400 seconds
    ipv6_packet[60] = 0x00;
    ipv6_packet[61] = 0x01;
    ipv6_packet[62] = 0x51;
    ipv6_packet[63] = 0x80;
    // Preferred lifetime: 14400 seconds
    ipv6_packet[64] = 0x00;
    ipv6_packet[65] = 0x00;
    ipv6_packet[66] = 0x38;
    ipv6_packet[67] = 0x40;
    // Prefix: 2001:db8::/64
    ipv6_packet[72] = 0x20;
    ipv6_packet[73] = 0x01;
    ipv6_packet[74] = 0x0d;
    ipv6_packet[75] = 0xb8;
    
    IPv6RAInfo ra_info;
    bool result = parse_router_advertisement(ipv6_packet, 88, &ra_info);
    
    assert(result == true);
    assert(ra_info.has_gateway == true);
    assert(ra_info.has_prefix == true);
    assert(ra_info.prefix_length == 64);
    assert(ra_info.prefix[0] == 0x20);
    assert(ra_info.prefix[1] == 0x01);
    assert(ra_info.prefix[2] == 0x0d);
    assert(ra_info.prefix[3] == 0xb8);
    assert(ra_info.gateway[0] == 0xfe);
    assert(ra_info.gateway[1] == 0x80);
    assert(ra_info.valid_lifetime == 86400);
    assert(ra_info.preferred_lifetime == 14400);
    
    printf("✅\n");
}

void test_icmpv6_neighbor_solicitation() {
    printf("Test 8: ICMPv6 Neighbor Solicitation detection... ");
    
    // Build NS packet
    uint8_t ipv6_packet[64] = {0};  // 40 (IPv6) + 24 (NS minimum)
    
    // IPv6 header
    ipv6_packet[0] = 0x60;  // Version 6
    ipv6_packet[4] = 0;     // Payload length high
    ipv6_packet[5] = 24;    // Payload length low
    ipv6_packet[6] = 58;    // Next header: ICMPv6
    ipv6_packet[7] = 255;   // Hop limit
    
    // Source: fe80::2
    ipv6_packet[8] = 0xfe;
    ipv6_packet[9] = 0x80;
    ipv6_packet[23] = 0x02;
    
    // Dest: ff02::1:ff00:1 (solicited-node multicast)
    ipv6_packet[24] = 0xff;
    ipv6_packet[25] = 0x02;
    ipv6_packet[37] = 0xff;
    ipv6_packet[39] = 0x01;
    
    // ICMPv6 NS
    ipv6_packet[40] = 135;  // Type: Neighbor Solicitation
    ipv6_packet[41] = 0;    // Code
    
    // Target: 2001:db8::1
    ipv6_packet[48] = 0x20;
    ipv6_packet[49] = 0x01;
    ipv6_packet[50] = 0x0d;
    ipv6_packet[51] = 0xb8;
    ipv6_packet[63] = 0x01;
    
    uint8_t target_ipv6[16];
    bool result = is_neighbor_solicitation(ipv6_packet, 64, target_ipv6);
    
    assert(result == true);
    assert(target_ipv6[0] == 0x20);
    assert(target_ipv6[1] == 0x01);
    assert(target_ipv6[2] == 0x0d);
    assert(target_ipv6[3] == 0xb8);
    assert(target_ipv6[15] == 0x01);
    
    printf("✅\n");
}

void test_icmpv6_neighbor_advertisement() {
    printf("Test 9: ICMPv6 Neighbor Advertisement building... ");
    
    uint8_t our_ipv6[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0x01
    };
    uint8_t our_mac[6] = {0x02, 0x00, 0x5E, 0x10, 0x20, 0x30};
    uint8_t solicitor_ipv6[16] = {
        0xfe, 0x80, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0x02
    };
    
    uint8_t na_packet[72];
    int32_t result = build_neighbor_advertisement(
        our_ipv6, our_mac, solicitor_ipv6, na_packet, 72
    );
    
    assert(result == 72);
    
    // Check IPv6 header
    assert((na_packet[0] >> 4) == 6);  // Version 6
    assert(na_packet[6] == 58);         // Next header: ICMPv6
    
    // Check source = our IPv6
    assert(memcmp(na_packet + 8, our_ipv6, 16) == 0);
    
    // Check dest = solicitor IPv6
    assert(memcmp(na_packet + 24, solicitor_ipv6, 16) == 0);
    
    // Check ICMPv6 header
    assert(na_packet[40] == 136);  // Type: Neighbor Advertisement
    assert(na_packet[41] == 0);    // Code
    
    // Check flags (Solicited + Override)
    assert((na_packet[44] & 0x60) == 0x60);
    
    // Check target = our IPv6
    assert(memcmp(na_packet + 48, our_ipv6, 16) == 0);
    
    // Check target link-layer address option
    assert(na_packet[64] == 2);  // Type: Target Link-Layer
    assert(na_packet[65] == 1);  // Length: 1 (8 bytes)
    assert(memcmp(na_packet + 66, our_mac, 6) == 0);
    
    printf("✅\n");
}

void test_dns_query_parsing() {
    printf("Test 10: DNS query parsing... ");
    
    // Build minimal DNS query for google.com A record
    uint8_t udp_packet[48] = {
        // UDP header
        0xC0, 0x01,  // Source port 49153
        0x00, 0x35,  // Dest port 53 (DNS)
        0x00, 0x28,  // Length 40
        0x00, 0x00,  // Checksum
        
        // DNS header
        0x12, 0x34,  // Transaction ID
        0x01, 0x00,  // Flags: standard query
        0x00, 0x01,  // QDCOUNT = 1
        0x00, 0x00,  // ANCOUNT = 0
        0x00, 0x00,  // NSCOUNT = 0
        0x00, 0x00,  // ARCOUNT = 0
        
        // Query: google.com
        0x06, 'g', 'o', 'o', 'g', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        
        0x00, 0x01,  // Type A
        0x00, 0x01   // Class IN
    };
    
    assert(dns_is_query(udp_packet, sizeof(udp_packet)) == true);
    
    DnsQuery query;
    assert(dns_parse_query(udp_packet, sizeof(udp_packet), &query) == true);
    assert(query.valid == true);
    assert(query.transaction_id == 0x1234);
    assert(query.type == 1);  // A record
    assert(strcmp(query.name, "google.com") == 0);
    
    printf("✅\n");
}

void test_dns_cache() {
    printf("Test 11: DNS cache operations... ");
    
    DnsCache* cache = dns_cache_create();
    assert(cache != NULL);
    
    // Build fake DNS response
    uint8_t response[64] = {
        0x12, 0x34,  // Transaction ID
        0x81, 0x80,  // Response flags
        0x00, 0x01,  // QDCOUNT
        0x00, 0x01,  // ANCOUNT
        0x00, 0x00, 0x00, 0x00,  // NSCOUNT, ARCOUNT
    };
    
    // Insert into cache
    dns_cache_insert(cache, "example.com", DNS_TYPE_A, response, 64, 300);
    
    // Look up (should hit)
    uint8_t cached_response[128];
    int32_t len = dns_cache_lookup(cache, "example.com", DNS_TYPE_A, 
                                   cached_response, sizeof(cached_response));
    assert(len == 64);
    assert(memcmp(cached_response, response, 64) == 0);
    
    // Look up different name (should miss)
    len = dns_cache_lookup(cache, "notfound.com", DNS_TYPE_A,
                          cached_response, sizeof(cached_response));
    assert(len == 0);
    
    // Get stats
    uint32_t valid, expired;
    dns_cache_stats(cache, &valid, &expired);
    assert(valid == 1);
    assert(expired == 0);
    
    dns_cache_destroy(cache);
    printf("✅\n");
}

void test_ipv4_fragmentation() {
    printf("Test 12: IPv4 fragmentation detection and reassembly... ");
    
    FragmentHandler* handler = fragment_handler_create();
    assert(handler != NULL);
    
    // Build first fragment (offset 0, MF=1, payload 24 bytes = 8-byte aligned)
    uint8_t frag1[44] = {
        0x45, 0x00, 0x00, 0x2C,  // Version, IHL, TOS, Total Length (44)
        0x12, 0x34,              // ID
        0x20, 0x00,              // Flags (MF=1), Offset (0)
        0x40, 0x11,              // TTL, Protocol (UDP)
        0x00, 0x00,              // Checksum
        0xC0, 0xA8, 0x01, 0x0A,  // Source IP: 192.168.1.10
        0xC0, 0xA8, 0x01, 0x01,  // Dest IP: 192.168.1.1
        // Payload (24 bytes, 8-byte aligned)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    };
    
    assert(is_ipv4_fragmented(frag1, sizeof(frag1)) == true);
    
    uint8_t reassembled[128];
    int32_t len = fragment_process_ipv4(handler, frag1, sizeof(frag1),
                                        reassembled, sizeof(reassembled));
    assert(len == 0);  // More fragments needed
    
    // Build second fragment (offset 24 bytes = 3 * 8, MF=0 - last fragment)
    uint8_t frag2[36] = {
        0x45, 0x00, 0x00, 0x24,  // Version, IHL, TOS, Total Length (36)
        0x12, 0x34,              // Same ID
        0x00, 0x03,              // Flags (MF=0), Offset (24 bytes / 8 = 3)
        0x40, 0x11,              // TTL, Protocol
        0x00, 0x00,              // Checksum
        0xC0, 0xA8, 0x01, 0x0A,  // Source IP
        0xC0, 0xA8, 0x01, 0x01,  // Dest IP
        // Payload (16 bytes)
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28
    };
    
    len = fragment_process_ipv4(handler, frag2, sizeof(frag2),
                                reassembled, sizeof(reassembled));
    assert(len > 0);  // Should be reassembled now
    
    // Check reassembled packet
    uint16_t total_len = (reassembled[2] << 8) | reassembled[3];
    assert(total_len == 20 + 24 + 16);  // IP header + frag1 payload + frag2 payload
    
    // Verify fragment flags are cleared
    assert((reassembled[6] & 0x20) == 0);  // MF flag cleared
    assert(reassembled[7] == 0);           // Offset cleared
    
    fragment_handler_destroy(handler);
    printf("✅\n");
}

void test_icmp_error_parsing() {
    printf("Test 13: ICMP error message parsing... ");
    
    // Build ICMP Destination Unreachable (type 3) with fragmentation needed (code 4)
    uint8_t icmp_packet[56] = {
        // ICMP header
        0x03,              // Type: Dest Unreachable
        0x04,              // Code: Fragmentation Needed
        0x00, 0x00,        // Checksum (unused in test)
        0x00, 0x00,        // Unused
        0x05, 0xDC,        // MTU: 1500
        // Embedded IP header (original packet that triggered the error)
        0x45, 0x00, 0x00, 0x30,  // Version, IHL, TOS, Total Length
        0x12, 0x34, 0x00, 0x00,  // ID, Flags, Offset
        0x40, 0x11,              // TTL, Protocol (UDP)
        0x00, 0x00,              // Checksum
        0xC0, 0xA8, 0x01, 0x0A,  // Source IP: 192.168.1.10
        0x08, 0x08, 0x08, 0x08,  // Dest IP: 8.8.8.8
        // Embedded UDP header (first 8 bytes)
        0x04, 0xD2,              // Source Port: 1234
        0x00, 0x35,              // Dest Port: 53 (DNS)
        0x00, 0x00, 0x00, 0x00,  // Length, Checksum
        // Some payload (for completeness)
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    
    assert(icmp_is_error(icmp_packet, sizeof(icmp_packet)) == true);
    
    ICMPErrorInfo info;
    assert(icmp_parse_error(icmp_packet, sizeof(icmp_packet), &info) == 0);
    
    assert(info.is_error == true);
    assert(info.type == 3);
    assert(info.code == 4);
    assert(info.mtu == 1500);
    assert(info.embedded_protocol == 17);  // UDP
    assert(info.embedded_src_ip == 0xC0A8010A);  // 192.168.1.10
    assert(info.embedded_dst_ip == 0x08080808);  // 8.8.8.8
    assert(info.embedded_src_port == 1234);
    assert(info.embedded_dst_port == 53);
    
    printf("✅\n");
}

void test_icmpv6_error_parsing() {
    printf("Test 14: ICMPv6 error message parsing... ");
    
    // Build ICMPv6 Packet Too Big (type 2)
    uint8_t icmpv6_packet[88] = {
        // ICMPv6 header
        0x02,              // Type: Packet Too Big
        0x00,              // Code: 0
        0x00, 0x00,        // Checksum (unused in test)
        0x00, 0x00, 0x05, 0xDC,  // MTU: 1500
        // Embedded IPv6 header (original packet)
        0x60, 0x00, 0x00, 0x00,  // Version, Traffic Class, Flow Label
        0x00, 0x10,              // Payload Length: 16
        0x11,                    // Next Header: UDP
        0x40,                    // Hop Limit: 64
        // Source IPv6: 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Dest IPv6: 2001:db8::2
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        // Embedded UDP header
        0x04, 0xD2,              // Source Port: 1234
        0x00, 0x35,              // Dest Port: 53 (DNS)
        0x00, 0x10, 0x00, 0x00,  // Length, Checksum
        // Some payload
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    
    assert(icmpv6_is_error(icmpv6_packet, sizeof(icmpv6_packet)) == true);
    
    ICMPErrorInfo info;
    assert(icmpv6_parse_error(icmpv6_packet, sizeof(icmpv6_packet), &info) == 0);
    
    assert(info.is_error == true);
    assert(info.type == 2);
    assert(info.code == 0);
    assert(info.mtu == 1500);
    assert(info.embedded_protocol == 17);  // UDP
    
    // Check IPv6 addresses
    uint8_t expected_src[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t expected_dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    assert(memcmp(info.embedded_src_ipv6, expected_src, 16) == 0);
    assert(memcmp(info.embedded_dst_ipv6, expected_dst, 16) == 0);
    
    assert(info.embedded_src_port == 1234);
    assert(info.embedded_dst_port == 53);
    
    printf("✅\n");
}

int main() {
    printf("=== VirtualTap C Implementation Tests ===\n\n");
    
    test_create_destroy();
    test_ip_to_ethernet();
    test_ethernet_to_ip();
    test_arp_handling();
    test_ipv6_to_ethernet();
    test_ipv6_from_ethernet();
    test_icmpv6_ra_parsing();
    test_icmpv6_neighbor_solicitation();
    test_icmpv6_neighbor_advertisement();
    test_dns_query_parsing();
    test_dns_cache();
    test_ipv4_fragmentation();
    test_icmp_error_parsing();
    test_icmpv6_error_parsing();
    
    printf("\n✅ All tests passed!\n");
    return 0;
}
