/*
 * Test VirtualTap DHCP Builder API
 * Verifies dhcp_build_discover() and dhcp_build_request() generate valid packets
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "../include/virtual_tap.h"

// Helper to print packet in hex
static void print_hex(const uint8_t *data, uint32_t len, const char *label) {
    printf("%s (%u bytes):\n", label, len);
    for (uint32_t i = 0; i < len && i < 128; i++) {  // Limit to 128 bytes
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len > 128) printf("... (%u more bytes)\n", len - 128);
    printf("\n");
}

// Verify Ethernet header is broadcast
static void verify_ethernet_broadcast(const uint8_t *pkt, const char *test_name) {
    printf("\n[%s] Verifying Ethernet header...\n", test_name);
    
    // Check destination MAC is broadcast (FF:FF:FF:FF:FF:FF)
    assert(pkt[0] == 0xFF && pkt[1] == 0xFF && pkt[2] == 0xFF &&
           pkt[3] == 0xFF && pkt[4] == 0xFF && pkt[5] == 0xFF);
    printf("  ✅ Destination MAC is broadcast\n");
    
    // Check EtherType is IPv4 (0x0800)
    assert(pkt[12] == 0x08 && pkt[13] == 0x00);
    printf("  ✅ EtherType is IPv4 (0x0800)\n");
}

// Verify IP header
static void verify_ip_header(const uint8_t *pkt, const char *test_name) {
    printf("\n[%s] Verifying IP header...\n", test_name);
    
    const uint8_t *ip = pkt + 14;  // Skip Ethernet
    
    // Check IP version (4) and header length (5 * 4 = 20 bytes)
    assert(ip[0] == 0x45);  // Version 4, header length 20 bytes
    printf("  ✅ IP version 4, header length 20 bytes\n");
    
    // Check protocol is UDP (17)
    assert(ip[9] == 17);
    printf("  ✅ Protocol is UDP (17)\n");
    
    // Check source IP is 0.0.0.0
    assert(ip[12] == 0 && ip[13] == 0 && ip[14] == 0 && ip[15] == 0);
    printf("  ✅ Source IP is 0.0.0.0\n");
    
    // Check dest IP is 255.255.255.255
    assert(ip[16] == 255 && ip[17] == 255 && ip[18] == 255 && ip[19] == 255);
    printf("  ✅ Dest IP is 255.255.255.255\n");
}

// Verify UDP header
static void verify_udp_header(const uint8_t *pkt, const char *test_name) {
    printf("\n[%s] Verifying UDP header...\n", test_name);
    
    const uint8_t *udp = pkt + 14 + 20;  // Skip Ethernet + IP
    
    // Check source port (68 = DHCP client)
    assert(udp[0] == 0x00 && udp[1] == 68);
    printf("  ✅ Source port is 68 (DHCP client)\n");
    
    // Check dest port (67 = DHCP server)
    assert(udp[2] == 0x00 && udp[3] == 67);
    printf("  ✅ Dest port is 67 (DHCP server)\n");
}

// Verify DHCP header
static void verify_dhcp_header(const uint8_t *pkt, uint32_t xid, const uint8_t *mac, const char *test_name) {
    printf("\n[%s] Verifying DHCP header...\n", test_name);
    
    const uint8_t *dhcp = pkt + 14 + 20 + 8;  // Skip Ethernet + IP + UDP
    
    // Check op = BOOTREQUEST (1)
    assert(dhcp[0] == 0x01);
    printf("  ✅ op = BOOTREQUEST (1)\n");
    
    // Check htype = Ethernet (1)
    assert(dhcp[1] == 0x01);
    printf("  ✅ htype = Ethernet (1)\n");
    
    // Check hlen = 6
    assert(dhcp[2] == 0x06);
    printf("  ✅ hlen = 6\n");
    
    // Check transaction ID
    uint32_t pkt_xid = (dhcp[4] << 24) | (dhcp[5] << 16) | (dhcp[6] << 8) | dhcp[7];
    assert(pkt_xid == xid);
    printf("  ✅ Transaction ID matches: 0x%08x\n", pkt_xid);
    
    // Check client MAC address (at offset 28)
    assert(memcmp(&dhcp[28], mac, 6) == 0);
    printf("  ✅ Client MAC matches: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    // Check magic cookie (at offset 236)
    assert(dhcp[236] == 0x63 && dhcp[237] == 0x82 && 
           dhcp[238] == 0x53 && dhcp[239] == 0x63);
    printf("  ✅ DHCP magic cookie present (0x63825363)\n");
}

// Test DHCP DISCOVER packet generation
static void test_dhcp_discover(void) {
    printf("\n========================================\n");
    printf("TEST: DHCP DISCOVER Packet Generation\n");
    printf("========================================\n");
    
    uint8_t client_mac[6] = {0x00, 0x50, 0x56, 0xC0, 0x00, 0x01};
    uint32_t xid = 0x12345678;
    uint8_t buffer[400];
    
    // Build DISCOVER packet
    int32_t len = dhcp_build_discover(client_mac, xid, buffer, sizeof(buffer));
    
    printf("\nResult: %d bytes\n", len);
    assert(len > 0);
    assert(len >= 280);  // Min size: Ethernet(14) + IP(20) + UDP(8) + DHCP(240+options)
    
    print_hex(buffer, len, "DHCP DISCOVER packet");
    
    // Verify packet structure
    verify_ethernet_broadcast(buffer, "DHCP DISCOVER");
    verify_ip_header(buffer, "DHCP DISCOVER");
    verify_udp_header(buffer, "DHCP DISCOVER");
    verify_dhcp_header(buffer, xid, client_mac, "DHCP DISCOVER");
    
    // Check DHCP message type option (53 = 1 = DISCOVER)
    const uint8_t *dhcp_options = buffer + 14 + 20 + 8 + 240;
    assert(dhcp_options[0] == 53);  // Option 53
    assert(dhcp_options[1] == 1);   // Length 1
    assert(dhcp_options[2] == 1);   // DISCOVER (1)
    printf("  ✅ DHCP message type = DISCOVER (1)\n");
    
    printf("\n✅ DHCP DISCOVER test PASSED\n");
}

// Test DHCP REQUEST packet generation
static void test_dhcp_request(void) {
    printf("\n========================================\n");
    printf("TEST: DHCP REQUEST Packet Generation\n");
    printf("========================================\n");
    
    uint8_t client_mac[6] = {0x00, 0x50, 0x56, 0xC0, 0x00, 0x01};
    uint32_t xid = 0x12345678;
    uint32_t requested_ip = 0x0A000002;  // 10.0.0.2 (little-endian)
    uint32_t server_ip = 0x0A000001;     // 10.0.0.1 (little-endian)
    uint8_t buffer[400];
    
    // Build REQUEST packet
    int32_t len = dhcp_build_request(client_mac, xid, requested_ip, server_ip, buffer, sizeof(buffer));
    
    printf("\nResult: %d bytes\n", len);
    assert(len > 0);
    assert(len >= 300);  // Min size: Ethernet(14) + IP(20) + UDP(8) + DHCP(240+options)
    
    print_hex(buffer, len, "DHCP REQUEST packet");
    
    // Verify packet structure
    verify_ethernet_broadcast(buffer, "DHCP REQUEST");
    verify_ip_header(buffer, "DHCP REQUEST");
    verify_udp_header(buffer, "DHCP REQUEST");
    verify_dhcp_header(buffer, xid, client_mac, "DHCP REQUEST");
    
    // Check DHCP message type option (53 = 3 = REQUEST)
    const uint8_t *dhcp_options = buffer + 14 + 20 + 8 + 240;
    assert(dhcp_options[0] == 53);  // Option 53
    assert(dhcp_options[1] == 1);   // Length 1
    assert(dhcp_options[2] == 3);   // REQUEST (3)
    printf("  ✅ DHCP message type = REQUEST (3)\n");
    
    printf("\n✅ DHCP REQUEST test PASSED\n");
}

// Test error handling
static void test_error_handling(void) {
    printf("\n========================================\n");
    printf("TEST: Error Handling\n");
    printf("========================================\n");
    
    uint8_t mac[6] = {0x00, 0x50, 0x56, 0xC0, 0x00, 0x01};
    uint8_t buffer[400];
    
    // Test NULL MAC
    int32_t result = dhcp_build_discover(NULL, 0x12345678, buffer, sizeof(buffer));
    assert(result == VTAP_ERROR_INVALID_PARAMS);
    printf("✅ NULL MAC returns VTAP_ERROR_INVALID_PARAMS\n");
    
    // Test NULL buffer
    result = dhcp_build_discover(mac, 0x12345678, NULL, sizeof(buffer));
    assert(result == VTAP_ERROR_INVALID_PARAMS);
    printf("✅ NULL buffer returns VTAP_ERROR_INVALID_PARAMS\n");
    
    // Test buffer too small for DISCOVER (needs 342 bytes)
    result = dhcp_build_discover(mac, 0x12345678, buffer, 300);
    assert(result == VTAP_ERROR_INVALID_PARAMS);
    printf("✅ Small buffer (300 bytes) returns VTAP_ERROR_INVALID_PARAMS\n");
    
    // Test buffer too small for REQUEST (needs 362 bytes)
    result = dhcp_build_request(mac, 0x12345678, 0x0A000002, 0x0A000001, buffer, 350);
    assert(result == VTAP_ERROR_INVALID_PARAMS);
    printf("✅ Small buffer (350 bytes) returns VTAP_ERROR_INVALID_PARAMS\n");
    
    printf("\n✅ Error handling tests PASSED\n");
}

int main(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  VirtualTap DHCP Builder API Test Suite                 ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    
    test_dhcp_discover();
    test_dhcp_request();
    test_error_handling();
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  🎉 ALL TESTS PASSED! 🎉                                 ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    return 0;
}
