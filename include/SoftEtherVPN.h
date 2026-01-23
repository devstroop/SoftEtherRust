// SoftEtherVPN.h - C header for iOS/macOS integration
//
// Include this header in your Swift bridging header or use directly from Objective-C.
//
// Example bridging header:
//   #import "SoftEtherVPN.h"

#ifndef SOFTETHER_VPN_H
#define SOFTETHER_VPN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Result Codes
// =============================================================================

typedef enum {
    SOFTETHER_OK = 0,
    SOFTETHER_INVALID_PARAM = -1,
    SOFTETHER_NOT_CONNECTED = -2,
    SOFTETHER_CONNECTION_FAILED = -3,
    SOFTETHER_AUTH_FAILED = -4,
    SOFTETHER_DHCP_FAILED = -5,
    SOFTETHER_TIMEOUT = -6,
    SOFTETHER_IO_ERROR = -7,
    SOFTETHER_ALREADY_CONNECTED = -8,
    SOFTETHER_QUEUE_FULL = -9,         // Backpressure - caller should retry
    SOFTETHER_INTERNAL_ERROR = -99,
} SoftEtherResult;

// =============================================================================
// Connection State
// =============================================================================

typedef enum {
    SOFTETHER_STATE_DISCONNECTED = 0,
    SOFTETHER_STATE_CONNECTING = 1,
    SOFTETHER_STATE_HANDSHAKING = 2,
    SOFTETHER_STATE_AUTHENTICATING = 3,
    SOFTETHER_STATE_ESTABLISHING_TUNNEL = 4,
    SOFTETHER_STATE_CONNECTED = 5,
    SOFTETHER_STATE_DISCONNECTING = 6,
    SOFTETHER_STATE_ERROR = 7,
} SoftEtherState;

// =============================================================================
// IP Version Preference
// =============================================================================

typedef enum {
    SOFTETHER_IP_AUTO = 0,        // Auto: Try both IPv4 and IPv6 (IPv4 required, IPv6 optional)
    SOFTETHER_IP_V4_ONLY = 1,     // IPv4 only: Skip DHCPv6
    SOFTETHER_IP_V6_ONLY = 2,     // IPv6 only: Skip IPv4 DHCP
} SoftEtherIpVersion;

// =============================================================================
// Authentication Method
// =============================================================================

typedef enum {
    SOFTETHER_AUTH_STANDARD_PASSWORD = 0, // Standard password auth (SHA-0 hashed)
    SOFTETHER_AUTH_RADIUS_NTDOMAIN = 1,   // RADIUS/NT Domain auth (plaintext over TLS)
    SOFTETHER_AUTH_CERTIFICATE = 2,        // Client certificate auth
    SOFTETHER_AUTH_ANONYMOUS = 3,          // Anonymous auth (no credentials)
} SoftEtherAuthMethod;

// =============================================================================
// Configuration
// =============================================================================

typedef struct {
    // Connection
    const char* server;           // Server hostname or IP (null-terminated UTF-8)
    unsigned int port;            // Server port (default 443)
    const char* hub;              // Virtual hub name
    
    // Authentication
    SoftEtherAuthMethod auth_method; // Authentication method (default: StandardPassword)
    const char* username;         // Username (required for password/radius auth)
    const char* password_hash;    // Hex-encoded SHA0 password hash (40 chars) for StandardPassword
    const char* password;         // Plaintext password for RadiusOrNtDomain auth (nullable)
    const char* certificate_pem;  // Client certificate PEM for Certificate auth (nullable)
    const char* private_key_pem;  // Client private key PEM for Certificate auth (nullable)
    
    // TLS Settings
    int skip_tls_verify;          // Skip TLS certificate verification (1 = yes, 0 = no)
    const char* custom_ca_pem;    // Custom CA certificate in PEM format (nullable)
    const char* cert_fingerprint_sha256; // Server cert SHA-256 fingerprint (64 hex chars, nullable)
    
    // Connection Settings
    unsigned int max_connections; // Max TCP connections (1-32, default 1)
    int half_connection;          // Half-connection mode (1 = yes, 0 = no). Requires max_connections >= 2
    unsigned int timeout_seconds; // Connection timeout in seconds (default 30)
    unsigned int mtu;             // MTU size (576-1500, default 1420)
    SoftEtherIpVersion ip_version; // IP version preference (default: Auto)
    
    // Protocol Features
    int use_encrypt;              // Use RC4 encryption within TLS (1 = yes, 0 = no)
    int use_compress;             // Use zlib compression (1 = yes, 0 = no)
    int udp_accel;                // Enable UDP acceleration (1 = yes, 0 = no)
    int qos;                      // Enable QoS/VoIP prioritization (1 = yes, 0 = no)
    
    // Session Mode
    int nat_traversal;            // NAT traversal mode (1 = NAT, 0 = Bridge)
    int monitor_mode;             // Monitor/packet capture mode (1 = yes, 0 = no)
    
    // Routing
    int default_route;            // Route all traffic through VPN (1 = yes, 0 = no)
    int accept_pushed_routes;     // Accept server-pushed routes (1 = yes, 0 = no)
    const char* ipv4_include;     // Comma-separated IPv4 CIDRs to include (nullable)
    const char* ipv4_exclude;     // Comma-separated IPv4 CIDRs to exclude (nullable)
    const char* ipv6_include;     // Comma-separated IPv6 CIDRs to include (nullable)
    const char* ipv6_exclude;     // Comma-separated IPv6 CIDRs to exclude (nullable)
    
    // Static IPv4 Configuration (optional, skips DHCP if set)
    const char* static_ipv4_address;  // Static IPv4 address, e.g., "10.0.0.100" (nullable for DHCP)
    const char* static_ipv4_netmask;  // Static IPv4 netmask, e.g., "255.255.255.0" (nullable)
    const char* static_ipv4_gateway;  // Static IPv4 gateway (nullable)
    const char* static_ipv4_dns1;     // Static IPv4 primary DNS (nullable)
    const char* static_ipv4_dns2;     // Static IPv4 secondary DNS (nullable)
    
    // Static IPv6 Configuration (optional)
    const char* static_ipv6_address;  // Static IPv6 address, e.g., "2001:db8::1" (nullable for SLAAC/DHCPv6)
    unsigned int static_ipv6_prefix_len; // IPv6 prefix length (0-128, 0 = not set)
    const char* static_ipv6_gateway;  // Static IPv6 gateway (nullable)
    const char* static_ipv6_dns1;     // Static IPv6 primary DNS (nullable)
    const char* static_ipv6_dns2;     // Static IPv6 secondary DNS (nullable)
} SoftEtherConfig;

// =============================================================================
// Session Information
// =============================================================================

typedef struct {
    uint32_t ip_address;          // Assigned IPv4 (network byte order)
    uint32_t subnet_mask;         // Subnet mask (network byte order)
    uint32_t gateway;             // Gateway IP (network byte order)
    uint32_t dns1;                // Primary DNS (network byte order)
    uint32_t dns2;                // Secondary DNS (network byte order)
    char connected_server_ip[64]; // Actual server IP (cluster server, for route exclusion)
    char original_server_ip[64];  // Original resolved server IP (before redirect, for route exclusion)
    uint32_t server_version;      // Server version
    uint32_t server_build;        // Server build number
    uint8_t mac_address[6];       // MAC address assigned to this session
    uint8_t gateway_mac[6];       // Gateway MAC address (learned from ARP)
    uint8_t ipv6_address[16];     // IPv6 address (0 if not assigned)
    uint8_t ipv6_prefix_len;      // IPv6 prefix length (e.g., 64 or 128)
    uint8_t _padding[3];          // Padding for alignment
    uint8_t dns1_v6[16];          // Primary IPv6 DNS (0 if not available)
    uint8_t dns2_v6[16];          // Secondary IPv6 DNS (0 if not available)
} SoftEtherSession;

// =============================================================================
// Statistics
// =============================================================================

typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t uptime_secs;
    unsigned int active_connections;
    unsigned int reconnect_count;
    uint64_t packets_dropped;         // Packets dropped due to queue full (backpressure)
} SoftEtherStats;

// =============================================================================
// Log Levels
// =============================================================================

/// Log levels for SoftEtherLogCallback.
/// Uses severity-based ordering (0 = most severe) matching the unified WorxVPN
/// logging standard and iOS os_log levels. See docs/LOGGING_STANDARD.md.
typedef enum {
    SOFTETHER_LOG_ERROR = 0,   // Errors (failures, unrecoverable conditions)
    SOFTETHER_LOG_WARN = 1,    // Warnings (retries, recoverable errors)
    SOFTETHER_LOG_INFO = 2,    // Informational (connected, auth success)
    SOFTETHER_LOG_DEBUG = 3,   // Debug info (connection steps, internal state)
    SOFTETHER_LOG_TRACE = 4,   // Verbose trace (packet hex dumps, wire data)
} SoftEtherLogLevel;

// =============================================================================
// Callbacks
// =============================================================================

typedef void (*SoftEtherStateCallback)(void* context, SoftEtherState state);
typedef void (*SoftEtherConnectedCallback)(void* context, const SoftEtherSession* session);
typedef void (*SoftEtherDisconnectedCallback)(void* context, SoftEtherResult result);
typedef void (*SoftEtherPacketsCallback)(void* context, const uint8_t* packets, size_t total_size, uint32_t count);

/// Log callback.
/// @param context User context passed to callbacks.
/// @param level Log level (see SoftEtherLogLevel enum).
/// @param message Null-terminated UTF-8 log message.
typedef void (*SoftEtherLogCallback)(void* context, int level, const char* message);

typedef int (*SoftEtherProtectSocketCallback)(void* context, int socket_fd);  // Returns 1 on success, 0 on failure
typedef int (*SoftEtherExcludeIpCallback)(void* context, const char* ip);     // Returns 1 on success, 0 on failure

typedef struct {
    void* context;                                    // User context passed to callbacks
    SoftEtherStateCallback on_state_changed;          // State change callback
    SoftEtherConnectedCallback on_connected;          // Connection established callback
    SoftEtherDisconnectedCallback on_disconnected;    // Disconnection callback
    SoftEtherPacketsCallback on_packets_received;     // Packets received callback
    SoftEtherLogCallback on_log;                      // Log message callback
    SoftEtherProtectSocketCallback protect_socket;    // Socket protection (Android/iOS VPN)
    SoftEtherExcludeIpCallback exclude_ip;            // IP exclusion for cluster redirects (Android VPN)
} SoftEtherCallbacks;

// =============================================================================
// Handle Type
// =============================================================================

typedef void* SoftEtherHandle;

// Null handle constant - use this instead of casting 0/NULL
// Note: Defined as extern const for Swift interoperability (macros aren't imported)
extern const SoftEtherHandle SOFTETHER_HANDLE_NULL;

// =============================================================================
// API Functions
// =============================================================================

/**
 * Create a new SoftEther VPN client.
 *
 * @param config VPN configuration (must not be NULL)
 * @param callbacks Optional callbacks for events (can be NULL)
 * @return Handle to the client, or SOFTETHER_HANDLE_NULL on error
 */
SoftEtherHandle softether_create(const SoftEtherConfig* config, const SoftEtherCallbacks* callbacks);

/**
 * Destroy a SoftEther VPN client.
 *
 * Disconnects if connected and releases all resources.
 * The handle must not be used after this call.
 *
 * @param handle Client handle
 */
void softether_destroy(SoftEtherHandle handle);

/**
 * Connect to the VPN server.
 *
 * This is an asynchronous operation. Connection status is reported
 * via the on_state_changed and on_connected callbacks.
 *
 * @param handle Client handle
 * @return SOFTETHER_OK if connection started, error code otherwise
 */
SoftEtherResult softether_connect(SoftEtherHandle handle);

/**
 * Disconnect from the VPN server.
 *
 * @param handle Client handle
 * @return SOFTETHER_OK on success
 */
SoftEtherResult softether_disconnect(SoftEtherHandle handle);

/**
 * Get current connection state.
 *
 * @param handle Client handle
 * @return Current state
 */
SoftEtherState softether_get_state(SoftEtherHandle handle);

/**
 * Get session information.
 *
 * @param handle Client handle
 * @param session Output pointer for session info
 * @return SOFTETHER_OK if connected, SOFTETHER_NOT_CONNECTED otherwise
 */
SoftEtherResult softether_get_session(SoftEtherHandle handle, SoftEtherSession* session);

/**
 * Get connection statistics.
 *
 * @param handle Client handle
 * @param stats Output pointer for statistics
 * @return SOFTETHER_OK on success
 */
SoftEtherResult softether_get_stats(SoftEtherHandle handle, SoftEtherStats* stats);

/**
 * Send packets to the VPN server.
 *
 * Packet format: [len:u16][data][len:u16][data]...
 * Each packet is prefixed with its 16-bit length in network byte order.
 *
 * @param handle Client handle
 * @param packets Packet data
 * @param total_size Total size of packet data
 * @param count Number of packets
 * @return Number of packets sent, or negative error code
 */
int softether_send_packets(SoftEtherHandle handle, const uint8_t* packets, size_t total_size, int count);

/**
 * Receive packets from the VPN server.
 *
 * Non-blocking. For best performance, use the on_packets_received callback.
 *
 * @param handle Client handle
 * @param buffer Output buffer for packets
 * @param buffer_size Size of output buffer
 * @param count Output pointer for number of packets received
 * @return Number of bytes written, or negative error code
 */
int softether_receive_packets(SoftEtherHandle handle, uint8_t* buffer, size_t buffer_size, int* count);

/**
 * Get library version.
 *
 * @return Version string (null-terminated)
 */
const char* softether_version(void);

/**
 * Get the last error message.
 *
 * Returns a pointer to a null-terminated string describing the last error
 * that occurred in the current thread. The pointer is valid until the next
 * call to any softether_* function on the same thread.
 *
 * Thread-safe: Each thread has its own error storage.
 *
 * @return Error message, or NULL if no error occurred
 */
const char* softether_get_last_error(void);

/**
 * Clear the last error message.
 *
 * Resets the thread-local error state to NULL.
 */
void softether_clear_last_error(void);

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Hash a password for SoftEther authentication.
 *
 * @param password User password (null-terminated UTF-8)
 * @param username Username (null-terminated UTF-8)
 * @param output Output buffer (must be at least 20 bytes)
 * @return SOFTETHER_OK on success
 */
SoftEtherResult softether_hash_password(const char* password, const char* username, uint8_t* output);

/**
 * Encode binary data as Base64.
 *
 * @param input Input data
 * @param input_len Input length
 * @param output Output buffer (must be at least (input_len * 4 / 3) + 4 bytes)
 * @param output_len Size of output buffer
 * @return Length of encoded string, or negative error code
 */
int softether_base64_encode(const uint8_t* input, size_t input_len, char* output, size_t output_len);

// =============================================================================
// ANE (Apple Network Extensions) - iOS/macOS Helper Functions
// =============================================================================

/**
 * Get the library version (same as softether_version).
 */
const char* softether_ios_version(void);

/**
 * Convert IPv4 address to dotted decimal string.
 *
 * @param ip IPv4 address in network byte order
 * @param buffer Output buffer (must be at least 16 bytes)
 * @param buffer_len Size of output buffer
 * @return Number of bytes written (excluding null terminator), or negative error code
 */
int softether_ios_ipv4_to_string(uint32_t ip, char* buffer, size_t buffer_len);

/**
 * Convert MAC address to colon-separated string.
 *
 * @param mac MAC address (6 bytes)
 * @param buffer Output buffer (must be at least 18 bytes)
 * @param buffer_len Size of output buffer
 * @return Number of bytes written (excluding null terminator), or negative error code
 */
int softether_ios_mac_to_string(const uint8_t* mac, char* buffer, size_t buffer_len);

/**
 * Check if an IPv4 address is valid (not 0.0.0.0).
 *
 * @param ip IPv4 address in network byte order
 * @return 1 if valid, 0 if invalid
 */
int softether_ios_is_valid_ipv4(uint32_t ip);

/**
 * Get session information into caller-provided buffer.
 * This is the recommended API - caller manages memory, avoiding thread-safety issues.
 *
 * @param handle Client handle
 * @param session_out Pointer to caller-allocated SoftEtherSession struct
 * @return SOFTETHER_OK on success, error code otherwise
 */
SoftEtherResult softether_ios_get_session(SoftEtherHandle handle, SoftEtherSession* session_out);

/**
 * Get statistics into caller-provided buffer.
 *
 * @param handle Client handle
 * @param stats_out Pointer to caller-allocated SoftEtherStats struct
 * @return SOFTETHER_OK on success, error code otherwise
 */
SoftEtherResult softether_ios_get_stats(SoftEtherHandle handle, SoftEtherStats* stats_out);

/**
 * Format byte count as human-readable string (B, KB, MB, GB).
 *
 * @param bytes Number of bytes
 * @param buffer Output buffer (must be at least 32 bytes)
 * @param buffer_len Size of output buffer
 * @return Number of bytes written (excluding null terminator), or negative error code
 */
int softether_ios_format_bytes(uint64_t bytes, char* buffer, size_t buffer_len);

/**
 * Check if the library is running on iOS (vs macOS).
 *
 * @return 1 if iOS, 0 otherwise
 */
int softether_ios_is_ios(void);

/**
 * Check if the library is running on macOS.
 *
 * @return 1 if macOS, 0 otherwise
 */
int softether_ios_is_macos(void);

/**
 * Get platform name ("ios" or "macos").
 *
 * @return Platform name as null-terminated string
 */
const char* softether_ios_platform(void);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_VPN_H
