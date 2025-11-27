/* SoftEther VPN Client FFI - iOS NetworkExtension Integration */

#ifndef SOFTETHER_FFI_H
#define SOFTETHER_FFI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle to VPN client instance */
typedef struct SoftEtherClient SoftEtherClient;

/* Callback types */
typedef void (*softether_rx_callback_t)(const uint8_t* data, uint32_t len, void* user_data);
typedef void (*softether_state_callback_t)(uint32_t state, void* user_data);
typedef void (*softether_event_callback_t)(uint32_t level, int32_t code, const char* message, void* user_data);

/* Connection states */
#define SOFTETHER_STATE_DISCONNECTED 0
#define SOFTETHER_STATE_CONNECTING 1
#define SOFTETHER_STATE_ESTABLISHED 2

/* Event levels */
#define SOFTETHER_EVENT_INFO 0
#define SOFTETHER_EVENT_WARN 1
#define SOFTETHER_EVENT_ERROR 2

/* Special event codes */
#define SOFTETHER_EVENT_NETWORK_SETTINGS 1001

/**
 * Create a new SoftEther VPN client from JSON configuration
 * 
 * @param config_json JSON string with server, port, hub, username, password_hash, etc.
 * @return Client handle or NULL on error
 */
SoftEtherClient* softether_client_create(const char* config_json);

/**
 * Set callback for receiving packets from VPN server (Server→iOS)
 * 
 * @param handle Client handle
 * @param callback Function called when packet received (may be NULL to clear)
 * @param user_data Opaque pointer passed to callback
 * @return 0 on success, -1 on error
 */
int softether_client_set_rx_callback(
    SoftEtherClient* handle,
    softether_rx_callback_t callback,
    void* user_data
);

/**
 * Set callback for connection state changes
 * 
 * @param handle Client handle
 * @param callback Function called on state change (may be NULL to clear)
 * @param user_data Opaque pointer passed to callback
 * @return 0 on success, -1 on error
 */
int softether_client_set_state_callback(
    SoftEtherClient* handle,
    softether_state_callback_t callback,
    void* user_data
);

/**
 * Set callback for events (logs, errors, network settings)
 * 
 * @param handle Client handle
 * @param callback Function called on event (may be NULL to clear)
 * @param user_data Opaque pointer passed to callback
 * @return 0 on success, -1 on error
 * 
 * Special: When code == SOFTETHER_EVENT_NETWORK_SETTINGS (1001),
 * message contains JSON network settings snapshot for iOS to apply.
 */
int softether_client_set_event_callback(
    SoftEtherClient* handle,
    softether_event_callback_t callback,
    void* user_data
);

/**
 * Connect to VPN server (async operation, returns immediately)
 * 
 * @param handle Client handle
 * @return 0 on success, -1 on error
 */
int softether_client_connect(SoftEtherClient* handle);

/**
 * Send packet to VPN server (iOS→Server direction)
 * 
 * @param handle Client handle
 * @param data Packet data
 * @param len Packet length
 * @return 0 on success, -1 on error
 */
int softether_client_send_frame(
    SoftEtherClient* handle,
    const uint8_t* data,
    uint32_t len
);

/**
 * Get network settings as JSON string (IPv4, DNS, routes)
 * 
 * @param handle Client handle
 * @return Allocated JSON string or NULL. Caller must call softether_free_string()
 */
char* softether_client_get_network_settings_json(SoftEtherClient* handle);

/**
 * Free string allocated by softether_client_get_network_settings_json
 * 
 * @param s String pointer from softether_client_get_network_settings_json
 */
void softether_free_string(char* s);

/**
 * Disconnect from VPN server
 * 
 * @param handle Client handle
 * @return 0 on success, -1 on error
 */
int softether_client_disconnect(SoftEtherClient* handle);

/**
 * Free VPN client resources
 * 
 * @param handle Client handle (must not be used after)
 */
void softether_client_free(SoftEtherClient* handle);

#ifdef __cplusplus
}
#endif

#endif /* SOFTETHER_FFI_H */
