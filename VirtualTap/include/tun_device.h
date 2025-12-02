#ifndef TUN_DEVICE_H
#define TUN_DEVICE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Create a TUN device (Layer 3)
/// Returns file descriptor on success, or negative on error
/// device_name will be filled with the actual device name (e.g., "utun7")
int tun_device_create(char *device_name, size_t device_name_size);

/// Close TUN device
void tun_device_close(int fd);

/// Read IP packet from TUN device
/// Returns number of bytes read (>0), 0 if no data (non-blocking), or negative on error
/// Note: Protocol headers are automatically stripped (macOS utun 4-byte header)
int32_t tun_device_read(int fd, uint8_t *buffer, uint32_t buffer_size);

/// Write IP packet to TUN device
/// Returns number of bytes written (>0), 0 if would block, or negative on error
/// Note: Protocol headers are automatically added (macOS utun 4-byte header)
int32_t tun_device_write(int fd, const uint8_t *packet, uint32_t packet_size);

#ifdef __cplusplus
}
#endif

#endif // TUN_DEVICE_H
