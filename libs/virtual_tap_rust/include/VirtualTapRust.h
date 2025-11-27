//
//  VirtualTapRust-Bridging-Header.h
//  VirtualTapRust C FFI
//
//  Swift bridge to VirtualTapRust Rust library
//

#ifndef VirtualTapRust_Bridging_Header_h
#define VirtualTapRust_Bridging_Header_h

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle to VirtualTapAdapter
typedef struct VTapHandle VTapHandle;

// Result codes
typedef enum {
    VTapSuccess = 0,
    VTapError = -1,
    VTapBufferFull = -2,
    VTapBufferEmpty = -3,
    VTapInvalidHandle = -4,
    VTapInvalidParameter = -5
} VTapResult;

// Statistics structure
typedef struct {
    uint64_t packets_written;
    uint64_t packets_read;
    uint64_t bytes_written;
    uint64_t bytes_read;
    uint64_t drops;
} VTapStats;

// Create a new VirtualTapAdapter
VTapHandle* vtap_create(const uint8_t* mac, size_t mtu);

// Destroy a VirtualTapAdapter
void vtap_destroy(VTapHandle* handle);

// Get the interface name (returns pointer to internal string)
const char* vtap_get_interface_name(const VTapHandle* handle);

// Get the file descriptor for the utun device
int vtap_get_fd(const VTapHandle* handle);

// Write a packet to the ring buffer (utun → VPN direction)
VTapResult vtap_write_packet(VTapHandle* handle, const uint8_t* data, size_t len);

// Read a packet from the ring buffer (VPN → utun direction)
VTapResult vtap_read_packet(VTapHandle* handle, uint8_t* buffer, size_t buffer_len, size_t* out_len);

// Get ring buffer statistics
VTapResult vtap_get_stats(const VTapHandle* handle, VTapStats* stats);

// Reset ring buffer statistics
VTapResult vtap_reset_stats(VTapHandle* handle);

#ifdef __cplusplus
}
#endif

#endif /* VirtualTapRust_Bridging_Header_h */
