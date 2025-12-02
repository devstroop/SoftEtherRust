// TUN device creation and I/O for VirtualTap
// Platform-specific implementation for macOS, Linux, iOS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifdef __APPLE__
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>

// macOS utun device creation
int tun_device_create_macos(char *device_name, size_t device_name_size) {
    struct sockaddr_ctl addr;
    struct ctl_info info;
    int fd = -1;
    int unit_number;

    // Get utun control ID
    int temp_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (temp_fd < 0) {
        fprintf(stderr, "[TUN] Failed to create socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));

    if (ioctl(temp_fd, CTLIOCGINFO, &info) < 0) {
        fprintf(stderr, "[TUN] CTLIOCGINFO failed: %s\n", strerror(errno));
        close(temp_fd);
        return -1;
    }
    close(temp_fd);

    // Try utun0-15
    for (unit_number = 0; unit_number < 16; unit_number++) {
        fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) {
            continue;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sc_len = sizeof(addr);
        addr.sc_family = AF_SYSTEM;
        addr.ss_sysaddr = AF_SYS_CONTROL;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = unit_number + 1; // utun0 = 1, utun1 = 2, etc.

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(fd);
            fd = -1;
            continue;
        }

        // Success!
        break;
    }

    if (fd < 0) {
        fprintf(stderr, "[TUN] Failed to find available utun device\n");
        return -1;
    }

    // Get device name
    socklen_t optlen = (socklen_t)device_name_size;
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, device_name, &optlen) < 0) {
        fprintf(stderr, "[TUN] UTUN_OPT_IFNAME failed: %s\n", strerror(errno));
        snprintf(device_name, device_name_size, "utun%d", unit_number);
    }

    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    fprintf(stderr, "[TUN] Created TUN device: %s (fd=%d)\n", device_name, fd);
    return fd;
}

#elif defined(__linux__)
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

// Linux TUN device creation
int tun_device_create_linux(char *device_name, size_t device_name_size) {
    struct ifreq ifr;
    int fd, err;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[TUN] Failed to open /dev/net/tun: %s\n", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN device, no protocol info

    if (device_name && device_name[0] != '\0') {
        strncpy(ifr.ifr_name, device_name, IFNAMSIZ);
    }

    err = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (err < 0) {
        fprintf(stderr, "[TUN] ioctl TUNSETIFF failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    // Copy device name back
    strncpy(device_name, ifr.ifr_name, device_name_size);
    
    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    fprintf(stderr, "[TUN] Created TUN device: %s (fd=%d)\n", device_name, fd);
    return fd;
}
#endif

// Platform-independent TUN device creation
int tun_device_create(char *device_name, size_t device_name_size) {
#ifdef __APPLE__
    return tun_device_create_macos(device_name, device_name_size);
#elif defined(__linux__)
    return tun_device_create_linux(device_name, device_name_size);
#else
    fprintf(stderr, "[TUN] Unsupported platform\n");
    return -1;
#endif
}

// Close TUN device
void tun_device_close(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}

// Read from TUN device (returns number of bytes read, or negative on error)
// On macOS, first 4 bytes are protocol info (0x00000002 = IPv4, 0x0000001e = IPv6)
int32_t tun_device_read(int fd, uint8_t *buffer, uint32_t buffer_size) {
    if (fd < 0 || !buffer) {
        return -1;
    }

    ssize_t n = read(fd, buffer, buffer_size);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; // No data available (non-blocking)
        }
        return -1; // Error
    }

#ifdef __APPLE__
    // macOS utun prepends 4-byte protocol header
    // Strip it before returning to caller
    if (n >= 4) {
        memmove(buffer, buffer + 4, n - 4);
        return (int32_t)(n - 4);
    } else {
        return 0; // Invalid packet
    }
#else
    return (int32_t)n;
#endif
}

// Write to TUN device (returns number of bytes written, or negative on error)
// On macOS, we need to prepend 4-byte protocol info
int32_t tun_device_write(int fd, const uint8_t *packet, uint32_t packet_size) {
    if (fd < 0 || !packet || packet_size == 0) {
        return -1;
    }

#ifdef __APPLE__
    // macOS utun requires 4-byte protocol header
    // Determine protocol from IP version field
    uint32_t protocol = 0x00000002; // IPv4 (default)
    if (packet_size > 0) {
        uint8_t version = (packet[0] >> 4) & 0x0F;
        if (version == 6) {
            protocol = 0x0000001e; // IPv6
        }
    }

    // Build packet with protocol header
    uint8_t buf[2048];
    if (packet_size + 4 > sizeof(buf)) {
        return -1; // Packet too large
    }

    // Write protocol in network byte order
    buf[0] = 0;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = (protocol == 0x0000001e) ? 0x1e : 0x02;
    
    memcpy(buf + 4, packet, packet_size);

    ssize_t n = write(fd, buf, packet_size + 4);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; // Would block
        }
        return -1; // Error
    }

    // Return bytes written (excluding protocol header)
    return (int32_t)(n > 4 ? n - 4 : 0);
#else
    ssize_t n = write(fd, packet, packet_size);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    return (int32_t)n;
#endif
}
