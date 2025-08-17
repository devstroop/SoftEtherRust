# adapter

**Virtual Network Interface Layer** - Platform-specific network adapter implementations

Provides unified interface abstraction across all supported platforms.

## Platform Support
- **Linux**: TUN/TAP interfaces via `/dev/net/tun`
- **macOS**: utun interfaces and feth (for development)
- **Windows**: TAP-Windows adapter integration
- **iOS**: NetworkExtension Packet Tunnel Provider
- **Android**: VpnService API integration

## Critical Implementation Details

### Ethernet Frame Validation
```rust
const MAC_HEADER_SIZE: usize = 14;  // Standard Ethernet header size
const MIN_PACKET_SIZE: usize = 14;  // Minimum valid frame size

// CRITICAL: Drop packets smaller than 14 bytes
// From C implementation: IPsec_EtherIP.c line 363
fn validate_frame(packet: &[u8]) -> bool {
    if packet.len() < MIN_PACKET_SIZE {
        // "The size of the MAC frame is less than 14 bytes"
        return false;
    }
    true
}
```

### MAC Header Structure
```rust
#[repr(C, packed)]
struct MacHeader {
    dest_address: [u8; 6],     // Destination MAC address
    src_address: [u8; 6],      // Source MAC address  
    protocol: u16,             // EtherType (big-endian)
}

// Protocol constants
const MAC_PROTO_IPV4: u16 = 0x0800;
const MAC_PROTO_IPV6: u16 = 0x86dd;
const MAC_PROTO_ARP: u16 = 0x0806;
const MAC_PROTO_VLAN: u16 = 0x8100;
```

### macOS feth Interface Implementation
```rust
// feth interface naming convention
// feth0 pairs with feth1024, feth1 pairs with feth1025, etc.
struct FethConfig {
    name: String,       // e.g., "feth0"
    peer_name: String,  // e.g., "feth1024"
    mac_address: [u8; 6],
}

fn calculate_feth_peer(name: &str) -> Result<String, Error> {
    if !name.starts_with("feth") {
        return Err(Error::InvalidName);
    }
    
    let index: u32 = name[4..].parse()
        .map_err(|_| Error::InvalidName)?;
        
    if index >= 1024 {
        return Err(Error::InvalidName);
    }
    
    Ok(format!("feth{}", index + 1024))
}
```

### BPF Packet Processing (macOS)
```rust
const READ_PKT_SIZE: usize = 131072;  // BPF buffer size
const WORD_SIZE: usize = std::mem::size_of::<usize>();

#[repr(C)]
struct BpfHeader {
    timestamp: timeval,
    caplen: u32,    // Captured packet length
    datalen: u32,   // Original packet length  
    hdrlen: u16,    // BPF header length
}

// CRITICAL: BPF word alignment calculation
fn bpf_word_align(x: usize) -> usize {
    (x + WORD_SIZE - 1) & !(WORD_SIZE - 1)
}

// Parse multiple packets from BPF buffer
fn parse_bpf_buffer(buffer: &[u8]) -> Vec<Packet> {
    let mut packets = Vec::new();
    let mut pos = 0;
    
    while pos < buffer.len() {
        let hdr = unsafe { 
            &*(buffer.as_ptr().add(pos) as *const BpfHeader)
        };
        
        let frame_start = pos + hdr.hdrlen as usize;
        let frame_end = frame_start + hdr.caplen as usize;
        
        if frame_end <= buffer.len() {
            packets.push(buffer[frame_start..frame_end].to_vec());
        }
        
        // CRITICAL: Advance position with proper word alignment
        pos += bpf_word_align(hdr.hdrlen as usize + hdr.caplen as usize);
    }
    
    packets
}
```

### BPF Configuration Sequence
```rust
// BPF setup sequence from Go implementation
fn setup_bpf_interface(interface: &str) -> Result<BpfSocket, Error> {
    let fd = open_bpf_device()?;
    
    // Set buffer size
    syscall::set_bpf_buflen(fd, READ_PKT_SIZE)?;
    
    // Enable immediate mode (no buffering delay)
    syscall::set_bpf_immediate(fd, 1)?;
    
    // Don't see sent packets
    syscall::ioctl_set_pointer_int(fd, BIOCSSEESENT, 0)?;
    
    // Bind to specific interface
    syscall::set_bpf_interface(fd, interface)?;
    
    // Complete headers in packets
    syscall::set_bpf_headercmpl(fd, 1)?;
    
    // Enable promiscuous mode
    syscall::set_bpf_promisc(fd, 1)?;
    
    Ok(BpfSocket { fd })
}
```

### NDRV Socket for Writing (macOS)
```rust
// Network Driver (NDRV) socket for packet injection
struct NdrvSocket {
    fd: RawFd,
    interface: String,
}

impl NdrvSocket {
    fn write_frame(&self, packet: &[u8]) -> Result<usize, Error> {
        // Write raw Ethernet frame directly to interface
        unsafe {
            libc::write(self.fd, packet.as_ptr() as *const _, packet.len())
        }
    }
}
```

### DHCP Integration
```rust
// Automatic DHCP configuration on interface creation
fn configure_dhcp(interface: &str) -> Result<(), Error> {
    // Execute: ipconfig set <interface> dhcp
    std::process::Command::new("/usr/sbin/ipconfig")
        .args(&["set", interface, "dhcp"])
        .output()
        .map_err(|e| Error::DhcpConfig(e))?;
    
    Ok(())
}
```

## Architecture Improvements

### Over C Implementation
- **Trait-Based Design**: `VirtualAdapter` trait with platform-specific implementations
- **Async Packet I/O**: Non-blocking packet reading/writing with tokio
- **Resource Safety**: Automatic cleanup via Drop trait, no manual resource management
- **Error Handling**: Proper error propagation instead of global error states

### Over Go Implementation  
- **Multi-Platform**: Full cross-platform support (vs Go's macOS-only)
- **Production Features**: Proper error recovery, interface monitoring, MTU handling
- **Performance**: Zero-copy packet handling where possible

## FFI Integration

For mobile platforms, this layer coordinates with the FFI module:
- **iOS**: Integrates with NetworkExtension framework via C bindings
- **Android**: Interfaces with VpnService through JNI layer
- **Desktop**: Direct system calls for maximum performance

## Key Design Patterns
- **Adapter Trait**: Unified interface for all platform implementations
- **Packet Abstraction**: Generic packet handling with platform-specific optimizations
- **Event-Driven**: Async streams for packet flow and interface events
- **Hot-Swappable**: Runtime adapter switching for failover scenarios

## Critical Gotchas & Implementation Notes

1. **Frame Size Validation**: Always validate minimum 14-byte frame size
2. **BPF Word Alignment**: Essential for proper multi-packet parsing on macOS
3. **feth Interface Pairing**: Specific naming convention (feth0 ↔ feth1024)
4. **NDRV vs BPF**: Use NDRV for writing, BPF for reading on macOS
5. **Header Completion**: Enable BPF_HEADERCMPL for complete Ethernet headers
6. **Promiscuous Mode**: Required for packet capture on virtual interfaces
