# VirtualTapRust

Pure Rust implementation of iOS Virtual Network Adapter using the native `utun` device.

## Overview

VirtualTapRust provides a safe, high-performance virtual network interface for iOS, replacing the C-based VirtualTap implementation with pure Rust for:

- **Memory Safety**: No unsafe C FFI boundary in the data path
- **Zero-Copy**: Rust ownership semantics eliminate buffer copies
- **Async Integration**: Native Tokio async/await support
- **Cross-Platform**: Single codebase for iOS and macOS

## Architecture

```
┌─────────────────┐
│  PacketTunnel   │ (Swift/iOS)
│    Provider     │
└────────┬────────┘
         │ NEPacketTunnelFlow
         ↓
┌─────────────────┐
│ VirtualTapRust  │ (Pure Rust)
│   - utun FD     │
│   - RingBuffer  │
│   - AsyncIO     │
└────────┬────────┘
         │ Crossbeam Channels
         ↓
┌─────────────────┐
│   DataPlane     │ (SoftEther VPN)
│  SessionManager │
└─────────────────┘
```

## Components

### IosUtunDevice (`ios_utun.rs`)

Low-level iOS utun device driver that:
- Creates utun devices via `com.apple.net.utun_control`
- Handles 4-byte protocol family prefix (AF_INET/AF_INET6)
- Provides async read/write with Tokio
- Auto-allocates unit numbers

### EthernetFrame (`packet.rs`)

Ethernet frame parser and builder:
- Validates frame structure (min 14 bytes, max 1518 bytes)
- Extracts MAC addresses and EtherType
- Wraps IP packets in Ethernet headers for utun
- Strips Ethernet headers when writing to utun

### RingBuffer (`ring_buffer.rs`)

Lock-free ring buffer for packet exchange:
- Uses crossbeam channels for zero-allocation passing
- Bidirectional: utun ↔ VPN engine
- Includes statistics (packets, bytes, drops)
- Backpressure handling

### VirtualTapAdapter (`lib.rs`)

Main adapter interface:
- `new(mac, mtu)` - Create adapter with MAC and MTU
- `read_packet()` - Async read from utun
- `write_packet(frame)` - Async write to utun
- `run()` - Main packet processing loop

## Usage

```rust
use virtual_tap_rust::VirtualTapAdapter;

// Create adapter
let mac = [0x02, 0x00, 0x00, 0x11, 0x22, 0x33];
let mut adapter = VirtualTapAdapter::new(mac, 1500)?;

// Get interface name
println!("Created interface: {}", adapter.interface_name());

// Run packet processing loop
adapter.run().await?;
```

## Testing

```bash
# Run unit tests (note: utun creation requires root)
cargo test -p virtual_tap_rust

# Run ignored tests (requires root)
cargo test -p virtual_tap_rust -- --ignored
```

## iOS utun Device Details

### Control Socket Setup

1. Create socket: `PF_SYSTEM/SOCK_DGRAM/SYSPROTO_CONTROL`
2. Get control ID: `ioctl(CTLIOCGINFO)` with name `com.apple.net.utun_control`
3. Connect: `connect()` with `SockaddrCtl` structure
4. Get unit: `getsockname()` to retrieve actual unit number

### Packet Format

iOS utun prepends a 4-byte protocol family to each packet:

```
┌──────────────┬──────────────┐
│ 4-byte AF    │ IP Packet    │
└──────────────┴──────────────┘
```

- `AF_INET` (0x00000002) for IPv4
- `AF_INET6` (0x0000001E) for IPv6

VirtualTapRust automatically:
- Strips the prefix when reading
- Adds the prefix when writing

## Performance

Zero-copy design with:
- Rust ownership eliminates memcpy
- Lock-free channels for inter-task communication
- Direct async I/O with Tokio
- No C FFI overhead in data path

## Status

✅ **Complete**:
- iOS utun device driver
- Ethernet frame handling
- Ring buffer implementation
- Main adapter interface
- C FFI bindings for Swift
- Swift wrapper class
- Unit tests

⏳ **Pending**:
- Integration with PacketTunnelProvider
- Performance benchmarking
- Replace C VirtualTap in iOS app

## Integration with iOS App

### 1. Build the Library

```bash
cd SoftEtherRust
cargo build --release --target aarch64-apple-ios -p virtual_tap_rust
```

The static library will be at:
`target/aarch64-apple-ios/release/libvirtual_tap_rust.a`

### 2. Add to Xcode Project

1. Copy `libvirtual_tap_rust.a` to your Xcode project
2. Add `include/VirtualTapRust.h` as a bridging header
3. Add `VirtualTapRust.swift` to your Swift target
4. Link against the static library in Build Settings

### 3. Usage in PacketTunnelProvider

```swift
import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var vtap: VirtualTapRust?
    
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        do {
            // Create adapter with MAC address
            let mac: [UInt8] = [0x02, 0x00, 0x00, 0x11, 0x22, 0x33]
            vtap = try VirtualTapRust(mac: mac, mtu: 1500)
            
            if let name = vtap?.interfaceName {
                NSLog("Created utun interface: \(name)")
            }
            
            // Forward packets from iOS to VPN
            self.packetFlow.readPackets { [weak self] (packets, protocols) in
                for packet in packets {
                    try? self?.vtap?.writePacket(packet)
                }
            }
            
            // Forward packets from VPN to iOS
            Task {
                while let packet = try? await self.vtap?.readPacket() {
                    self.packetFlow.writePackets([packet], withProtocols: [AF_INET])
                }
            }
            
            completionHandler(nil)
        } catch {
            completionHandler(error)
        }
    }
}
```

## Dependencies

- `nix` 0.29 - Safe system call bindings
- `tokio` 1.47 - Async runtime
- `crossbeam` 0.8 - Lock-free channels
- `parking_lot` 0.12 - High-performance locks
- `thiserror` 1.0 - Error derive macros

## License

Apache-2.0
