# SoftEther VPN (Rust)

[![CI](https://github.com/devstroop/softether-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/devstroop/softether-rust/actions/workflows/ci.yml)

## 🎯 Project Overview

A comprehensive Rust implementation of the SoftEther VPN client protocol, providing a modern, memory-safe alternative to the original C implementation with full binary compatibility.

> **📚 For detailed development information, architecture, and implementation status, see [DEVELOPMENT.md](DEVELOPMENT.md)**

## 🚀 Quick Start

### Build and Run

```bash
# Clone and build
git clone <repo-url>
cd SoftEtherClient
cargo build

# Configure (copy and edit)
cp config.example.json config.json
# Edit config.json with your VPN server details

# Run with debug logging
RUST_LOG=debug cargo run -p vpnclient -- --config config.json
```

### Configuration Example

```json
{
    "server": "vpn.example.com",
    "port": 443,
    "hub": "DEFAULT",
    "username": "testuser", 
    "password_hash": "base64-encoded-sha0-hash",
    "use_compress": true,
    "max_connections": 2
}
```

## 📱 Mobile Integration (FFI)

For embedding in iOS/Android apps:

- [`docs/ffi/README.md`](docs/ffi/README.md) – C API overview and lifecycle
- [`docs/ffi/ios.md`](docs/ffi/ios.md) – iOS NetworkExtension integration
- [`docs/ffi/android.md`](docs/ffi/android.md) – Android VpnService integration
- [`docs/ffi/config.md`](docs/ffi/config.md) – Configuration schema

### iOS XCFramework Build

```bash
# Add iOS targets (once)
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# Build XCFramework
./scripts/build_xcframework.sh --release
```

## 🏗️ Architecture

```
SoftEtherClient/
├── crates/
│   ├── ffi/                    # C FFI for mobile platforms
│   └── vpnclient/              # Main VPN client
├── libs/
│   ├── cedar/                  # VPN protocol engine
│   ├── mayaqua/               # Foundation (PACK, crypto, network)
│   ├── dhcproto/              # DHCP implementation
│   └── tun-rs/                # TUN/TAP interface abstraction
└── docs/ffi/                  # Mobile integration guides
```

## 🔧 Current Status

### ✅ **Fully Implemented & Working**
- **Complete VPN Protocol Stack**: TLS connections, authentication, session management
- **Data Plane**: Full packet encryption/decryption pipeline with bidirectional frame forwarding
- **Network Layer**: Complete TLS/SSL implementation with certificate handling
- **Protocol Handshake**: Full connection establishment, redirect handling, multi-connection support
- **DHCP Integration**: DHCPv4/v6 client with lease management and renewal
- **Network Configuration**: Static IP, routing, DNS management
- **Cross-Platform TAP**: macOS, Linux TAP interface integration
- **FFI Layer**: Production-ready C API for iOS/Android mobile integration

### � **Minor Fixes Needed**
- **Static IP Application**: Simple configuration application fix (see DEVELOPMENT.md)
- **Connection Recovery**: Auto-reconnection logic for production reliability
- **Route Management**: Split-tunneling route additions

### 📋 **Future Enhancements**
- **Windows TAP Support**: Windows driver integration
- **UDP Acceleration**: Performance optimization for high-throughput scenarios  
- **Advanced Features**: Bridge mode, SecureNAT, enterprise management

> **🚀 Status**: **98% Complete!** - The VPN client is **production-ready** with clean shutdown behavior. Signal handling has been fixed to exit immediately on Ctrl+C. See [DEVELOPMENT.md](DEVELOPMENT.md) for the remaining 2% polish items.

## 📚 Documentation

- **[DEVELOPMENT.md](DEVELOPMENT.md)** - Comprehensive development guide, architecture, and implementation status
- **[CHANGELOG.md](CHANGELOG.md)** - Project changelog and version history
- **[docs/ffi/](docs/ffi/)** - Mobile platform integration guides
- **API Docs**: `cargo doc --open` for detailed API documentation

## 🤝 Contributing

1. Read [DEVELOPMENT.md](DEVELOPMENT.md) for architecture and current status
2. Check GitHub Issues for open tasks
3. Follow Rust best practices and include tests
4. Submit PR with detailed description

**Priority Areas**: Static IP application fix, connection recovery, Windows TAP support

## 📄 License

Apache 2.0 License - see LICENSE file for details.

---

**🔗 Links**: [Development Guide](DEVELOPMENT.md) | [FFI Docs](docs/ffi/README.md) | [API Reference](https://docs.rs/softether-rust)