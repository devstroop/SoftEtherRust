# SoftEther VPN Client for Rust

A high-performance SoftEther VPN client implementation in Rust, featuring async I/O, TLS support, and cross-platform compatibility.

## Features

- **Full SoftEther Protocol Support**: Compatible with SoftEther VPN Server
- **Secure Authentication**: SHA-0 based password hashing (SoftEther legacy)
- **TLS Encryption**: Full TLS 1.2/1.3 support with rustls
- **Cross-Platform**: macOS (utun) and Linux (TUN) support
- **Async/Await**: Built on Tokio for efficient async networking
- **DHCP Client**: Automatic IP configuration via DHCP
- **ARP Handler**: Gateway MAC address discovery

## Requirements

- Rust 1.75 or later
- Root/Administrator privileges (for TUN device creation)
- macOS 10.12+ or Linux 3.10+

## Installation

### From Source

```bash
git clone https://github.com/yourusername/SoftEtherRust
cd SoftEtherRust
cargo build --release
```

### Binary

The compiled binary will be at `target/release/vpnclient`.

## Usage

### Quick Start

```bash
# Generate a sample configuration file
./vpnclient gen-config -o config.json

# Edit the configuration
vim config.json

# Connect to VPN
sudo ./vpnclient connect -c config.json
```

### Command Line Options

```
SoftEther VPN Client

Usage: vpnclient [OPTIONS] <COMMAND>

Commands:
  connect     Connect to a VPN server
  disconnect  Disconnect from the VPN
  status      Show connection status
  gen-config  Generate a sample configuration file
  help        Print this message or the help of the given subcommand(s)

Options:
  -c, --config <FILE>  Configuration file path
  -v, --verbose        Enable verbose output
  -d, --debug          Enable debug output
  -h, --help           Print help
  -V, --version        Print version
```

### Connect Command

```bash
# Using command line arguments
sudo ./vpnclient connect \
  --server vpn.example.com \
  --port 443 \
  --hub VPN \
  --username myuser \
  --password mypassword

# Using config file
sudo ./vpnclient connect -c config.json

# With TLS verification disabled (for self-signed certs)
sudo ./vpnclient connect -c config.json --no-verify
```

## Configuration File

Create a JSON configuration file:

```json
{
  "server": "vpn.example.com",
  "port": 443,
  "hub": "VPN",
  "username": "your_username",
  "password": "your_password",
  "use_tls": true,
  "verify_server_cert": false,
  "timeout_seconds": 30
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `server` | string | required | VPN server hostname or IP |
| `port` | number | `443` | Server port |
| `hub` | string | required | Virtual Hub name |
| `username` | string | required | Username for authentication |
| `password` | string | required | Password (or leave empty to prompt) |
| `use_tls` | boolean | `true` | Enable TLS encryption |
| `verify_server_cert` | boolean | `false` | Verify server certificate |
| `timeout_seconds` | number | `30` | Connection timeout |

## Library Usage

You can also use SoftEther Rust as a library in your own projects:

```rust
use softether_rust::{VpnClient, VpnConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = VpnConfig {
        server: "vpn.example.com".to_string(),
        port: 443,
        hub: "VPN".to_string(),
        username: "user".to_string(),
        password: "password".to_string(),
        ..Default::default()
    };

    let mut client = VpnClient::new(config);
    client.connect().await?;

    // VPN is now connected
    // ...

    client.disconnect();
    Ok(())
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         VpnClient                                │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │   Protocol   │  │   Crypto     │  │     Adapter          │   │
│  │  ┌────────┐  │  │  ┌────────┐  │  │  ┌────────────────┐  │   │
│  │  │  HTTP  │  │  │  │  SHA-0 │  │  │  │  TunAdapter    │  │   │
│  │  └────────┘  │  │  └────────┘  │  │  └────────────────┘  │   │
│  │  ┌────────┐  │  │  ┌────────┐  │  │         │            │   │
│  │  │  Pack  │  │  │  │ Password│ │  │  ┌──────┴──────┐    │   │
│  │  └────────┘  │  │  └────────┘  │  │  │             │    │   │
│  │  ┌────────┐  │  └──────────────┘  │  │  utun    tun │    │   │
│  │  │  Auth  │  │                    │  │ (macOS) (Linux)   │   │
│  │  └────────┘  │                    │  └──────────────┘    │   │
│  │  ┌────────┐  │                    └──────────────────────┘   │
│  │  │ Tunnel │  │                                               │
│  │  └────────┘  │                                               │
│  └──────────────┘                                               │
├─────────────────────────────────────────────────────────────────┤
│                     Network I/O (Tokio)                         │
└─────────────────────────────────────────────────────────────────┘
```

## Protocol Flow

1. **TCP Connection**: Establish TCP connection to server
2. **TLS Handshake**: Negotiate TLS if enabled
3. **HTTP Handshake**: Send POST request, receive server hello (Pack format)
4. **Authentication**: Send credentials, receive session key
5. **Data Connection**: Establish additional connection for tunnel data
6. **DHCP**: Request IP configuration via DHCP
7. **Tunnel**: Exchange Ethernet frames through block-based protocol

## Security Considerations

- **SHA-0**: SoftEther uses SHA-0 for password hashing (legacy compatibility)
- **TLS**: All traffic is encrypted with TLS when enabled
- **Self-Signed Certs**: Server certificate verification can be disabled for self-signed certificates

## Building

### Debug Build

```bash
cargo build
```

### Release Build (Optimized)

```bash
cargo build --release
```

### Run Tests

```bash
cargo test
```

### Generate Documentation

```bash
cargo doc --open
```

## Troubleshooting

### Permission Denied

TUN device creation requires root privileges:
```bash
sudo ./vpnclient connect ...
```

### Connection Timeout

Check:
- Server is reachable: `telnet vpn.example.com 443`
- Firewall allows outbound TCP 443
- DNS resolves correctly

### Authentication Failed

- Verify username and password
- Check hub name is correct
- Ensure user has permission to connect to the hub

### TLS Certificate Errors

For self-signed certificates, use:
```bash
./vpnclient connect ... --no-verify
```

## License

Apache License 2.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- [SoftEther VPN Project](https://www.softether.org/)
- Reference implementations in Swift and Zig
