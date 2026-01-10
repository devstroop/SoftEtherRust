# SoftEther VPN Client (Rust)

A high-performance, fully async SoftEther VPN client library and CLI in Rust with native iOS/Android/FFI support.

## Features

### Core Protocol
- **Full SoftEther Protocol** — Complete protocol implementation compatible with SoftEther VPN Server
- **Multi-Connection Mode** — Up to 32 parallel TCP connections with half-connection support
- **UDP Acceleration** — V1 (RC4+SHA-1) and V2 (ChaCha20-Poly1305 AEAD) protocols
- **Cluster Support** — Automatic redirect handling for SoftEther VPN clusters
- **TLS 1.2/1.3** — Secure connections via rustls with certificate pinning support

### Networking
- **DHCP/DHCPv6** — Automatic IPv4/IPv6 configuration with lease renewal/rebind
- **Static IP** — Optional manual IP configuration (bypass DHCP)
- **ARP Handler** — Gateway MAC address resolution for L2 operation
- **IP Fragmentation** — Fragment reassembly for oversized packets
- **Split Tunneling** — Include/exclude CIDR lists for IPv4 and IPv6

### Security
- **Multiple Auth Methods** — Password, RADIUS/NT Domain, Certificate, Anonymous
- **RC4 Defense-in-Depth** — Optional packet encryption within TLS tunnel
- **Certificate Pinning** — SHA-256 fingerprint verification
- **Custom CA** — Support for private PKI

### Performance
- **LZ4 Compression** — Reduced bandwidth usage
- **QoS Prioritization** — VoIP/real-time traffic handling
- **NAT-T Keepalive** — Connection persistence through NAT

### Platform Support

| Platform | Interface | Status |
|----------|-----------|--------|
| macOS | utun | ✅ Native CLI |
| Linux | TUN | ✅ Native CLI |
| iOS | NEPacketTunnelProvider | ✅ FFI Library |
| Android | VpnService | ✅ JNI Library |

## Requirements

### Desktop CLI
- Rust 1.75+
- Root/sudo privileges (TUN device creation)
- macOS 10.12+ or Linux 3.10+

### Mobile Development
- Xcode 14+ (iOS)
- Android NDK r25+ (Android)

## Installation

### CLI

```bash
git clone https://github.com/AlfredAkku/SoftEtherRust
cd SoftEtherRust
cargo build --release
```

Binary: `target/release/vpnclient`

### iOS Library

```bash
./scripts/build-ios.sh
```

Output: `target/ios/SoftEtherVPN.xcframework`

### Android Library

```bash
./scripts/build-android.sh
```

Output: `target/android/jniLibs/`

## Quick Start

```bash
# Generate password hash
./vpnclient hash -u your_username -p your_password

# Generate sample config
./vpnclient gen-config -o config.json

# Edit config.json with your server details

# Connect
sudo ./vpnclient connect -c config.json
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `connect` | Connect to VPN server |
| `hash` | Generate SHA-0 password hash |
| `gen-config` | Generate sample configuration |

### Connect Options

```bash
sudo ./vpnclient connect [OPTIONS]

Options:
  -c, --config <FILE>         Configuration file path
  -s, --server <HOST>         Server hostname or IP
  -p, --port <PORT>           Server port (default: 443)
  -H, --hub <HUB>             Virtual Hub name
  -u, --username <USER>       Username
      --password-hash <HASH>  Pre-computed password hash (40 hex chars)
      --skip-tls-verify       Skip TLS certificate verification
  -v, --verbose               Enable verbose output
  -d, --debug                 Enable debug output
```

## Configuration

See [config.example.json](config.example.json) for a complete example.

### Connection

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `server` | string | *required* | VPN server hostname or IP |
| `port` | number | `443` | Server port |
| `hub` | string | *required* | Virtual Hub name |
| `timeout_seconds` | number | `30` | Connection timeout |

### Authentication

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `auth.method` | string | `standard_password` | Auth method: `standard_password`, `radius_or_nt_domain`, `certificate`, `anonymous` |
| `auth.username` | string | — | Username |
| `auth.password_hash` | string | — | SHA-0 password hash (40 hex chars) |
| `auth.password` | string | — | Plaintext password (RADIUS/NT Domain only) |
| `auth.certificate_pem` | string | — | Client certificate PEM (cert auth) |
| `auth.private_key_pem` | string | — | Client private key PEM (cert auth) |

### TLS

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `skip_tls_verify` | boolean | `true` | Skip certificate verification |
| `custom_ca_pem` | string | — | Custom CA certificate PEM |
| `cert_fingerprint_sha256` | string | — | Certificate pinning (64 hex chars) |

### Tunnel

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `use_encrypt` | boolean | `true` | RC4 encryption (defense in depth) |
| `use_compress` | boolean | `true` | LZ4 compression |
| `udp_accel` | boolean | `false` | UDP acceleration |
| `qos` | boolean | `false` | VoIP/QoS prioritization |

### Session

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `nat_traversal` | boolean | `false` | NAT mode vs Bridge mode |
| `monitor_mode` | boolean | `false` | Packet capture mode |

### Performance

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_connections` | number | `1` | TCP connections (1–32) |
| `half_connection` | boolean | `false` | Split send/receive connections |
| `mtu` | number | `1400` | TUN device MTU |

### IP Version

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ip_version` | string | `auto` | `auto`, `ipv4`, `ipv6` |

### Routing

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `routing.default_route` | boolean | `false` | Route all traffic through VPN |
| `routing.accept_pushed_routes` | boolean | `true` | Accept server-pushed routes |
| `routing.ipv4_include` | array | `[]` | IPv4 CIDRs to route through VPN |
| `routing.ipv4_exclude` | array | `[]` | IPv4 CIDRs to exclude |
| `routing.ipv6_include` | array | `[]` | IPv6 CIDRs to route through VPN |
| `routing.ipv6_exclude` | array | `[]` | IPv6 CIDRs to exclude |

### Static IP (Optional)

When configured, DHCP is skipped.

| Option | Type | Description |
|--------|------|-------------|
| `static_ip.ipv4_address` | string | Static IPv4 address |
| `static_ip.ipv4_netmask` | string | IPv4 subnet mask |
| `static_ip.ipv4_gateway` | string | IPv4 gateway |
| `static_ip.ipv4_dns1` | string | Primary DNS |
| `static_ip.ipv4_dns2` | string | Secondary DNS |
| `static_ip.ipv6_address` | string | Static IPv6 address |
| `static_ip.ipv6_prefix_len` | number | IPv6 prefix length |
| `static_ip.ipv6_gateway` | string | IPv6 gateway |
| `static_ip.ipv6_dns1` | string | Primary IPv6 DNS |
| `static_ip.ipv6_dns2` | string | Secondary IPv6 DNS |

## Mobile Integration

### iOS

1. Add `SoftEtherVPN.xcframework` to your Xcode project
2. Add `include/SoftEtherVPN.h` via bridging header
3. Use `SoftEtherBridge.swift` wrapper (see [examples/ios/](examples/ios/))

```swift
let config = SoftEtherBridge.Configuration(
    server: "vpn.example.com",
    port: 443,
    hub: "VPN",
    username: "user",
    passwordHash: "..."
)

let vpn = SoftEtherBridge()
try vpn.create(config: config)
try vpn.connect()
```

### Android

1. Copy `jniLibs/` to `app/src/main/jniLibs/`
2. Use `SoftEtherBridge.kt` wrapper (see [examples/android/](examples/android/))

```kotlin
val config = SoftEtherBridge.Configuration(
    server = "vpn.example.com",
    port = 443,
    hub = "VPN",
    username = "user",
    passwordHash = "..."
)

val bridge = SoftEtherBridge()
bridge.create(config)
bridge.connect()
```

See [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) for detailed mobile integration.

## Library Usage

```rust
use softether::{VpnClient, VpnConfig, crypto};
use softether::config::{AuthConfig, AuthMethod};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let password_hash = crypto::hash_password("password", "user");

    let config = VpnConfig {
        server: "vpn.example.com".to_string(),
        port: 443,
        hub: "VPN".to_string(),
        auth: AuthConfig {
            method: AuthMethod::StandardPassword,
            username: "user".to_string(),
            password_hash: Some(hex::encode(password_hash)),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut client = VpnClient::new(config);
    client.connect().await?;

    Ok(())
}
```

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                         VpnClient                              │
├────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────────┐  │
│  │  Protocol   │  │   Crypto    │  │        Adapter         │  │
│  │  ┌───────┐  │  │  ┌───────┐  │  │  ┌─────────────────┐   │  │
│  │  │ HTTP  │  │  │  │ SHA-0 │  │  │  │   TunAdapter    │   │  │
│  │  │ Codec │  │  │  └───────┘  │  │  │  ┌────┐ ┌────┐  │   │  │
│  │  └───────┘  │  │  ┌───────┐  │  │  │  │utun│ │tun │  │   │  │
│  │  ┌───────┐  │  │  │  RC4  │  │  │  │  └────┘ └────┘  │   │  │
│  │  │ Pack  │  │  │  └───────┘  │  │  │  macOS   Linux  │   │  │
│  │  └───────┘  │  │  ┌───────┐  │  │  └─────────────────┘   │  │
│  │  ┌───────┐  │  │  │ChaCha │  │  │  ┌─────────────────┐   │  │
│  │  │ Auth  │  │  │  │Poly   │  │  │  │   FFI Layer     │   │  │
│  │  └───────┘  │  │  └───────┘  │  │  │  ┌────┐ ┌─────┐ │   │  │
│  └─────────────┘  └─────────────┘  │  │  │iOS │ │JNI  │ │   │  │
│                                    │  │  └────┘ └─────┘ │   │  │
│  ┌─────────────┐  ┌─────────────┐  │  └─────────────────┘   │  │
│  │   Tunnel    │  │    Net      │  └────────────────────────┘  │
│  │  ┌───────┐  │  │  ┌───────┐  │  ┌────────────────────────┐  │
│  │  │ DHCP  │  │  │  │  UDP  │  │  │   ConnectionManager    │  │
│  │  │DHCPv6 │  │  │  │ Accel │  │  │  ┌─────────────────┐   │  │
│  │  └───────┘  │  │  │ V1+V2 │  │  │  │ Multi-Connection│   │  │
│  │  ┌───────┐  │  │  └───────┘  │  │  │ Half-Connection │   │  │
│  │  │  ARP  │  │  │             │  │  └─────────────────┘   │  │
│  │  └───────┘  │  │             │  └────────────────────────┘  │
│  └─────────────┘  └─────────────┘                              │
├────────────────────────────────────────────────────────────────┤
│                     Tokio Async Runtime                        │
│               (TCP/TLS/UDP, Timers, Signals)                   │
└────────────────────────────────────────────────────────────────┘
```

## Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Build iOS framework
./scripts/build-ios.sh

# Build Android libraries
./scripts/build-android.sh
```

## Troubleshooting

### Permission Denied
TUN device creation requires root:
```bash
sudo ./vpnclient connect -c config.json
```

### Connection Timeout
- Verify server reachable: `nc -zv vpn.example.com 443`
- Check firewall allows outbound TCP 443

### Authentication Failed
- Regenerate password hash with `vpnclient hash`
- Verify hub name matches exactly
- Confirm user permissions on hub

### TLS Certificate Errors
Most SoftEther servers use self-signed certificates. Use `skip_tls_verify: true` or configure `custom_ca_pem` / `cert_fingerprint_sha256`.

## Security

- **TLS 1.2/1.3** — All connections encrypted via rustls
- **SHA-0** — Legacy protocol requirement for password hashing
- **RC4** — Optional defense-in-depth within TLS tunnel
- **ChaCha20-Poly1305** — UDP Acceleration V2 AEAD
- **Certificate Pinning** — SHA-256 fingerprint verification
- **Constant-Time RSA** — Uses [hardened RSA fork](https://github.com/itsalfredakku/RustRSA) mitigating [Marvin Attack](https://people.redhat.com/~hkario/marvin/) (RUSTSEC-2023-0071)

## Documentation

- [FEATURE_MATRIX.md](FEATURE_MATRIX.md) — Detailed feature status by platform
- [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) — iOS/Android integration guide
- [config.example.json](config.example.json) — Complete configuration example

## License

Apache License 2.0

## Related Projects

- [SoftEther VPN](https://www.softether.org/) — Official SoftEther VPN Project
