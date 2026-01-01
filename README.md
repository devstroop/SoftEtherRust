# SoftEther VPN Client (Rust)

A high-performance, fully async SoftEther VPN client implementation in Rust.

## Features

- **Full Protocol Compatibility** — Connects to SoftEther VPN Server with complete protocol support
- **Multi-Connection Mode** — Configurable TCP connections (1–32) for improved throughput
- **Cluster Support** — Automatic redirect handling for SoftEther VPN cluster servers
- **DHCP Client** — Automatic IP configuration from the VPN server
- **ARP Handler** — Gateway MAC address resolution for proper L2 operation
- **Flexible Routing** — Split tunneling with include/exclude CIDR lists
- **Cross-Platform** — macOS (utun) and Linux (TUN) support
- **TLS 1.2/1.3** — Secure connections via rustls with optional certificate verification
- **RC4 Encryption** — Optional packet-level encryption within the TLS tunnel
- **Compression** — Optional zlib compression for reduced bandwidth
- **QoS Support** — VoIP/real-time traffic prioritization

## Requirements

- Rust 1.75+
- Root/sudo privileges (TUN device creation)
- macOS 10.12+ or Linux 3.10+

## Installation

```bash
git clone https://github.com/yourusername/SoftEtherRust
cd SoftEtherRust
cargo build --release
```

Binary location: `target/release/vpnclient`

## Quick Start

```bash
# 1. Generate a password hash (required for config)
./vpnclient hash -u your_username -p your_password

# 2. Generate sample config
./vpnclient gen-config -o config.json

# 3. Edit config.json with your server details and password hash

# 4. Connect
sudo ./vpnclient -c config.json
```

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `connect` | Connect to a VPN server |
| `hash` | Generate password hash for authentication |
| `gen-config` | Generate a sample configuration file |
| `disconnect` | Disconnect from VPN (daemon mode, not yet implemented) |
| `status` | Show connection status (daemon mode, not yet implemented) |

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
      --skip-tls-verify       Verify TLS certificate 
  -v, --verbose               Enable verbose output
  -d, --debug                 Enable debug output
```

### Generate Password Hash

SoftEther uses SHA-0 hashed passwords. Generate once and store in your config:

```bash
./vpnclient hash -u myuser -p mypassword

# Output:
# Password hash for user 'myuser':
# a1b2c3d4e5f6... (40 hex characters)
```

## Configuration

### Example Configuration

```json
{
  "server": "vpn.example.com",
  "port": 443,
  "hub": "DEFAULT",
  "username": "your_username",
  "password_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",

  "skip_tls_verify": true,
  "timeout_seconds": 30,

  "use_encrypt": true,
  "use_compress": false,
  "udp_accel": false,
  "qos": true,

  "nat_traversal": false,
  "monitor_mode": false,
  "max_connections": 1,
  "mtu": 1400,

  "routing": {
    "default_route": false,
    "accept_pushed_routes": true,
    "ipv4_include": [],
    "ipv4_exclude": []
  }
}
```

### Configuration Reference

#### Connection

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `server` | string | *required* | VPN server hostname or IP |
| `port` | number | `443` | Server port |
| `hub` | string | *required* | Virtual Hub name |
| `timeout_seconds` | number | `30` | Connection timeout |

#### Authentication

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `username` | string | *required* | Username |
| `password_hash` | string | *required* | SHA-0 password hash (40 hex chars) |

#### TLS

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `skip_tls_verify` | boolean | `true` | Skip certificate verification |

#### Tunnel Features

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `use_encrypt` | boolean | `true` | RC4 packet encryption (defense in depth) |
| `use_compress` | boolean | `false` | Enable zlib compression |
| `udp_accel` | boolean | `false` | UDP acceleration (experimental) |
| `qos` | boolean | `true` | VoIP/QoS prioritization |

#### Session Mode

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `nat_traversal` | boolean | `false` | NAT mode (`true`) vs Bridge mode (`false`) |
| `monitor_mode` | boolean | `false` | Packet capture mode (requires permissions) |

#### Performance

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_connections` | number | `1` | TCP connections (1–32) |
| `mtu` | number | `1400` | TUN device MTU |

#### Routing

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `routing.default_route` | boolean | `false` | Route all traffic through VPN |
| `routing.accept_pushed_routes` | boolean | `true` | Accept server-pushed routes |
| `routing.ipv4_include` | array | `[]` | CIDRs to route through VPN |
| `routing.ipv4_exclude` | array | `[]` | CIDRs to exclude from VPN |

### Environment Variables

Configuration can be overridden via environment variables:

| Variable | Description |
|----------|-------------|
| `SOFTETHER_SERVER` | Server address |
| `SOFTETHER_PORT` | Server port |
| `SOFTETHER_HUB` | Hub name |
| `SOFTETHER_USER` | Username |
| `SOFTETHER_PASSWORD_HASH` | Password hash |

## Library Usage

```rust
use softether_rust::{VpnClient, VpnConfig, crypto};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Generate password hash (do this once, store the result)
    let hash = crypto::hash_password("password", "username");
    let hash_hex = hex::encode(hash);

    let config = VpnConfig {
        server: "vpn.example.com".to_string(),
        port: 443,
        hub: "VPN".to_string(),
        username: "username".to_string(),
        password_hash: hash_hex,
        ..Default::default()
    };

    let mut client = VpnClient::new(config);
    client.connect().await?;

    Ok(())
}
```

## Architecture

```
+--------------------------------------------------------------------+
|                           VpnClient                                |
+--------------------------------------------------------------------+
|  +-----------------+  +-------------+  +------------------------+  |
|  |    Protocol     |  |   Crypto    |  |       Adapter          |  |
|  |  +-----------+  |  |  +-------+  |  |  +------------------+  |  |
|  |  |   HTTP    |  |  |  | SHA-0 |  |  |  |   TunAdapter     |  |  |
|  |  |  Codec    |  |  |  +-------+  |  |  |                  |  |  |
|  |  +-----------+  |  |  +-------+  |  |  |  +----+  +-----+ |  |  |
|  |  +-----------+  |  |  |  RC4  |  |  |  |  |utun|  | tun | |  |  |
|  |  |   Pack    |  |  |  +-------+  |  |  |  +----+  +-----+ |  |  |
|  |  | Serialize |  |  +-------------+  |  |  macOS   Linux   |  |  |
|  |  +-----------+  |                   |  +------------------+  |  |
|  |  +-----------+  |  +-------------+  +------------------------+  |
|  |  |   Auth    |  |  |   Tunnel    |                              |
|  |  +-----------+  |  |  +-------+  |  +------------------------+  |
|  |  +-----------+  |  |  | DHCP  |  |  |   ConnectionManager    |  |
|  |  |  Tunnel   |  |  |  |Client |  |  |  +------------------+  |  |
|  |  |  Codec    |  |  |  +-------+  |  |  | Multi-Connection |  |  |
|  |  +-----------+  |  |  +-------+  |  |  |     Support      |  |  |
|  +-----------------+  |  |  ARP  |  |  |  +------------------+  |  |
|                       |  +-------+  |  +------------------------+  |
|                       +-------------+                              |
+--------------------------------------------------------------------+
|                    Tokio Async Runtime                             |
|              (TCP/TLS with rustls, Timers, Signals)                |
+--------------------------------------------------------------------+
```

## Protocol Flow

```
Client                                          Server
   |                                               |
   |---- TCP Connect ----------------------------->|
   |<--- TLS Handshake --------------------------->|
   |                                               |
   |---- POST /vpnsvc/connect.cgi ---------------->|
   |     (VPNCONNECT signature)                    |
   |<--- 200 OK + Hello Pack ----------------------|
   |     (server random)                           |
   |                                               |
   |---- POST /vpnsvc/vpn.cgi -------------------->|
   |     (Auth Pack: hub, user, hashed password)   |
   |<--- 200 OK + Auth Result ---------------------|
   |     (session_key, policy, redirect?)          |
   |                                               |
   |        +--- If Cluster Redirect ---+          |
   |        |  Connect to redirect IP   |          |
   |        |  Authenticate with ticket |          |
   |        +---------------------------+          |
   |                                               |
   |<--- Block-based Tunnel Protocol ------------->|
   |     (Ethernet frames, compressed/encrypted)   |
   |                                               |
   |---- DHCP Discover --------------------------->|
   |<--- DHCP Offer -------------------------------|
   |---- DHCP Request ---------------------------->|
   |<--- DHCP Ack (IP, Gateway, DNS) --------------|
   |                                               |
   |---- ARP Request (Gateway MAC) --------------->|
   |<--- ARP Reply --------------------------------|
   |                                               |
   |<--- Tunnel Data (L2 Ethernet Frames) -------->|
   |                                               |
```

## Building

```bash
# Debug build
cargo build

# Release build (optimized, stripped)
cargo build --release

# Run tests
cargo test

# Generate docs
cargo doc --open
```

## Troubleshooting

### Permission Denied

TUN device creation requires root:

```bash
sudo ./vpnclient connect -c config.json
```

### Connection Timeout

- Verify server is reachable: `nc -zv vpn.example.com 443`
- Check firewall allows outbound TCP 443
- Verify DNS resolution

### Authentication Failed

- Ensure password hash is correct (regenerate with `hash` command)
- Verify hub name matches server configuration exactly
- Confirm user has permissions on the hub

### TLS Certificate Errors

Most SoftEther servers use self-signed certificates. The default `skip_tls_verify: true` handles this. For production, consider:

```json
{
  "skip_tls_verify": false
}
```

And ensure proper CA certificates are available.

### Multi-Connection Issues

If experiencing instability with `max_connections > 1`, try reducing to `1` for debugging.

## Security Notes

- **SHA-0**: SoftEther uses SHA-0 for password hashing (legacy protocol requirement)
- **TLS**: All connections use TLS 1.2/1.3 via rustls
- **RC4**: Optional packet encryption within the TLS tunnel (defense in depth)
- **Password Storage**: Store `password_hash` in config, not plaintext passwords

## License

Apache License 2.0

## Related Projects

- [SoftEther VPN](https://www.softether.org/) — Official SoftEther VPN Project
- [SoftEtherSwift](https://github.com/devstroop/SoftEtherSwift) — Swift implementation
- [SoftEtherZig](https://github.com/devstroop/SoftEtherZig) — Zig implementation
