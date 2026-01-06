# SoftEther Rust Feature Matrix

## Platform Support Overview

| Feature | Desktop (Mac/Linux/Windows) | iOS (FFI) | Android (JNI) |
|---------|---------------------------|-----------|---------------|
| **TLS Connection** | ✅ | ✅ | ✅ |
| **Authentication** | ✅ | ✅ | ✅ |
| **DHCP** | ✅ | ✅ | ✅ |
| **DHCPv6** | ✅ (code exists) | ✅ | ✅ |
| **Multi-Connection** | ✅ | ❌ | ❌ |
| **Half-Connection Mode** | ✅ | ❌ | ❌ |
| **RC4 Encryption** | ✅ | ✅ | ✅ |
| **Compression** | ✅ | ✅ | ✅ |
| **UDP Acceleration** | ❌ (auth only) | ❌ (auth only) | ❌ (auth only) |
| **Socket Protection** | N/A | ✅ | ✅ |
| **IP Exclusion (Cluster)** | N/A | ✅ | ✅ |
| **Certificate Pinning** | ✅ | ✅ | ✅ |
| **NAT-T Keepalive** | ✅ | ✅ | ✅ |
| **IP Fragmentation** | ✅ | ✅ | ✅ |
| **DHCP Renewal/Rebind** | ✅ | ✅ | ✅ |
| **TUN/TAP Adapter** | ✅ | N/A (PacketTunnel) | N/A (VpnService) |

---

## Detailed Analysis

### 1. RC4 Tunnel Encryption ✅ COMPLETE

**Desktop (tunnel/runner.rs):**
- ✅ Parses RC4 keys from server Welcome packet via `AuthResult.rc4_key_pair`
- ✅ `TunnelEncryption` struct with `send_cipher`/`recv_cipher`
- ✅ Encrypts outgoing frames before send (`send_frame_encrypted`)
- ✅ Decrypts incoming frames after receive

**FFI Client (ffi/client.rs):**
- ✅ Parses `use_encrypt` config flag
- ✅ Server returns RC4 keys in auth response (parsed in `protocol/auth.rs`)
- ✅ `TunnelEncryption` struct in `run_packet_loop`
- ✅ Encrypts outgoing frames before send
- ✅ Decrypts incoming frames after receive

**Implementation:** Both paths share `crate::crypto::{Rc4, Rc4KeyPair}` and apply streaming RC4 cipher to all tunnel data when `use_encrypt=true` and server provides keys.

---

### 2. Multi-Connection / Half-Connection Mode

**Desktop:**
- ✅ `MultiConnectionManager` supports multiple TCP connections
- ✅ `TcpDirection` enum for half-connection mode
- ✅ Round-robin load balancing for send
- ✅ Parallel receive from all connections

**FFI/Mobile:**
- Uses `ConnectionManager` but effectively single connection
- No multi-connection negotiation
- Not a critical gap (single connection works fine for mobile)

---

### 3. UDP Acceleration

**All Platforms:**
- ✅ Auth flow sends UDP accel params (`udp_accel: true`)
- ✅ Server response parsed (`UdpAccelResponse`)
- ❌ No UDP data path implemented
- ❌ No fallback/upgrade to UDP when available

**Priority:** Low - TCP works fine, UDP is a performance optimization.

---

### 4. Socket Protection

**Desktop:** N/A (not needed - direct TUN/TAP access)

**Android:** ✅ `protect_socket` callback in JNI - calls `VpnService.protect()` to exclude socket from VPN

**iOS:** ✅ `protect_socket` callback + `excludedRoutes`:
  - `setsockopt(SO_NET_SERVICE_TYPE, NET_SERVICE_TYPE_VV)` marks socket as VPN traffic
  - `NEIPv4Route.excludedRoutes` excludes server IP from VPN routing
  - Dual-layer protection for reliable operation

---

### 5. Cluster Redirect / IP Exclusion

**Desktop:** Uses TUN/TAP routing directly

**iOS:** ✅ `excludedRoutes` in NEPacketTunnelNetworkSettings excludes server IP from VPN

**Android:** ✅ `exclude_ip` callback + `protect()` socket:
  - `onExcludeIp(ip)` callback notifies app of IPs to exclude
  - `VpnService.protect(fd)` prevents VPN routing loop for sockets
  - Excluded IPs stored for tunnel reconfiguration

---

## Code Locations

| Feature | Desktop | FFI/Mobile |
|---------|---------|------------|
| RC4 Encryption | `src/tunnel/runner.rs:TunnelEncryption` | `src/ffi/client.rs:TunnelEncryption` |
| Compression | `src/protocol/tunnel.rs:compress/decompress` | Same (shared) |
| Multi-Connection | `src/client/multi_connection.rs` | N/A |
| DHCP | `src/tunnel/runner.rs` (desktop), `src/ffi/client.rs:perform_dhcp` | Separate impls |
| Auth | `src/protocol/auth.rs` | Same (shared) |
| RC4 Crypto | `src/crypto/rc4.rs` | Same (shared) |

---

## Recommended Fixes

### Low Priority

1. **UDP acceleration data path**
   - Requires parallel UDP socket management
   - Deferred until TCP performance issues reported

2. **Multi-connection for mobile**
   - Single connection is sufficient for mobile use cases
   - Would add complexity with minimal benefit
