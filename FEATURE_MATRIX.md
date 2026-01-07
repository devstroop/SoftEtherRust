# SoftEther Rust Feature Matrix

## Platform Support Overview

| Feature | Desktop (Mac/Linux/Windows) | iOS (FFI) | Android (JNI) |
|---------|---------------------------|-----------|---------------|
| **TLS Connection** | ✅ | ✅ | ✅ |
| **Authentication** | ✅ | ✅ | ✅ |
| **DHCP** | ✅ | ✅ | ✅ |
| **DHCPv6** | ✅ | ✅ | ✅ |
| **Multi-Connection** | ✅ | ✅ | ✅ |
| **Half-Connection Mode** | ✅ | ✅ | ✅ |
| **RC4 Encryption** | ✅ | ✅ | ✅ |
| **Compression** | ✅ | ✅ | ✅ |
| **UDP Acceleration** | ✅ V1+V2 | ✅ V1+V2 | ✅ V1+V2 |
| **Socket Protection** | N/A | ✅ | ✅ |
| **IP Exclusion (Cluster)** | N/A | ✅ | ✅ |
| **Certificate Pinning** | ✅ | ✅ | ✅ |
| **NAT-T Keepalive** | ✅ | ✅ | ✅ |
| **IP Fragmentation** | ✅ | ✅ | ✅ |
| **DHCP Renewal/Rebind** | ✅ | ✅ | ✅ |
| **Reconnection (User In Use)** | ✅ | ✅ | ✅ |
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

### 2. Multi-Connection / Half-Connection Mode ✅ COMPLETE

**Desktop:**
- ✅ `MultiConnectionManager` supports multiple TCP connections
- ✅ `TcpDirection` enum for half-connection mode
- ✅ Round-robin load balancing for send
- ✅ Parallel receive from all connections

**FFI/Mobile:**
- ✅ Uses same `ConnectionManager` from desktop implementation
- ✅ Calls `establish_additional_connections()` after DHCP
- ✅ Half-connection mode auto-enabled when `max_connections > 1`
- ✅ Primary connection always ClientToServer (send), additional get directions from server

---

### 3. UDP Acceleration

**All Platforms:**
- ✅ Auth flow sends UDP accel params (`udp_accel: true`)
- ✅ Server response parsed (`UdpAccelResponse`)
- ✅ UDP data path implemented (`src/net/udp_accel.rs`)
- ✅ V1 protocol (RC4 + SHA-1) fully implemented
- ✅ V2 protocol (ChaCha20-Poly1305 AEAD) fully implemented
- ✅ Automatic fallback to TCP when UDP not ready
- ✅ Parallel send/receive in packet loop

**Implementation Details:**
- `UdpAccel::send()` - Encode and encrypt packets for UDP
- `UdpAccel::try_recv()` - Non-blocking receive from UDP socket
- `UdpAccel::is_send_ready()` - Check if UDP path is established
- `UdpAccel::send_keepalive()` - Keep UDP connection alive
- V1 packet format: IV (20B) + Cookie + Timestamps + Size + Flag + Data + Verify (20B zeros)
- V1 key derivation: SHA-1(common_key || iv) for RC4 encryption
- V2 packet format: Nonce (12B) + [Encrypted Payload] + Tag (16B)
- V2 uses ChaCha20-Poly1305 AEAD (first 32 bytes of 128B common key)

**Priority:** ✅ Complete for V1 and V2.

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
| Multi-Connection | `src/client/multi_connection.rs` | Same (shared) |
| UDP Acceleration | `src/net/udp_accel.rs` | Same (shared) |
| DHCP | `src/tunnel/runner.rs` (desktop), `src/ffi/client.rs:perform_dhcp` | Separate impls |
| Auth | `src/protocol/auth.rs` | Same (shared) |
| RC4 Crypto | `src/crypto/rc4.rs` | Same (shared) |

---

## Completed Items

All major features are now complete:
- ✅ TLS/HTTPS connection with certificate pinning
- ✅ Password and secure authentication
- ✅ DHCP v4 and v6 with lease renewal/rebind
- ✅ Multi-connection and half-connection modes
- ✅ RC4 tunnel encryption
- ✅ LZ4 compression
- ✅ UDP Acceleration V1 (RC4 + SHA-1) and V2 (ChaCha20-Poly1305)
- ✅ Socket protection (iOS/Android)
- ✅ IP exclusion for cluster redirects
- ✅ NAT-T keepalive
- ✅ IP fragmentation and reassembly
- ✅ QoS packet prioritization
- ✅ ARP/Gateway MAC learning
- ✅ Packet statistics tracking
- ✅ Reconnection logic for "User Already Logged In"

---

## Config Parameter Comparison

| Parameter | Android | iOS | Rust FFI |
|-----------|---------|-----|----------|
| Server/Port/Hub | ✅ | ✅ | ✅ |
| Username/PasswordHash | ✅ | ✅ | ✅ |
| Skip TLS Verify | ✅ | ✅ | ✅ |
| Custom CA PEM | ❌ | ✅ | ✅ |
| Cert Fingerprint | ❌ | ✅ | ✅ |
| Max Connections | ✅ | ✅ | ✅ |
| Timeout Seconds | ✅ | ✅ | ✅ |
| MTU | ✅ | ✅ | ✅ |
| Encryption | ✅ | ✅ | ✅ |
| Compression | ✅ | ✅ | ✅ |
| UDP Acceleration | ✅ | ✅ | ✅ |
| QoS | ✅ | ✅ | ✅ |
| NAT Traversal | ✅ | ✅ | ✅ |
| Monitor Mode | ✅ | ✅ | ✅ |
| Default Route | ✅ | ✅ | ✅ |
| Accept Pushed Routes | ✅ | ✅ | ✅ |
| IPv4 Include/Exclude | ✅ | ✅ | ✅ |
| IPv6 Include/Exclude | ❌ | ✅ | ✅ |
| Static IPv4 | ❌ | ✅ | ✅ |
| Static IPv6 | ❌ | ✅ | ✅ |
