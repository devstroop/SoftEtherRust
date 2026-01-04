# Issues & TODO

## 1. Critical

_All critical issues resolved._

---

## 2. iOS Integration

_All iOS integration issues resolved._

---

## 3. Android

### 3.1 Example Kotlin Bridge Missing Options
- `nativeCreate` accepts all config but `SoftEtherBridge.kt` doesn't expose: MTU, routing options
- File: `examples/android/SoftEtherBridge.kt`

### 3.2 Hardcoded MAC Address
- `SoftEtherVpnService.kt` uses hardcoded `srcMAC` instead of session MAC from callback

### 3.3 Packet Queue No Backpressure
- Fixed 256 queue size, packets silently dropped when full
- Location: `src/ffi/client.rs:20`

---

## 4. Protocol

### 4.1 UDP Acceleration Not Integrated
- Code exists in `src/net/udp_accel.rs` but not wired into:
  - Auth flow: UDP accel params not sent during authentication
  - Tunnel runner: No fallback/upgrade to UDP when available
- Official C: `UdpAccel` integrated with `SessionMain()`, parallel send/recv paths

### 4.2 Certificate Pinning Missing
- Only supports: skip verify or system roots
- No custom CA or fingerprint pinning

### 4.3 Keep-Alive NAT-T Port Signaling Not Implemented
- Official C: `SendKeepAlive()` embeds UDP NAT-T port via `UDP_NAT_T_PORT_SIGNATURE_IN_KEEP_ALIVE` prefix
- Allows server to discover client's NAT-mapped UDP port for acceleration
- Current code sends random keep-alive padding without this signature

### 4.4 UseSSLDataEncryption Flag Not Handled
- Official C: If `UseEncrypt=true` but `UseFastRC4=false`, sets `UseSSLDataEncryption=true`
- This means data encryption is handled by TLS layer, not application-level RC4
- Need to detect this case and skip application-level encryption

---

## 5. Performance

### 5.1 Compression Level
- `src/protocol/tunnel.rs:92` uses `Compression::default()`, should use `Compression::fast()`

### 5.2 Tokio Threads Hardcoded
- FFI uses 2 worker threads, should be 1 for mobile battery

### 5.3 FIFO Buffer Pre-allocation
- Official C pre-allocates `RecvFifo`/`SendFifo` per connection
- Rust uses `BytesMut::with_capacity()` but could benefit from pool allocation for high throughput

---

## 6. Half-Connection Mode

### 6.1 Direction Assignment Not Verified
- Implementation exists in `src/client/multi_connection.rs`
- Official C: First connection is always `TCP_CLIENT_TO_SERVER`, server assigns additional connection directions
- Need to verify direction parsing matches official: `1=ServerToClient`, `2=ClientToServer`
- Current implementation looks correct but needs integration testing

---

## 7. Resolved

- ✅ Compression latency (switched to fast level)
- ✅ Android socket protection
- ✅ DHCP through tunnel
- ✅ C header state enum fixed
- ✅ Half-connection mode direction parsing (TcpDirection enum)
- ✅ RC4 Tunnel Encryption (src/crypto/rc4.rs with streaming cipher)
- ✅ RC4 Key Pair parsing from server Welcome packet
- ✅ RC4 integration in tunnel TX/RX paths (single-conn Unix & Windows)
- ✅ Swift bridge field name mismatches fixed (skip_tls_verify, timeout_seconds, mtu, etc.)
- ✅ Swift bridge missing fields added (useEncrypt, udpAccel, qos, natTraversal, routing)
- ✅ Swift Session mac_address and gateway_mac added
- ✅ Swift log callback wired (on_log)
