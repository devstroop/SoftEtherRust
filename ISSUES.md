# Issues & TODO

## 1. Critical

_All critical issues resolved._

---

## 2. iOS Integration

_All iOS integration issues resolved._

---

## 3. Android

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

---

## 5. Performance

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
- ✅ Kotlin bridge all config options exposed (MTU, encrypt, udpAccel, qos, routing)
- ✅ Kotlin Session now includes macAddress from session
- ✅ VpnService uses session MAC instead of hardcoded
- ✅ Kotlin log callback and socket protection callback added
- ✅ UseSSLDataEncryption flag handled (skip RC4 when no keys present)
- ✅ NAT-T port keepalive signaling implemented (encode_keepalive_with_nat_t)
- ✅ Compression switched to fast level for low latency
- ✅ Tokio worker threads reduced to 1 for mobile battery
- ✅ Certificate pinning implemented (custom CA PEM and SHA-256 fingerprint verification)
