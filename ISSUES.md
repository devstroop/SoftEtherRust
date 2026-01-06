# Issues & TODO

## 1. Critical

_No critical issues._

---

## 2. iOS Integration

_All iOS integration issues resolved._

---

## 3. Android

_All Android issues resolved._

---

## 4. Protocol

### 4.1 UDP Acceleration Data Path Not Integrated
- ✅ UDP accel params now sent during authentication (when `udp_accel: true`)
- ✅ Server UDP accel response is parsed and logged
- ❌ UDP data path NOT integrated into tunnel runner
- ❌ No fallback/upgrade to UDP when available
- Note: Auth negotiation is complete, but actual UDP send/recv requires tunnel runner changes
- Official C: `UdpAccel` integrated with `SessionMain()`, parallel send/recv paths

---

## 5. Performance

_All performance issues resolved._

---

## 6. Half-Connection Mode

_All half-connection mode issues resolved._

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
- ✅ Packet queue backpressure implemented (QueueFull result code, dropped packet stats)
- ✅ UDP acceleration auth flow wired (params sent, server response parsed)
- ✅ FIFO buffer pre-allocation (compress_into for zero-alloc hot path, pre-alloc comp_buf)
- ✅ iOS socket protection via setsockopt(SO_NET_SERVICE_TYPE, NET_SERVICE_TYPE_VV)
- ✅ RC4 encryption in FFI/mobile packet loop (TunnelEncryption with encrypt/decrypt)
- ✅ Half-connection mode direction verified (TcpDirection 0=Both, 1=ServerToClient, 2=ClientToServer matches official C; primary always ClientToServer; can_send/can_recv filters connections correctly)
