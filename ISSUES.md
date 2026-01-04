# Issues & TODO

## 1. Critical

### 1.1 RC4 Tunnel Encryption Not Implemented
- `use_encrypt` flag sent to server but no actual encryption in data path
- Official C code uses `UseFastRC4` flag → calls `WriteSendFifo()`/`WriteRecvFifo()` with `Encrypt()` (RC4 stream cipher)
- Key exchange: Server sends `rc4_key_client_to_server` and `rc4_key_server_to_client` in Welcome packet (16 bytes each)
- Client must call equivalent of `InitTcpSockRc4Key()` to create separate `SendKey`/`RecvKey` crypt contexts
- Without RC4: server expects encrypted data if `use_encrypt=true`, connection may fail or produce garbage
- Need: `src/crypto/rc4.rs` with streaming cipher
- Need: Parse RC4 keys from auth response in `src/protocol/auth.rs`
- Need: Integrate into `src/tunnel/runner.rs` TX/RX paths

### 1.2 RC4 Key Pair Not Parsed from Server Response
- Server returns `rc4_key_client_to_server` and `rc4_key_server_to_client` (both 16 bytes) in auth Welcome packet
- `AuthResult::from_pack()` doesn't parse these fields
- Missing: `RC4_KEY_PAIR` struct with `ClientToServerKey[16]` and `ServerToClientKey[16]`

---

## 2. iOS Integration

### 2.1 Swift Bridge Mismatches Rust FFI
- Wrong field names: `use_tls` → `skip_tls_verify`, `connect_timeout_secs` → `timeout_seconds`
- Missing fields: `mtu`, `use_encrypt`, `udp_accel`, `qos`, `nat_traversal`, routing options
- Missing: `mac_address`, `gateway_mac` in Session struct
- File: `examples/ios/SoftEtherBridge.swift`

### 2.2 Log Callback Not Wired
- `on_log` callback exists in FFI but Swift bridge doesn't implement it

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
