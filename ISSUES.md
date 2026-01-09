# Known Issues & Technical Debt

This document tracks known issues, potential bugs, and areas for improvement in the SoftEther Rust client.

---

## 🐛 Potential Bugs

### 1. RC4 Stream Corruption on Reconnect
**Severity:** High  
**Location:** `src/tunnel/runner.rs`, `src/ffi/client.rs`

If a connection drops and reconnects, the RC4 cipher state may be out of sync with the server. The streaming cipher maintains internal state that must match between client and server.

**Impact:** Tunnel data corruption after reconnection.

**Fix:** Reinitialize RC4 ciphers on each new connection, not just on initial connect.

---

### 2. Frame Split Across Multi-Connections
**Severity:** Medium  
**Location:** `src/tunnel/runner.rs:1580`

```rust
let mut codecs: Vec<TunnelCodec> = (0..num_conns).map(|_| TunnelCodec::new()).collect();
```

Each connection has its own `TunnelCodec` for stateful frame parsing. If a single tunnel frame is split across TCP segments that arrive on different connections (in half-connection mode), the codec will fail to reassemble.

**Impact:** Packet loss or decode errors in multi-connection mode.

**Investigation needed:** Verify SoftEther protocol guarantees frame boundaries align with TCP segment boundaries per connection.

---

### 3. Missing Timeout on Additional Connection Establishment
**Severity:** Medium  
**Location:** `src/client/multi_connection.rs`

```rust
async fn establish_one_additional(&self) -> Result<ManagedConnection> {
    // No timeout wrapper - could hang indefinitely
}
```

**Impact:** Connection setup could hang forever if server doesn't respond.

**Fix:** Wrap in `tokio::time::timeout()`.

---

### 4. Panic on Invalid Password Hash Length
**Severity:** Low  
**Location:** `src/client/mod.rs:522`

```rust
let password_hash_bytes: [u8; 20] = password_hash_vec.try_into().unwrap();
```

Uses `unwrap()` which will panic if the password hash is not exactly 20 bytes.

**Impact:** Panic instead of graceful error.

**Fix:** Use `.map_err()` to convert to `Error::Config`.

---

### 5. DHCP Response Race in Half-Connection Mode
**Severity:** Medium  
**Location:** `src/tunnel/runner.rs:1565`

In half-connection mode, the primary connection is temporarily set to bidirectional for DHCP. If DHCP responses arrive on a receive-only connection before the primary is restored, they may be processed incorrectly.

**Impact:** DHCP may fail intermittently in multi-connection mode.

---

### 6. Thread-Local Storage in iOS FFI Returns Stale Data
**Severity:** Medium  
**Location:** `src/ffi/ios.rs:95-110`

```rust
thread_local! {
    static SESSION_STORAGE: std::cell::RefCell<SoftEtherSession> = ...
}
```

The `softether_ios_get_session` function returns a pointer to thread-local storage. If called from different threads, each gets its own (potentially outdated) copy. Also, the returned pointer is only valid until the next call.

**Impact:** Stale session data or undefined behavior if pointer is stored.

**Fix:** Document lifetime limitations or use caller-provided buffer.

---

### 7. Unchecked Array Index in ARP Parsing
**Severity:** Low  
**Location:** `src/packet/arp.rs:233`

```rust
let sender_mac: [u8; 6] = frame[arp_start + 8..arp_start + 14].try_into().unwrap();
```

While the frame length is checked at the function start (>=42 bytes), this `unwrap()` could panic if the slice range is somehow invalid.

**Impact:** Potential panic on malformed ARP packets.

**Fix:** Use explicit error handling or `?` operator.

---

### 8. UDP Accel Session Not Closed on Disconnect
**Severity:** Low  
**Location:** `src/net/udp_accel.rs`, `src/tunnel/runner.rs`

When the VPN disconnects, the UDP acceleration socket may not be explicitly closed, relying on Drop. This could leave stale UDP sessions on the server.

**Impact:** Server resource leak, potential port exhaustion.

**Fix:** Send explicit close packet before dropping UdpAccel.

---

## 🔧 Technical Debt

### 1. Large File: tunnel/runner.rs (2247 lines)
**Priority:** High

This file handles too many concerns:
- Platform-specific TUN operations (macOS/Linux/Windows)
- DHCP state machine
- ARP handling
- Multi-connection coordination
- RC4 encryption state
- Data loop

**Recommendation:** Split into:
- `tunnel/dhcp_handler.rs`
- `tunnel/data_loop_unix.rs`
- `tunnel/data_loop_windows.rs`
- `tunnel/arp_handler.rs` (move from packet/)

---

### 2. Large File: ffi/client.rs (2725 lines)
**Priority:** High

The FFI layer reimplements much of the desktop client logic instead of wrapping it.

**Duplication:**
- DHCP handling
- ARP handling
- Packet loop
- Multi-connection management

**Recommendation:** Extract shared logic into `client/shared.rs` or use the desktop `TunnelRunner` with platform-specific packet I/O callbacks.

---

### 3. Duplicated Data Loop Code (~70% overlap)
**Priority:** Medium  
**Location:** `run_data_loop_unix` vs `run_data_loop_windows`

Both functions share most of their logic:
- Keepalive handling
- ARP processing
- Compression/decompression
- Frame encoding/decoding

**Recommendation:** Extract common logic into trait methods or a shared function that takes platform-specific callbacks.

---

### 4. Inconsistent Error Handling in FFI
**Priority:** Medium  
**Location:** `src/ffi/client.rs`

FFI functions return `NULL_HANDLE` or raw error codes instead of using a consistent error reporting mechanism.

```rust
if config.is_null() {
    return NULL_HANDLE;  // No error info for caller
}
```

**Recommendation:** Add `softether_get_last_error()` function that returns detailed error string, or use out-parameter for error details.

---

### 5. Missing Integration Tests for Multi-Connection
**Priority:** Medium

Multi-connection mode (half-connection) has complex state transitions:
- Primary connection starts bidirectional for handshake/auth/DHCP
- Server assigns direction to each connection after auth:
  - **C2S (Client→Server)**: Used for sending VPN packets to server
  - **S2C (Server→Client)**: Used for receiving VPN packets from server
- With N connections, server splits them ~evenly (e.g., 4 conns → 2 C2S + 2 S2C)
- Connection failure requires rebalancing remaining connections

**Why half-connection?** TCP works better when data flows primarily one direction (ACKs don't compete with data). Separating upload/download paths improves throughput.

**Recommendation:** Add integration tests that mock the server to verify state machine correctness.

---

### 6. Multiple `unwrap()` Calls in TLS Config
**Priority:** Low  
**Location:** `src/client/connection.rs:202-244`

```rust
.with_safe_default_protocol_versions()
.unwrap()
```

Multiple `unwrap()` calls in TLS configuration that could panic on edge cases.

**Recommendation:** Use `?` operator and return proper errors.

---

### 7. Duplicated Authentication Pack Logic
**Priority:** Low  
**Location:** `src/protocol/auth.rs`

The `AuthPack` struct has multiple constructors (`new`, `new_plain_password`, `new_anonymous`, `new_certificate`, `new_ticket`) that share ~60% of their code for client fields.

**Status:** Partially addressed - `add_client_fields()` extracts common logic, but still some duplication in ticket auth.

---

### 8. Windows TUN Device Abstraction Incomplete
**Priority:** Medium  
**Location:** `src/adapter/windows.rs`

The Windows adapter exists but is less feature-complete than macOS/Linux:
- Missing DNS configuration via Windows APIs
- Route cleanup on drop may not work correctly

---

## 📈 Performance Improvements

### 1. Buffer Pool for Receive Allocations
**Priority:** Medium  
**Location:** `src/client/concurrent_reader.rs`

```rust
let data: Vec<u8> = packet.data.to_vec();  // Allocation per packet
```

**Recommendation:** Use `bytes::BytesMut` pool or arena allocator for receive buffers.

---

### 2. Redundant Compression Check
**Priority:** Low  
**Location:** `src/tunnel/runner.rs`

```rust
let frame_data: &[u8] = if is_compressed(packet) { ... }
```

Called for every packet even when compression is disabled.

**Recommendation:** Check `use_compress` config flag first, skip `is_compressed()` call if disabled.

---

### 3. RC4 Batch Processing
**Priority:** Low  
**Location:** `src/crypto/rc4.rs`

Currently encrypts/decrypts one buffer at a time. For multi-packet frames, batching could reduce function call overhead.

---

### 4. Fragment Reassembly HashMap Growth
**Priority:** Low  
**Location:** `src/packet/fragment.rs`

```rust
states: HashMap<FragmentKey, ReassemblyState>,
```

The fragment reassembler uses a HashMap that can grow unbounded until cleanup runs. Consider using `HashMap::with_capacity()` or a bounded data structure.

---

### 5. String Allocations in JNI Layer
**Priority:** Low  
**Location:** `src/ffi/android.rs`

```rust
let server_str = match get_string(&mut env, &server) { ... }
```

Multiple string allocations when copying from JNI. Consider using stack-allocated buffers for small strings.

---

## 📋 Missing Features

### 1. Daemon Mode (CLI)
**Status:** Not implemented  
**Location:** `src/main.rs`

`disconnect` and `status` commands are stubbed out. Need daemon process with IPC.

---

### 2. DHCP Lease Renewal
**Status:** Partially implemented  
**Location:** `src/packet/dhcp.rs`

`DhcpState::Renewing` and `DhcpState::Rebinding` states exist but renewal timer is not wired in the tunnel runner.

---

### 3. IPv6 Default Route
**Status:** Not implemented  
**Location:** `src/tunnel/runner.rs`

IPv6 routing is parsed from config but `set_default_route` only handles IPv4.

---

### 4. Connection Statistics Export
**Status:** Partial  
**Location:** `src/ffi/client.rs`

`SoftEtherStats` struct exists but detailed per-connection stats are not exposed.

---

### 5. Graceful Reconnection
**Status:** Not implemented  
**Location:** `src/client/mod.rs`

No automatic reconnection on connection drop. Mobile apps handle this at the Swift/Kotlin layer, but desktop CLI has no reconnect logic.

---

### 6. UDP Acceleration V2 Full Support
**Status:** Partial  
**Location:** `src/net/udp_accel.rs`

ChaCha20-Poly1305 encryption is implemented, but:
- NAT traversal (NAT-T) is not fully implemented
- Fast disconnect detection is parsed but not acted upon

---

### 7. DHCPv6 Lease Renewal
**Status:** Not implemented  
**Location:** `src/packet/dhcpv6.rs`

DHCPv6 handler has `Dhcpv6State::Renewing` and `needs_renewal()` methods, but they're not wired into the tunnel runner.

---

## 🏗️ Architecture Observations

### Positive Patterns

1. **Zero-copy networking** - `bytes::Bytes` and slice references used throughout packet handling
2. **Modular crypto** - SHA-0, RC4, ChaCha20-Poly1305 in separate modules
3. **Platform abstraction** - `TunAdapter` trait for cross-platform TUN device
4. **Good test coverage** - Most packet/protocol modules have unit tests
5. **Clear separation** - Protocol parsing (protocol/), packet handling (packet/), networking (net/)
6. **Concurrent reader** - Well-designed channel-based concurrent TCP reader

### Areas for Improvement

1. **FFI/Desktop split** - Two separate implementations instead of shared core
2. **Large files** - tunnel/runner.rs and ffi/client.rs need decomposition
3. **Error propagation** - Mix of `Result`, `Option`, and panics
4. **State machine clarity** - Connection states could use a proper state machine pattern

---

## ✅ Recently Fixed

- [x] Marvin Attack RSA vulnerability (RUSTSEC-2023-0071) - Fixed by using hardened RSA fork
- [x] Digest version conflict - Updated sha1 to 0.11.0-rc.3
- [x] Auth restructure for multiple auth methods (password, RADIUS, certificate, anonymous)

---

## 🧪 Test Coverage Status

| Module | Unit Tests | Notes |
|--------|------------|-------|
| `packet/arp.rs` | ✅ Yes | Good coverage |
| `packet/dhcp.rs` | ✅ Yes | State machine tests |
| `packet/dhcpv6.rs` | ✅ Yes | Basic coverage |
| `packet/ethernet.rs` | ✅ Yes | Zero-copy helpers tested |
| `packet/fragment.rs` | ✅ Yes | Reassembly tested |
| `packet/qos.rs` | ✅ Yes | Priority detection |
| `protocol/pack.rs` | ✅ Yes | Serialization |
| `protocol/auth.rs` | ✅ Yes | Auth pack building |
| `crypto/sha0.rs` | ✅ Yes | Known test vectors |
| `crypto/rc4.rs` | ✅ Yes | Stream cipher |
| `net/udp_accel.rs` | ⚠️ Partial | Only structure tests |
| `tunnel/runner.rs` | ❌ No | Complex, needs mocking |
| `ffi/client.rs` | ❌ No | Needs integration tests |
| `client/mod.rs` | ⚠️ Partial | Connection tests only |

---

## Contributing

When fixing an issue:
1. Reference this document in your PR
2. Add tests for the fix
3. Update this document to mark as fixed with date

Last updated: January 2026
