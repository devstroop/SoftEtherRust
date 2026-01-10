# Known Issues & Technical Debt

> SoftEther VPN Rust Client - Issue Tracker  
> Last updated: January 2026

---

## 📊 Summary

| Category | High | Medium | Low | Total |
|----------|------|--------|-----|-------|
| Issues | 0 | 1 | 3 | 4 |
| Tech Debt | 2 | 4 | 2 | 8 |
| Performance | 0 | 1 | 4 | 5 |
| Missing Features | - | - | - | 7 |

---

## 🐛 Issues

### High Severity

*No high severity issues currently open.*

---

### Medium Severity

#### ISSUE-4: DHCP Response Race in Half-Connection Mode *(Needs Verification)*
**Location:** `src/tunnel/runner.rs:1374`

In half-connection mode with multiple connections, DHCP timing:
- Desktop client: Establishes ALL connections first, then DHCP polls receive-only connections
- FFI client: Does DHCP on primary (temporarily bidirectional) BEFORE additional connections

**Potential Issue:** If server hasn't fully established half-connection routing when DHCP starts, responses could be misrouted.

**Mitigating Factors:**
1. SoftEther's virtual switch broadcasts DHCP to all receive-capable connections
2. FFI client does DHCP with single bidirectional connection (no race possible)
3. Desktop client waits for all connections before DHCP

**Status:** Low likelihood - needs real-world testing with high-latency servers to confirm.
**If confirmed, fix:** Add small delay after connection establishment, or retry DHCP on timeout.

---

### Low Severity

#### ISSUE-6: Panic on Invalid Password Hash Length
**Location:** `src/client/mod.rs:522`

```rust
let password_hash_bytes: [u8; 20] = password_hash_vec.try_into().unwrap();
```

**Impact:** Panic instead of graceful error.  
**Fix:** Use `.map_err()` to convert to `Error::Config`.

---

#### ISSUE-7: Unchecked Array Index in ARP Parsing
**Location:** `src/packet/arp.rs:233`

```rust
let sender_mac: [u8; 6] = frame[arp_start + 8..arp_start + 14].try_into().unwrap();
```

**Impact:** Potential panic on malformed ARP packets.  
**Fix:** Use explicit error handling.

---

#### ISSUE-8: UDP Accel Session Not Closed on Disconnect
**Location:** `src/net/udp_accel.rs`

UDP socket relies on Drop instead of explicit close packet.

**Impact:** Server resource leak, potential port exhaustion.  
**Fix:** Send explicit close packet before dropping.

---

## 🔧 Technical Debt

### High Priority

#### DEBT-1: Large File - tunnel/runner.rs (2247 lines)

Handles too many concerns:
- Platform-specific TUN operations
- DHCP state machine
- ARP handling
- Multi-connection coordination
- RC4 encryption
- Data loop

**Recommendation:** Split into:
- `tunnel/dhcp_handler.rs`
- `tunnel/data_loop_unix.rs`
- `tunnel/data_loop_windows.rs`

---

#### DEBT-2: Large File - ffi/client.rs (2725 lines)

FFI layer reimplements desktop client logic instead of wrapping it.

**Duplication:** DHCP, ARP, packet loop, multi-connection management (~70% overlap)

**Recommendation:** Extract shared logic into `client/shared.rs`.

---

### Medium Priority

#### DEBT-3: Duplicated Data Loop Code
**Location:** `run_data_loop_unix` vs `run_data_loop_windows`

Both share: keepalive, ARP processing, compression, frame encoding.

**Recommendation:** Extract common logic with platform-specific callbacks.

---

#### DEBT-4: Inconsistent FFI Error Handling
**Location:** `src/ffi/client.rs`

```rust
if config.is_null() {
    return NULL_HANDLE;  // No error info for caller
}
```

**Recommendation:** Add `softether_get_last_error()` function.

---

#### DEBT-5: Missing Integration Tests for Multi-Connection

Half-connection mode state transitions:
```
┌─────────────────────────────────────────────────────────┐
│                    SoftEther Server                      │
└────────────┬──────────────┬──────────────┬──────────────┘
             │              │              │
        Connection 1   Connection 2   Connection 3
        (C2S - Send)   (S2C - Recv)   (S2C - Recv)
             │              │              │
             ▼              ▼              ▼
┌─────────────────────────────────────────────────────────┐
│                    VPN Client                            │
└─────────────────────────────────────────────────────────┘
```

- Primary starts bidirectional (handshake/auth/DHCP)
- Server assigns direction: C2S (upload) or S2C (download)
- N connections split ~evenly (4 conns → 2 C2S + 2 S2C)

**Why?** TCP ACKs don't compete with data when separated.

---

#### DEBT-6: Windows TUN Incomplete
**Location:** `src/adapter/windows.rs`

Missing DNS configuration and route cleanup on drop.

---

### Low Priority

#### DEBT-7: Multiple `unwrap()` in TLS Config
**Location:** `src/client/connection.rs:202-244`

**Recommendation:** Use `?` operator and return proper errors.

---

#### DEBT-8: Duplicated Auth Pack Logic
**Location:** `src/protocol/auth.rs`

Multiple constructors share ~60% code. Partially addressed with `add_client_fields()`.

---

## 📈 Performance

### Medium Priority

#### PERF-1: Buffer Pool for Receive Allocations
**Location:** `src/client/concurrent_reader.rs`

```rust
let data: Vec<u8> = packet.data.to_vec();  // Allocation per packet
```

**Recommendation:** Use `bytes::BytesMut` pool or arena allocator.

---

### Low Priority

#### PERF-2: Redundant Compression Check
**Location:** `src/tunnel/runner.rs`

Called for every packet even when compression is disabled.

**Recommendation:** Check `use_compress` flag first.

---

#### PERF-3: RC4 Batch Processing
**Location:** `src/crypto/rc4.rs`

Single buffer at a time. Batching could reduce overhead.

---

#### PERF-4: Fragment Reassembly HashMap Growth
**Location:** `src/packet/fragment.rs`

HashMap grows unbounded until cleanup. Use `with_capacity()`.

---

#### PERF-5: JNI String Allocations
**Location:** `src/ffi/android.rs`

Multiple allocations when copying from JNI. Consider stack buffers.

---

## 📋 Missing Features

| Feature | Status | Location |
|---------|--------|----------|
| Daemon Mode (CLI) | Not implemented | `src/main.rs` |
| DHCP Lease Renewal | Partial - timer not wired | `src/packet/dhcp.rs` |
| DHCPv6 Lease Renewal | Not implemented | `src/packet/dhcpv6.rs` |
| IPv6 Default Route | Not implemented | `src/tunnel/runner.rs` |
| Graceful Reconnection | Not implemented | `src/client/mod.rs` |
| UDP Accel V2 NAT-T | Partial | `src/net/udp_accel.rs` |
| Per-Connection Stats | Partial | `src/ffi/client.rs` |

---

## 🏗️ Architecture

### ✅ Positive Patterns

| Pattern | Description |
|---------|-------------|
| Zero-copy networking | `bytes::Bytes` and slice references throughout |
| Modular crypto | SHA-0, RC4, ChaCha20-Poly1305 in separate modules |
| Platform abstraction | `TunAdapter` trait for cross-platform TUN |
| Good test coverage | Most packet/protocol modules have unit tests |
| Clear separation | protocol/, packet/, net/, client/, ffi/ |
| Concurrent reader | Channel-based concurrent TCP reader |

### ⚠️ Areas for Improvement

| Issue | Impact |
|-------|--------|
| FFI/Desktop split | Two implementations instead of shared core |
| Large files | runner.rs (2247) and client.rs (2725) need splitting |
| Error propagation | Mix of `Result`, `Option`, and panics |
| State machine clarity | Connection states could use proper FSM pattern |

---

## 🧪 Test Coverage

| Module | Status | Notes |
|--------|--------|-------|
| `packet/arp.rs` | ✅ | Good coverage |
| `packet/dhcp.rs` | ✅ | State machine tests |
| `packet/dhcpv6.rs` | ✅ | Basic coverage |
| `packet/ethernet.rs` | ✅ | Zero-copy helpers |
| `packet/fragment.rs` | ✅ | Reassembly tested |
| `packet/qos.rs` | ✅ | Priority detection |
| `protocol/pack.rs` | ✅ | Serialization |
| `protocol/auth.rs` | ✅ | Auth pack building |
| `crypto/sha0.rs` | ✅ | Known test vectors |
| `crypto/rc4.rs` | ✅ | Stream cipher |
| `net/udp_accel.rs` | ⚠️ | Structure tests only |
| `tunnel/runner.rs` | ❌ | Complex, needs mocking |
| `ffi/client.rs` | ❌ | Needs integration tests |
| `client/mod.rs` | ⚠️ | Connection tests only |

---

## ✅ Recently Fixed

- [x] **ISSUE-5: Thread-Local Storage in iOS FFI** (Jan 2026) - Changed `softether_ios_get_session()` and `softether_ios_get_stats()` to use caller-provided buffers instead of thread-local storage. Prevents stale data across threads and pointer invalidation. API now consistent with other iOS helper functions.
- [x] **ISSUE-3: Missing Timeout on Additional Connection** (Jan 2026) - Wrapped `establish_one_additional()` with `tokio::time::timeout()` using `config.timeout_seconds`. Prevents hanging if server accepts TCP but never responds to handshake.
- [x] **ISSUE-2: Frame Split Across Multi-Connections** (Jan 2026) - **Closed as not a bug.** Analysis of official SoftEther source (Connection.c) confirms each TCP socket has independent `RecvFifo` and frame parsing state. Server sends complete frames to individual connections (never splits across connections). Per-connection `TunnelCodec` is correct.
- [x] **ISSUE-1: RC4 Stream Corruption** (Jan 2026) - Implemented per-connection RC4 cipher state. Each `ManagedConnection` now has its own `TunnelEncryption` instance, matching server's per-socket encryption model. Files: `multi_connection.rs`, `concurrent_reader.rs`, `runner.rs`
- [x] **Config layer restructure** (Jan 2026) - Authentication moved to nested `auth` object with method selection (password, RADIUS, cert, anonymous)
- [x] **Marvin Attack** (RUSTSEC-2023-0071) - Hardened RSA fork
- [x] **Digest conflict** - Updated sha1 to 0.11.0-rc.3

---

## Contributing

1. Reference this document in your PR (e.g., "Fixes ISSUE-3")
2. Add tests for the fix
3. Update this document to mark as fixed with date
