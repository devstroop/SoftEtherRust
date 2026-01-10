# Known Issues & Technical Debt

> SoftEther VPN Rust Client - Issue Tracker  
> Last updated: January 2026

---

## 📊 Summary

| Category | High | Medium | Low | Total |
|----------|------|--------|-----|-------|
| Issues | 0 | 0 | 0 | 0 |
| Tech Debt | 0 | 1 | 2 | 3 |
| Performance | 0 | 1 | 4 | 5 |
| Missing Features | - | - | - | 7 |

---

## 🐛 Issues

### High Severity

*No high severity issues currently open.*

---

### Medium Severity

*No medium severity issues currently open.*

---

### Low Severity

*No low severity issues currently open.*

---

## 🔧 Technical Debt

### Medium Priority

#### DEBT-5: Missing Integration Tests for Multi-Connection *(Fixed)*

**Status:** RESOLVED - Added 28 unit tests covering multi-connection logic.

**Test Coverage Added:**
| Module | Tests | Coverage |
|--------|-------|----------|
| `multi_connection.rs` | 17 | TcpDirection, ConnectionStats, round-robin, extraction |
| `concurrent_reader.rs` | 11 | ReceivedPacket, shutdown flags, bytes tracking |

**Tested Scenarios:**
- TcpDirection parsing from server (0=Both, 1=S2C, 2=C2S)
- Half-connection mode direction assignment
- Connection distribution for 4 and 8 connections
- Round-robin send/recv selection
- Connection extraction for ConcurrentReader
- Per-connection RC4 cipher independence
- Pack format for additional_connect method
- Shutdown flag propagation across tasks
- Connection index preservation

---

#### DEBT-6: Windows TUN Incomplete
**Location:** `src/adapter/windows.rs`

Missing DNS configuration and route cleanup on drop.

---

### Low Priority

#### DEBT-2: Large File - ffi/client.rs (2727 lines) *(Intentional Design)*

**Status:** Closed - intentional architectural split. FFI layer has different I/O model (callbacks vs TUN). Shared logic already extracted to `TunnelCodec`, `DhcpClient`, `ConnectionManager`.

---

#### DEBT-1: Large File - tunnel/runner.rs (2219 lines) *(Fixed)*

**Status:** RESOLVED - Split into multiple focused modules.

**Original File:** 2219 lines

**New Structure:**
| File | Lines | Purpose |
|------|-------|---------|
| `runner.rs` | 329 | Core TunnelRunner struct, entry points, routes |
| `dhcp_handler.rs` | 384 | DHCP handling (single + multi-connection) |
| `single_conn.rs` | 697 | Single-connection data loop (Unix + Windows) |
| `multi_conn.rs` | 659 | Multi-connection data loop (half-connection mode) |
| `packet_processor.rs` | 209 | Shared packet processing utilities |

Each file now has a single responsibility and is under 700 lines.

---

#### DEBT-7: Multiple `unwrap()` in TLS Config *(Fixed)*
**Location:** `src/client/connection.rs:202-244`

**Status:** RESOLVED - Replaced 4 `unwrap()` calls with proper `?` operator and `map_err()` to convert rustls errors to `Error::Tls`.

**Changes:**
- All 4 `with_safe_default_protocol_versions().unwrap()` calls now use `.map_err(|e| Error::Tls(...))?`
- Errors now propagate with descriptive message: "Failed to set TLS protocol versions: {error}"

---

#### DEBT-8: Duplicated Auth Pack Logic *(Fixed)*
**Location:** `src/protocol/auth.rs`

**Status:** RESOLVED - Refactored `new()` and `new_ticket()` to use `add_client_fields()`.

**Changes:**
- `AuthPack::new()`: Replaced ~75 lines of inline code with call to `add_client_fields()`
- `AuthPack::new_ticket()`: Replaced ~70 lines of inline code with call to `add_client_fields()`
- All 5 constructors now consistently use the shared helper function
- File reduced from 978 → 872 lines (~106 lines removed)

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
| Large files | ~~runner.rs (2247)~~ and client.rs (2725) - runner.rs split, client.rs intentional |
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

- [x] **DEBT-8: Duplicated Auth Pack Logic** (Jan 2026) - Refactored `AuthPack::new()` and `AuthPack::new_ticket()` to use `add_client_fields()` helper. All 5 auth constructors now share common code. File reduced from 978 → 872 lines (~106 lines removed).
- [x] **DEBT-7: Multiple `unwrap()` in TLS Config** (Jan 2026) - Replaced 4 `unwrap()` calls in `create_tls_config()` with proper error handling using `map_err()` to convert rustls errors to `Error::Tls`. Errors now propagate correctly instead of panicking.
- [x] **DEBT-5: Missing Integration Tests for Multi-Connection** (Jan 2026) - Added 28 unit tests: 17 in `multi_connection.rs` (TcpDirection, ConnectionStats, round-robin, half-connection distribution, RC4 independence) and 11 in `concurrent_reader.rs` (ReceivedPacket, bytes tracking, shutdown flags, connection index preservation). Test count increased from 118 to 145.
- [x] **DEBT-1: Large File - tunnel/runner.rs** (Jan 2026) - Split into 5 modules: `runner.rs` (329 lines), `dhcp_handler.rs` (384 lines), `single_conn.rs` (697 lines), `multi_conn.rs` (659 lines), `packet_processor.rs` (209 lines). Each module has a single responsibility.
- [x] **DEBT-3: Duplicated Data Loop Code** (Jan 2026) - Created `src/tunnel/packet_processor.rs` with shared utilities (`init_arp`, `send_keepalive_if_needed`, `send_periodic_garp_if_needed`, `send_pending_arp_reply`, `send_frame_encrypted`, `build_ethernet_frame`). Updated both `run_data_loop_unix` and `run_data_loop_windows` to use shared functions, eliminating ~60 lines of duplication.
- [x] **DEBT-4: Inconsistent FFI Error Handling** (Jan 2026) - Added `softether_get_last_error()` and `softether_clear_last_error()` FFI functions. Thread-local storage holds detailed error message on failure. Updated `softether_create()` to set specific error messages (e.g., "config is null", "server is null or invalid UTF-8").
- [x] **ISSUE-7: ARP Array Index Panic** (Jan 2026) - **Closed as safe code.** Line 201 validates `frame.len() >= 42` before any access. The slice `[arp_start+8..arp_start+14]` = `[22..28]` only needs indices 0-27, well within the 42-byte minimum. The `unwrap()` is unreachable.
- [x] **ISSUE-6: Password Hash Panic** (Jan 2026) - **Closed as safe code.** The `unwrap()` at line 524 is preceded by explicit length validation (lines 518-523) that returns `Error::Config` if not 20 bytes. The `unwrap()` is unreachable on invalid input.
- [x] **ISSUE-4: DHCP Response Race** (Jan 2026) - **Closed as works-as-designed.** FFI does DHCP on single bidirectional connection before additional connections. Desktop establishes all connections before DHCP. No race condition possible.
- [x] **ISSUE-8: UDP Accel Session Not Closed** (Jan 2026) - **Closed as works-as-designed.** Official SoftEther `FreeUdpAccel()` also relies on socket close + server keepalive timeout (9s). No explicit close packet in protocol.
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
