# Known Issues & Technical Debt

> SoftEther VPN Rust Client - Issue Tracker  
> Last updated: January 15, 2026

---

## 📊 Summary

| Category | Critical | High | Medium | Low | Total |
|----------|----------|------|--------|-----|-------|
| Performance | 5 | 2 | 2 | 3 | 12 |
| Architecture | 0 | 1 | 1 | 0 | 2 |
| Tech Debt | 0 | 0 | 1 | 2 | 3 |
| Missing Features | - | - | - | - | 7 |

---

## 🎯 Execution Plan

### Phase 1: Fix Contention (Critical - Fixes Seesaw)

| # | Task | File(s) | Effort | Impact |
|---|------|---------|--------|--------|
| 1.1 | **Remove `biased` from select** OR use poll()/mio | `src/ffi/client.rs:1790` | Medium | **Fixes UL/DL seesaw** |
| 1.2 | Set TCP_NODELAY on all connections | `src/client/connection.rs` | Low | -40ms per packet |
| 1.3 | Reduce write queue depth 64 → 4 | `src/ffi/client.rs:1569` | Low | -200ms latency |

### Phase 2: Reduce iOS Buffering (High - iOS Specific)

| # | Task | File(s) | Effort | Impact |
|---|------|---------|--------|--------|
| 2.1 | **Remove Swift PacketBuffer entirely** | `SoftEtherBridge.swift:490-530` | Low | **-500-2000ms** |
| 2.2 | Direct TUN write in callback (sync) | `PacketTunnelProvider.swift` | Low | Eliminate async hop |
| 2.3 | Thin SoftEtherBridge to FFI-only | `SoftEtherBridge.swift` | Medium | Cleaner code |

### Phase 3: Optimize Hot Path (Medium)

| # | Task | File(s) | Effort | Impact |
|---|------|---------|--------|--------|
| 3.1 | Pre-allocate decompress buffer | `src/ffi/client.rs:1840` | Medium | +15% throughput |
| 3.2 | Remove callback_buffer copy | `src/ffi/client.rs:1564` | Medium | +5% throughput |
| 3.3 | Use stack buffers like Zig | `src/ffi/client.rs` | Medium | Reduce allocations |

### Phase 4: Validate & Benchmark

| # | Task | Tool | Success Criteria |
|---|------|------|------------------|
| 4.1 | Throughput test | iperf3 | ≥50 Mbps **both directions simultaneously** |
| 4.2 | Latency test | ping | ≤200ms base, ≤800ms peak |
| 4.3 | Stability test | 1hr continuous | No seesaw behavior |

---

## 🚨 Performance Crisis Summary

**Current State vs Targets:**

| Metric | Target | iOS WiFi+VPN | macOS WiFi+VPN | Old C Code |
|--------|--------|--------------|----------------|------------|
| **Download** | 50-60+ Mbps | **4.14 Mbps** ❌ | 12-46 Mbps (variable) | 100+ Mbps |
| **Upload** | 50+ Mbps | ~10 Mbps | ~20 Mbps | 100+ Mbps |
| **Latency** | 165ms base | **6787ms** ❌ | 324ms (spikes to 4573ms) | 168ms stable |

---

## 📚 Deep Dive: C vs Rust Implementation Analysis

### Official SoftEther C Code (Session.c, Connection.c)

The official implementation uses a **sequential poll-based loop** with `Select()`:

```c
// Session.c:213-510 - SessionMain() main loop
while (true) {
    // 1. RECEIVE: Poll ALL sockets via Select() (fair multiplexing)
    ConnectionReceive(c, s->Cancel1, s->Cancel2);
    
    // 2. PROCESS: Immediately write to TUN (NO BUFFERING)
    while (b = GetNext(c->ReceivedBlocks)) {
        pa->PutPacket(s, b->Buf, b->Size);  // DIRECT kernel call
    }
    
    // 3. GET OUTBOUND: Read packets from TUN
    while (packet = pa->GetNextPacket(s, &packet)) {
        InsertQueue(c->SendBlocks, NewBlock(packet, packet_size, compress));
    }
    
    // 4. SEND: Write to TCP (select LEAST LOADED socket)
    ConnectionSend(c, now);
}
```

**Connection.c:1728 - Fair Socket Selection:**
```c
// Select() with all sockets - NO BIAS
Select(&set, time, c1, c2);  // Fair polling of ALL file descriptors
```

**Connection.c:1032-1065 - Least-Loaded Socket for Send:**
```c
for (i = 0; i < num; i++) {
    if (IS_SEND_TCP_SOCK(tcpsock)) {
        if (tcpsock->LateCount <= min_count) {
            min_count = tcpsock->LateCount;
            ts = tcpsock;  // Select socket with fewest delays
        }
    }
}
```

### Rust Implementation (client.rs) - PROBLEMATIC

```rust
// client.rs:1790-2100 - BROKEN pattern
tokio::select! {
    biased;  // ← ROOT CAUSE: Branch 1 ALWAYS checked first
    
    // Branch 1: TCP Read (ALWAYS wins when data available)
    result = conn_mgr.read_any(&mut read_buf) => { ... }
    
    // Branch 2: Upload (ONLY runs if Branch 1 has nothing)
    Some(data) = tx_recv.recv() => { ... }
    
    // Branch 3: TCP Write drain (conditional guard)
    Some(data) = write_rx.recv(), if pending_write.is_none() => { ... }
}
```

---

## 🔍 Buffering Layer Comparison

### C Code: Minimal Buffering (1 layer)

| Buffer | Purpose | Behavior |
|--------|---------|----------|
| `RecvFifo` (per socket) | Frame parsing | Drained to `ReceivedBlocks` |
| `ReceivedBlocks` queue | Hold decoded frames | **Immediately drained to TUN** |
| `SendBlocks` queue | Outbound frames | Limited by `MAX_SEND_SOCKET_QUEUE_SIZE` |

```c
// Session.c:369 - Direct TUN write, NO intermediate buffer
pa->PutPacket(s, b->Buf, b->Size);  // Synchronous kernel call
```

### Rust + Swift: 5+ Buffer Layers

| # | Buffer | Size | Location | Latency Added |
|---|--------|------|----------|---------------|
| 1 | `read_buf` | 128KB | client.rs:1562 | Needed |
| 2 | `callback_buffer` | 65KB | client.rs:1564 | **+copy** |
| 3 | `write_tx` channel | 64 slots | client.rs:1569 | **+240ms** |
| 4 | Swift `PacketBuffer` | 8 batches | SoftEtherBridge.swift:490 | **+500-2000ms** |
| 5 | `DispatchQueue.async` | unbounded | SoftEtherBridge.swift:567 | **+async hop** |
| 6 | `packetFlow` | kernel | iOS | Needed |

**Swift PacketBuffer (SoftEtherBridge.swift:490-530):**
```swift
private class PacketBuffer {
    private var pendingPackets: [[Data]] = []
    private let maxPendingBatches = 8  // Up to 8 batches queued!
    
    func enqueue(_ packets: [Data], callback: @escaping ([Data]) -> Void) {
        queue.async { [self] in  // ← ASYNC HOP adds latency
            pendingPackets.append(packets)
            // ...
        }
    }
}
```

**SoftEtherBridge.swift:567 - Async enqueueing:**
```swift
// Enqueue for async processing - returns immediately to unblock Rust TCP reads
packetBuffer.enqueue(parsedPackets, callback: callback)  // ← WRONG
```

---

## 🔑 Root Cause: Contention Model Mismatch

### Problem: Rust Uses Biased Async Select (WRONG)

```rust
tokio::select! {
    biased;  // ← FUNDAMENTAL PROBLEM
    // Download checked first EVERY time
    result = conn_mgr.read_any(&mut read_buf) => { ... }
    // Upload only runs if download has nothing
    Some(data) = tx_recv.recv() => { ... }
}
```

### Result: UL/DL Starve Each Other

| Scenario | Upload | Download | Why |
|----------|--------|----------|-----|
| Heavy DL traffic | ❌ Starved | ✅ Works | Biased always picks DL |
| DL pauses | ✅ Bursts | ❌ Buffers fill | UL runs, DL accumulates |

### Solution: Match C's Fair Sequential Model

Either:
1. **Remove `biased`** + use fair async polling
2. **Use poll()/epoll()** like C and Zig (preferred)
3. **Separate tasks** with dedicated connections per direction

---

## 🔴 Critical Performance Issues

### PERF-10: Write Queue Bufferbloat
**Severity:** 🔴 Critical  
**Location:** `src/ffi/client.rs:1569`  
**Impact:** +200-500ms latency  
**Status:** Open

The two-stage async write queue buffers up to 64 messages before backpressure:

```rust
let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(64);

match write_tx.try_send(to_send) {
    Ok(_) => { WRITE_QUEUE_DEPTH.fetch_add(1, Ordering::Relaxed); }
    Err(mpsc::error::TrySendError::Full(data)) => {
        // Queue full - blocking send (backpressure kicks in too late!)
        WRITE_QUEUE_BLOCKED.fetch_add(1, Ordering::Relaxed);
        write_tx.send(data).await;
    }
}
```

**Problem:** 64 slots × ~24KB avg = ~1.5MB buffered before backpressure. At 50 Mbps this adds ~240ms latency.

**Fix:** Reduce queue depth to 4-8 slots, or eliminate queue entirely for direct writes.

---

### PERF-11: TCP_NODELAY Not Set
**Severity:** 🔴 Critical  
**Location:** `src/client/connection.rs` (TCP setup)  
**Impact:** +40ms per small packet (Nagle's algorithm)  
**Status:** Open

The Swift reference implementation explicitly sets TCP optimizations:

```swift
// SoftEtherSwift/Sources/SoftEtherClient.swift L210-220
var options = NWProtocolTCP.Options()
options.noDelay = true                    // ✅ Disable Nagle
options.disableAckStretching = true       // ✅ Reduce ACK delays  
options.enableFastOpen = true             // ✅ TCP Fast Open
```

**The Rust implementation relies on system defaults** which may have Nagle enabled.

**Fix:** Add to TCP connection setup:
```rust
socket.set_nodelay(true)?;
```

---

### PERF-12: Multiple Download Buffering Layers (iOS)
**Severity:** 🔴 Critical  
**Location:** `src/ffi/client.rs`, `WorxVPNTunnel/SoftEtherBridge.swift`  
**Impact:** +500-2000ms latency on iOS  
**Status:** Open

Download path has **4 buffering points**:

1. **Rust read_buf** (128KB) - client.rs L1514
2. **callback_buffer** (65KB) - client.rs L1516
3. **Swift PacketBuffer** (8 batches max) - SoftEtherBridge.swift
4. **iOS packetFlow** - kernel buffer

Each layer adds latency. The Swift PacketBuffer is particularly problematic:

```swift
// Adds async queue on already-async path
packetBuffer.enqueue(batch: packets)  // Up to 8 batches buffered!
```

**Fix:** Remove PacketBuffer, write directly to TUN in callback (sync path).

---

### PERF-13: Async Write After Select
**Severity:** 🟠 High  
**Location:** `src/ffi/client.rs` L2100-2114  
**Impact:** Head-of-line blocking, variable latency  
**Status:** Open

TCP writes happen *after* the select loop:

```rust
// Handle pending TCP write - this happens AFTER select returns
if let Some(data) = pending_write.take() {
    conn_mgr.write_all(&data).await;  // Blocks next iteration!
}
```

**Problem:** A large download can delay uploads for multiple iterations. Writes should be interleaved with reads.

**Fix:** Move write handling into the select! block or use separate write task.

---

### PERF-14: Per-Frame Allocation in Hot Path
**Severity:** 🟠 High  
**Location:** `src/ffi/client.rs` L1762-1777  
**Impact:** -15% throughput, GC pressure  
**Status:** Open

Every compressed frame allocates:

```rust
if is_comp {
    match decompress(frame) {
        Ok(d) => {
            decompressed = Some(d);  // ALLOCATION per frame!
        }
    }
}
```

**Compare to Zig (zero-copy):**
```zig
var recv_scratch: [512 * 1600]u8 = undefined;  // Stack, reused
```

**Fix:** Pre-allocate decompression buffer, reuse across frames.

---

### PERF-15: Biased Select Causes UL/DL Contention ⚠️ ROOT CAUSE
**Severity:** 🔴 Critical  
**Location:** `src/ffi/client.rs` L1661-1680  
**Impact:** Upload/download starve each other - one works, other breaks  
**Status:** Open - **FIX THIS FIRST**

```rust
tokio::select! {
    biased;  // ← ROOT CAUSE: Download ALWAYS gets priority
    result = conn_mgr.read_any(&mut read_buf) => { ... }
    Some(first_frame_data) = tx_recv.recv() => { ... }
    // This only runs when pending_write is None!
    Some(data) = write_rx.recv(), if pending_write.is_none() => { ... }
}
```

**Observed Behavior (user's exact words):**
> "when up speed is high and latency is lower to stable then down has been broken but when down is good, up seems breaking or dead"

| When | Upload | Download | Why |
|------|--------|----------|-----|
| Heavy download | ❌ Starved | ✅ Works | Biased select always picks download first |
| Light download | ✅ Works | ❌ Latency spikes | Upload runs, download accumulates in buffer |

**Problem:** Single-threaded select with `biased` means:
1. Download branch (TCP read) checked first EVERY iteration
2. If ANY data available on TCP, upload branch SKIPPED
3. Upload queue fills → backpressure → upload stalls
4. When download pauses briefly, upload bursts → download buffers fill → latency spike

**This explains the seesaw behavior:** The paths compete for the same executor.

**Compare to official C code (Connection.c:1728):**
```c
// Fair polling of ALL file descriptors - no bias
Select(&set, time, c1, c2);  // Uses select() not tokio::select!
```

**Fix Options (in order of preference):**
1. **Use poll()/mio** - Match C/Zig pattern with fair I/O multiplexing (best)
2. **Remove `biased`** - Let tokio fairly schedule both branches (quick fix)
3. **Separate tasks** - Spawn dedicated upload/download tasks
4. **True half-connection** - Dedicate TCP connections to each direction

---

### PERF-16: Callback Buffer Intermediate Copy
**Severity:** 🟡 Medium  
**Location:** `src/ffi/client.rs` L1516, L1795-1800  
**Impact:** Extra memory copy per callback  
**Status:** Open

```rust
let mut callback_buffer = Vec::with_capacity(65536);
// ... later ...
callback_buffer.extend_from_slice(&len.to_be_bytes());
callback_buffer.extend_from_slice(frame_slice);
```

Frames are copied into callback_buffer before being passed to Swift. Could pass slices directly.

---

### ARCH-1: SoftEtherBridge Layer Redundancy
**Severity:** 🟡 Medium  
**Location:** `WorxVPNTunnel/SoftEtherBridge.swift`  
**Impact:** Unnecessary complexity, contributes to buffering issues  
**Status:** Open

The `SoftEtherBridge` Swift class adds a thick abstraction layer that duplicates what Rust FFI already provides:

**Current Bridge Responsibilities (too many):**
| What it does | Needed? |
|--------------|---------|
| C pointer safety | ✅ Yes |
| Callback bridging (closure→fn ptr) | ✅ Yes |
| String/type conversions | ✅ Yes |
| Config struct building | ✅ Yes |
| `PacketBuffer` async queuing | ❌ **No - adds latency** |
| Async dispatch in callbacks | ❌ **No - sync is faster** |
| Additional state management | ❌ **No - Rust tracks state** |

**Problem:** The Rust FFI layer already handles:
- Packet framing/deframing
- Compression/decompression
- Encryption (TLS + RC4)
- DHCP, ARP handling
- Statistics tracking
- Flow control

The bridge should be ~200 lines of FFI glue, not a processing layer.

**Fix:** Refactor SoftEtherBridge to thin wrapper:
1. Remove `PacketBuffer` class entirely
2. Execute callbacks synchronously on Rust's thread
3. Remove any buffering/queuing logic
4. Keep only: config builder, callback setup, `connect()`/`disconnect()`/`sendPackets()` thin wrappers

**Note:** A bridge layer IS necessary for safe Swift↔C interop (unsafe pointer handling, memory management), but it should not add processing or buffering.

---

## 📐 Architecture Comparison

### Rust (Current) - Async with Queues
```
TLS Read → Decode → Decompress → callback_buffer → FFI Callback
                                                        ↓
                                            Swift PacketBuffer (async)
                                                        ↓
                                              TUN Write (async)
```
**Latency:** 4+ async hops, multiple queues

### Zig (Reference) - Sync Direct
```
TLS Read → Decode → Decompress → TUN Write
          (stack buffers, no allocation)
```
**Latency:** 1 sync path, zero queues

### Swift NIO (Reference) - Optimized Async
```
TLS Read → channelRead → onBatchReceived callback → TUN Write
           (NIO managed, batched delivery)
```
**Latency:** 2 async hops, NIO optimized

---

## 🎯 Recommended Fix Priority

| Priority | Issue | Estimated Impact | Effort | Phase |
|----------|-------|------------------|--------|-------|
| **1** | **PERF-15: Fix UL/DL contention** (remove biased/use poll) | **Fixes seesaw behavior** | Medium | Phase 1.1 |
| 2 | PERF-11: Set TCP_NODELAY | -40ms per packet | Low | Phase 1.2 |
| 3 | PERF-10: Reduce write queue (64→4) | -200ms | Low | Phase 1.3 |
| **4** | **PERF-12: Remove Swift PacketBuffer** | **-500-2000ms** | Low | Phase 2.1 |
| 5 | ARCH-1: Thin SoftEtherBridge | -100ms, cleaner code | Medium | Phase 2.3 |
| 6 | PERF-14: Pre-allocate decompress buffer | +15% throughput | Medium | Phase 3.1 |
| 7 | PERF-16: Remove callback_buffer copy | +5% throughput | Medium | Phase 3.2 |

---

## �🐛 Issues

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

#### PERF-1: Buffer Pool for Receive Allocations *(Fixed)*
**Location:** `src/client/concurrent_reader.rs`

**Status:** RESOLVED - Implemented `BufferPool` using pre-allocated `BytesMut` buffers.

**Implementation:**
- `BufferPool` struct with channel-based buffer recycling
- Pre-allocates `BUFFERS_PER_READER * num_connections + channel_size` buffers
- Reader tasks grab from pool, read directly into `BytesMut`, freeze to `Bytes` (zero-copy)
- `try_reclaim()` method recycles `Bytes` back to `BytesMut` when sole owner
- Stats tracking: `pool_stats()` returns (hits, misses, hit_rate%)
- Graceful degradation: allocates new buffer when pool empty

**Before:** `Bytes::copy_from_slice(&buf[..n])` - allocation per packet
**After:** `buf.freeze()` - zero-copy conversion from pooled BytesMut

---

#### PERF-6: Upload Path Throttling and Latency Oscillation *(Fixed)*
**Location:** `src/client/multi_connection.rs`

**Status:** RESOLVED - Implemented least-loaded connection selection and removed blocking flushes.

**Root Causes:**
1. Round-robin selection didn't consider TCP buffer pressure
2. `flush().await` after every write blocked on TCP ACKs
3. No load balancing across send connections

**Fixes:**
- Added `pending_send_bytes` tracking with time-based decay (~10 MB/s assumed)
- `get_send_connection()` now selects least-loaded connection
- Removed explicit `flush()` calls (TCP_NODELAY ensures immediate send)
- Added `record_write()` to track per-connection send load
- Added `estimated_pending()` with automatic decay calculation

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

- [x] **PERF-6: Upload Path Throttling** (Jan 2026) - Replaced round-robin send selection with least-loaded connection selection using `pending_send_bytes` tracking. Removed blocking `flush()` calls that caused latency oscillation. TCP_NODELAY ensures immediate transmission. Added 7 tests (test count 154 → 161).
- [x] **PERF-1: Buffer Pool for Receive Allocations** (Jan 2026) - Implemented `BufferPool` in `concurrent_reader.rs` using pre-allocated `BytesMut` buffers. Reader tasks grab from pool, read directly, freeze to `Bytes` (zero-copy). Includes `try_reclaim()` for buffer recycling and stats tracking. Added 9 new tests (test count 145 → 154).
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
