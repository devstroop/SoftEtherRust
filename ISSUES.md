## Project Issue Tracker

Purpose: Single, maintained source of truth for active problems. Scope is only real correctness / quality gaps. No “ideas parking lot.”

Severity Legend: P0 = breakage/correctness, P1 = important quality, P2 = nice-to-have.
Lifecycle: Open -> In Progress -> Review -> Done (retain 1 release) -> Prune.

### New Issue Template (copy this)
- Title: `#NNN [P0|P1|P2] Short, actionable title`
- State: Open | Owner: (name) | Created: YYYY-MM-DD
- Area: (TLS / DataPlane / DHCPv4 / DHCPv6 / IPv6 / NetworkConfig / CLI / FFI)
- Affected platforms: (macOS/Linux/iOS/Windows)
- Repro steps: (config.json excerpt + exact run/env)
- Logs/Events: (relevant event codes from docs/ffi/events.md)
- Root Cause: (fill once known)
- Acceptance:
	- [ ] …
- Test Plan:
	- [ ] Unit/Integration covering acceptance items
- Touched files: (paths)
- Risks: (perf/compat/security)
- Rollout/Backout: (notes)
- Blocked by: (issue/PR)
- Links: (PR, commit)

### Quick Filters
- Open P0: (#003, #014, #015, #016, #027)
- Needing Decision: (#003 nat/udp decision, #014 UDP scope)

---
### #001 P0 Static IPv6 Apply/Teardown
State: Done | Owner: (unassigned) | Created: 2025-08-27 | Closed: 2025-08-27
Summary: Implemented static IPv6 address/route apply + teardown with idempotence signature.
Acceptance (final):
 - [x] IPv6 address + prefix applied (macOS/Linux)
 - [x] Default route added when gateway present
 - [x] Clean removal on disconnect
 - [x] Idempotence guard prevents duplicate apply
Artifacts: commit <pending-commit-hash> (update once merged)
Move to Recently Addressed after next release.

### #002 P0 DHCP MAC Unwrap Panic
State: Done | Owner: (unassigned) | Closed: 2025-08-27
Summary: Replaced unwrap with safe fallback; logs single warning when fallback occurs.
Acceptance (final):
 - [x] No panics if MAC absent
 - [x] Warning logged once
 - [x] Deterministic MAC fallback used
Artifacts: commit <pending-commit-hash>
Notes: Zero-panic policy maintained.

### #003 P0 nat_traversal / udp_acceleration Semantics & Implementation
State: Resolved — Decision A (Visibility Only) | Owner: (unassigned) | Decided: 2025-08-27
Deployment stance (confirmed):
 - SecureNAT disabled (no internal DHCP/NAT)
 - Local Bridge mode (direct L2 bridging)
 - UDP acceleration disabled via config
 - NAT-T disabled via config
Decision:
 - Keep both config flags; pass through exactly as provided. Do not implement UDP acceleration or NAT-T data paths by default. Provide visibility only.
What the code already does:
 - `vpnclient/auth.rs` maps config to `ClientOption.with_udp_acceleration(..)` and `.with_nat_traversal(..)`; in cedar this flips `no_udp_acceleration` and `enable_nat_traversal` bits.
 - Event 406 logs negotiated state: `transport: udp_accel=on|off nat_traversal=on|off`.
 - No UDP/NAT-T sockets are opened when disabled.
Area: CLI / Engine config / Handshake
Acceptance (final):
 - [x] Connect event (406) logs off/off when config has both disabled
 - [ ] Docs updated to state that for Local Bridge deployments both should typically remain false (config reference)
 - [ ] Unit test asserts config → `ClientOption` bit mapping (follow-up)
Test Plan:
 - [ ] Given `{ nat_traversal:false, udp_acceleration:false }` → `enable_nat_traversal=false`, `no_udp_acceleration=true`
 - [ ] Given `{ nat_traversal:true, udp_acceleration:true }` → flags reflect enabled
Notes:
 - Full UDP acceleration datapath remains tracked under #014 and is out of scope for this decision.

### #004 P1 Background Task Lifecycle (DHCPv6 Renew)
State: Open
Symptom: Renew loop handle not tracked; may outlive client.
Area: DHCPv6 / Tasks
Affected platforms: All
Acceptance:
 - [ ] All spawned tasks appear in `aux_tasks`
 - [ ] Abort on disconnect
Test Plan:
 - [ ] Connect -> verify task tracked; Disconnect -> verify aborted
Touched files: `crates/vpnclient/src/vpnclient.rs`
Fix Sketch: Store JoinHandle; unify spawn helper.

### #005 P1 Static IP Validation
State: Done | Closed: 2025-08-27
Summary: CIDR parsing, prefix bounds, /0 rejection, gateway & DNS family checks enforced in `TryFrom<ClientConfig>`.
Acceptance (final):
 - [x] Invalid prefix rejected (>32 v4, >128 v6, /0)
 - [x] Family mismatch rejected (ip vs gateway/dns)
 - [x] DNS family mismatch rejected
 - [x] Error variant provides specific reason
 - [x] Valid config passes unchanged
Artifacts: commit <pending-commit-hash>
Notes: Future enhancement: aggregate multiple DNS errors (low priority).

### #006 P1 Unified Snapshot Builder & Dedup (Merged #006 + #007)
State: Open
Symptom: Multiple snapshot construction paths; potential duplicates; future maintenance cost.
Acceptance:
 - [ ] Single builder function merges static/DHCP, v4/v6
 - [ ] Duplicate suppression via hash/signature
 - [ ] Initial snapshot always includes any static v6 only configuration
 - [ ] Code paths for placeholder, server, DHCP reuse builder
Test Plan:
 - [ ] Static IPv6 only -> snapshot includes ipv6
 - [ ] Rapid renew events -> no duplicate emission
Notes: Original #007 merged here; mark #007 closed (superseded) without implementation.

### (Closed) #007 P1 Combined Snapshot Structure / Dup Logic
Superseded by #006.

### #008 P2 Dead Code / allow(dead_code)
State: Open
Scope: connection_manager, connection_pool, unused structs.
Acceptance: Either removed or justified with comment “Reserved for X”. Zero stray `allow(dead_code)` for unknown reasons.

### #009 / #019 P1 DNS Apply & Restore (Consolidated)
State: Done | Closed: 2025-08-28
Summary: DNS backup & restore implemented (macOS service-specific; Linux resolv.conf) with events 3301 (restore) / 3302 (fallback). Manual recovery docs added.
Acceptance (final):
 - [x] Pre-change DNS saved
 - [x] IPv4 + IPv6 DNS applied where supported
 - [x] DNS restored on disconnect (best-effort)
 - [x] Events emitted (3301 restore, 3302 fallback)
 - [x] README contains recovery steps
Artifacts: commit <pending-commit-hash>
Notes: Future: crash recovery persistent backup (planned enhancement #019 follow-up not needed after consolidation unless persistence added).

### #010 P2 Unknown Config Key Warning
State: Open
Symptom: Typos silently ignored.
Area: Config UX
Affected platforms: All
Acceptance:
 - [x] Log one-line warning listing unknown keys post-load (non-fatal)
 - [ ] Provide extra key; observe single warning
 - [ ] Provide only known keys; no warning
Test Plan:
 - [ ] Provide extra key; observe single warning
 - [ ] Provide extra key twice (same run) -> only one warning line (manual validate; code currently emits once per run load path)
 - [ ] Provide only known keys; no warning
Fix Sketch: Deserialize to `serde_json::Value`, compare keys to known set before full parse.

### #011 P2 Logging Clarity (DHCP Events)
State: Open
Symptom: Generic logs lacking context.
Area: Logging
Affected platforms: All
Acceptance:
 - [ ] Logs include iface + family + attempt count
 - [ ] Event codes mapped in docs for common phases

### #012 P1 Route & Resource Cleanup
State: Done | Closed: 2025-08-28
Summary: AppliedResources structure drives deterministic disconnect cleanup (routes removed reverse-order, IPs removed, interface down last). Fallback only if tracker missing.
Acceptance (final):
 - [x] Routes tracked & removed
 - [x] IP addresses tracked & removed
 - [x] Cleanup on disconnect
 - [x] Fallback path only when no tracking present
Notes: Crash recovery guidance still pending (future enhancement tie-in with DNS persistence).

### #013 P1 DHCP Renew Timing RFC Alignment
State: Open
Symptom: Hard-coded 50% renew; ignoring lease T1/T2.
### #014 P0 UDP Acceleration Data Path Implementation
State: Open | Area: DataPlane / Transport
Symptom: Flag present; no UDP socket / packet acceleration implemented.
Impact: Throughput / latency regress vs C client.
Acceptance:
 - [ ] UDP accelerator module (socket open, handshake, NAT-T keepalives if enabled)
 - [ ] Fallback to pure TCP when disabled/unavailable
 - [ ] Event: negotiated UDP port & status (code TBD)
 - [ ] Bench shows improved PPS vs TCP-only path
Test Plan: Synthetic throughput test; toggle flag.
Risks: NAT traversal variance across networks.

### #015 P0 Certificate Authentication Support
State: Open | Area: Auth
Symptom: Only password/hash path supported; cert-based servers unusable.
Acceptance:
 - [ ] Load PEM/PKCS#12 cert+key from config
 - [ ] Option pack includes cert method selection
 - [ ] Failure emits clear event code
Test Plan: Connect to cert-required hub.

### #016 P0 HTTP/SOCKS Proxy Traversal
State: Open | Area: Transport
Symptom: Cannot connect behind corporate proxy.
Acceptance:
 - [ ] HTTP CONNECT supported
 - [ ] SOCKS5 (auth + no-auth) supported
 - [ ] Configurable via `proxy` block
 - [ ] Failure fallback & clear event code
Test Plan: Mock proxy integration tests.

### #017 P1 Extended DHCP Options
State: Open | Area: DHCPv4
Symptom: Only basic options (IP/gateway/DNS) parsed.
Acceptance:
 - [ ] Domain name, NTP, NetBIOS, search list parsed & exposed
 - [ ] Snapshot includes additional fields when present
 - [ ] Graceful ignore when absent
Test Plan: Inject test lease with options.

### #018 P1 IPv6 Router Advertisement Handling
State: Open | Area: IPv6
Symptom: No SLAAC / RA processing; DHCPv6 only.
Acceptance:
 - [ ] Listen for RA on tun, extract prefix & router
 - [ ] Apply prefix/address (if permitted) without conflicting static
 - [ ] Snapshot reflects SLAAC-derived address
Test Plan: Simulated RA frames.

### #019 (Merged) See #009
Closed: Duplicate; tracked work consolidated under #009.

### #020 P1 Reconnect Ticket / Session Resumption
State: Open | Area: Session
Symptom: Full re-auth on every reconnect.
Acceptance:
 - [ ] Ticket stored securely in-memory (optional disk opt-in)
 - [ ] Reconnect within validity window skips auth
 - [ ] Fallback path when server rejects
Test Plan: Disconnect/reconnect timing tests.

### #021 P2 VLAN Tag Handling
State: Open | Area: DataPlane
Symptom: 802.1Q frames untreated; tags dropped or passed raw.
Acceptance:
 - [ ] Preserve VLAN tags end-to-end
 - [ ] Optional filtering per policy
Test Plan: Inject tagged frames.

### #022 P2 Multi-Hub Support (Sequential Connections)
State: Open | Area: Session Management
Symptom: Requires config edit for each hub.
Acceptance:
 - [ ] CLI/API allows specifying hub per connect
 - [ ] Reuse base server config across hubs
Test Plan: Connect to two hubs sequentially.

### #023 P2 Bridge Mode (Local Adapter Integration)
State: Open | Area: Network Integration
Symptom: No local bridge to physical adapters.
Acceptance:
 - [ ] Enumerate host adapters
 - [ ] Transparent forwarding path selected adapter <-> tunnel
Test Plan: Broadcast traversal verified.
Risks: Platform-specific privilege & performance.

### #024 P2 SecureNAT Support (Deferred)
State: Open | Area: NAT / Virtual Services
Symptom: Cannot leverage server SecureNAT features (internal DHCP/NAT) locally.
Acceptance: (Deferred until core transport parity achieved) Placeholder.

### #025 P2 Logging Clarity & Context (Supersedes #011)
State: Open | Area: Logging
Symptom: DHCP & transport logs lack iface/family context.
Acceptance:
 - [ ] Structured logs include iface, family, attempt, xid
 - [ ] EVENTS.md updated with new codes
Test Plan: Run acquisition; inspect logs.
Notes: Fold original #011 into this broader logging improvement.

### #026 P2 Dead Code Elimination & Justification
State: Open | Area: Code Hygiene
Symptom: Unused connection manager / pool placeholders.
Acceptance:
 - [ ] Remove or annotate each `allow(dead_code)` with rationale
 - [ ] Zero unexplained dead code warnings
Test Plan: `cargo clippy` clean (excluding unrelated crates).

### #027 P0 DHCP No OFFER (Framing / Layer Mismatch)
State: In Progress | Area: DHCPv4 / DataPlane
Symptom: Repeated DISCOVER (events 298 / 295) with OFFER timeout (297); zero 294 mismatch frame events; no lease ever acquired in bridged hub where DHCP should exist.
Impact: Client cannot obtain IPv4 address in standard Local Bridge deployments (core functionality broken).
Root Cause (composite):
 1. Outbound frame builder (`wrap_dhcp`) prepends full Ethernet header while cedar `DataPlane` likely expects raw IPv4 packets (L3 over tunnel) → server drops malformed frame.
 2. Inbound parser `extract_dhcp` rejects frames without a 14‑byte Ethernet header & ethertype 0x0800, so raw IP (if delivered) is ignored.
 3. Unicast REQUEST path uses destination MAC of all zeros (invalid if Ethernet mode actually required).
 4. Potential MAC identity mismatch: DHCP chaddr = deterministic client MAC; virtual NIC MAC presented to server may differ (needs verification once parsing fixed).
 5. Missing broadcast/OFFER diagnostics: no counters for inbound broadcast frames → hard to distinguish “no broadcast arriving” vs “parser dropped it”.
 6. TUN (utun) interface use indicates L3 semantics; code assumes L2 bridging for DHCP (Ethernet encapsulation) leading to inconsistent layering.
Acceptance:
 - [x] Parser accepts both Ethernet+IP and raw IPv4 UDP(67/68) frames (dual-mode extraction).
 - [x] Outbound DISCOVER transitional dual-send (Ethernet + raw IPv4) for first two attempts (will converge to single raw IPv4 after validation).
 - [ ] At least one DHCP OFFER decoded (event sequence: 298 -> 294 (if mismatches) -> OFFER success) on a known working bridged hub.
 - [x] Diagnostic event 2998 (no DHCP traffic observed) emitted when zero frames seen during window.
 - [x] Throttled decode error event 2999 emitted (max 3 / discovery or ack wait cycle).
 - [ ] Unicast REQUEST (renew path) sets valid destination MAC or stays broadcast-only (current unicast renew still uses zero dst MAC placeholder).
 - [ ] Chaddr confirmed to match server’s expected client MAC (one-time log) or adjusted.
 - [x] Unit tests for raw IP & Ethernet encapsulated OFFER parsing.
 - [x] Regression test: malformed short frame rejected.
Test Plan:
 1. Instrument local test harness injecting synthetic OFFER as raw IP → ensure acceptance.
 2. Repeat with Ethernet frame wrapper.
 3. Live run on bridged hub: observe OFFER within first 2 attempts; no timeout 297.
 4. Toggle env `RUST_DHCP_DEBUG_FRAMES=1` to confirm hex dump for first DISCOVER and first OFFER.
Fix Sketch (updated):
	- DONE: Dual-mode parser (`extract_dhcp`) tries Ethernet then raw IPv4.
	- DONE: Transitional dual-send for first two DISCOVER attempts.
	- TODO: Live validation on bridged hub; capture first successful OFFER & log chosen frame mode (decide to drop Ethernet path).
	- TODO: Learn source MAC from OFFER if Ethernet present OR treat dataplane as pure L3 and remove Ethernet construction.
	- TODO: Replace zero dst MAC in unicast renew with learned server MAC or avoid unicast renew until learned.
	- TODO: One-time chaddr vs presented MAC event (debug) for operator confirmation.
Risks:
	- Temporary dual-send increases initial DHCP traffic slightly.
	- If server rejects malformed Ethernet variant, logs may still show retransmits until raw path succeeds (need explicit OFFER log to confirm).
Notes:
	- No new config flags added; transition removal of Ethernet pending live test.
	- Post-validation: collapse to single raw IPv4 path & document layer expectations.
	- Deployment Clarification (2025-08-27): Primary target profile provided by user runs Local Bridge with SecureNAT disabled and uses static addressing (no DHCP service reachable; UDP 67/68 not expected). Maintain DHCP logic for broader interoperability but do not block static-only flows; see #035 for explicit skip behavior.
	- Environment Note: In the user's baseline deployment DHCP is intentionally absent. Full OFFER acquisition remains desirable for bridged-with-DHCP scenarios, but absence should short-circuit sooner once #035 implemented.

### #035 P1 No-DHCP Deployment Profile (Early Skip & Event)
State: Open | Area: DHCPv4 / Config
Symptom: Client continues DHCP discovery attempts in deployments where no DHCP server will ever respond (SecureNAT disabled, Local Bridge present, static addressing policy). Wastes time before applying static config feedback.
Impact: Unnecessary delay and log noise; potential operator confusion seeing repeated DISCOVER timeouts in expected no-DHCP environments.
Acceptance:
 - [ ] When `static_ip` provided and results in usable IPv4, emit single event (292) "dhcp skipped (static profile)" and do not start discovery loop.
 - [ ] When no `static_ip` and DHCP disabled via new config flag `require_static_ip=true`, fail fast with clear error/event (293) instead of attempting DHCP.
 - [ ] Documentation (vpnclient README) adds "No-DHCP Local Bridge" profile guidance (static required, SecureNAT disabled, UDP 67/68 absent).
 - [ ] #027 references updated to indicate OFFER acquisition only required when DHCP actually configured.
 - [ ] Unit test: static config -> no DHCP attempt event 298 absent; event 292 present.
 - [ ] Unit test: require_static_ip=true without static_ip -> immediate error/event 293.
Test Plan:
 - [ ] Run with static_ip -> observe skip event; no DISCOVER events.
 - [ ] Run with require_static_ip=true missing static -> process exits (or returns error) quickly.
 - [ ] Run without static_ip or flag -> legacy behavior unchanged (DISCOVER attempts present).
Fix Sketch:
 - Add optional boolean `require_static_ip` to `ClientConfig` (default false) and include in unknown-key allowlist.
 - In `vpnclient.rs` before DHCP acquisition: if static settings already applied, emit skip event (292) and bypass DHCP block.
 - If `require_static_ip` set and static not provided, emit event 293 and abort connection setup with error.
Risks:
 - Minor: additional config field; keep default false to avoid breaking existing configs.
 - Ensure event codes (292,293) do not collide with existing assignments.
Touched files: `shared_config.rs`, `vpnclient.rs`, `docs/ffi/events.md`, `README.md`.
Links: (#027 reference for scoping) #003 (deployment semantics).

Acceptance: Uses provided T1 / T2 when available; falls back gracefully.

### #028 P1 DHCP Parser Silent Error Handling (dhcproto)
State: Open | Area: DHCPv4 Library
Symptom: Multiple `// TODO: error?` markers (decoder.rs lines ~107/118) and ambiguous correctness comments (`// TODO: not sure if this is correct` options.rs ~1121) indicate branches that silently ignore malformed option/data states.
Impact: Corrupted or adversarial DHCP packets may be accepted or produce undefined option state leading to incorrect network configuration.
Acceptance:
 - [ ] Replace ambiguous branches with explicit Result errors (MalformedPacket / TruncatedOption)
 - [ ] Fuzz corpus (minimal) does not crash or silently drop critical errors
 - [ ] Unit tests for truncated option list & overlength option
 - [ ] Remove or resolve all DHCP parsing TODO markers referenced
Test Plan:
 - [ ] Add targeted tests under `libs/dhcproto/tests/` for malformed length, bad magic cookie, truncated option
 - [ ] Run cargo fuzz (optional if harness added) else manual randomized generator
Risks: Stricter parsing could reject previously accepted but tolerated packets (log downgrade path once).

### #029 P2 Compression Accounting / Feature Toggle Clarity
State: Open | Area: Stats / ProtocolOptions
Symptom: Session stats increment `total_send_size_real` with a TODO “Account for compression” though compression feature not implemented; metrics may mislead operators.
Acceptance:
 - [ ] Either implement compression negotiation (set `use_compress`) or adjust stats to mirror send size with clarified naming
 - [ ] README / EVENTS docs clarify compression unsupported (if deferring)
 - [ ] Remove stale TODO
Test Plan: Connect session -> stats show consistent values; enabling future compression changes only *_real counters.
Decision Needed: Implement now (complex) vs rename & document.

### #030 P1 Secret Material Handling (Credentials / Keys Zeroization)
State: Open | Area: Security / Memory Hygiene
Symptom: Credentials, session keys, UDP keys, and private key material stored in ordinary Vec/String without zeroization on drop.
Impact: Increased risk of credential recovery from process memory dumps.
Acceptance:
 - [ ] Introduce secure buffer type (zeroize on Drop) for passwords, keys
 - [ ] Apply to ClientAuth secret fields & session UDP keys
 - [ ] Audit: no raw copies remain in long-lived plain Strings
 - [ ] Document threat model (best-effort, not SGX)
Test Plan: Unit test uses `memchr`/pattern search pre/post drop (best-effort) or rely on zeroize crate test helpers.
Risks: Slight perf impact; additional dependency (zeroize).

### #031 P2 Platform Abstraction Stubs (mayaqua)
State: Open | Area: Platform Layer
Symptom: Numerous TODOs in `mayaqua` (platform.rs, network.rs, crypto.rs, memory.rs) indicate incomplete abstraction (interface enumeration, memory utilities, extended crypto).
Impact: Future cross-platform features (bridge mode, adapter selection) blocked or will embed ad-hoc code paths.
Acceptance:
 - [ ] Catalog each TODO with concrete subtask or remove if obsolete
 - [ ] Provide minimal interface enumeration API (macOS/Linux) returning list of iface names + MTU
 - [ ] Crypto TODOs either implemented or deferred with issue references
Test Plan: Call new enumeration API returns at least loopback + active interface.
Risks: Scope creep; keep MVP minimal.

### #032 P1 Zero-Panic Policy Enforcement (Mutex Poison & unwrap Audit)
State: Open | Area: Reliability
Symptom: Multiple `lock().unwrap()` usages in core structs (connection_mgr.rs, session_mgr.rs). Panic on mutex poison violates zero-panic goal (#002 precedent).
Impact: Single thread panic can tear down whole process rather than surface recoverable error.
Acceptance:
 - [ ] Replace `.lock().unwrap()` with helper handling poison via `into_inner()` or logging + recreate state
 - [ ] Audit non-test `unwrap()` / `expect()` usage; enumerate and justify or remove
 - [ ] Add CI lint (deny `unwrap` except in tests) via clippy allowlist
Test Plan: Inject artificial poison (panic inside lock holder) -> subsequent lock acquisition does not panic.
Risks: Over-broad deny could block reasonable unwrap in test code; mitigate by scoping.

### #033 P2 Session Timing Config Extensibility
State: Open | Area: SessionConfig
Symptom: Keep-alive intervals & retry timings hard-coded defaults; no user override except building custom binary.
Impact: Tuning for high-latency or mobile networks impossible; may cause unnecessary reconnects.
Acceptance:
 - [ ] Expose optional timing overrides in config (validated sane range)
 - [ ] Document defaults & supported ranges
 - [ ] Events include chosen effective intervals once
Test Plan: Provide override -> observe applied intervals in log/event.
Risks: Misconfiguration leading to floods; enforce min/max.

### #034 P1 Crash Recovery Persistence (Applied Resources & DNS)
State: Open | Area: NetworkConfig / Recovery
Symptom: Applied resources (routes/IP/DNS) only tracked in-memory; crash or power loss can leave stale DNS or routes with no reapply/cleanup path.
Impact: User may experience broken name resolution until manual intervention.
Acceptance:
 - [ ] Optional persistence file (atomic write) capturing pre-change DNS + applied resources
 - [ ] On startup, detect stale file -> offer (log) restoration action or auto-clean with event
 - [ ] Secure handling: file permissions 0600
 - [ ] Cleanup deletes persistence file upon graceful disconnect
Test Plan: Simulate crash (kill -9) post-apply -> restart binary -> restoration logic triggers and restores prior state.
Risks: Stale file after improper manual deletion; mitigate with versioning & checksum.

---
## Recently Addressed (Trim after next release)
 - #012 Route & resource cleanup tracking + deterministic teardown
 - #009/#019 DNS backup & restore with events 3301/3302 + docs
 - #005 Static IP validation
 - #002 DHCP MAC unwrap panic removed
 - #001 Static IPv6 apply + teardown + idempotence
 - Encryption flag removal (always-on TLS)
 - Config de-bloat: interface_auto + telemetry knobs removed
 - Unified StaticIpConfig (v4/v6) + IPv6 fields in NetworkSettings
 - macOS: apply IP/MTU using actual utun name when auto-assigned (improves reliability of `ifconfig`/MTU steps)
 - Snapshot includes IPv6 for static path (partial toward #006)

## Workflow / Definition of Done
For each issue before marking Done:
 - Code merged & build passes
 - Minimal test (unit/integration) if logic branch added or changed
 - README / EVENTS updated if external behavior altered
 - ISSUES.md updated: add commit hash, move to Recently Addressed
	- Release note considered (Yes/No)
	- Backport required? (Yes/No)

## Triage Checklist (Use per new issue)
1. Confirm reproducibility (steps / config snippet)
2. Classify severity (P0–P2)
3. Identify owning module(s)
4. Define clear acceptance criteria (bullet list)
5. Provide fix sketch or mark as “needs investigation”

## Next Action Proposal (Pick & Execute)
1. (#004) Track DHCPv6 renew task handle
2. (#006) Unify interface snapshot builder & dedup
3. (#003) Decide path for nat_traversal / udp_acceleration (A/B/C)
4. (#014) Draft UDP acceleration design (handshake + socket path)
5. (#010) Implement unknown key warning

---
Edit manually; no generator. Keep sharp and minimal.
