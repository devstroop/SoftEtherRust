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
- Open P0: (#003, #014, #015, #016)
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
State: Decision Needed (was: vague / potential no-op)
Context (2025-08-27 clarification):
 - Historical client variant used a custom single UDP port for *all* accelerated traffic and in-tunnel control.
 - We now rely on cedar’s built-in UDP acceleration path; DHCP itself still rides inside the tunnel (ports 67/68 encapsulated) and does not require a custom outer UDP port.
 - `udp_acceleration` should strictly toggle cedar's accelerated data path (setting `no_udp_acceleration = !enable`).
 - `nat_traversal` should explicitly enable NAT-T (keepalives / encapsulation) only when the deployment requires it. Many SoftEther server setups disable SecureNAT and use Local Bridge; in those cases NAT-T may be unnecessary overhead and should remain off unless user opts in.
Problem:
 - Current code passes both flags into `ClientOption`, but no validation / logging confirms effective enablement and NAT-T behavioral layer (keepalive cadence) is not surfaced.
 - Semantics unclear in docs; user expectation: enabling `nat_traversal` actively turns on NAT-T; disabling ensures no probing or SecureNAT dependency.
Decisions To Make:
 A Keep both flags; implement minimal visibility (event 406) confirming negotiated state.
 B Deprecate one (e.g. remove `nat_traversal` if cedar auto-handles) and retain only `udp_acceleration`.
 C Implement minimal NAT-T keepalive emission & log stats (larger scope) if server supports.
Risks:
 - Removing flags alters auth/option handshake bits (compat risk with servers expecting explicit disable/enable).
 - Implementing partial NAT-T without full traversal logic could mislead users.
Area: CLI / Engine config / Handshake
Affected platforms: All
Acceptance (independent of chosen path):
 - [x] Connect event (406) logs `udp_accel=on|off nat_traversal=on|off`
 - [ ] README documents semantics clearly
 - [ ] Unsupported server response yields single warn (405)
 - [ ] Options pack bits verified in debug log (or test) match config
 - [ ] Decision recorded (A=visibility only / B=deprecate / C=enhanced NAT-T)
 - [ ] Tests assert config->option mapping
Test Plan:
 - [ ] Config with both flags off -> handshake bits off
 - [ ] Only udp_acceleration on -> no_udp_acceleration false
 - [ ] Only nat_traversal on -> enable_nat_traversal true
 - [ ] Both on -> both flags set
 - [ ] Unsupported server scenario -> warn 405 once
Fix Sketch:
 - Add post-auth debug/event summarizing resolved `ClientOption` flags
 - Add small helper `log_transport_features(&ClientOption)`
 - Optionally capture the built auth/option pack (behind debug) for inspection
 - If choosing A/C and NAT-T not currently implemented in cedar layer, guard with feature flag or emit warn that NAT-T is negotiated but passive.

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
 - [ ] Log one-line warning listing unknown keys post-load (non-fatal)
Test Plan:
 - [ ] Provide extra key; observe single warning
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

Acceptance: Uses provided T1 / T2 when available; falls back gracefully.

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
