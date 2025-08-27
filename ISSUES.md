## Project Issue Tracker (Improved)

Purpose: Single, maintained source of truth for active problems. Scope is only real correctness / quality gaps. No “ideas parking lot.”

Severity Legend: P0 = breakage/correctness, P1 = important quality, P2 = nice-to-have.
Lifecycle: Open -> In Progress -> Review -> Done (retain 1 release) -> Prune.

### Quick Filters
- Open P0: (#001, #002, #003)
- Needing Decision: (#003 nat/udp)

---
### #001 P0 Static IPv6 Not Applied
State: Open  | Owner: (unassigned) | Created: 2025-08-27
Symptom: Parsed into `NetworkSettings` but never configured on OS.
Impact: No IPv6 connectivity when statically configured.
Root Cause: Missing platform branch in network apply logic.
Acceptance:
 - IPv6 address + prefix visible in `ip -6 addr` / `ifconfig`
 - Default route added when `gateway` present
 - No duplicate adds on reconnect
 - Clean removal on disconnect
Fix Sketch: Inject apply after TUN creation; store applied v6 for teardown.
Risks: Platform variance (macOS vs Linux commands).

### #002 P0 DHCP MAC Unwrap Panic
State: Open | Owner: (unassigned)
Symptom: `unwrap()` on `dhcp_mac` may panic before initialization.
Impact: Crash during acquisition edge cases.
Acceptance: No panics if MAC absent; warning logged once; deterministic MAC fallback used.
Fix Sketch: `let mac = self.dhcp_mac.unwrap_or(self.config.client.mac_address);`

### #003 P0 nat_traversal / udp_acceleration Flags Are No-Op
State: Decision Needed
Symptom: Flags parsed, unused.
Options:
 A Remove flags + document removal.
 B Stub event warning “feature not implemented”.
 C Implement minimal NAT-T keepalive (larger effort) before keeping.
Acceptance: Clear, intentional behavior (either functional or removed) + README updated.

### #004 P1 Background Task Lifecycle (DHCPv6 Renew)
State: Open
Symptom: Renew loop handle not tracked; may outlive client.
Acceptance: All spawned tasks appear in `aux_tasks`; abort on disconnect.
Fix Sketch: Store JoinHandle; unify spawn helper.

### #005 P1 Static IP Validation Missing
State: Open
Problems:
 - Accepts invalid CIDR prefix
 - Family mismatches (gateway/dns) silent
 - /0 accepted accidentally
Acceptance: Invalid config yields `ConfigError::Invalid` with specific reason; valid passes unchanged.
Fix Sketch: Parse + validate early in `TryFrom<ClientConfig>`.

### #006 P1 Interface Snapshot v6 Inconsistency
State: Open
Symptom: Initial interface snapshot lacks static IPv6; appears only in settings.
Acceptance: First snapshot includes v4/v6 if present (static or DHCP).
Fix Sketch: Merge static v6 from runtime before emitting first snapshot.

### #007 P1 Combined Snapshot Structure / Dup Logic
State: Open
Symptom: Separate v6 renew snapshots + v4 primary snapshot create duplication.
Acceptance: Single canonical snapshot event per material change.
Fix Sketch: Consolidate emission path; deprecate separate v6-only snapshot code.

### #008 P2 Dead Code / allow(dead_code)
State: Open
Scope: connection_manager, connection_pool, unused structs.
Acceptance: Either removed or justified with comment “Reserved for X”. Zero stray `allow(dead_code)` for unknown reasons.

### #009 P2 DNS Apply & Restore (IPv4/IPv6)
State: Open
Symptom: DNS changes not reverted on disconnect; IPv6 DNS ignored.
Acceptance: Pre-change DNS saved; both families applied; restored on disconnect.

### #010 P2 Unknown Config Key Warning
State: Open
Symptom: Typos silently ignored.
Acceptance: Log one-line warning listing unknown keys post-load (non-fatal).
Fix Sketch: Deserialize to `serde_json::Value`, compare keys to known set before full parse.

### #011 P2 Logging Clarity (DHCP Events)
State: Open
Symptom: Generic logs lacking context.
Acceptance: Logs include iface + family + attempt count.

### #012 P1 Route & Resource Cleanup
State: Open
Symptom: Added routes / settings may persist after abnormal termination.
Acceptance: Tracked applied routes; best-effort cleanup in disconnect & Drop.

### #013 P1 DHCP Renew Timing RFC Alignment
State: Open
Symptom: Hard-coded 50% renew; ignoring lease T1/T2.
Acceptance: Uses provided T1 / T2 when available; falls back gracefully.

---
## Recently Addressed (Trim after next release)
 - Encryption flag removal (always-on TLS)
 - Config de-bloat: interface_auto + telemetry knobs removed
 - Unified StaticIpConfig (v4/v6) + IPv6 fields in NetworkSettings

## Workflow / Definition of Done
For each issue before marking Done:
 - Code merged & build passes
 - Minimal test (unit/integration) if logic branch added or changed
 - README / EVENTS updated if external behavior altered
 - ISSUES.md updated: add commit hash, move to Recently Addressed

## Triage Checklist (Use per new issue)
1. Confirm reproducibility (steps / config snippet)
2. Classify severity (P0–P2)
3. Identify owning module(s)
4. Define clear acceptance criteria (bullet list)
5. Provide fix sketch or mark as “needs investigation”

## Next Action Proposal (Pick & Execute)
1. (#001) Implement static IPv6 apply
2. (#002) Remove DHCP unwrap panic
3. (#003) Decide: Remove nat/udp flags (lean choice)
4. (#005) Add static IP validation
5. (#006/#007) Unify interface snapshot emission

---
Edit manually; no generator. Keep sharp and minimal.
