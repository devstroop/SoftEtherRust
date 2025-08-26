# client

**Application Layer** - User-facing client application and orchestration

Top-level application logic that coordinates all other modules.

## Core Responsibilities
- **Configuration Management**: Account profiles, connection settings, preferences
- **CLI Interface**: Command-line tools for headless operation
- **GUI Coordination**: Interface for desktop GUI applications  
- **Account Management**: Multiple VPN account support with profiles
- **Auto-Start**: Background service and system integration

## Client Architecture
## File name alignment with C

The C client spans multiple areas across `Cedar` and the client service. This Rust crate aligns names conceptually:

Where naming differs due to Rust conventions, we provide one-to-one module mapping in the cedar crate. The `protocol_client.rs` module is temporary and may be removed once cedar exposes the end-to-end client flow.

### Improvements over C Implementation

### Improvements over Go Implementation

## Key Components

## Design Philosophy

 C: Adapter (platform implementations) → Rust: external crate `crates/adapter` (this crate uses only the external adapter crate).

A Rust CLI client for SoftEther VPN that mirrors the classic vpnclient behavior: connects, handles redirects, establishes a session, applies network settings, and keeps running until you exit.

## macOS DNS service name

If you enable DNS application in your config, specify which macOS Network Service to apply DNS to (for example, "Wi-Fi" or "Ethernet"). Add this under `client`:

```json
{
  "connection": {
    "apply_dns": true
  },
  "client": {
    "macos_dns_service_name": "Wi-Fi"
  }
}
```

If omitted, the client will try a best-effort heuristic and otherwise print a manual `networksetup -setdnsservers` command.

## Run

```bash
cargo run -p client -- --config config.json connect
```

Use Ctrl+C to disconnect. Set `RUST_LOG=info` or `RUST_LOG=debug` for more detail.

## In‑Tunnel DHCP & Lease Caching

When the server does not push IPv4 settings, the client can negotiate a DHCP lease over the encrypted tunnel using the embedded `dhcproto` + `tun-rs` path (raw Ethernet/IPv4/UDP frames injected via the dataplane).

Config fields (add under the top‑level JSON, or where your loader maps into `ClientConfig`):

```jsonc
{
  // ... existing fields ...
  "enable_in_tunnel_dhcp": true,        // set false to skip DHCP attempt
  "lease_cache_path": "/var/tmp/sevpn_lease.json", // optional path to persist lease
  "interface_auto": true, // force OS auto-assigned TUN name ignoring interface_name
  "dhcp_metrics_interval_secs": 300     // periodic metrics emission interval (min 10s)
  ,"interface_snapshot_redact": false    // redact IP/DNS in interface snapshot events
  ,"interface_snapshot_verbose": false  // include extended details (more DNS entries) in snapshots
}
```

Behavior:
- On connect, if no server‑assigned IP and DHCP is enabled, a cached lease is first loaded (if not expired) to provide immediate network settings.
- If no valid cache, the client sends DHCP DISCOVER/REQUEST frames; on ACK, it applies IP/DNS (subject to `apply_dns`) and persists the lease.
- Renewal lifecycle (RFC‑inspired):
  - T1 (~50%): Unicast RENEW (REQUEST w/ ciaddr+ServerID) attempted with jitter (configurable pct). Up to 3 cycles with exponential backoff (1s,2s,4s equivalent delays).
  - Fallback: Broadcast RENEW if unicast fails in a cycle.
  - T2 (~87.5%): REBIND (broadcast REQUEST without ServerID) if all RENEW cycles failed.
  - Final fallback: Full rediscovery (DISCOVER/REQUEST) before expiry.
  - Successful RENEW/REBIND/REDISCOVER restarts the cycle with the new lease time.

Notes:
- Structured events (ClientEvent codes):
  - 300: renew attempt cycle start
  - 301: renew success
  - 302: renew phase exhausted (enter rebind)
  - 303: rebind attempt
  - 304: rebind success
  - 305: rebind failed (rediscover next)
  - 306: rediscover success
  - 307: rediscover failed (lease may expire; connection keeps last settings)
  - 221: interface created (message: `interface: <ifname>`)
  - 2211: periodic DHCP metrics snapshot (`{"kind":"dhcp_metrics",...}` every 5m)
  - 222: final DHCP metrics snapshot on disconnect (includes `final_snapshot:true`)
- Disable with `"enable_in_tunnel_dhcp": false` if the server reliably provides IP settings or for static addressing.
- The lease cache file is JSON; remove it to force fresh negotiation.
- Lease cache now also persists `iface` and `xid`; startup reuses the cached transaction ID (xid) and adopts cached iface name if none already established. This can help DHCP servers correlate renewals.
- Public API: `dhcp_metrics_snapshot()` returns `(renew_attempts,renew_success,rebind_attempts,rebind_success,rediscover_attempts,rediscover_success,failures)` if DHCP enabled.
- Metrics (in‑memory) track counts of attempts/success/failures for renew/rebind/rediscover; future API exposure may surface them.

Security Considerations:
- The cached lease contains only layer‑3 parameters (no secrets). Ensure the directory has appropriate permissions if multi‑user.

### Lease Cache JSON Schema (example)

```json
{
  "lease": {
    "client_ip": "10.10.20.34",
    "server_ip": "10.10.20.1",
    "subnet_mask": "255.255.255.0",
    "router": "10.10.20.1",
    "dns_servers": ["10.10.20.1","1.1.1.1"],
    "lease_time": 86400              // seconds (serialized Duration)
  },
  "expires_at": 1724699999,          // unix epoch seconds when considered stale
  "iface": "utun5",                  // last interface name used (optional)
  "xid": 305419896                   // last DHCP transaction ID (u32)
}
```

Field notes:
- `lease_time` may be absent/null if server omits it.
- Client discards cache if `expires_at` <= current time.
- `iface` is advisory; if OS assigns a different name, new name overwrites on next persist.
- `xid` reused on next negotiation to improve continuity; if missing a new random one is generated.

