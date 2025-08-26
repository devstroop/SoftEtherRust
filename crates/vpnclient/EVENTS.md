# Event Stream Reference

This document consolidates DHCP metrics and interface snapshot related events emitted by the VPN client.

## Event Codes

| Code | Level | Kind / Meaning | Payload (message) |
|------|-------|----------------|-------------------|
| 220  | Info  | tunnel opened  | text |
| 221  | Info  | interface created | `interface: <ifname>` |
| 2211 | Info  | periodic DHCP metrics | JSON `{ "kind":"dhcp_metrics", ... }` |
| 222  | Info  | final metrics snapshot (disconnect) | JSON `{ "kind":"dhcp_metrics", "final_snapshot":true, ... , "interface":{...}}` |
| 2220 | Info  | initial interface snapshot | JSON `{ "kind":"interface_snapshot", ... , "initial":true }` |
| 2221 | Info  | interface change snapshot | JSON `{ "kind":"interface_snapshot", ... , "initial":false }` |
| 2222 | Warn  | lease health warning | JSON `{ "kind":"lease_health", "remaining_pct": <int>, ... }` |
| 300  | Info  | DHCP renew attempt cycle | text |
| 301  | Info  | DHCP renew success | text |
| 302  | Warn  | Renew phase exhausted (rebind next) | text |
| 303  | Info  | Rebind attempt | text |
| 304  | Info  | Rebind success | text |
| 305  | Warn  | Rebind failed (rediscover next) | text |
| 306  | Info  | Rediscover success | text |
| 307  | Error | Rediscover failed | text |

## DHCP Metrics JSON Structure

Example (periodic / final):
```json
{
  "kind": "dhcp_metrics",
  "final_snapshot": false,
  "renew_attempts": 3,
  "renew_success": 1,
  "rebind_attempts": 1,
  "rebind_success": 1,
  "rediscover_attempts": 0,
  "rediscover_success": 0,
  "failures": 0
}
```

Final (code 222) adds `"final_snapshot": true` and may include an `interface` object:
```json
{
  "kind": "dhcp_metrics",
  "final_snapshot": true,
  "renew_attempts": 4,
  "renew_success": 2,
  "rebind_attempts": 1,
  "rebind_success": 1,
  "rediscover_attempts": 0,
  "rediscover_success": 0,
  "failures": 0,
  "interface": { "name": "utun8", "ipv4": "10.10.20.34", "dns": ["10.10.20.1"] }
}
```

## Interface Snapshot JSON Structure

Initial (2220) or change (2221):
```json
{
  "kind": "interface_snapshot",
  "name": "utun8",
  "ipv4": "10.10.20.34/24",
  "router": "10.10.20.1",
  "dns": ["10.10.20.1","1.1.1.1"],
  "lease_seconds_total": 86400,
  "lease_seconds_remaining": 85213,
  "t1_epoch": 1724702222,
  "t2_epoch": 1724705555,
  "expiry_epoch": 1724788888,
  "mtu": 1500,
  "xid": 305419896,
  "cache_reused": true,
  "interface_auto": true,
  "initial": true,
  "verbose": false
}
```

  IPv6 placeholder fields currently emitted as null (or omitted in some parsers):
  `ipv6`, `dns6`. These will be populated once DHCPv6 / RA handling is implemented.

Redacted output (when `interface_snapshot_redact=true` or `--redact-interface`):
```json
{
  "kind": "interface_snapshot",
  "name": "utun8",
  "ipv4": "***",
  "router": "***",
  "dns": ["***"],
  "lease_seconds_total": 86400,
  "lease_seconds_remaining": 86400,
  "t1_epoch": 1724702222,
  "t2_epoch": 1724705555,
  "expiry_epoch": 1724788888,
  "mtu": 1500,
  "xid": 305419896,
  "cache_reused": false,
  "interface_auto": true,
  "initial": true,
  "verbose": false
}
```

## Controls

Configuration fields:
- `dhcp_metrics_interval_secs`: metrics emission interval (min 10).
- `interface_snapshot_redact`: redact IP/DNS in snapshots.
- `interface_snapshot_verbose`: include more DNS entries (up to 8) and mark `verbose:true`.

CLI overrides:
- `--redact-interface`: force redaction for this run.
- `--verbose-interface`: force verbose snapshot for this run.

## Noise Management

- Initial snapshot emitted only once per connect.
- Change snapshots only emitted on material change (IP, mask, router, DNS list).
- DNS list truncated (4 entries normal, 8 in verbose mode).
- Periodic metrics controlled by interval setting; final metrics always emitted on disconnect (if DHCP enabled).

## Parsing Guidance

Use `kind` field to route events:
- `dhcp_metrics` → update counters dashboard.
- `interface_snapshot` → update interface status pane.

Unknown extra fields should be ignored for forward compatibility.

## Future Extensions

Implemented additions:
- Lease health warning event (2222) when remaining percent <= configured threshold.
- Renew elapsed reset marker (3001) to allow external tracking of time since last successful lease refresh.

Planned:
- Add IPv6 snapshot fields.
- Include per-phase timing stats in metrics.
