# Events and States reference

The client emits states and events that you can subscribe to via the C API.

## States

Delivered via `softether_client_set_state_callback(h, cb, user)`:

- 0: Idle
- 1: Connecting
- 2: Established
- 3: Disconnecting

## Events

Delivered via `softether_client_set_event_callback(h, cb, user)` as `(level, code, message)`.

- Levels: 0=Info, 1=Warn, 2=Error
- Codes (current set, may expand):
  - 100..103: State transitions (info) — mirrors the state callback
  - 200: Connect attempt failed (warn)
  - 201: Connection timeout (warn)
  - 210: Redirect to another host/port (info)
  - 220: Tunnel opened (info)
  - 292: DHCP skipped (static profile) (info)
    - Emitted when a static IP configuration is present and DHCP discovery is bypassed intentionally.
    - Message example: "dhcp skipped (static_ip present)"
  - 293: DHCP required static missing (warn)
    - Emitted when configuration sets `require_static_ip=true` but no valid `static_ip` block provided; connection setup aborts.
  - 295: DHCP retransmit (info)
    - Message example: "dhcp discover retransmit iface=utun8 mac=.. xid=0x.. attempt=2"
  - 296: DHCP ACK timeout (warn)
  - 297: DHCP OFFER timeout (warn)
  - 298: DHCP send (info)
    - Message examples: "dhcp discover sent ...", "dhcp request sent ..."
  - 299: DHCP acquisition attempt (info)
  - 2998: DHCP no-traffic observed within window (info)
    - Emitted if no DHCP frames are seen on RX during the discover window; indicates likely framing mismatch.
  - 2999: DHCP decode error (info, throttled)
    - Emitted up to a few times per cycle when dhcproto fails to parse a candidate DHCP message; helps surface silent drops.
  - 1201: Policy summary (info)
    - Emits flags the server advertised that may affect networking (e.g., NoRouting=1, NoBroadcast=1)
  - 3301: DNS restore applied (info)
    - Message examples:
      - "dns_restore: linux resolv.conf restored from snapshot"
      - "dns_restore: macos restored '<Service>' to 1.1.1.1,1.0.0.1"
      - "dns_restore: macos restored '<Service>' to Empty"
  - 3302: DNS restore fallback (info)
    - Emitted when no original DNS snapshot was available; the client falls back to clearing DNS.
    - Message examples:
      - "dns_restore: linux no snapshot; cleared resolv.conf"
      - "dns_restore: macos no snapshot for '<Service>'; set to Empty"
      - "dns_restore: macos fallback; set '<Service>' to Empty"

### Settings snapshot event (iOS/Android helpers)

- 1001: Network settings JSON (info)
  - Emitted after a successful connect with a JSON `message` containing fields such as `assigned_ipv4`, `subnet_mask`, `gateway`, and `dns_servers`.
  - Intended to help mobile platforms configure their virtual interfaces (NEPacketTunnelProvider on iOS, VpnService on Android).
  - You can also fetch the same JSON on demand via `softether_client_get_network_settings_json()`.

Notes

- Treat codes as hints for UX; do not build strict logic around them. Prefer the state callback for lifecycle.
- Additional error codes may be added in future for richer diagnostics.
