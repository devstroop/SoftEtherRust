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

### Settings snapshot event (iOS/Android helpers)

- 1001: Network settings JSON (info)
  - Emitted after a successful connect with a JSON `message` containing fields such as `assigned_ipv4`, `subnet_mask`, `gateway`, and `dns_servers`.
  - Intended to help mobile platforms configure their virtual interfaces (NEPacketTunnelProvider on iOS, VpnService on Android).
  - You can also fetch the same JSON on demand via `softether_client_get_network_settings_json()`.

Notes

- Treat codes as hints for UX; do not build strict logic around them. Prefer the state callback for lifecycle.
- Additional error codes may be added in future for richer diagnostics.
