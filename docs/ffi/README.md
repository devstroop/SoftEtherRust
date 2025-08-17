# SoftEther Rust FFI: Embedding Guide

This guide explains how to embed the Rust SoftEther VPN client into apps via the C API (`softether_c_api`). It covers:

- What the C API provides and how callbacks work
- JSON config schema and password hashing options
- iOS (Swift, NetworkExtension Packet Tunnel)
- Android (JNI, VpnService/TUN)
- A tiny desktop C harness for smoke tests

See also: `crates/ffi/c_api/include/softether_c_api.h`.

## C API surface

Key functions (see header for signatures):

- create/free: `softether_client_create(json)`, `softether_client_free(h)`
- connect/disconnect: `softether_client_connect(h)`, `softether_client_disconnect(h)`
- frame I/O: `softether_client_set_rx_callback(h, cb, user)`, `softether_client_send_frame(h, data, len)`
- state/events: `softether_client_set_state_callback(h, cb, user)`, `softether_client_set_event_callback(h, cb, user)`
- utils: `softether_b64_decode(b64, out, cap)`, `softether_client_version()`, `softether_client_get_network_settings_json(h)`

Threading and lifetime

- Callbacks may be invoked from internal worker threads; keep them fast and thread-safe.
- The handle is opaque; create once, set callbacks, then connect. Free only after disconnect returns.
- `send_frame` is non-blocking; returns 1 if queued, 0 if not ready, negative on error.

## Config JSON schema

The JSON passed to `softether_client_create` maps to `crates/config::ClientConfig`:

```
{
  "server": "vpn.example.com",
  "port": 443,
  "hub": "DEFAULT",
  "username": "user1",
  "password": "pass123",                  // optional if hashes provided
  "password_hash": "...",// base64(SHA0(password + UPPER(username))) 20 bytes
  "insecure_skip_verify": false,           // skip TLS verify (development only)
  "use_compress": false,
  "use_encrypt": true,
  "max_connections": 1,
  "udp_port": null
}
```

Rules

- If `password` is set, it is used to derive hashes internally.
- `password_hash` is recommended for compatibility; most servers expect this variant.

For more config details, see `docs/ffi/config.md`.

## Platform guides

- iOS Swift + NetworkExtension: `docs/ffi/ios.md`
- Android JNI + VpnService: `docs/ffi/android.md`
- Events and states: `docs/ffi/events.md`
  - Includes event code 1001 delivering a JSON snapshot of network settings after connect.

## Example harness

For a tiny C smoke test and build notes, see `docs/ffi/c-harness.md` and `crates/ffi/c_api/examples/ffi_harness.c`.
