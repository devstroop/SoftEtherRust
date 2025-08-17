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
