# C API (cdylib/staticlib)

General C API exports for embedding the Rust SoftEther client in other applications.

Provides a stable C interface for:
- Language bindings (Python, Node.js, etc.)
- Legacy application integration
- Cross-platform library usage

## Build (desktop)

```
cargo build -p softether_ffi --release
```

Outputs a shared library (macOS: `libsoftether_ffi.dylib`, Linux: `libsoftether_ffi.so`).

## Build for iOS (XCFramework)

Use the helper script which builds static archives for device/simulator and packages an xcframework:

```
./scripts/build_xcframework.sh --release [--copy-to /path/to/YouriOSRepo/Vendor]
```

Output: `target/xcframework/SoftEtherClient.xcframework`

If `--copy-to` is provided, the xcframework will also be copied into the specified directory (useful when your iOS app lives in a separate repo).

## API

Header: `include/softether_ffi.h`

### Config JSON example

```
{
	"server": "vpn.example.com",
	"port": 443,
	"hub": "DEFAULT",
	"username": "user1",
	"password": "pass123",
	"use_compress": false,
	"use_encrypt": true,
	"max_connections": 1,
	"skip_tls_verify": false
}
```

Alternatively, provide `password_hash` instead of `password`.

### Tunnel settings JSON

On successful `connect`, the event callback may receive an Info event with code `1001` whose message is a JSON object containing tunnel settings:

```
{
	"kind": "settings",
	"assigned_ipv4": "10.0.0.2",
	"subnet_mask": "255.255.255.0",
	"gateway": "10.0.0.1",
	"dns_servers": ["1.1.1.1", "8.8.8.8"]
}
```

You can also query these settings on-demand via:

```
char* softether_client_get_network_settings_json(softether_client_t*);
// free with softether_string_free
```
