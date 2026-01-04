# FFI/JNI Integration Guide

This document explains how to integrate the SoftEther VPN Rust library with iOS and Android applications.

## Overview

The Rust library exposes a C ABI (Application Binary Interface) that can be called from:
- **Swift** (iOS/macOS) via C bridging
- **Kotlin** (Android) via JNI

## Building

### Prerequisites

- Rust toolchain (rustup)
- Xcode (for iOS)
- Android NDK (for Android)

### Build Commands

```bash
# Make the build script executable
chmod +x build-mobile.sh

# Build for iOS (creates XCFramework)
./build-mobile.sh ios

# Build for Android (creates JNI libraries)
./build-mobile.sh android

# Build for macOS (universal binary)
./build-mobile.sh macos

# Build for all platforms
./build-mobile.sh all
```

## iOS Integration

### 1. Add the XCFramework

After building, add `target/ios/SoftEtherVPN.xcframework` to your Xcode project:

1. Drag the XCFramework into your project
2. Ensure it's added to your app target's "Frameworks, Libraries, and Embedded Content"
3. Set "Embed" to "Embed & Sign"

### 2. Add the C Header

Copy `include/SoftEtherVPN.h` to your project and create a bridging header:

```c
// YourProject-Bridging-Header.h
#import "SoftEtherVPN.h"
```

### 3. Use the Swift Wrapper

Copy `examples/ios/SoftEtherBridge.swift` to your project. Example usage:

```swift
import NetworkExtension

class MyPacketTunnelProvider: NEPacketTunnelProvider {
    let vpn = SoftEtherBridge()
    
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let config = SoftEtherBridge.Configuration(
            server: "vpn.example.com",
            port: 443,
            hub: "VPN",
            username: "user",
            passwordHash: "your_hash_here"
        )
        
        vpn.listener = self
        
        do {
            try vpn.create(config: config)
            try vpn.connect()
            completionHandler(nil)
        } catch {
            completionHandler(error)
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        vpn.disconnect()
        completionHandler()
    }
}
```

### 4. Network Extension Entitlements

Add to your entitlements:

```xml
<key>com.apple.developer.networking.networkextension</key>
<array>
    <string>packet-tunnel-provider</string>
</array>
```

## Android Integration

### 1. Add JNI Libraries

Copy the contents of `target/android/jniLibs/` to your Android project's `app/src/main/jniLibs/` directory:

```
app/
└── src/
    └── main/
        └── jniLibs/
            ├── arm64-v8a/
            │   └── libsoftether.so
            ├── armeabi-v7a/
            │   └── libsoftether.so
            ├── x86_64/
            │   └── libsoftether.so
            └── x86/
                └── libsoftether.so
```

### 2. Add the Kotlin Wrapper

Copy `examples/android/SoftEtherBridge.kt` to your project (adjust package name).

### 3. Create VpnService

Copy `examples/android/RustVpnService.kt` and modify for your app:

```kotlin
class MyVpnService : VpnService(), SoftEtherBridge.Listener {
    private val bridge = SoftEtherBridge()
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val config = SoftEtherBridge.Configuration(
            server = "vpn.example.com",
            port = 443,
            hub = "VPN",
            username = "user",
            passwordHash = "your_hash_here"
        )
        
        bridge.listener = this
        bridge.create(config)
        bridge.connect()
        
        return START_STICKY
    }
    
    override fun onDestroy() {
        bridge.disconnect()
        bridge.destroy()
        super.onDestroy()
    }
}
```

### 4. AndroidManifest.xml

```xml
<service
    android:name=".MyVpnService"
    android:permission="android.permission.BIND_VPN_SERVICE"
    android:exported="false">
    <intent-filter>
        <action android:name="android.net.VpnService" />
    </intent-filter>
</service>
```

### 5. Request VPN Permission

```kotlin
val intent = VpnService.prepare(context)
if (intent != null) {
    startActivityForResult(intent, VPN_REQUEST_CODE)
} else {
    startVpnService()
}
```

## API Reference

### Configuration

| Field | Type | Description |
|-------|------|-------------|
| server | String | VPN server hostname or IP |
| port | UInt16 | Server port (usually 443) |
| hub | String | Virtual Hub name |
| username | String | Authentication username |
| passwordHash | String | SHA-0 hashed password (40 hex chars) |
| useTls | Bool | Use TLS encryption (default: true) |
| maxConnections | UInt8 | Number of TCP connections (1-32) |
| useCompress | Bool | Enable compression |

### Connection States

| State | Description |
|-------|-------------|
| Disconnected | Not connected |
| Connecting | Connection in progress |
| Authenticating | Performing authentication |
| Connected | Successfully connected |
| Disconnecting | Disconnect in progress |
| Reconnecting | Auto-reconnecting |

### Result Codes

| Code | Description |
|------|-------------|
| Ok | Success |
| InvalidParam | Invalid parameter |
| NetworkError | Network failure |
| AuthFailed | Authentication failed |
| Timeout | Connection timeout |
| NotConnected | Operation requires connection |
| AlreadyConnected | Already connected |
| InternalError | Internal error |

## Generating Password Hash

The SoftEther protocol uses SHA-0 hashed passwords. Generate with:

```bash
# Using the Rust CLI
vpnclient hash -u username -p password

# Output: 40-character hex string
```

## Troubleshooting

### iOS

1. **Library not loaded**: Ensure XCFramework is embedded
2. **Symbol not found**: Check bridging header is configured
3. **Network extension won't start**: Check entitlements and provisioning profile

### Android

1. **UnsatisfiedLinkError**: Ensure .so files are in correct jniLibs folders
2. **VPN permission denied**: Request permission before starting service
3. **Connection fails**: Check network permissions in manifest

## Thread Safety

The FFI layer uses interior mutability with `Mutex`. All operations are thread-safe, but:

- Don't call `softether_destroy()` while other calls are in progress
- Callbacks are invoked on the Rust runtime thread
- On iOS, dispatch callbacks to main thread if updating UI
- On Android, post callbacks to main looper if updating UI

## Memory Management

- `softether_create()` allocates resources
- `softether_destroy()` frees all resources
- Session pointers are only valid while connected
- Packet buffers are owned by the caller

## Example: Full iOS PacketTunnelProvider

See `examples/ios/RustPacketTunnelProvider.swift` for a complete implementation.

## Example: Full Android VpnService

See `examples/android/RustVpnService.kt` for a complete implementation.
