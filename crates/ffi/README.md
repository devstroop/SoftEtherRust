# ffi

Foreign Function Interface (FFI) bindings and wrappers for mobile and other platforms.

## Structure

- `ios/` - C bindings for iOS NetworkExtension framework
- `android/` - JNI bindings for Android VpnService API  
- `c_api/` - General C API exports for embedding in other applications

## Purpose

Enables the Rust core to be integrated into:
- iOS apps (via NetworkExtension packet tunnel providers)
- Android apps (via VpnService JNI)
- Other languages/frameworks requiring C bindings

## Start here

- Docs overview: `docs/ffi/README.md`
- iOS guide: `docs/ffi/ios.md` (uses `scripts/build_xcframework.sh` to produce `SoftEtherClient.xcframework`)
- Android guide: `docs/ffi/android.md`
- Events reference: `docs/ffi/events.md` (includes code 1001 with a JSON settings snapshot)
