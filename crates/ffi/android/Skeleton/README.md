# Android VpnService Skeleton

This folder provides guidance to wire the Rust C API into an Android VpnService via JNI.

## Outline
- Build `softether_c_api` for `armeabi-v7a`, `arm64-v8a`, `x86_64` and package as `.so` in `src/main/jniLibs/<abi>/`.
- Create JNI bridge methods to call `softether_client_*` C functions.
- From `VpnService`, manage a worker thread that:
  - Creates the client from JSON
  - Registers state/rx callbacks
  - Calls `connect`
  - Reads from `ParcelFileDescriptor` (tun) and forwards via `softether_client_send_frame`
  - On RX callback, write to the tun file descriptor

## Kotlin Pseudocode

```kotlin
class MyVpnService: VpnService() {
  external fun seCreate(json: String): Long
  external fun seConnect(h: Long): Int
  external fun seDisconnect(h: Long): Int
  external fun seFree(h: Long)
  external fun seSetRx(h: Long)
  external fun seSend(h: Long, buf: ByteArray, len: Int): Int

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    val json = "{...}" // build from preferences
    val h = seCreate(json)
    seSetRx(h)
    seConnect(h)
    // start loop to read from TUN fd and call seSend
    return START_STICKY
  }
}
```

Note: Use the provided header `softether_c_api.h` from JNI C/C++ glue. Ensure proper calling conventions and lifetime management.
