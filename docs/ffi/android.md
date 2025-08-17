# Android integration (JNI + VpnService)

Wire the Rust client via the C API into an Android VpnService.

## Build native libraries

- Build `softether_c_api` as `.so` for each ABI you need: `armeabi-v7a`, `arm64-v8a`, `x86_64`.
- Place them under `app/src/main/jniLibs/<abi>/libsoftether_c_api.so`.
- Include the header `softether_c_api.h` in your JNI C/C++ folder.

## JNI bridge (C/C++)

Example signatures:

```c
#include <jni.h>
#include "softether_c_api.h"

JNIEXPORT jlong JNICALL Java_com_example_vpn_Native_seCreate(JNIEnv* env, jclass, jstring jjson) {
  const char* json = (*env)->GetStringUTFChars(env, jjson, 0);
  softether_client_t* h = softether_client_create(json);
  (*env)->ReleaseStringUTFChars(env, jjson, json);
  return (jlong) (intptr_t) h;
}

JNIEXPORT jint JNICALL Java_com_example_vpn_Native_seConnect(JNIEnv*, jclass, jlong h) {
  return softether_client_connect((softether_client_t*)(intptr_t)h);
}

JNIEXPORT void JNICALL Java_com_example_vpn_Native_seSetRx(JNIEnv* env, jclass, jlong h) {
  softether_client_set_rx_callback((softether_client_t*)(intptr_t)h, /* your rx cb */, NULL);
}

JNIEXPORT jint JNICALL Java_com_example_vpn_Native_seSend(JNIEnv* env, jclass, jlong h, jbyteArray arr, jint len) {
  jbyte* p = (*env)->GetByteArrayElements(env, arr, NULL);
  int r = softether_client_send_frame((softether_client_t*)(intptr_t)h, (const uint8_t*)p, (uint32_t)len);
  (*env)->ReleaseByteArrayElements(env, arr, p, JNI_ABORT);
  return r;
}
```

## Kotlin service

```kotlin
class MyVpnService: VpnService() {
  external fun seCreate(json: String): Long
  external fun seConnect(h: Long): Int
  external fun seDisconnect(h: Long): Int
  external fun seFree(h: Long)
  external fun seSetRx(h: Long)
  external fun seSend(h: Long, buf: ByteArray, len: Int): Int

  private var h: Long = 0
  private var tun: ParcelFileDescriptor? = null

  override fun onCreate() {
    super.onCreate()
    System.loadLibrary("softether_c_api")
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    val b = Builder()
    b.setSession("SoftEther")
    b.addAddress("10.0.0.2", 24) // placeholder
    b.addRoute("0.0.0.0", 0)
    tun = b.establish()

    val json = "{\"server\":\"vpn.example.com\",\"port\":443,\"hub\":\"DEFAULT\",\"username\":\"user\",\"password\":\"pass\",\"use_encrypt\":true,\"use_compress\":false,\"max_connections\":1}"
    h = seCreate(json)
    seSetRx(h)
    seConnect(h)

    Thread { readLoop() }.start()
    return START_STICKY
  }

  private fun readLoop() {
    val fd = tun?.fileDescriptor ?: return
    val inCh = FileInputStream(fd).channel
    val buf = ByteBuffer.allocate(2000)
    while (true) {
      buf.clear()
      val n = inCh.read(buf)
      if (n <= 0) break
      val arr = ByteArray(n)
      buf.flip(); buf.get(arr)
      seSend(h, arr, n)
    }
  }

  override fun onDestroy() {
    seDisconnect(h); seFree(h)
    tun?.close()
    super.onDestroy()
  }
}
```

Notes

- Replace placeholder IP with addresses assigned by the server or via in-tunnel DHCP logic.
- Implement the RX callback to write received frames to the TUN fd using `FileOutputStream`.
- Ensure proper threading and lifecycle per Android guidelines.

### Applying network settings

Listen for event code `1001` (Info) from the event callback to receive a JSON snapshot of the assigned IP, subnet mask (or prefix), gateway, and DNS servers. Use this to configure your `VpnService.Builder` before calling `establish()`:

```
{
  "assigned_ipv4": "10.0.0.2",
  "subnet_mask": "255.255.255.0",
  "gateway": "10.0.0.1",
  "dns_servers": ["1.1.1.1", "8.8.8.8"]
}
```

Alternatively, call `softether_client_get_network_settings_json(h)` after a successful connect to fetch the same JSON.
