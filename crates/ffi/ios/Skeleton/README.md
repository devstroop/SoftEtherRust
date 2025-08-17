# iOS Packet Tunnel Skeleton

This folder provides guidance to wire the Rust C API into a NetworkExtension Packet Tunnel Provider.

## Outline
- Build `softether_c_api` as an XCFramework using `scripts/build_xcframework.sh` (preferred).
- In your Packet Tunnel Provider (Swift):
  - Load JSON config (from provider config or app group container)
  - Call `softether_client_create` with JSON
  - Register state/rx callbacks
  - Call `softether_client_connect`
  - On inbound packets from NEPacketTunnelFlow, call `softether_client_send_frame`
  - On RX callback, write packets back to NEPacketTunnelFlow
  - Optionally, listen for event code 1001 to receive a JSON snapshot of network settings to apply to `NEPacketTunnelNetworkSettings`, or fetch via `softether_client_get_network_settings_json()`

## Swift Pseudocode

```swift
class PacketTunnelProvider: NEPacketTunnelProvider {
  var handle: OpaquePointer?

  override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
    let json = "{...}" // load from configuration
    handle = softether_client_create(json)
    softether_client_set_state_callback(handle) { state, user in /* update UI/log */ }
    softether_client_set_rx_callback(handle) { data, len, user in
      let pkt = Data(bytes: data, count: Int(len))
      self.packetFlow.writePackets([pkt], withProtocols: [NSNumber(value: AF_INET)])
    }
    softether_client_connect(handle)
    completionHandler(nil)
  }

  override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
    if let h = handle { softether_client_disconnect(h); softether_client_free(h) }
    completionHandler()
  }
}
```

Note: Link the generated header `softether_c_api.h` via a bridging header.
