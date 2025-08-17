# iOS integration (Swift + NetworkExtension)

This shows how to embed the Rust client in a Packet Tunnel Provider.

## Build the XCFramework

Use the helper script to build a universal XCFramework for device and simulator:

- `scripts/build_xcframework.sh [--release] [--copy-to /path/to/YouriOSRepo/Vendor]`
  - Produces: `target/xcframework/SoftEtherClient.xcframework`
  - Optionally copies the `.xcframework` into your external iOS app repo via `--copy-to`.
  - Contains static libs per-arch and `Headers/softether_c_api.h`.

## Add to Xcode

- Add the library (per-arch) and header to your app/extension target.
- Create a bridging header and import `softether_c_api.h`.
- In the extension capabilities, enable Network Extensions (Packet Tunnel Provider).

## Swift usage

```swift
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
  var se: OpaquePointer?

  override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
    // Build Network Settings early (TUN interface)
    let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
    settings.ipv4Settings = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"]) // placeholder
    settings.mtu = 1500 as NSNumber
    self.setTunnelNetworkSettings(settings) { err in
      if let err = err { completionHandler(err); return }

      // Load config JSON (from provider configuration or app group)
      let json = "{ \"server\": \"vpn.example.com\", \"port\": 443, \"hub\": \"DEFAULT\", \"username\": \"user\", \"password\": \"pass\", \"use_encrypt\": true, \"use_compress\": false, \"max_connections\": 1 }"
  self.se = softether_client_create(json)

      // State callback
      softether_client_set_state_callback(self.se) { state, user in
        NSLog("SE state: %d", state)
      }

    // Event callback
      softether_client_set_event_callback(self.se) { lvl, code, cmsg, _ in
        if let cmsg = cmsg {
          let msg = String(cString: cmsg)
      // When code==1001 and lvl==0, message is a JSON settings snapshot
          if code == 1001, let data = msg.data(using: .utf8),
             let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            // Apply NEPacketTunnelNetworkSettings from obj here if desired
            NSLog("SE settings: \(obj)")
          } else {
            NSLog("SE event[\(lvl)/\(code)]: \(msg)")
          }
        }
      }

      // RX callback -> write to NEPacketTunnelFlow
      softether_client_set_rx_callback(self.se) { data, len, _ in
        guard let data = data else { return }
        let pkt = Data(bytes: data, count: Int(len))
        self.packetFlow.writePackets([pkt], withProtocols: [NSNumber(value: AF_INET as Int32)])
      }

  // Start connect
      _ = softether_client_connect(self.se)
      completionHandler(nil)

      // Start reading from flow and forward to client
      self.readLoop()
    }
  }

  private func readLoop() {
    self.packetFlow.readPackets { packets, _ in
      if let se = self.se {
        for pkt in packets { _ = pkt.withUnsafeBytes { p in softether_client_send_frame(se, p.bindMemory(to: UInt8.self).baseAddress, UInt32(pkt.count)) } }
      }
      self.readLoop()
    }
  }

  override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
    if let se = se { _ = softether_client_disconnect(se); softether_client_free(se) }
    completionHandler()
  }
}
```

Notes

- Replace placeholder IP settings with actual addresses after connection. You can fetch a JSON snapshot via `softether_client_get_network_settings_json()` or listen for event code 1001 to get settings.
- After parsing the JSON, create and apply `NEPacketTunnelNetworkSettings` (IPv4 address, subnet, routes, DNS) to the provider via `setTunnelNetworkSettings`.
- Ensure your library is code signed and packaged per Apple requirements. XCFramework is recommended.
