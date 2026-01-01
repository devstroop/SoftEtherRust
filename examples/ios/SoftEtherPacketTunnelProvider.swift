// Example: Using SoftEtherBridge in a PacketTunnelProvider (iOS)
//
// This shows how to integrate the Rust-based SoftEther client
// with iOS Network Extension.

import NetworkExtension
import os.log

class SoftEtherPacketTunnelProvider: NEPacketTunnelProvider {
    
    private let logger = Logger(subsystem: "com.example.vpn", category: "SoftEtherTunnel")
    private var bridge: SoftEtherBridge?
    private var pendingCompletion: ((Error?) -> Void)?
    
    // MARK: - Lifecycle
    
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting tunnel with Rust bridge")
        
        guard let config = loadConfiguration() else {
            completionHandler(NSError(domain: "VPN", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid configuration"]))
            return
        }
        
        pendingCompletion = completionHandler
        
        // Create and configure bridge
        let vpnBridge = SoftEtherBridge()
        
        vpnBridge.onStateChanged = { [weak self] state in
            self?.logger.info("State changed: \(String(describing: state))")
        }
        
        vpnBridge.onConnected = { [weak self] session in
            self?.logger.info("Connected! IP: \(session.ipAddressString)")
            self?.configureTunnel(with: session)
        }
        
        vpnBridge.onDisconnected = { [weak self] error in
            self?.logger.info("Disconnected: \(error?.localizedDescription ?? "clean")")
        }
        
        vpnBridge.onPacketsReceived = { [weak self] packets in
            self?.handleReceivedPackets(packets)
        }
        
        self.bridge = vpnBridge
        
        // Connect
        do {
            try vpnBridge.connect(config: config)
        } catch {
            logger.error("Connect failed: \(error.localizedDescription)")
            completionHandler(error)
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Stopping tunnel")
        bridge?.disconnect()
        bridge = nil
        completionHandler()
    }
    
    // MARK: - Configuration
    
    private func loadConfiguration() -> SoftEtherBridge.Configuration? {
        guard let tunnelConfig = protocolConfiguration as? NETunnelProviderProtocol,
              let config = tunnelConfig.providerConfiguration,
              let server = config["server"] as? String,
              let username = config["username"] as? String,
              let passwordHash = config["passwordHash"] as? String else {
            return nil
        }
        
        return SoftEtherBridge.Configuration(
            server: server,
            port: UInt16(config["port"] as? Int ?? 443),
            hub: config["hub"] as? String ?? "VPN",
            username: username,
            passwordHash: passwordHash
        )
    }
    
    // MARK: - Tunnel Configuration
    
    private func configureTunnel(with session: SoftEtherBridge.Session) {
        let settings = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: session.connectedServerIP.isEmpty ? "10.0.0.1" : session.connectedServerIP
        )
        
        // IPv4
        let ipv4 = NEIPv4Settings(
            addresses: [session.ipAddressString],
            subnetMasks: [session.subnetMaskString]
        )
        ipv4.includedRoutes = [
            NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "128.0.0.0"),
            NEIPv4Route(destinationAddress: "128.0.0.0", subnetMask: "128.0.0.0")
        ]
        if !session.connectedServerIP.isEmpty {
            ipv4.excludedRoutes = [
                NEIPv4Route(destinationAddress: session.connectedServerIP, subnetMask: "255.255.255.255")
            ]
        }
        settings.ipv4Settings = ipv4
        
        // DNS
        var dnsServers = session.dnsServers
        if dnsServers.isEmpty {
            dnsServers = ["8.8.8.8", "8.8.4.4"]
        }
        settings.dnsSettings = NEDNSSettings(servers: dnsServers)
        
        settings.mtu = 1400
        
        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                self?.logger.error("Failed to configure tunnel: \(error.localizedDescription)")
                self?.pendingCompletion?(error)
            } else {
                self?.logger.info("Tunnel configured successfully")
                self?.startReadingPackets()
                self?.pendingCompletion?(nil)
            }
            self?.pendingCompletion = nil
        }
    }
    
    // MARK: - Packet Handling
    
    private func handleReceivedPackets(_ frames: [Data]) {
        // Convert L2 Ethernet frames to L3 IP packets
        var ipPackets: [Data] = []
        var protocols: [NSNumber] = []
        
        for frame in frames {
            guard frame.count > 14 else { continue }
            let etherType = UInt16(frame[12]) << 8 | UInt16(frame[13])
            guard etherType == 0x0800 else { continue }  // IPv4 only
            
            ipPackets.append(frame.dropFirst(14))
            protocols.append(NSNumber(value: AF_INET))
        }
        
        if !ipPackets.isEmpty {
            packetFlow.writePackets(ipPackets, withProtocols: protocols)
        }
    }
    
    private func startReadingPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            self?.sendPacketsToServer(packets)
            self?.startReadingPackets()
        }
    }
    
    private func sendPacketsToServer(_ ipPackets: [Data]) {
        guard let bridge = bridge, let session = bridge.session else { return }
        
        // Get gateway MAC (would need to be tracked from ARP)
        let gatewayMAC: [UInt8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        let srcMAC: [UInt8] = [0x5E, 0x00, 0x00, 0x00, 0x00, 0x01]
        
        // Convert L3 IP packets to L2 Ethernet frames
        var frames: [Data] = []
        for packet in ipPackets {
            var frame = Data(capacity: 14 + packet.count)
            frame.append(contentsOf: gatewayMAC)   // Dest MAC
            frame.append(contentsOf: srcMAC)       // Src MAC
            frame.append(contentsOf: [0x08, 0x00]) // EtherType IPv4
            frame.append(packet)
            frames.append(frame)
        }
        
        try? bridge.sendPackets(frames)
    }
}
