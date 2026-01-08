// Example: Using SoftEtherBridge in a PacketTunnelProvider (iOS)
//
// This shows how to integrate the Rust-based SoftEther client
// with iOS Network Extension.
//
// Provider Configuration Keys (pass via NETunnelProviderProtocol.providerConfiguration):
//
// === Server (Required) ===
// - server: String - VPN server hostname or IP address
// - port: Int - Server port (default: 443)
// - hub: String - Virtual Hub name
// - skip_tls_verify: Bool - Skip TLS certificate verification (default: false)
// - custom_ca_pem: String? - Custom CA certificate in PEM format
// - cert_fingerprint_sha256: String? - Server cert SHA-256 fingerprint for pinning
//
// === Authentication (Required) ===
// - username: String - Username for authentication
// - passwordHash: String - Pre-computed SHA-0 password hash (40 hex chars)
//
// === Connection ===
// - max_connections: Int - Max TCP connections (1-32, default: 1)
// - half_connection: Bool - Half-duplex mode (default: false)
// - timeout_seconds: Int - Connection timeout (default: 30)
// - mtu: Int - MTU size for TUN device (default: 1400)
//
// === Session ===
// - nat_traversal: Bool - NAT traversal mode (default: false = bridge mode)
// - use_encrypt: Bool - Enable RC4 encryption inside TLS tunnel (default: true)
// - use_compress: Bool - Enable compression (default: false)
// - udp_accel: Bool - Enable UDP acceleration (default: false)
//
// === Options ===
// - qos: Bool - Enable VoIP/QoS prioritization (default: false)
// - monitor_mode: Bool - Request monitor mode (default: false)
//
// === Routing ===
// - default_route: Bool - Route all traffic through VPN (default: true)
// - accept_pushed_routes: Bool - Accept DHCP-pushed routes (default: true)

import NetworkExtension
import os.log

class SoftEtherPacketTunnelProvider: NEPacketTunnelProvider {
    
    private let logger = Logger(subsystem: "com.example.vpn", category: "SoftEtherTunnel")
    private var bridge: SoftEtherBridge?
    private var pendingCompletion: ((Error?) -> Void)?
    
    // IPs to exclude from VPN routing (cluster redirects)
    private var excludedIps = Set<String>()
    
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
        
        vpnBridge.onExcludeIp = { [weak self] ip in
            self?.logger.info("Excluding IP from VPN: \(ip)")
            self?.excludedIps.insert(ip)
            return true
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
              let hub = config["hub"] as? String,
              let username = config["username"] as? String,
              let passwordHash = config["passwordHash"] as? String else {
            return nil
        }
        
        return SoftEtherBridge.Configuration(
            // Server
            server: server,
            port: UInt16(config["port"] as? Int ?? 443),
            hub: hub,
            skipTlsVerify: config["skip_tls_verify"] as? Bool ?? false,
            customCaPem: config["custom_ca_pem"] as? String,
            certFingerprintSha256: config["cert_fingerprint_sha256"] as? String,
            // Authentication
            username: username,
            passwordHash: passwordHash,
            // Connection
            maxConnections: UInt8(config["max_connections"] as? Int ?? 1),
            halfConnection: config["half_connection"] as? Bool ?? false,
            timeoutSeconds: UInt32(config["timeout_seconds"] as? Int ?? 30),
            mtu: UInt32(config["mtu"] as? Int ?? 1400),
            // Session
            natTraversal: config["nat_traversal"] as? Bool ?? false,
            useEncrypt: config["use_encrypt"] as? Bool ?? true,
            useCompress: config["use_compress"] as? Bool ?? false,
            udpAccel: config["udp_accel"] as? Bool ?? false,
            // Options
            qos: config["qos"] as? Bool ?? false,
            monitorMode: config["monitor_mode"] as? Bool ?? false,
            // Routing
            defaultRoute: config["default_route"] as? Bool ?? true,
            acceptPushedRoutes: config["accept_pushed_routes"] as? Bool ?? true
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
        
        // Include routes (split tunnel using 0/1 and 128/1 to avoid replacing default gateway)
        ipv4.includedRoutes = [
            NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "128.0.0.0"),
            NEIPv4Route(destinationAddress: "128.0.0.0", subnetMask: "128.0.0.0")
        ]
        
        // Exclude routes: VPN server IP + any cluster redirect IPs
        var excludedRoutes: [NEIPv4Route] = []
        if !session.connectedServerIP.isEmpty {
            excludedRoutes.append(
                NEIPv4Route(destinationAddress: session.connectedServerIP, subnetMask: "255.255.255.255")
            )
        }
        for excludedIp in excludedIps {
            excludedRoutes.append(
                NEIPv4Route(destinationAddress: excludedIp, subnetMask: "255.255.255.255")
            )
        }
        ipv4.excludedRoutes = excludedRoutes
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
        
        // Use gateway MAC from session (learned from ARP) or broadcast if not available
        let gatewayMAC = session.gatewayMac.isEmpty || session.gatewayMac == [0, 0, 0, 0, 0, 0]
            ? [UInt8](repeating: 0xFF, count: 6)
            : session.gatewayMac
        
        // Use session MAC address for source
        let srcMAC = session.macAddress
        
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
        
        do {
            try bridge.sendPackets(frames)
        } catch BridgeError.queueFull {
            // Backpressure - drop packets (common under heavy load)
            logger.debug("Queue full, dropping \(ipPackets.count) packets")
        } catch {
            logger.warning("Send failed: \(error.localizedDescription)")
        }
    }
}
