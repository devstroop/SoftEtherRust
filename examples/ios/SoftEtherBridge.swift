// SoftEtherBridge.swift - Swift wrapper for Rust FFI
//
// This provides a Swift-friendly API over the C FFI layer.
// Include the SoftEtherVPN.h header in your bridging header.

import Foundation
import NetworkExtension

/// Swift wrapper for SoftEther VPN client.
public class SoftEtherBridge {
    
    // MARK: - Types
    
    public enum ConnectionState {
        case disconnected
        case connecting
        case handshaking
        case authenticating
        case connected
        case disconnecting
        case error
        
        init(from cState: SoftEtherState) {
            switch cState {
            case SOFTETHER_STATE_DISCONNECTED: self = .disconnected
            case SOFTETHER_STATE_CONNECTING: self = .connecting
            case SOFTETHER_STATE_HANDSHAKING: self = .handshaking
            case SOFTETHER_STATE_AUTHENTICATING: self = .authenticating
            case SOFTETHER_STATE_CONNECTED: self = .connected
            case SOFTETHER_STATE_DISCONNECTING: self = .disconnecting
            case SOFTETHER_STATE_ERROR: self = .error
            default: self = .disconnected
            }
        }
    }
    
    public struct Session {
        public let ipAddress: UInt32
        public let subnetMask: UInt32
        public let gateway: UInt32
        public let dns1: UInt32
        public let dns2: UInt32
        public let connectedServerIP: String
        public let serverVersion: UInt32
        public let serverBuild: UInt32
        public let macAddress: [UInt8]
        public let gatewayMac: [UInt8]
        
        public var ipAddressString: String {
            formatIPv4(ipAddress)
        }
        
        public var subnetMaskString: String {
            formatIPv4(subnetMask)
        }
        
        public var gatewayString: String {
            formatIPv4(gateway)
        }
        
        public var dnsServers: [String] {
            var servers: [String] = []
            if dns1 != 0 { servers.append(formatIPv4(dns1)) }
            if dns2 != 0 { servers.append(formatIPv4(dns2)) }
            return servers
        }
        
        public var macAddressString: String {
            macAddress.map { String(format: "%02x", $0) }.joined(separator: ":")
        }
        
        public var gatewayMacString: String {
            gatewayMac.map { String(format: "%02x", $0) }.joined(separator: ":")
        }
        
        private func formatIPv4(_ ip: UInt32) -> String {
            let a = (ip >> 24) & 0xFF
            let b = (ip >> 16) & 0xFF
            let c = (ip >> 8) & 0xFF
            let d = ip & 0xFF
            return "\(a).\(b).\(c).\(d)"
        }
    }
    
    public struct Statistics {
        public let bytesSent: UInt64
        public let bytesReceived: UInt64
        public let packetsSent: UInt64
        public let packetsReceived: UInt64
        public let uptimeSeconds: UInt64
        public let activeConnections: UInt32
        public let reconnectCount: UInt32
    }
    
    public struct Configuration {
        public let server: String
        public let port: UInt16
        public let hub: String
        public let username: String
        public let passwordHash: String
        
        // TLS Settings
        public let skipTlsVerify: Bool
        /// Custom CA certificate in PEM format for server verification.
        public let customCaPem: String?
        /// Server certificate SHA-256 fingerprint for pinning (64 hex chars).
        public let certFingerprintSha256: String?
        
        // Connection Settings
        public let maxConnections: UInt8
        public let timeoutSeconds: UInt32
        public let mtu: UInt32
        
        // Protocol Features
        public let useEncrypt: Bool
        public let useCompress: Bool
        public let udpAccel: Bool
        public let qos: Bool
        
        // Session Mode
        public let natTraversal: Bool
        public let monitorMode: Bool
        
        // Routing
        public let defaultRoute: Bool
        public let acceptPushedRoutes: Bool
        public let ipv4Include: String?
        public let ipv4Exclude: String?
        
        public init(
            server: String,
            port: UInt16 = 443,
            hub: String,
            username: String,
            passwordHash: String,
            skipTlsVerify: Bool = false,
            customCaPem: String? = nil,
            certFingerprintSha256: String? = nil,
            maxConnections: UInt8 = 1,
            timeoutSeconds: UInt32 = 30,
            mtu: UInt32 = 1400,
            useEncrypt: Bool = true,
            useCompress: Bool = false,
            udpAccel: Bool = false,
            qos: Bool = false,
            natTraversal: Bool = true,
            monitorMode: Bool = false,
            defaultRoute: Bool = true,
            acceptPushedRoutes: Bool = true,
            ipv4Include: String? = nil,
            ipv4Exclude: String? = nil
        ) {
            self.server = server
            self.port = port
            self.hub = hub
            self.username = username
            self.passwordHash = passwordHash
            self.skipTlsVerify = skipTlsVerify
            self.customCaPem = customCaPem
            self.certFingerprintSha256 = certFingerprintSha256
            self.maxConnections = maxConnections
            self.timeoutSeconds = timeoutSeconds
            self.mtu = mtu
            self.useEncrypt = useEncrypt
            self.useCompress = useCompress
            self.udpAccel = udpAccel
            self.qos = qos
            self.natTraversal = natTraversal
            self.monitorMode = monitorMode
            self.defaultRoute = defaultRoute
            self.acceptPushedRoutes = acceptPushedRoutes
            self.ipv4Include = ipv4Include
            self.ipv4Exclude = ipv4Exclude
        }
    }
    
    // MARK: - Callbacks
    
    public var onStateChanged: ((ConnectionState) -> Void)?
    public var onConnected: ((Session) -> Void)?
    public var onDisconnected: ((Error?) -> Void)?
    public var onPacketsReceived: (([Data]) -> Void)?
    public var onLog: ((LogLevel, String) -> Void)?
    
    public enum LogLevel: Int {
        case error = 0
        case warn = 1
        case info = 2
        case debug = 3
        case trace = 4
    }
    
    // MARK: - Private
    
    private var handle: SoftEtherHandle = SOFTETHER_HANDLE_NULL
    private var callbackContext = CallbackContext()
    
    // MARK: - Lifecycle
    
    public init() {}
    
    deinit {
        disconnect()
        if handle != SOFTETHER_HANDLE_NULL {
            softether_destroy(handle)
            handle = SOFTETHER_HANDLE_NULL
        }
    }
    
    // MARK: - Public API
    
    /// Create and connect to VPN server.
    public func connect(config: Configuration) throws {
        if handle != SOFTETHER_HANDLE_NULL {
            throw BridgeError.alreadyConnected
        }
        
        // Store self reference in callback context
        callbackContext.bridge = self
        
        // Create C config
        var cConfig = SoftEtherConfig()
        
        let serverCString = config.server.withCString { strdup($0) }!
        let hubCString = config.hub.withCString { strdup($0) }!
        let usernameCString = config.username.withCString { strdup($0) }!
        let passwordHashCString = config.passwordHash.withCString { strdup($0) }!
        let ipv4IncludeCString = config.ipv4Include?.withCString { strdup($0) }
        let ipv4ExcludeCString = config.ipv4Exclude?.withCString { strdup($0) }
        let customCaPemCString = config.customCaPem?.withCString { strdup($0) }
        let certFingerprintCString = config.certFingerprintSha256?.withCString { strdup($0) }
        
        defer {
            free(serverCString)
            free(hubCString)
            free(usernameCString)
            free(passwordHashCString)
            if let ptr = ipv4IncludeCString { free(ptr) }
            if let ptr = ipv4ExcludeCString { free(ptr) }
            if let ptr = customCaPemCString { free(ptr) }
            if let ptr = certFingerprintCString { free(ptr) }
        }
        
        cConfig.server = UnsafePointer(serverCString)
        cConfig.port = UInt32(config.port)
        cConfig.hub = UnsafePointer(hubCString)
        cConfig.username = UnsafePointer(usernameCString)
        cConfig.password_hash = UnsafePointer(passwordHashCString)
        
        // TLS Settings
        cConfig.skip_tls_verify = config.skipTlsVerify ? 1 : 0
        cConfig.custom_ca_pem = customCaPemCString.map { UnsafePointer($0) }
        cConfig.cert_fingerprint_sha256 = certFingerprintCString.map { UnsafePointer($0) }
        
        // Connection Settings
        cConfig.max_connections = UInt32(config.maxConnections)
        cConfig.timeout_seconds = config.timeoutSeconds
        cConfig.mtu = config.mtu
        
        // Protocol Features
        cConfig.use_encrypt = config.useEncrypt ? 1 : 0
        cConfig.use_compress = config.useCompress ? 1 : 0
        cConfig.udp_accel = config.udpAccel ? 1 : 0
        cConfig.qos = config.qos ? 1 : 0
        
        // Session Mode
        cConfig.nat_traversal = config.natTraversal ? 1 : 0
        cConfig.monitor_mode = config.monitorMode ? 1 : 0
        
        // Routing
        cConfig.default_route = config.defaultRoute ? 1 : 0
        cConfig.accept_pushed_routes = config.acceptPushedRoutes ? 1 : 0
        cConfig.ipv4_include = ipv4IncludeCString.map { UnsafePointer($0) }
        cConfig.ipv4_exclude = ipv4ExcludeCString.map { UnsafePointer($0) }
        
        // Create C callbacks
        var cCallbacks = SoftEtherCallbacks()
        cCallbacks.context = Unmanaged.passUnretained(callbackContext).toOpaque()
        cCallbacks.on_state_changed = stateChangedCallback
        cCallbacks.on_connected = connectedCallback
        cCallbacks.on_disconnected = disconnectedCallback
        cCallbacks.on_packets_received = packetsReceivedCallback
        cCallbacks.on_log = logCallback
        
        // Create client
        handle = softether_create(&cConfig, &cCallbacks)
        if handle == SOFTETHER_HANDLE_NULL {
            throw BridgeError.createFailed
        }
        
        // Start connection
        let result = softether_connect(handle)
        if result != SOFTETHER_OK {
            softether_destroy(handle)
            handle = SOFTETHER_HANDLE_NULL
            throw BridgeError.connectFailed(code: Int(result.rawValue))
        }
    }
    
    /// Disconnect from VPN server.
    public func disconnect() {
        if handle != SOFTETHER_HANDLE_NULL {
            _ = softether_disconnect(handle)
        }
    }
    
    /// Get current connection state.
    public var state: ConnectionState {
        if handle == SOFTETHER_HANDLE_NULL {
            return .disconnected
        }
        return ConnectionState(from: softether_get_state(handle))
    }
    
    /// Get session information (only valid when connected).
    public var session: Session? {
        var cSession = SoftEtherSession()
        let result = softether_get_session(handle, &cSession)
        guard result == SOFTETHER_OK else { return nil }
        
        return Session(
            ipAddress: cSession.ip_address,
            subnetMask: cSession.subnet_mask,
            gateway: cSession.gateway,
            dns1: cSession.dns1,
            dns2: cSession.dns2,
            connectedServerIP: withUnsafePointer(to: cSession.connected_server_ip) {
                $0.withMemoryRebound(to: CChar.self, capacity: 64) {
                    String(cString: $0)
                }
            },
            serverVersion: cSession.server_version,
            serverBuild: cSession.server_build,
            macAddress: Array(withUnsafeBytes(of: cSession.mac_address) { Array($0) }),
            gatewayMac: Array(withUnsafeBytes(of: cSession.gateway_mac) { Array($0) })
        )
    }
        )
    }
    
    /// Get connection statistics.
    public var statistics: Statistics {
        var cStats = SoftEtherStats()
        _ = softether_get_stats(handle, &cStats)
        
        return Statistics(
            bytesSent: cStats.bytes_sent,
            bytesReceived: cStats.bytes_received,
            packetsSent: cStats.packets_sent,
            packetsReceived: cStats.packets_received,
            uptimeSeconds: cStats.uptime_secs,
            activeConnections: cStats.active_connections,
            reconnectCount: cStats.reconnect_count
        )
    }
    
    /// Send packets to VPN server.
    /// Each packet should be a complete Ethernet frame (L2).
    /// Throws `queueFull` if backpressure is detected - caller should retry.
    public func sendPackets(_ packets: [Data]) throws {
        guard !packets.isEmpty else { return }
        
        // Calculate total size: [len:u16][data] for each packet
        var totalSize = 0
        for packet in packets {
            totalSize += 2 + packet.count
        }
        
        // Build buffer
        var buffer = Data(capacity: totalSize)
        for packet in packets {
            // Add 16-bit length prefix (network byte order)
            var len = UInt16(packet.count).bigEndian
            buffer.append(Data(bytes: &len, count: 2))
            buffer.append(packet)
        }
        
        // Send
        let result = buffer.withUnsafeBytes { ptr in
            softether_send_packets(
                handle,
                ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                buffer.count,
                Int32(packets.count)
            )
        }
        
        if result == Int32(SOFTETHER_QUEUE_FULL.rawValue) {
            throw BridgeError.queueFull
        } else if result < 0 {
            throw BridgeError.sendFailed(code: Int(result))
        }
    }
    
    // MARK: - Static Helpers
    
    /// Hash password for SoftEther authentication.
    public static func hashPassword(_ password: String, username: String) -> Data? {
        var output = [UInt8](repeating: 0, count: 20)
        let result = softether_hash_password(password, username, &output)
        guard result == SOFTETHER_OK else { return nil }
        return Data(output)
    }
    
    /// Get library version.
    public static var version: String {
        String(cString: softether_version())
    }
}

// MARK: - Callback Context

private class CallbackContext {
    weak var bridge: SoftEtherBridge?
}

// MARK: - C Callbacks

private func stateChangedCallback(context: UnsafeMutableRawPointer?, state: SoftEtherState) {
    guard let context = context else { return }
    let ctx = Unmanaged<CallbackContext>.fromOpaque(context).takeUnretainedValue()
    ctx.bridge?.onStateChanged?(SoftEtherBridge.ConnectionState(from: state))
}

private func connectedCallback(context: UnsafeMutableRawPointer?, session: UnsafePointer<SoftEtherSession>?) {
    guard let context = context, let session = session else { return }
    let ctx = Unmanaged<CallbackContext>.fromOpaque(context).takeUnretainedValue()
    
    let s = session.pointee
    let swiftSession = SoftEtherBridge.Session(
        ipAddress: s.ip_address,
        subnetMask: s.subnet_mask,
        gateway: s.gateway,
        dns1: s.dns1,
        dns2: s.dns2,
        connectedServerIP: withUnsafePointer(to: s.connected_server_ip) {
            $0.withMemoryRebound(to: CChar.self, capacity: 64) {
                String(cString: $0)
            }
        },
        serverVersion: s.server_version,
        serverBuild: s.server_build,
        macAddress: Array(withUnsafeBytes(of: s.mac_address) { Array($0) }),
        gatewayMac: Array(withUnsafeBytes(of: s.gateway_mac) { Array($0) })
    )
    
    ctx.bridge?.onConnected?(swiftSession)
}

private func disconnectedCallback(context: UnsafeMutableRawPointer?, result: SoftEtherResult) {
    guard let context = context else { return }
    let ctx = Unmanaged<CallbackContext>.fromOpaque(context).takeUnretainedValue()
    
    let error: Error? = result == SOFTETHER_OK ? nil : BridgeError.disconnected(code: Int(result.rawValue))
    ctx.bridge?.onDisconnected?(error)
}

private func packetsReceivedCallback(
    context: UnsafeMutableRawPointer?,
    packets: UnsafePointer<UInt8>?,
    totalSize: Int,
    count: UInt32
) {
    guard let context = context, let packets = packets, count > 0 else { return }
    let ctx = Unmanaged<CallbackContext>.fromOpaque(context).takeUnretainedValue()
    
    // Parse packets from buffer
    var parsedPackets: [Data] = []
    parsedPackets.reserveCapacity(Int(count))
    
    var offset = 0
    while offset + 2 <= totalSize {
        let len = Int(UInt16(bigEndian: packets.advanced(by: offset).withMemoryRebound(to: UInt16.self, capacity: 1) { $0.pointee }))
        offset += 2
        
        if offset + len <= totalSize {
            let data = Data(bytes: packets.advanced(by: offset), count: len)
            parsedPackets.append(data)
            offset += len
        } else {
            break
        }
    }
    
    ctx.bridge?.onPacketsReceived?(parsedPackets)
}

private func logCallback(context: UnsafeMutableRawPointer?, level: Int32, message: UnsafePointer<CChar>?) {
    guard let context = context, let message = message else { return }
    let ctx = Unmanaged<CallbackContext>.fromOpaque(context).takeUnretainedValue()
    
    let logLevel = SoftEtherBridge.LogLevel(rawValue: Int(level)) ?? .info
    let logMessage = String(cString: message)
    ctx.bridge?.onLog?(logLevel, logMessage)
}

// MARK: - Errors

public enum BridgeError: Error {
    case alreadyConnected
    case createFailed
    case connectFailed(code: Int)
    case sendFailed(code: Int)
    case disconnected(code: Int)
    case queueFull  // Backpressure - caller should retry
}
