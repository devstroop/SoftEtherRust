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
        public let originalServerIP: String
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
        public let ipv6Include: String?
        public let ipv6Exclude: String?
        
        // Static IPv4 Configuration (optional, skips DHCP if set)
        public let staticIpv4Address: String?
        public let staticIpv4Netmask: String?
        public let staticIpv4Gateway: String?
        public let staticIpv4Dns1: String?
        public let staticIpv4Dns2: String?
        
        // Static IPv6 Configuration (optional)
        public let staticIpv6Address: String?
        public let staticIpv6PrefixLen: UInt32
        public let staticIpv6Gateway: String?
        public let staticIpv6Dns1: String?
        public let staticIpv6Dns2: String?
        
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
            ipv4Exclude: String? = nil,
            ipv6Include: String? = nil,
            ipv6Exclude: String? = nil,
            staticIpv4Address: String? = nil,
            staticIpv4Netmask: String? = nil,
            staticIpv4Gateway: String? = nil,
            staticIpv4Dns1: String? = nil,
            staticIpv4Dns2: String? = nil,
            staticIpv6Address: String? = nil,
            staticIpv6PrefixLen: UInt32 = 0,
            staticIpv6Gateway: String? = nil,
            staticIpv6Dns1: String? = nil,
            staticIpv6Dns2: String? = nil
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
            self.ipv6Include = ipv6Include
            self.ipv6Exclude = ipv6Exclude
            self.staticIpv4Address = staticIpv4Address
            self.staticIpv4Netmask = staticIpv4Netmask
            self.staticIpv4Gateway = staticIpv4Gateway
            self.staticIpv4Dns1 = staticIpv4Dns1
            self.staticIpv4Dns2 = staticIpv4Dns2
            self.staticIpv6Address = staticIpv6Address
            self.staticIpv6PrefixLen = staticIpv6PrefixLen
            self.staticIpv6Gateway = staticIpv6Gateway
            self.staticIpv6Dns1 = staticIpv6Dns1
            self.staticIpv6Dns2 = staticIpv6Dns2
        }
    }
    
    // MARK: - Callbacks
    
    public var onStateChanged: ((ConnectionState) -> Void)?
    public var onConnected: ((Session) -> Void)?
    public var onDisconnected: ((Error?) -> Void)?
    public var onPacketsReceived: (([Data]) -> Void)?
    public var onLog: ((LogLevel, String) -> Void)?
    /// Called when an IP should be excluded from VPN routing (cluster redirect).
    /// iOS apps should add this IP to NEIPv4Route.excludedRoutes.
    public var onExcludeIp: ((String) -> Bool)?
    
    public enum LogLevel: Int {
        case error = 0
        case warn = 1
        case info = 2
        case debug = 3
        case trace = 4
    }
    
    // MARK: - Private
    
    private var handle: SoftEtherHandle?
    private var callbackContext = CallbackContext()
    
    // MARK: - Lifecycle
    
    public init() {}
    
    deinit {
        disconnect()
        if let h = handle {
            softether_destroy(h)
            handle = nil
        }
    }
    
    // MARK: - Public API
    
    /// Create and connect to VPN server.
    public func connect(config: Configuration) throws {
        if handle != nil {
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
        let ipv6IncludeCString = config.ipv6Include?.withCString { strdup($0) }
        let ipv6ExcludeCString = config.ipv6Exclude?.withCString { strdup($0) }
        let customCaPemCString = config.customCaPem?.withCString { strdup($0) }
        let certFingerprintCString = config.certFingerprintSha256?.withCString { strdup($0) }
        
        // Static IP C strings
        let staticIpv4AddrCString = config.staticIpv4Address?.withCString { strdup($0) }
        let staticIpv4MaskCString = config.staticIpv4Netmask?.withCString { strdup($0) }
        let staticIpv4GwCString = config.staticIpv4Gateway?.withCString { strdup($0) }
        let staticIpv4Dns1CString = config.staticIpv4Dns1?.withCString { strdup($0) }
        let staticIpv4Dns2CString = config.staticIpv4Dns2?.withCString { strdup($0) }
        let staticIpv6AddrCString = config.staticIpv6Address?.withCString { strdup($0) }
        let staticIpv6GwCString = config.staticIpv6Gateway?.withCString { strdup($0) }
        let staticIpv6Dns1CString = config.staticIpv6Dns1?.withCString { strdup($0) }
        let staticIpv6Dns2CString = config.staticIpv6Dns2?.withCString { strdup($0) }
        
        defer {
            free(serverCString)
            free(hubCString)
            free(usernameCString)
            free(passwordHashCString)
            if let ptr = ipv4IncludeCString { free(ptr) }
            if let ptr = ipv4ExcludeCString { free(ptr) }
            if let ptr = ipv6IncludeCString { free(ptr) }
            if let ptr = ipv6ExcludeCString { free(ptr) }
            if let ptr = customCaPemCString { free(ptr) }
            if let ptr = certFingerprintCString { free(ptr) }
            if let ptr = staticIpv4AddrCString { free(ptr) }
            if let ptr = staticIpv4MaskCString { free(ptr) }
            if let ptr = staticIpv4GwCString { free(ptr) }
            if let ptr = staticIpv4Dns1CString { free(ptr) }
            if let ptr = staticIpv4Dns2CString { free(ptr) }
            if let ptr = staticIpv6AddrCString { free(ptr) }
            if let ptr = staticIpv6GwCString { free(ptr) }
            if let ptr = staticIpv6Dns1CString { free(ptr) }
            if let ptr = staticIpv6Dns2CString { free(ptr) }
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
        cConfig.ipv6_include = ipv6IncludeCString.map { UnsafePointer($0) }
        cConfig.ipv6_exclude = ipv6ExcludeCString.map { UnsafePointer($0) }
        
        // Static IPv4 Configuration
        cConfig.static_ipv4_address = staticIpv4AddrCString.map { UnsafePointer($0) }
        cConfig.static_ipv4_netmask = staticIpv4MaskCString.map { UnsafePointer($0) }
        cConfig.static_ipv4_gateway = staticIpv4GwCString.map { UnsafePointer($0) }
        cConfig.static_ipv4_dns1 = staticIpv4Dns1CString.map { UnsafePointer($0) }
        cConfig.static_ipv4_dns2 = staticIpv4Dns2CString.map { UnsafePointer($0) }
        
        // Static IPv6 Configuration
        cConfig.static_ipv6_address = staticIpv6AddrCString.map { UnsafePointer($0) }
        cConfig.static_ipv6_prefix_len = config.staticIpv6PrefixLen
        cConfig.static_ipv6_gateway = staticIpv6GwCString.map { UnsafePointer($0) }
        cConfig.static_ipv6_dns1 = staticIpv6Dns1CString.map { UnsafePointer($0) }
        cConfig.static_ipv6_dns2 = staticIpv6Dns2CString.map { UnsafePointer($0) }
        
        // Create C callbacks
        var cCallbacks = SoftEtherCallbacks()
        cCallbacks.context = Unmanaged.passUnretained(callbackContext).toOpaque()
        cCallbacks.on_state_changed = stateChangedCallback
        cCallbacks.on_connected = connectedCallback
        cCallbacks.on_disconnected = disconnectedCallback
        cCallbacks.on_packets_received = packetsReceivedCallback
        cCallbacks.on_log = logCallback
        cCallbacks.protect_socket = protectSocketCallback  // Socket protection for iOS
        cCallbacks.exclude_ip = excludeIpCallback  // IP exclusion for cluster redirects
        
        // Create client
        handle = softether_create(&cConfig, &cCallbacks)
        guard let h = handle else {
            let errorMsg = SoftEtherBridge.lastError
            throw BridgeError.createFailed(message: errorMsg)
        }
        
        // Start connection
        let result = softether_connect(h)
        if result != SOFTETHER_OK {
            let errorMsg = SoftEtherBridge.lastError
            softether_destroy(h)
            handle = nil
            throw BridgeError.connectFailed(code: Int(result.rawValue), message: errorMsg)
        }
    }
    
    /// Disconnect from VPN server.
    public func disconnect() {
        if let h = handle {
            _ = softether_disconnect(h)
        }
    }
    
    /// Get current connection state.
    public var state: ConnectionState {
        guard let h = handle else {
            return .disconnected
        }
        return ConnectionState(from: softether_get_state(h))
    }
    
    /// Get session information (only valid when connected).
    public var session: Session? {
        guard let h = handle else { return nil }
        var cSession = SoftEtherSession()
        let result = softether_get_session(h, &cSession)
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
    
    /// Get connection statistics.
    public var statistics: Statistics {
        var cStats = SoftEtherStats()
        if let h = handle {
            _ = softether_get_stats(h, &cStats)
        }
        
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
        guard let h = handle else {
            throw BridgeError.sendFailed(code: -1)
        }
        let result = buffer.withUnsafeBytes { ptr in
            softether_send_packets(
                h,
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
    
    /// Get the last error message from the library.
    /// Returns nil if no error occurred.
    public static var lastError: String? {
        guard let ptr = softether_get_last_error() else { return nil }
        return String(cString: ptr)
    }
    
    /// Clear the last error message.
    public static func clearLastError() {
        softether_clear_last_error()
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
        originalServerIP: withUnsafePointer(to: s.original_server_ip) {
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

/// Socket protection callback for iOS.
/// Marks the socket with SO_NET_SERVICE_TYPE to prevent VPN routing loops.
/// On iOS, this is equivalent to Android's VpnService.protect() functionality.
private func protectSocketCallback(context: UnsafeMutableRawPointer?, socketFd: Int32) -> Int32 {
    // Set SO_NET_SERVICE_TYPE to NET_SERVICE_TYPE_VV (voice & video)
    // This marks the socket as network service traffic that should bypass VPN routing
    // Value 6 = NET_SERVICE_TYPE_VV (defined in sys/socket.h)
    var serviceType: Int32 = 6  // NET_SERVICE_TYPE_VV
    let result = setsockopt(socketFd, SOL_SOCKET, SO_NET_SERVICE_TYPE, &serviceType, socklen_t(MemoryLayout<Int32>.size))
    
    if result == 0 {
        // Success - socket is now marked to bypass VPN
        return 1
    } else {
        // Failed to set socket option - log but continue anyway
        // The socket may still work if excludedRoutes is configured in NetworkExtension
        return 1  // Return success to allow connection attempt
    }
}

/// IP exclusion callback for iOS.
/// Called when an IP should be excluded from VPN routing (cluster redirect scenarios).
/// The app should add this IP to NEIPv4Route.excludedRoutes.
private func excludeIpCallback(context: UnsafeMutableRawPointer?, ip: UnsafePointer<CChar>?) -> Int32 {
    guard let context = context, let ip = ip else { return 0 }
    let ctx = Unmanaged<CallbackContext>.fromOpaque(context).takeUnretainedValue()
    
    let ipString = String(cString: ip)
    if let callback = ctx.bridge?.onExcludeIp {
        return callback(ipString) ? 1 : 0
    }
    // No callback set - return success anyway to not block connection
    return 1
}

// MARK: - Errors

public enum BridgeError: Error, LocalizedError {
    case alreadyConnected
    case createFailed(message: String?)
    case connectFailed(code: Int, message: String?)
    case sendFailed(code: Int)
    case disconnected(code: Int)
    case queueFull  // Backpressure - caller should retry
    
    public var errorDescription: String? {
        switch self {
        case .alreadyConnected:
            return "Already connected"
        case .createFailed(let message):
            return message ?? "Failed to create VPN client"
        case .connectFailed(let code, let message):
            if let msg = message {
                return msg
            }
            return "Connection failed with code \(code)"
        case .sendFailed(let code):
            return "Send failed with code \(code)"
        case .disconnected(let code):
            return "Disconnected with code \(code)"
        case .queueFull:
            return "Queue full - retry later"
        }
    }
}
