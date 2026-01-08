// SoftEtherBridge.kt - Kotlin wrapper for Rust FFI
//
// This provides a Kotlin-friendly API over the JNI/C FFI layer.
// Load the native library in your Application class or before use.
//
// Example:
//   System.loadLibrary("softether")

package com.example.softether

import android.net.VpnService
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Kotlin wrapper for SoftEther VPN Rust library.
 */
class SoftEtherBridge {
    
    companion object {
        init {
            System.loadLibrary("softether")
        }
        
        // Result codes (match C enum)
        const val RESULT_OK = 0
        const val RESULT_INVALID_PARAM = -1
        const val RESULT_NOT_CONNECTED = -2
        const val RESULT_CONNECTION_FAILED = -3
        const val RESULT_AUTH_FAILED = -4
        const val RESULT_DHCP_FAILED = -5
        const val RESULT_TIMEOUT = -6
        const val RESULT_IO_ERROR = -7
        const val RESULT_ALREADY_CONNECTED = -8
        const val RESULT_QUEUE_FULL = -9      // Backpressure - caller should retry
        const val RESULT_INTERNAL_ERROR = -99
        
        /**
         * Hash password for SoftEther authentication.
         */
        @JvmStatic
        external fun hashPassword(password: String, username: String): ByteArray?
        
        /**
         * Get library version.
         */
        @JvmStatic
        external fun getVersion(): String
    }
    
    // MARK: - Types
    
    enum class ConnectionState {
        DISCONNECTED,
        CONNECTING,
        HANDSHAKING,
        AUTHENTICATING,
        CONNECTED,
        DISCONNECTING,
        ERROR;
        
        companion object {
            fun fromInt(value: Int): ConnectionState = when (value) {
                0 -> DISCONNECTED
                1 -> CONNECTING
                2 -> HANDSHAKING
                3 -> AUTHENTICATING
                4 -> CONNECTED
                5 -> DISCONNECTING
                else -> ERROR
            }
        }
    }
    
    data class Session(
        val ipAddress: Int,
        val subnetMask: Int,
        val gateway: Int,
        val dns1: Int,
        val dns2: Int,
        val connectedServerIP: String,
        val serverVersion: Int,
        val serverBuild: Int,
        val macAddress: ByteArray = ByteArray(6)
    ) {
        val ipAddressString: String get() = formatIPv4(ipAddress)
        val subnetMaskString: String get() = formatIPv4(subnetMask)
        val gatewayString: String get() = formatIPv4(gateway)
        
        val dnsServers: List<String>
            get() = listOfNotNull(
                if (dns1 != 0) formatIPv4(dns1) else null,
                if (dns2 != 0) formatIPv4(dns2) else null
            )
        
        val macAddressString: String
            get() = macAddress.joinToString(":") { String.format("%02x", it) }
        
        private fun formatIPv4(ip: Int): String {
            return "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"
        }
        
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as Session
            return ipAddress == other.ipAddress && subnetMask == other.subnetMask &&
                   gateway == other.gateway && dns1 == other.dns1 && dns2 == other.dns2 &&
                   connectedServerIP == other.connectedServerIP &&
                   serverVersion == other.serverVersion && serverBuild == other.serverBuild &&
                   macAddress.contentEquals(other.macAddress)
        }
        
        override fun hashCode(): Int {
            var result = ipAddress
            result = 31 * result + subnetMask
            result = 31 * result + gateway
            result = 31 * result + dns1
            result = 31 * result + dns2
            result = 31 * result + connectedServerIP.hashCode()
            result = 31 * result + serverVersion
            result = 31 * result + serverBuild
            result = 31 * result + macAddress.contentHashCode()
            return result
        }
    }
    
    data class Statistics(
        val bytesSent: Long,
        val bytesReceived: Long,
        val packetsSent: Long,
        val packetsReceived: Long,
        val uptimeSeconds: Long,
        val activeConnections: Int,
        val reconnectCount: Int
    )
    
    /**
     * VPN Configuration structured by logical sections.
     *
     * @property server VPN server hostname or IP address
     * @property port Server port (default: 443)
     * @property hub Virtual Hub name
     * @property username Username for authentication
     * @property passwordHash Pre-computed SHA-0 password hash (40 hex chars)
     *
     * ## Server/TLS Settings
     * @property skipTlsVerify Skip TLS certificate verification (default: false)
     * @property customCaPem Custom CA certificate in PEM format
     * @property certFingerprintSha256 Server cert SHA-256 fingerprint for pinning (64 hex chars)
     *
     * ## Connection Settings
     * @property maxConnections Max TCP connections (1-32, default: 1)
     * @property halfConnection Half-duplex mode - each connection is one direction only (default: false)
     *   Requires maxConnections >= 2 to function properly.
     * @property timeoutSeconds Connection timeout in seconds (default: 30)
     * @property mtu MTU size for TUN device (default: 1400)
     *
     * ## Session/Protocol Features
     * @property natTraversal NAT traversal mode (default: false = bridge mode)
     * @property useEncrypt Enable RC4 encryption inside TLS tunnel (default: true)
     *   Note: TLS is ALWAYS used. This controls optional additional RC4 layer for defense in depth.
     * @property useCompress Enable compression (default: false)
     * @property udpAccel Enable UDP acceleration (default: false)
     * @property qos Enable VoIP/QoS prioritization (default: false)
     * @property monitorMode Request monitor mode for packet capture (default: false)
     *
     * ## Routing
     * @property defaultRoute Route all traffic through VPN (default: true)
     * @property acceptPushedRoutes Accept DHCP-pushed routes (default: true)
     * @property ipv4Include IPv4 networks to route through VPN (comma-separated CIDRs)
     * @property ipv4Exclude IPv4 networks to exclude from VPN (comma-separated CIDRs)
     * @property ipv6Include IPv6 networks to route through VPN (comma-separated CIDRs)
     * @property ipv6Exclude IPv6 networks to exclude from VPN (comma-separated CIDRs)
     *
     * ## Static IP Configuration (optional, skips DHCP if set)
     */
    data class Configuration(
        // === Server ===
        val server: String,
        val port: Int = 443,
        val hub: String,
        val skipTlsVerify: Boolean = false,
        val customCaPem: String? = null,
        val certFingerprintSha256: String? = null,

        // === Authentication ===
        val username: String,
        val passwordHash: String,

        // === Connection ===
        val maxConnections: Int = 1,
        val halfConnection: Boolean = false,
        val timeoutSeconds: Int = 30,
        val mtu: Int = 1400,

        // === Session ===
        val natTraversal: Boolean = false,
        val useEncrypt: Boolean = true,
        val useCompress: Boolean = false,
        val udpAccel: Boolean = false,

        // === Options ===
        val qos: Boolean = false,
        val monitorMode: Boolean = false,

        // === Routing ===
        val defaultRoute: Boolean = true,
        val acceptPushedRoutes: Boolean = true,
        val ipv4Include: String? = null,
        val ipv4Exclude: String? = null,
        val ipv6Include: String? = null,
        val ipv6Exclude: String? = null,

        // === Static IPv4 Configuration ===
        val staticIpv4Address: String? = null,
        val staticIpv4Netmask: String? = null,
        val staticIpv4Gateway: String? = null,
        val staticIpv4Dns1: String? = null,
        val staticIpv4Dns2: String? = null,

        // === Static IPv6 Configuration ===
        val staticIpv6Address: String? = null,
        val staticIpv6PrefixLen: Int = 0,
        val staticIpv6Gateway: String? = null,
        val staticIpv6Dns1: String? = null,
        val staticIpv6Dns2: String? = null
    )
    
    // MARK: - Callbacks
    
    enum class LogLevel(val value: Int) {
        ERROR(0), WARN(1), INFO(2), DEBUG(3), TRACE(4);
        
        companion object {
            fun fromInt(value: Int): LogLevel = values().find { it.value == value } ?: INFO
        }
    }
    
    interface Listener {
        fun onStateChanged(state: ConnectionState)
        fun onConnected(session: Session)
        fun onDisconnected(error: Throwable?)
        fun onPacketsReceived(packets: List<ByteArray>)
        fun onLog(level: LogLevel, message: String) {}
        fun onProtectSocket(fd: Int): Boolean = false
        /** Called when an IP should be excluded from VPN routing (cluster redirect). */
        fun onExcludeIp(ip: String): Boolean = false
    }
    
    var listener: Listener? = null
    
    // MARK: - Native Handle
    
    private var nativeHandle: Long = 0
    
    // MARK: - Native Methods
    
    private external fun nativeCreate(
        // === Server ===
        server: String,
        port: Int,
        hub: String,
        skipTlsVerify: Boolean,
        customCaPem: String?,
        certFingerprintSha256: String?,
        // === Authentication ===
        username: String,
        passwordHash: String,
        // === Connection ===
        maxConnections: Int,
        halfConnection: Boolean,
        timeoutSeconds: Int,
        mtu: Int,
        // === Session ===
        natTraversal: Boolean,
        useEncrypt: Boolean,
        useCompress: Boolean,
        udpAccel: Boolean,
        // === Options ===
        qos: Boolean,
        monitorMode: Boolean,
        // === Routing ===
        defaultRoute: Boolean,
        acceptPushedRoutes: Boolean,
        ipv4Include: String?,
        ipv4Exclude: String?,
        ipv6Include: String?,
        ipv6Exclude: String?,
        // === Static IPv4 Configuration ===
        staticIpv4Address: String?,
        staticIpv4Netmask: String?,
        staticIpv4Gateway: String?,
        staticIpv4Dns1: String?,
        staticIpv4Dns2: String?,
        // === Static IPv6 Configuration ===
        staticIpv6Address: String?,
        staticIpv6PrefixLen: Int,
        staticIpv6Gateway: String?,
        staticIpv6Dns1: String?,
        staticIpv6Dns2: String?
    ): Long
    
    private external fun nativeDestroy(handle: Long)
    private external fun nativeConnect(handle: Long): Int
    private external fun nativeDisconnect(handle: Long): Int
    private external fun nativeGetState(handle: Long): Int
    private external fun nativeGetSession(handle: Long): LongArray?
    private external fun nativeGetSessionServerIP(handle: Long): String?
    private external fun nativeGetSessionMAC(handle: Long): ByteArray?
    private external fun nativeGetStats(handle: Long): LongArray?
    private external fun nativeSendPackets(handle: Long, data: ByteArray, count: Int): Int
    private external fun nativeReceivePackets(handle: Long, buffer: ByteArray): Int
    
    // MARK: - Public API
    
    /**
     * Create and connect to VPN server.
     */
    fun connect(config: Configuration) {
        if (nativeHandle != 0L) {
            throw IllegalStateException("Already connected")
        }
        
        nativeHandle = nativeCreate(
            // Server
            config.server,
            config.port,
            config.hub,
            config.skipTlsVerify,
            config.customCaPem,
            config.certFingerprintSha256,
            // Authentication
            config.username,
            config.passwordHash,
            // Connection
            config.maxConnections,
            config.halfConnection,
            config.timeoutSeconds,
            config.mtu,
            // Session
            config.natTraversal,
            config.useEncrypt,
            config.useCompress,
            config.udpAccel,
            // Options
            config.qos,
            config.monitorMode,
            // Routing
            config.defaultRoute,
            config.acceptPushedRoutes,
            config.ipv4Include,
            config.ipv4Exclude,
            config.ipv6Include,
            config.ipv6Exclude,
            // Static IPv4
            config.staticIpv4Address,
            config.staticIpv4Netmask,
            config.staticIpv4Gateway,
            config.staticIpv4Dns1,
            config.staticIpv4Dns2,
            // Static IPv6
            config.staticIpv6Address,
            config.staticIpv6PrefixLen,
            config.staticIpv6Gateway,
            config.staticIpv6Dns1,
            config.staticIpv6Dns2
        )
        
        if (nativeHandle == 0L) {
            throw RuntimeException("Failed to create client")
        }
        
        val result = nativeConnect(nativeHandle)
        if (result != RESULT_OK) {
            nativeDestroy(nativeHandle)
            nativeHandle = 0
            throw RuntimeException("Connection failed: $result")
        }
    }
    
    /**
     * Disconnect from VPN server.
     */
    fun disconnect() {
        if (nativeHandle != 0L) {
            nativeDisconnect(nativeHandle)
            nativeDestroy(nativeHandle)
            nativeHandle = 0
        }
    }
    
    /**
     * Get current connection state.
     */
    val state: ConnectionState
        get() = if (nativeHandle == 0L) {
            ConnectionState.DISCONNECTED
        } else {
            ConnectionState.fromInt(nativeGetState(nativeHandle))
        }
    
    /**
     * Get session information (only valid when connected).
     */
    val session: Session?
        get() {
            if (nativeHandle == 0L) return null
            val data = nativeGetSession(nativeHandle) ?: return null
            if (data.size < 7) return null
            
            val macAddress = nativeGetSessionMAC(nativeHandle) ?: ByteArray(6)
            
            return Session(
                ipAddress = data[0].toInt(),
                subnetMask = data[1].toInt(),
                gateway = data[2].toInt(),
                dns1 = data[3].toInt(),
                dns2 = data[4].toInt(),
                connectedServerIP = nativeGetSessionServerIP(nativeHandle) ?: "",
                serverVersion = data[5].toInt(),
                serverBuild = data[6].toInt(),
                macAddress = macAddress
            )
        }
    
    /**
     * Get connection statistics.
     */
    val statistics: Statistics
        get() {
            val data = if (nativeHandle != 0L) nativeGetStats(nativeHandle) else null
            return if (data != null && data.size >= 7) {
                Statistics(
                    bytesSent = data[0],
                    bytesReceived = data[1],
                    packetsSent = data[2],
                    packetsReceived = data[3],
                    uptimeSeconds = data[4],
                    activeConnections = data[5].toInt(),
                    reconnectCount = data[6].toInt()
                )
            } else {
                Statistics(0, 0, 0, 0, 0, 0, 0)
            }
        }
    
    /**
     * Send packets to VPN server.
     * Each packet should be a complete Ethernet frame (L2).
     * @throws QueueFullException if backpressure is detected - caller should retry.
     */
    fun sendPackets(packets: List<ByteArray>) {
        if (nativeHandle == 0L || packets.isEmpty()) return
        
        // Calculate total size: [len:u16][data] for each packet
        var totalSize = 0
        for (packet in packets) {
            totalSize += 2 + packet.size
        }
        
        // Build buffer
        val buffer = ByteBuffer.allocate(totalSize)
        buffer.order(ByteOrder.BIG_ENDIAN)
        
        for (packet in packets) {
            buffer.putShort(packet.size.toShort())
            buffer.put(packet)
        }
        
        val result = nativeSendPackets(nativeHandle, buffer.array(), packets.size)
        if (result == RESULT_QUEUE_FULL) {
            throw QueueFullException("Queue full - backpressure, retry later")
        } else if (result < 0) {
            throw RuntimeException("Send failed: $result")
        }
    }
    
    /** Exception thrown when the packet queue is full (backpressure). */
    class QueueFullException(message: String) : Exception(message)
    
    /**
     * Receive packets from VPN server.
     * Non-blocking. For best performance, use the listener callback.
     */
    fun receivePackets(): List<ByteArray> {
        if (nativeHandle == 0L) return emptyList()
        
        val buffer = ByteArray(65536)
        val bytesReceived = nativeReceivePackets(nativeHandle, buffer)
        
        if (bytesReceived <= 0) return emptyList()
        
        // Parse packets from buffer
        val packets = mutableListOf<ByteArray>()
        val bb = ByteBuffer.wrap(buffer, 0, bytesReceived)
        bb.order(ByteOrder.BIG_ENDIAN)
        
        while (bb.remaining() >= 2) {
            val len = bb.short.toInt() and 0xFFFF
            if (bb.remaining() < len) break
            
            val packet = ByteArray(len)
            bb.get(packet)
            packets.add(packet)
        }
        
        return packets
    }
    
    // MARK: - Callbacks from Native
    
    @Suppress("unused")  // Called from JNI
    private fun onNativeStateChanged(state: Int) {
        listener?.onStateChanged(ConnectionState.fromInt(state))
    }
    
    @Suppress("unused")  // Called from JNI
    private fun onNativeConnected(
        ipAddress: Int,
        subnetMask: Int,
        gateway: Int,
        dns1: Int,
        dns2: Int,
        connectedServerIP: String,
        serverVersion: Int,
        serverBuild: Int,
        macAddress: ByteArray
    ) {
        listener?.onConnected(Session(
            ipAddress, subnetMask, gateway, dns1, dns2,
            connectedServerIP, serverVersion, serverBuild, macAddress
        ))
    }
    
    @Suppress("unused")  // Called from JNI
    private fun onNativeDisconnected(errorCode: Int) {
        val error = if (errorCode == RESULT_OK) null else RuntimeException("Disconnected: $errorCode")
        listener?.onDisconnected(error)
    }
    
    @Suppress("unused")  // Called from JNI
    private fun onNativePacketsReceived(data: ByteArray, count: Int) {
        if (count == 0) return
        
        // Parse packets
        val packets = mutableListOf<ByteArray>()
        val bb = ByteBuffer.wrap(data)
        bb.order(ByteOrder.BIG_ENDIAN)
        
        repeat(count) {
            if (bb.remaining() < 2) return@repeat
            val len = bb.short.toInt() and 0xFFFF
            if (bb.remaining() < len) return@repeat
            
            val packet = ByteArray(len)
            bb.get(packet)
            packets.add(packet)
        }
        
        listener?.onPacketsReceived(packets)
    }
    
    @Suppress("unused")  // Called from JNI
    private fun onNativeLog(level: Int, message: String) {
        listener?.onLog(LogLevel.fromInt(level), message)
    }
    
    @Suppress("unused")  // Called from JNI
    private fun onProtectSocket(fd: Int): Boolean {
        return listener?.onProtectSocket(fd) ?: false
    }
    
    @Suppress("unused")  // Called from JNI
    private fun onExcludeIp(ip: String): Boolean {
        return listener?.onExcludeIp(ip) ?: false
    }
    
    // MARK: - Cleanup
    
    protected fun finalize() {
        disconnect()
    }
}
