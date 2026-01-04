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
    
    data class Configuration(
        val server: String,
        val port: Int = 443,
        val hub: String,
        val username: String,
        val passwordHash: String,
        // TLS Settings
        val skipTlsVerify: Boolean = false,
        // Connection Settings
        val maxConnections: Int = 1,
        val timeoutSeconds: Int = 30,
        val mtu: Int = 1400,
        // Protocol Features
        val useEncrypt: Boolean = true,
        val useCompress: Boolean = false,
        val udpAccel: Boolean = false,
        val qos: Boolean = false,
        // Session Mode
        val natTraversal: Boolean = true,
        val monitorMode: Boolean = false,
        // Routing
        val defaultRoute: Boolean = true,
        val acceptPushedRoutes: Boolean = true,
        val ipv4Include: String? = null,
        val ipv4Exclude: String? = null
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
    }
    
    var listener: Listener? = null
    
    // MARK: - Native Handle
    
    private var nativeHandle: Long = 0
    
    // MARK: - Native Methods
    
    private external fun nativeCreate(
        server: String,
        port: Int,
        hub: String,
        username: String,
        passwordHash: String,
        // TLS Settings
        skipTlsVerify: Boolean,
        // Connection Settings
        maxConnections: Int,
        timeoutSeconds: Int,
        mtu: Int,
        // Protocol Features
        useEncrypt: Boolean,
        useCompress: Boolean,
        udpAccel: Boolean,
        qos: Boolean,
        // Session Mode
        natTraversal: Boolean,
        monitorMode: Boolean,
        // Routing
        defaultRoute: Boolean,
        acceptPushedRoutes: Boolean,
        ipv4Include: String?,
        ipv4Exclude: String?
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
            config.server,
            config.port,
            config.hub,
            config.username,
            config.passwordHash,
            config.skipTlsVerify,
            config.maxConnections,
            config.timeoutSeconds,
            config.mtu,
            config.useEncrypt,
            config.useCompress,
            config.udpAccel,
            config.qos,
            config.natTraversal,
            config.monitorMode,
            config.defaultRoute,
            config.acceptPushedRoutes,
            config.ipv4Include,
            config.ipv4Exclude
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
        if (result < 0) {
            throw RuntimeException("Send failed: $result")
        }
    }
    
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
    
    // MARK: - Cleanup
    
    protected fun finalize() {
        disconnect()
    }
}
