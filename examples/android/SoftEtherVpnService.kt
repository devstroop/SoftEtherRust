// Example: Using SoftEtherBridge in a VpnService (Android)
//
// This shows how to integrate the Rust-based SoftEther client
// with Android VpnService.

package com.example.softether

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

class SoftEtherVpnService : VpnService(), SoftEtherBridge.Listener {
    
    companion object {
        private const val TAG = "SoftEtherVpnService"
        private const val NOTIFICATION_CHANNEL_ID = "vpn_channel"
        private const val NOTIFICATION_ID = 1
        
        const val ACTION_CONNECT = "com.example.softether.CONNECT"
        const val ACTION_DISCONNECT = "com.example.softether.DISCONNECT"
        
        const val EXTRA_SERVER = "server"
        const val EXTRA_PORT = "port"
        const val EXTRA_HUB = "hub"
        const val EXTRA_USERNAME = "username"
        const val EXTRA_PASSWORD_HASH = "password_hash"
    }
    
    private var bridge: SoftEtherBridge? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private var inputStream: FileInputStream? = null
    private var outputStream: FileOutputStream? = null
    
    private val isRunning = AtomicBoolean(false)
    private var readerThread: Thread? = null
    
    // IPs to exclude from VPN routing (cluster redirects)
    private val excludedIps = mutableSetOf<String>()
    
    // Gateway MAC for outbound frames (learned from ARP or broadcast)
    private var gatewayMAC = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
    // Source MAC from session (set on connection)
    private var srcMAC = byteArrayOf(0x5E, 0x00, 0x00, 0x00, 0x00, 0x01)
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val config = SoftEtherBridge.Configuration(
                    server = intent.getStringExtra(EXTRA_SERVER) ?: return START_NOT_STICKY,
                    port = intent.getIntExtra(EXTRA_PORT, 443),
                    hub = intent.getStringExtra(EXTRA_HUB) ?: "VPN",
                    username = intent.getStringExtra(EXTRA_USERNAME) ?: return START_NOT_STICKY,
                    passwordHash = intent.getStringExtra(EXTRA_PASSWORD_HASH) ?: return START_NOT_STICKY
                )
                connect(config)
            }
            ACTION_DISCONNECT -> {
                disconnect()
            }
        }
        return START_STICKY
    }
    
    private fun connect(config: SoftEtherBridge.Configuration) {
        Log.i(TAG, "Connecting to ${config.server}:${config.port}")
        
        // Create foreground notification
        startForeground(NOTIFICATION_ID, createNotification("Connecting..."))
        
        // Create bridge
        val vpnBridge = SoftEtherBridge()
        vpnBridge.listener = this
        bridge = vpnBridge
        
        try {
            vpnBridge.connect(config)
        } catch (e: Exception) {
            Log.e(TAG, "Connect failed: ${e.message}")
            stopSelf()
        }
    }
    
    private fun disconnect() {
        Log.i(TAG, "Disconnecting")
        
        isRunning.set(false)
        readerThread?.interrupt()
        readerThread = null
        
        try {
            inputStream?.close()
            outputStream?.close()
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing VPN interface: ${e.message}")
        }
        
        inputStream = null
        outputStream = null
        vpnInterface = null
        
        bridge?.disconnect()
        bridge = null
        
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }
    
    // MARK: - Tunnel Configuration
    
    private fun configureTunnel(session: SoftEtherBridge.Session) {
        Log.i(TAG, "Configuring tunnel: IP=${session.ipAddressString}")
        
        val builder = Builder()
            .setSession("SoftEther VPN")
            .setMtu(1400)
            .addAddress(session.ipAddressString, 16) // /16 subnet
        
        // Add VPN server IP to exclusion list
        if (session.connectedServerIP.isNotEmpty()) {
            excludedIps.add(session.connectedServerIP)
        }
        
        // Exclude VPN server and cluster IPs from VPN routing
        // By adding /32 routes that go through the underlying network
        for (excludedIp in excludedIps) {
            try {
                // Note: On Android, we protect the socket AND ensure the server IP is routed
                // outside the VPN. The protect() call on the socket is the primary mechanism,
                // but we log excluded IPs for debugging.
                Log.d(TAG, "Excluding IP from VPN: $excludedIp")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to process excluded IP $excludedIp: ${e.message}")
            }
        }
        
        // Routes (full tunnel using split routes to avoid default gateway issues)
        builder.addRoute("0.0.0.0", 1)
        builder.addRoute("128.0.0.0", 1)
        
        // DNS
        for (dns in session.dnsServers) {
            builder.addDnsServer(dns)
        }
        if (session.dnsServers.isEmpty()) {
            builder.addDnsServer("8.8.8.8")
            builder.addDnsServer("8.8.4.4")
        }
        
        vpnInterface = builder.establish()
        
        if (vpnInterface == null) {
            Log.e(TAG, "Failed to establish VPN interface")
            disconnect()
            return
        }
        
        inputStream = FileInputStream(vpnInterface!!.fileDescriptor)
        outputStream = FileOutputStream(vpnInterface!!.fileDescriptor)
        
        // Start packet reading
        isRunning.set(true)
        startPacketReader()
        
        // Update notification
        updateNotification("Connected: ${session.ipAddressString}")
    }
    
    // MARK: - Packet Handling
    
    private fun startPacketReader() {
        readerThread = Thread {
            val buffer = ByteBuffer.allocate(2048)
            
            while (isRunning.get()) {
                try {
                    buffer.clear()
                    val length = inputStream?.channel?.read(buffer) ?: -1
                    
                    if (length > 0) {
                        buffer.flip()
                        val packet = ByteArray(length)
                        buffer.get(packet)
                        
                        // Convert L3 to L2 and send
                        sendPacketToServer(packet)
                    } else if (length < 0) {
                        break
                    }
                } catch (e: InterruptedException) {
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Packet read error: ${e.message}")
                    break
                }
            }
            
            Log.d(TAG, "Packet reader stopped")
        }
        readerThread?.start()
    }
    
    private fun sendPacketToServer(ipPacket: ByteArray) {
        // Build Ethernet frame
        val frame = ByteArray(14 + ipPacket.size)
        System.arraycopy(gatewayMAC, 0, frame, 0, 6)  // Dest MAC
        System.arraycopy(srcMAC, 0, frame, 6, 6)       // Src MAC
        frame[12] = 0x08  // EtherType IPv4
        frame[13] = 0x00
        System.arraycopy(ipPacket, 0, frame, 14, ipPacket.size)
        
        try {
            bridge?.sendPackets(listOf(frame))
        } catch (e: Exception) {
            Log.w(TAG, "Send failed: ${e.message}")
        }
    }
    
    private fun handleReceivedPackets(frames: List<ByteArray>) {
        val output = outputStream ?: return
        
        for (frame in frames) {
            // Check Ethernet frame validity
            if (frame.size <= 14) continue
            
            val etherType = ((frame[12].toInt() and 0xFF) shl 8) or (frame[13].toInt() and 0xFF)
            if (etherType != 0x0800) continue  // IPv4 only
            
            // Extract IP packet
            val ipPacket = frame.copyOfRange(14, frame.size)
            
            try {
                output.write(ipPacket)
            } catch (e: Exception) {
                Log.w(TAG, "Write failed: ${e.message}")
            }
        }
    }
    
    // MARK: - SoftEtherBridge.Listener
    
    override fun onStateChanged(state: SoftEtherBridge.ConnectionState) {
        Log.d(TAG, "State changed: $state")
    }
    
    override fun onConnected(session: SoftEtherBridge.Session) {
        Log.i(TAG, "Connected! IP=${session.ipAddressString}, MAC=${session.macAddressString}")
        // Use session MAC address for outbound frames
        srcMAC = session.macAddress
        configureTunnel(session)
    }
    
    override fun onDisconnected(error: Throwable?) {
        Log.i(TAG, "Disconnected: ${error?.message ?: "clean"}")
        disconnect()
    }
    
    override fun onPacketsReceived(packets: List<ByteArray>) {
        handleReceivedPackets(packets)
    }
    
    override fun onProtectSocket(fd: Int): Boolean {
        // Protect the socket from VPN routing to prevent loops
        return protect(fd)
    }
    
    override fun onExcludeIp(ip: String): Boolean {
        // Add IP to exclusion list for cluster redirect scenarios
        Log.d(TAG, "Excluding IP from VPN routing: $ip")
        excludedIps.add(ip)
        return true
    }
    
    // MARK: - Notifications
    
    private fun createNotification(text: String): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "VPN Status",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
        
        return Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("SoftEther VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .build()
    }
    
    private fun updateNotification(text: String) {
        val notification = createNotification(text)
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, notification)
    }
    
    override fun onDestroy() {
        disconnect()
        super.onDestroy()
    }
}
