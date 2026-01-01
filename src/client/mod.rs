//! SoftEther VPN client implementation.

mod concurrent_reader;
mod connection;
mod multi_connection;
mod state;

pub use concurrent_reader::{ConcurrentReader, ReceivedPacket};
pub use connection::VpnConnection;
pub use multi_connection::{ConnectionManager, ConnectionStats, ManagedConnection, TcpDirection};
pub use state::VpnState;

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::adapter::TunAdapter;
use crate::config::VpnConfig;
use crate::error::{Error, Result};
use crate::net::{UdpAccel, UdpAccelAuthParams};
use crate::packet::{DhcpConfig, EtherType};
use crate::protocol::{
    AuthPack, AuthResult, AuthType, ConnectionOptions, HelloResponse, HttpCodec, HttpRequest, Pack,
    RedirectInfo, TunnelCodec, CONTENT_TYPE_PACK, CONTENT_TYPE_SIGNATURE, SIGNATURE_TARGET,
    VPN_SIGNATURE, VPN_TARGET,
};
use crate::tunnel::{RouteConfig, TunnelConfig, TunnelRunner};

/// VPN client statistics.
#[derive(Debug, Clone, Default)]
pub struct VpnStats {
    /// Bytes sent through the tunnel.
    pub bytes_sent: u64,
    /// Bytes received from the tunnel.
    pub bytes_received: u64,
    /// Packets sent.
    pub packets_sent: u64,
    /// Packets received.
    pub packets_received: u64,
    /// Connection start time.
    pub connected_at: Option<Instant>,
}

/// SoftEther VPN client.
pub struct VpnClient {
    config: VpnConfig,
    state: VpnState,
    stats: Arc<VpnStats>,
    running: Arc<AtomicBool>,
    /// UDP acceleration instance (if enabled).
    udp_accel: Option<UdpAccel>,
}

impl VpnClient {
    /// Create a new VPN client with the given configuration.
    pub fn new(config: VpnConfig) -> Self {
        Self {
            config,
            state: VpnState::Disconnected,
            stats: Arc::new(VpnStats::default()),
            running: Arc::new(AtomicBool::new(false)),
            udp_accel: None,
        }
    }

    /// Get the current connection state.
    pub fn state(&self) -> &VpnState {
        &self.state
    }

    /// Get connection statistics.
    pub fn stats(&self) -> &VpnStats {
        &self.stats
    }

    /// Check if the client is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Connect to the VPN server and run the tunnel.
    pub async fn connect(&mut self) -> Result<()> {
        self.state = VpnState::Connecting;
        self.running.store(true, Ordering::SeqCst);

        // Log multi-connection configuration
        if self.config.max_connections > 1 {
            debug!(
                max_connections = self.config.max_connections,
                "Multi-connection mode enabled"
            );
        }

        info!(server = %self.config.server, port = self.config.port, hub = %self.config.hub,
            "Connecting to VPN server");

        // Resolve initial server IP for routing
        let initial_server_ip = self.resolve_server_ip(&self.config.server)?;

        // Establish connection
        let mut conn = VpnConnection::connect(&self.config).await?;
        debug!("TCP connection established");

        // Initialize UDP acceleration if enabled
        if self.config.udp_accel {
            // No NAT-T needed if we know the server UDP port (not implemented yet)
            let no_nat_t = false;
            match UdpAccel::new(None, true, no_nat_t) {
                Ok(accel) => {
                    debug!(port = accel.my_port, "UDP acceleration initialized");
                    self.udp_accel = Some(accel);
                }
                Err(e) => {
                    warn!(
                        "Failed to initialize UDP acceleration: {}. Continuing without UDP accel.",
                        e
                    );
                    self.udp_accel = None;
                }
            }
        }

        // Perform HTTP handshake
        self.state = VpnState::Handshaking;
        let hello = self.perform_handshake(&mut conn).await?;
        debug!(
            version = hello.server_version,
            build = hello.server_build,
            server = %hello.server_string,
            "Server hello received"
        );

        // Authenticate (with UDP accel params if available)
        self.state = VpnState::Authenticating;
        let mut auth_result = self.authenticate(&mut conn, &hello).await?;
        info!("Authenticated successfully");

        // Track the actual connection to use and server IP
        let mut active_conn = conn;
        let mut actual_server_ip = initial_server_ip;
        // Track the actual server address and port (may change after redirect)
        let mut actual_server_addr = self.config.server.clone();
        let mut actual_server_port = self.config.port;

        // Handle cluster redirect if needed
        if let Some(redirect) = auth_result.redirect.take() {
            let redirect_server = redirect.ip_string();
            let redirect_port = redirect.port;
            debug!(server = %redirect_server, port = redirect_port, "Cluster redirect");

            // Update actual server IP to redirect server
            if let Ok(ip) = redirect_server.parse::<Ipv4Addr>() {
                actual_server_ip = ip;
            }
            // Update actual server address and port for additional connections
            actual_server_addr = redirect_server.clone();
            actual_server_port = redirect_port;

            // Send empty Pack acknowledgment
            let ack_pack = Pack::new();
            let request = HttpRequest::post(VPN_TARGET)
                .header("Content-Type", CONTENT_TYPE_PACK)
                .header("Connection", "Keep-Alive")
                .body(ack_pack.to_bytes());

            let host = format!("{}:{}", self.config.server, self.config.port);
            let request_bytes = request.build(&host);
            active_conn.write_all(&request_bytes).await?;

            // Small delay before closing
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Close current connection
            drop(active_conn);

            // Connect to redirect server with ticket auth
            let (redirect_conn, redirect_result) = self.connect_redirect(&hello, &redirect).await?;
            auth_result = redirect_result;
            active_conn = redirect_conn;
        }

        // Check for session key
        if auth_result.session_key.is_empty() {
            return Err(Error::AuthenticationFailed(
                "No session key received".into(),
            ));
        }

        debug!(
            key_len = auth_result.session_key.len(),
            "Session key received"
        );

        // Create ConnectionManager for multi-connection support
        // Pass the actual server address (after redirect) for additional connections
        let mut conn_mgr = ConnectionManager::new(
            active_conn,
            &self.config,
            &auth_result,
            &actual_server_addr,
            actual_server_port,
        );

        // Start tunnel
        self.state = VpnState::EstablishingTunnel;
        info!("VPN session established");

        // Run the tunnel data loop
        self.state = VpnState::Connected;

        // Build routes from config
        let routes: Vec<RouteConfig> =
            crate::config::RoutingConfig::parse_ipv4_cidrs(&self.config.routing.ipv4_include)
                .into_iter()
                .map(|(dest, prefix_len)| RouteConfig { dest, prefix_len })
                .collect();

        let tunnel_config = TunnelConfig {
            keepalive_interval: 5,
            dhcp_timeout: 30,
            mtu: self.config.mtu,
            default_route: self.config.routing.default_route,
            routes,
            use_compress: self.config.use_compress,
            vpn_server_ip: Some(actual_server_ip),
        };

        let mut runner = TunnelRunner::new(tunnel_config);

        // Set up Ctrl+C handler
        let running = runner.running();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            debug!("Shutdown signal received");
            running.store(false, Ordering::SeqCst);
        });

        // Run the tunnel with multi-connection support
        match runner.run_multi(&mut conn_mgr).await {
            Ok(()) => {
                debug!("Tunnel stopped cleanly");
                let stats = conn_mgr.stats();
                info!(
                    "Connection stats: {} connections, {} bytes sent, {} bytes received",
                    stats.total_connections, stats.total_bytes_sent, stats.total_bytes_received
                );
            }
            Err(e) => {
                error!("Tunnel error: {}", e);
                return Err(e);
            }
        }

        Ok(())
    }

    /// Connect to redirect server and return connection + auth result.
    async fn connect_redirect(
        &self,
        _hello: &HelloResponse,
        redirect: &RedirectInfo,
    ) -> Result<(VpnConnection, AuthResult)> {
        // Create a modified config for the redirect server
        let redirect_server = redirect.ip_string();
        let redirect_port = redirect.port;

        debug!(server = %redirect_server, port = redirect_port, "Connecting to cluster server");

        let mut redirect_config = self.config.clone();
        redirect_config.server = redirect_server.clone();
        redirect_config.port = redirect_port;

        // Connect to redirect server
        let mut conn = VpnConnection::connect(&redirect_config).await?;

        // Perform handshake
        let redirect_hello = self.perform_handshake(&mut conn).await?;
        debug!("Redirect server hello: {:?}", redirect_hello);

        // Build connection options from config
        // Multi-connection support: use actual max_connections value
        let options = ConnectionOptions {
            max_connections: self.config.max_connections,
            use_encrypt: self.config.use_encrypt,
            use_compress: self.config.use_compress,
            udp_accel: self.config.udp_accel,
            bridge_mode: !self.config.nat_traversal,
            monitor_mode: self.config.monitor_mode,
            qos: self.config.qos,
        };

        // Build UDP acceleration params if we have an active UDP accel instance
        let udp_accel_params = self
            .udp_accel
            .as_ref()
            .map(UdpAccelAuthParams::from_udp_accel);

        // Authenticate with ticket
        let auth_pack = AuthPack::new_ticket(
            &self.config.hub,
            &self.config.username,
            &redirect_hello.random,
            &redirect.ticket,
            &options,
            udp_accel_params.as_ref(),
        );

        let request = HttpRequest::post(VPN_TARGET)
            .header("Content-Type", CONTENT_TYPE_PACK)
            .header("Connection", "Keep-Alive")
            .body(auth_pack.to_bytes());

        let host = format!("{}:{}", redirect_server, redirect_port);
        let request_bytes = request.build(&host);

        debug!("Sending ticket authentication");
        conn.write_all(&request_bytes).await?;

        // Read response
        let mut codec = HttpCodec::new();
        let mut buf = vec![0u8; 8192];

        loop {
            let n = conn.read(&mut buf).await?;
            if n == 0 {
                return Err(Error::ConnectionFailed(
                    "Connection closed during redirect authentication".into(),
                ));
            }

            if let Some(response) = codec.feed(&buf[..n])? {
                if response.status_code != 200 {
                    return Err(Error::AuthenticationFailed(format!(
                        "Redirect server returned status {}",
                        response.status_code
                    )));
                }

                if !response.body.is_empty() {
                    let pack = Pack::deserialize(&response.body)?;
                    debug!(
                        "Redirect auth response keys: {:?}",
                        pack.keys().collect::<Vec<_>>()
                    );

                    let result = AuthResult::from_pack(&pack)?;

                    if result.error > 0 {
                        return Err(Error::AuthenticationFailed(format!(
                            "Redirect authentication error code: {}",
                            result.error
                        )));
                    }

                    return Ok((conn, result));
                } else {
                    return Err(Error::ServerError(
                        "Empty redirect authentication response".into(),
                    ));
                }
            }
        }
    }

    /// Perform HTTP handshake with the server.
    ///
    /// Phase 1: Send "VPNCONNECT" signature to /vpnsvc/connect.cgi
    /// The server responds with a Hello Pack containing server random.
    async fn perform_handshake(&self, conn: &mut VpnConnection) -> Result<HelloResponse> {
        // Build HTTP POST request for signature
        let request = HttpRequest::post(SIGNATURE_TARGET)
            .header("Content-Type", CONTENT_TYPE_SIGNATURE)
            .header("Connection", "Keep-Alive")
            .body(VPN_SIGNATURE);

        let host = format!("{}:{}", self.config.server, self.config.port);
        let request_bytes = request.build(&host);

        debug!("Sending signature to {}", SIGNATURE_TARGET);
        conn.write_all(&request_bytes).await?;
        debug!("Sent signature ({} bytes)", VPN_SIGNATURE.len());

        // Read response
        let mut codec = HttpCodec::new();
        let mut buf = vec![0u8; 4096];

        loop {
            let n = conn.read(&mut buf).await?;
            if n == 0 {
                return Err(Error::ConnectionFailed(
                    "Connection closed during handshake".into(),
                ));
            }
            debug!("Received {} bytes", n);

            if let Some(response) = codec.feed(&buf[..n])? {
                debug!("HTTP response: status={}", response.status_code);

                if response.status_code != 200 {
                    return Err(Error::ServerError(format!(
                        "Server returned status {}",
                        response.status_code
                    )));
                }

                // Parse the Pack from response body
                if !response.body.is_empty() {
                    debug!("Response body: {} bytes", response.body.len());
                    let pack = Pack::deserialize(&response.body)?;
                    let hello = HelloResponse::from_pack(&pack)?;
                    return Ok(hello);
                } else {
                    return Err(Error::ServerError("Empty response body".into()));
                }
            }
        }
    }

    /// Authenticate with the server.
    ///
    /// Phase 2: Send auth Pack to /vpnsvc/vpn.cgi
    async fn authenticate(
        &self,
        conn: &mut VpnConnection,
        hello: &HelloResponse,
    ) -> Result<AuthResult> {
        // Determine authentication type
        let auth_type = if hello.use_secure_password {
            AuthType::SecurePassword
        } else {
            AuthType::Password
        };

        info!("Using authentication type: {:?}", auth_type);

        // Build connection options from config
        // Multi-connection support: use actual max_connections value
        // With max_connections > 1, the server uses half-connection mode
        let options = ConnectionOptions {
            max_connections: self.config.max_connections,
            use_encrypt: self.config.use_encrypt,
            use_compress: self.config.use_compress,
            udp_accel: self.config.udp_accel,
            bridge_mode: !self.config.nat_traversal,
            monitor_mode: self.config.monitor_mode,
            qos: self.config.qos,
        };

        // Build UDP acceleration params if we have an active UDP accel instance
        let udp_accel_params = self
            .udp_accel
            .as_ref()
            .map(UdpAccelAuthParams::from_udp_accel);

        // Decode password hash from hex string
        let password_hash_vec = hex::decode(&self.config.password_hash)
            .map_err(|e| Error::Config(format!("Invalid password_hash hex: {}", e)))?;
        if password_hash_vec.len() != 20 {
            return Err(Error::Config(format!(
                "password_hash must be 20 bytes (40 hex chars), got {} bytes",
                password_hash_vec.len()
            )));
        }
        let password_hash_bytes: [u8; 20] = password_hash_vec.try_into().unwrap();

        // Build authentication pack with decoded hash
        let auth_pack = AuthPack::new(
            &self.config.hub,
            &self.config.username,
            &password_hash_bytes,
            auth_type,
            &hello.random,
            &options,
            udp_accel_params.as_ref(),
        );

        // Build HTTP request with auth data - use VPN_TARGET and CONTENT_TYPE_PACK
        let request = HttpRequest::post(VPN_TARGET)
            .header("Content-Type", CONTENT_TYPE_PACK)
            .header("Connection", "Keep-Alive")
            .body(auth_pack.to_bytes());

        let host = format!("{}:{}", self.config.server, self.config.port);
        let request_bytes = request.build(&host);

        debug!("Sending authentication to {}", VPN_TARGET);
        conn.write_all(&request_bytes).await?;
        debug!(
            "Sent authentication request ({} bytes)",
            auth_pack.to_bytes().len()
        );

        // Read response
        let mut codec = HttpCodec::new();
        let mut buf = vec![0u8; 8192];

        loop {
            let n = conn.read(&mut buf).await?;
            if n == 0 {
                return Err(Error::ConnectionFailed(
                    "Connection closed during authentication".into(),
                ));
            }
            debug!("Received {} bytes", n);

            if let Some(response) = codec.feed(&buf[..n])? {
                debug!("HTTP response: status={}", response.status_code);

                if response.status_code != 200 {
                    return Err(Error::AuthenticationFailed(format!(
                        "Server returned status {}",
                        response.status_code
                    )));
                }

                if !response.body.is_empty() {
                    debug!("Response body: {} bytes", response.body.len());
                    let pack = Pack::deserialize(&response.body)?;

                    // Debug: print all keys in response
                    debug!(
                        "Auth response pack keys: {:?}",
                        pack.keys().collect::<Vec<_>>()
                    );
                    if let Some(error) = pack.get_int("error") {
                        debug!("Error code in pack: {}", error);
                    }
                    if pack.contains("session_key") {
                        debug!("session_key found!");
                    }
                    if let Some(direction) = pack.get_int("direction") {
                        debug!("Direction in pack: {}", direction);
                    }

                    let result = AuthResult::from_pack(&pack)?;
                    debug!("Auth result direction: {}", result.direction);

                    // Check for errors
                    if result.error > 0 {
                        return Err(Error::AuthenticationFailed(format!(
                            "Authentication error code: {}",
                            result.error
                        )));
                    }

                    return Ok(result);
                } else {
                    return Err(Error::ServerError("Empty authentication response".into()));
                }
            }
        }
    }

    /// Establish additional data connection.
    #[allow(dead_code)]
    async fn establish_data_connection(
        &self,
        auth: &AuthResult,
        server: &str,
        port: u16,
    ) -> Result<VpnConnection> {
        // Create config for the target server
        let mut conn_config = self.config.clone();
        conn_config.server = server.to_string();
        conn_config.port = port;

        // Connect to the session server
        let mut conn = VpnConnection::connect(&conn_config).await?;

        // Send additional connection signature
        let mut pack = Pack::new();
        pack.add_data("session_key", auth.session_key.to_vec());
        pack.add_int("connection_type", 1); // Additional connection

        let request = HttpRequest::post(VPN_TARGET)
            .header("Content-Type", CONTENT_TYPE_PACK)
            .header("Connection", "Keep-Alive")
            .body(pack.to_bytes());

        let host = format!("{}:{}", server, port);
        let request_bytes = request.build(&host);
        conn.write_all(&request_bytes).await?;

        // Read response
        let mut codec = HttpCodec::new();
        let mut buf = vec![0u8; 4096];

        loop {
            let n = conn.read(&mut buf).await?;
            if n == 0 {
                return Err(Error::ConnectionFailed(
                    "Connection closed during data connection setup".into(),
                ));
            }

            if let Some(response) = codec.feed(&buf[..n])? {
                if response.status_code == 200 {
                    return Ok(conn);
                } else {
                    return Err(Error::ServerError(format!(
                        "Data connection rejected: {}",
                        response.status_code
                    )));
                }
            }
        }
    }

    /// Run the tunnel data loop.
    pub async fn run_tunnel<T: TunAdapter>(
        &mut self,
        tun: &mut T,
        conn: &mut VpnConnection,
        dhcp_config: &DhcpConfig,
    ) -> Result<()> {
        info!("Starting tunnel data loop");

        // Configure TUN device
        tun.configure(dhcp_config.ip, dhcp_config.netmask)?;
        tun.set_up()?;
        tun.set_mtu(1400)?; // Leave room for VPN overhead

        // Set up routes
        if let Some(gateway) = dhcp_config.gateway {
            tun.add_route(
                Ipv4Addr::new(0, 0, 0, 0),
                Ipv4Addr::new(0, 0, 0, 0),
                gateway,
            )?;
        }

        let running = self.running.clone();
        let mut tunnel_codec = TunnelCodec::new();

        // Buffers
        let tun_buf = vec![0u8; 65536];
        let mut net_buf = vec![0u8; 65536];

        // Keepalive interval
        let mut keepalive_interval = interval(Duration::from_secs(3));
        let mut last_activity = Instant::now();

        while running.load(Ordering::SeqCst) {
            tokio::select! {
                // Read from TUN device
                result = tokio::task::spawn_blocking({
                    let _tun_buf = tun_buf.clone();
                    move || {
                        // This would need to be made async properly
                        // For now, this is a placeholder
                        Ok::<_, std::io::Error>(0usize)
                    }
                }) => {
                    match result {
                        Ok(Ok(n)) if n > 0 => {
                            // Wrap in Ethernet frame and send
                            let frame = tunnel_codec.encode(&[&tun_buf[..n]]);
                            conn.write_all(&frame).await?;
                            last_activity = Instant::now();
                        }
                        Ok(Err(e)) => {
                            error!("TUN read error: {}", e);
                        }
                        Err(e) => {
                            error!("TUN task error: {}", e);
                        }
                        _ => {}
                    }
                }

                // Read from network
                result = conn.read(&mut net_buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            // Decode tunnel frames
                            if let Ok(frames) = tunnel_codec.decode(&net_buf[..n]) {
                                for frame in frames {
                                    // Extract IP packet from Ethernet frame and write to TUN
                                    if frame.len() > 14 {
                                        let _dst_mac = &frame[0..6];
                                        let _src_mac = &frame[6..12];
                                        let ether_type = u16::from_be_bytes([frame[12], frame[13]]);

                                        if ether_type == EtherType::Ipv4 as u16 {
                                            let ip_packet = &frame[14..];
                                            if let Err(e) = tun.write(ip_packet) {
                                                warn!("TUN write error: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                            last_activity = Instant::now();
                        }
                        Ok(_) => {
                            info!("Connection closed by server");
                            break;
                        }
                        Err(e) => {
                            error!("Network read error: {}", e);
                            break;
                        }
                    }
                }

                // Keepalive timer
                _ = keepalive_interval.tick() => {
                    if last_activity.elapsed() > Duration::from_secs(10) {
                        // Send keepalive
                        let keepalive = tunnel_codec.encode_keepalive();
                        if let Err(e) = conn.write_all(&keepalive).await {
                            error!("Failed to send keepalive: {}", e);
                            break;
                        }
                        debug!("Sent keepalive");
                    }
                }
            }
        }

        info!("Tunnel data loop ended");
        Ok(())
    }

    /// Resolve a hostname or IP string to an Ipv4Addr.
    fn resolve_server_ip(&self, server: &str) -> Result<Ipv4Addr> {
        // First try to parse as IP address directly
        if let Ok(ip) = server.parse::<Ipv4Addr>() {
            return Ok(ip);
        }

        // Try to parse as generic IpAddr (handles IPv4 and IPv6)
        if let Ok(std::net::IpAddr::V4(ip)) = server.parse::<std::net::IpAddr>() {
            return Ok(ip);
        }

        // Resolve hostname using DNS
        use std::net::ToSocketAddrs;
        let addr_str = format!("{}:443", server);
        match addr_str.to_socket_addrs() {
            Ok(mut addrs) => {
                // Find first IPv4 address
                for addr in addrs.by_ref() {
                    if let std::net::SocketAddr::V4(v4) = addr {
                        return Ok(*v4.ip());
                    }
                }
                Err(Error::ConnectionFailed(format!(
                    "No IPv4 address found for {}",
                    server
                )))
            }
            Err(e) => Err(Error::ConnectionFailed(format!(
                "Failed to resolve {}: {}",
                server, e
            ))),
        }
    }

    /// Disconnect from the VPN server.
    pub fn disconnect(&mut self) {
        info!("Disconnecting from VPN");
        self.running.store(false, Ordering::SeqCst);
        self.state = VpnState::Disconnected;
    }
}

impl Drop for VpnClient {
    fn drop(&mut self) {
        self.disconnect();
    }
}
