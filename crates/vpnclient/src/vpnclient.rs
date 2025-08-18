//! Main VPN client implementation

use anyhow::{Context, Result};
use base64;
use base64::prelude::*;
use cedar::constants::{MAX_RETRY_INTERVAL_MS, MIN_RETRY_INTERVAL_MS};
use cedar::{ConnectionManager, ConnectionPool, DataPlane, EngineConfig, SessionManager};
use rand::RngCore;
use tracing::{debug, error, info, warn}; // for fill_bytes
#[cfg(unix)]
fn local_hostname() -> String {
    use std::ffi::CStr;
    let mut buf = [0u8; 256];
    unsafe {
        if libc::gethostname(buf.as_mut_ptr() as *mut i8, buf.len()) == 0 {
            if let Ok(cstr) = CStr::from_bytes_until_nul(&buf) {
                return cstr.to_string_lossy().into_owned();
            }
        }
    }
    "unknown".to_string()
}
#[cfg(not(unix))]
fn local_hostname() -> String {
    "unknown".to_string()
}
use cedar::handshake::secure_password; // for secure password derivation
use cedar::{AuthType, ClientAuth, ClientOption, Session, SessionConfig};
use mayaqua::logging::redact_pack;
use mayaqua::Pack;
use std::time::Duration;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::config::{AuthConfig, VpnConfig};
use crate::dhcp::DhcpClient;
use crate::dhcp::Lease as DhcpLease;
use crate::network::SecureConnection;
use crate::{CLIENT_BUILD, CLIENT_STRING, CLIENT_VERSION};
#[cfg(feature = "adapter")]
use adapter::VirtualAdapter;
use config as shared_config;
use mayaqua::crypto::softether_password_hash; // SHA-0(password + UPPER(username))
use mayaqua::get_tick64;
use std::net::Ipv4Addr;
use std::net::{SocketAddr, ToSocketAddrs};

/// SoftEther VPN Client
pub struct VpnClient {
    config: VpnConfig,
    connection: Option<SecureConnection>,
    session: Option<Session>,
    session_manager: SessionManager,
    #[allow(dead_code)]
    connection_manager: ConnectionManager,
    #[allow(dead_code)]
    connection_pool: ConnectionPool,
    dataplane: Option<DataPlane>,
    is_connected: bool,
    pub redirect_ticket: Option<[u8; 20]>,
    network_settings: Option<NetworkSettings>,
    #[cfg(feature = "adapter")]
    adapter: Option<VirtualAdapter>,
    // Server policy constraints (best-effort parsed from welcome/auth)
    server_policy_max_connections: Option<u32>,
    // Server-negotiated max_connection reported in welcome (often echo of requested <= policy)
    server_negotiated_max_connections: Option<u32>,
    // Background tasks for auxiliary links (scaffold)
    aux_tasks: Vec<JoinHandle<()>>,
    // Server-provided session key (20 bytes) used for additional connections bonding
    server_session_key: Option<[u8; 20]>,
    // Directions recorded for additional links (0: both or RX/TX per server; 1: client->server, 2: server->client per SoftEther)
    aux_directions: std::sync::Arc<std::sync::Mutex<Vec<i32>>>,
    // Round-robin endpoint list (hosts) to spread additional links across farm IPs
    endpoints_rr: Vec<String>,
    // TLS SNI host to use for certificate verification when connecting to an IP after redirect
    sni_host: Option<String>,
    // Connection state tracking and keep-alive
    state: ConnectionState,
    last_noop_sent: u64,
    // Server-reported timeout (ms) for HTTP keep-alive / control channel guidance
    server_timeout_ms: Option<u32>,
    // True once adapter<->dataplane bridging is fully set up
    bridge_ready: bool,
    // Prevent duplicate DHCP/monitor spawning across code paths
    dhcp_spawned: bool,
    // Optional state notification channel for embedders/FFI
    state_tx: Option<mpsc::UnboundedSender<ClientState>>,
    // Optional event channel for embedders/FFI
    event_tx: Option<mpsc::UnboundedSender<ClientEvent>>,
}

/// Parsed network settings (assigned IP, DNS, policy flags) extracted from welcome/auth packs
#[derive(Debug, Clone, Default)]
pub struct NetworkSettings {
    pub assigned_ipv4: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub policies: Vec<(String, u32)>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub ports: Vec<u16>,
}

/// Helper: serialize a snapshot of NetworkSettings to a compact JSON used by FFI/events.
/// If include_kind is true, a { kind: "settings", ... } wrapper is emitted to distinguish event payloads.
pub fn settings_json_with_kind(ns: Option<&NetworkSettings>, include_kind: bool) -> String {
    #[derive(serde::Serialize)]
    struct SettingsJson<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        kind: Option<&'a str>,
        assigned_ipv4: Option<String>,
        subnet_mask: Option<String>,
        gateway: Option<String>,
        dns_servers: Vec<String>,
    }

    let mut json = SettingsJson {
        kind: include_kind.then_some("settings"),
        assigned_ipv4: None,
        subnet_mask: None,
        gateway: None,
        dns_servers: vec![],
    };
    if let Some(ns) = ns {
        if let Some(ip) = ns.assigned_ipv4 {
            json.assigned_ipv4 = Some(ip.to_string());
        }
        if let Some(m) = ns.subnet_mask {
            json.subnet_mask = Some(m.to_string());
        }
        if let Some(g) = ns.gateway {
            json.gateway = Some(g.to_string());
        }
        json.dns_servers = ns.dns_servers.iter().map(|d| d.to_string()).collect();
    }
    serde_json::to_string(&json).unwrap_or_else(|_| "{}".to_string())
}

/// Convert a DHCP lease into NetworkSettings (IP/mask/gateway/DNS)
fn network_settings_from_lease(lease: &DhcpLease) -> NetworkSettings {
    let mut ns = NetworkSettings::default();
    ns.assigned_ipv4 = Some(std::net::Ipv4Addr::new(
        lease.yiaddr[0],
        lease.yiaddr[1],
        lease.yiaddr[2],
        lease.yiaddr[3],
    ));
    if let Some(m) = lease.subnet {
        ns.subnet_mask = Some(std::net::Ipv4Addr::new(m[0], m[1], m[2], m[3]));
    }
    if let Some(r) = lease.router {
        ns.gateway = Some(std::net::Ipv4Addr::new(r[0], r[1], r[2], r[3]));
    }
    for d in &lease.dns {
        ns.dns_servers
            .push(std::net::Ipv4Addr::new(d[0], d[1], d[2], d[3]));
    }
    ns
}

impl VpnClient {
    /// Best-effort mapping of common SoftEther error codes to names for logs
    fn softether_err_name(code: i64) -> &'static str {
        match code {
            0 => "ERR_NO_ERROR",
            1 => "ERR_INTERNAL_ERROR",
            2 => "ERR_DISCONNECTED",
            5 => "ERR_AUTH_FAILED",
            7 => "ERR_PROTOCOL_ERROR",
            9 => "ERR_INVALID_PROTOCOL",
            13 => "ERR_SESSION_TIMEOUT",
            59 => "ERR_TOO_MANY_CONNECTION",
            _ => "ERR_UNKNOWN",
        }
    }
    /// Build a VpnClient from the shared config::ClientConfig (preferred public API)
    pub fn from_shared_config(cc: shared_config::ClientConfig) -> Result<Self> {
        use base64::Engine as _;
        // Map shared -> internal config (prefer SHA-0 of password+UPPER(username))
        let auth = if let Some(b64) = cc.password_hash.clone() {
            // Direct SHA-0 hash provided (20 bytes, base64)
            AuthConfig::Password {
                hashed_password: b64,
            }
        } else if let Some(pass) = cc.password.clone() {
            // Derive SHA-0(password + UPPER(username)) locally
            let hp = softether_password_hash(&pass, &cc.username);
            let b64 = base64::prelude::BASE64_STANDARD.encode(hp);
            AuthConfig::Password {
                hashed_password: b64,
            }
        } else {
            AuthConfig::Anonymous
        };
        let mut v = VpnConfig::new_anonymous(cc.server, cc.port, cc.hub);
        v.username = cc.username;
        v.auth = auth;
        v.connection.max_connections = cc.max_connections;
        v.connection.use_compression = cc.use_compress;
        v.connection.use_encryption = cc.use_encrypt;
        // respect TLS verification toggle
        v.connection.skip_tls_verify = cc.skip_tls_verify;
        // udp_port not wired in legacy config yet; reserved for future use
        Self::new(v)
    }
    /// Create a new VPN client with the given configuration
    pub fn new(config: VpnConfig) -> Result<Self> {
        config.validate()?;
        // Prepare RR endpoints list before moving config
        let endpoints_rr = vec![config.host.clone()];

        Ok(Self {
            config,
            connection: None,
            session: None,
            session_manager: SessionManager::new(EngineConfig::default()),
            connection_manager: ConnectionManager::new(),
            connection_pool: ConnectionPool::new(),
            dataplane: None,
            is_connected: false,
            redirect_ticket: None,
            network_settings: None,
            #[cfg(feature = "adapter")]
            adapter: None,
            server_policy_max_connections: None,
            server_negotiated_max_connections: None,
            aux_tasks: Vec::new(),
            server_session_key: None,
            aux_directions: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            endpoints_rr,
            sni_host: None,
            state: ConnectionState::Idle,
            last_noop_sent: 0,
            server_timeout_ms: None,
            bridge_ready: false,
            dhcp_spawned: false,
            state_tx: None,
            event_tx: None,
        })
    }

    /// Connect to the VPN server
    pub async fn connect(&mut self) -> Result<()> {
        info!(
            "Starting VPN connection to {}",
            self.config.server_address()
        );

        self.set_state(ConnectionState::Connecting);
        let mut redirect_count = 0u8;
        let mut attempt: u32 = 0;
        loop {
            if redirect_count > 1 {
                anyhow::bail!("Too many redirects");
            }

            let client_auth = self.create_client_auth()?;
            let client_option = self.create_client_option()?;
            let session_config = SessionConfig {
                timeout: self.config.connection.timeout,
                max_connection: self.config.connection.max_connections,
                keep_alive_interval: 50,
                additional_connection_interval: 1000,
                connection_disconnect_span: 12000,
                retry_interval: 15,
                qos: false,
            };
            let mut session = Session::new(
                format!("SoftEtherRustClient_{}", uuid::Uuid::new_v4()),
                client_option.clone(),
                client_auth.clone(),
                session_config,
            )?;

            let timeout_duration = Duration::from_secs(self.config.connection.timeout as u64);
            // Establish connection with exponential backoff on failures
            let mut connection = loop {
                match timeout(timeout_duration, self.establish_connection()).await {
                    Ok(Ok(c)) => break c,
                    Ok(Err(e)) => {
                        attempt = attempt.saturating_add(1);
                        let delay_ms = (MIN_RETRY_INTERVAL_MS as u64)
                            .saturating_mul(1u64 << (attempt.min(6))) // cap doubling
                            .min(MAX_RETRY_INTERVAL_MS as u64);
                        warn!(
                            "Connect attempt {} failed: {} (retry in {} ms)",
                            attempt, e, delay_ms
                        );
                        self.emit_event(
                            EventLevel::Warn,
                            200,
                            format!("connect attempt {} failed: {}", attempt, e),
                        );
                        sleep(Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    Err(_) => {
                        attempt = attempt.saturating_add(1);
                        let delay_ms = (MIN_RETRY_INTERVAL_MS as u64)
                            .saturating_mul(1u64 << (attempt.min(6)))
                            .min(MAX_RETRY_INTERVAL_MS as u64);
                        warn!(
                            "Connection timeout (attempt {}), retry in {} ms",
                            attempt, delay_ms
                        );
                        self.emit_event(
                            EventLevel::Warn,
                            201,
                            format!("timeout on attempt {}", attempt),
                        );
                        sleep(Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                }
            };

            if let Some((new_host, new_port)) = self
                .perform_authentication(&mut connection, &client_auth, &client_option)
                .await?
            {
                redirect_count += 1;
                // Track both current and redirected endpoints for RR spawning later
                if !self.endpoints_rr.iter().any(|h| h == &self.config.host) {
                    self.endpoints_rr.push(self.config.host.clone());
                }
                if !self.endpoints_rr.iter().any(|h| h == &new_host) {
                    self.endpoints_rr.push(new_host.clone());
                }
                self.config.host = new_host;
                self.config.port = new_port;
                info!(
                    "Redirecting to {}:{} (attempt {})",
                    self.config.host, self.config.port, redirect_count
                );
                self.emit_event(
                    EventLevel::Info,
                    210,
                    format!(
                        "redirect to {}:{} (attempt {})",
                        self.config.host, self.config.port, redirect_count
                    ),
                );
                continue;
            }

            session.start().await?;
            debug!(
                "[DEBUG] session_established (local) session_name={}",
                session.name
            );
            // Create dataplane bound to the session's packet channels (tunnel protocol TBD)
            let half_connection = self.config.connection.half_connection;
            let mut sess = session;
            let dp = DataPlane::new(&mut sess, half_connection);
            if dp.is_none() {
                warn!("Failed to initialize dataplane; using connection manager only");
            }
            self.dataplane = dp;
            self.session = Some(sess);
            // Keep the primary CGI TLS connection for control; data links will be opened via additional_connect
            self.connection = Some(connection);
            self.session_manager.mark_established();
            self.is_connected = true;
            self.set_state(ConnectionState::Established);
            info!("SoftEther tunnel opened");
            self.emit_event(EventLevel::Info, 220, "tunnel opened");
            // Establish the first bulk data link via additional_connect before bridging/DHCP
            if let Err(e) = self.open_primary_data_link().await {
                error!("Failed to establish primary data link: {}", e);
                return Err(e);
            }
            // Create adapter and start bridging so DHCP can flow
            if let Err(e) = self.start_adapter_and_bridge().await {
                warn!("Failed to start adapter bridging: {}", e);
            }
            // Try DHCP over dataplane on macOS when no assigned IP from server
            #[cfg(target_os = "macos")]
            if self.bridge_ready
                && self
                    .network_settings
                    .as_ref()
                    .and_then(|n| n.assigned_ipv4)
                    .is_none()
            {
                #[cfg(feature = "adapter")]
                if let (Some(dp), Some(adp)) = (self.dataplane.clone(), self.adapter.as_ref()) {
                    let ifname = adp.name().to_string();
                    // Ensure the dataplane has at least one registered link before attempting DHCP
                    {
                        let start = std::time::Instant::now();
                        while dp.summary().total_links == 0
                            && start.elapsed() < Duration::from_secs(3)
                        {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                    // Attempt in-tunnel DHCP first; only kick system DHCP later if needed
                    let mut mac = [0u8; 6];
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    use std::hash::Hash;
                    use std::hash::Hasher;
                    adp.name().hash(&mut h);
                    let v = h.finish();
                    mac.copy_from_slice(&[
                        ((v >> 0) as u8) | 0x02,
                        ((v >> 8) as u8),
                        ((v >> 16) as u8),
                        ((v >> 24) as u8),
                        ((v >> 32) as u8),
                        ((v >> 40) as u8),
                    ]);
                    mac[0] = (mac[0] & 0b1111_1110) | 0b0000_0010; // locally administered, unicast
                    let dhcp = DhcpClient::new(dp, mac);
                    info!("Attempting DHCP over tunnel on {}", ifname);
                    let lease = dhcp
                        .run_once(&ifname, Duration::from_secs(30))
                        .await
                        .ok()
                        .flatten();
                    if let Some(lease) = lease {
                        // Reflect DHCP lease in network_settings for consistent summary logs
                        self.network_settings = Some(network_settings_from_lease(&lease));
                        // Notify embedders that settings are available now (JSON event 1001)
                        self.emit_settings_snapshot();

                        self.log_adapter_summary();
                        // Now that we have a lease, start a brief monitor to surface final IP/DNS/Connected
                        // Avoid spawning the generic macOS interface monitor here to prevent
                        // duplicate "IP Address/DNS/Connected" messages sourced from system DNS.
                        // Optionally apply DNS on macOS (best-effort), similar to apply_network_settings
                        #[cfg(target_os = "macos")]
                        if self.config.connection.apply_dns {
                            use tokio::process::Command;
                            if let Some(ref ns2) = self.network_settings {
                                if !ns2.dns_servers.is_empty() {
                                    let mut service_name: Option<String> =
                                        self.config.client.macos_dns_service_name.clone();
                                    if service_name.is_none() {
                                        // Try to detect a reasonable default service name
                                        let list = Command::new("bash")
                                                .arg("-c")
                                                .arg("networksetup -listnetworkserviceorder | sed -n 's/.*Device: (\\(.*\\)).*/\\1/p'")
                                                .output()
                                                .await
                                                .ok();
                                        if let Some(out) = list {
                                            let services = String::from_utf8_lossy(&out.stdout);
                                            if services.contains(&ifname) {
                                                service_name = Some("Wi-Fi".to_string());
                                            }
                                        }
                                    }
                                    if let Some(svc) = service_name {
                                        let args = ns2
                                            .dns_servers
                                            .iter()
                                            .map(|d| d.to_string())
                                            .collect::<Vec<_>>()
                                            .join(" ");
                                        let cmd = format!(
                                            "networksetup -setdnsservers '{}' {}",
                                            svc.replace("'", "'\\''"),
                                            args
                                        );
                                        if let Ok(out) =
                                            Command::new("bash").arg("-c").arg(&cmd).output().await
                                        {
                                            if out.status.success() {
                                                info!("Applied DNS servers to service '{}'", svc);
                                            } else {
                                                warn!(
                                                    "Failed to apply macOS DNS: {}",
                                                    String::from_utf8_lossy(&out.stderr)
                                                );
                                            }
                                        }
                                    } else {
                                        info!(
                                                "(macOS) DNS servers suggested: {} (manual apply with: networksetup -setdnsservers <ServiceName> <servers> )",
                                                ns2.dns_servers.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", ")
                                            );
                                    }
                                }
                            }
                        }
                        self.spawn_additional_links();
                        self.start_connections_summary_logger();
                        info!("VPN connection established successfully");
                        return Ok(());
                    }
                    // No lease yet; defer to apply_network_settings() to kick system DHCP/monitor if needed
                }
            }

            // On iOS, attempt DHCP over dataplane when server did not provide IP settings
            #[cfg(target_os = "ios")]
            if self
                .network_settings
                .as_ref()
                .and_then(|n| n.assigned_ipv4)
                .is_none()
            {
                if let Some(dp) = self.dataplane.clone() {
                    // Wait briefly for at least one TX-capable link to register
                    let start = std::time::Instant::now();
                    while dp.summary().total_links == 0 && start.elapsed() < Duration::from_secs(3)
                    {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    // Generate a locally-administered, unicast MAC; stable enough for a single run
                    let mut mac = [0u8; 6];
                    rand::rng().fill_bytes(&mut mac);
                    mac[0] = (mac[0] & 0b1111_1110) | 0b0000_0010;
                    let dhcp = DhcpClient::new(dp, mac);
                    info!("Attempting DHCP over tunnel (iOS)");
                    let lease = dhcp
                        .run_once("utun", Duration::from_secs(30))
                        .await
                        .ok()
                        .flatten();
                    if let Some(lease) = lease {
                        self.network_settings = Some(network_settings_from_lease(&lease));
                        // Notify embedders that settings are available now (JSON event 1001)
                        self.emit_settings_snapshot();
                        // No platform adapter apply on iOS; extension will consume settings via FFI JSON/event
                        self.spawn_additional_links();
                        self.start_connections_summary_logger();
                        info!("VPN connection established successfully");
                        return Ok(());
                    }
                }
            }
            // Attempt to apply network settings (best-effort); if DHCP is used, monitor will print upon success
            if let Err(e) = self.apply_network_settings().await {
                warn!("Failed to apply network settings: {}", e);
            }
            // Print adapter summary (if any)
            self.log_adapter_summary();
            // Scaffold: spawn auxiliary links up to min(policy, config)
            self.spawn_additional_links();
            // Start periodic connections summary logging
            self.start_connections_summary_logger();
            info!("VPN connection established successfully");
            return Ok(());
        }
    }

    /// Get a clone of the current dataplane if available.
    pub fn dataplane(&self) -> Option<cedar::DataPlane> {
        self.dataplane.clone()
    }

    /// Expose current network settings (assigned IP, DNS, etc.) for embedders/FFI.
    pub fn get_network_settings(&self) -> Option<NetworkSettings> {
        self.network_settings.clone()
    }

    /// Provide a channel to receive state transitions.
    pub fn set_state_channel(&mut self, tx: mpsc::UnboundedSender<ClientState>) {
        self.state_tx = Some(tx);
    }

    /// Provide a channel to receive client events (info/warn/error codes and messages).
    pub fn set_event_channel(&mut self, tx: mpsc::UnboundedSender<ClientEvent>) {
        self.event_tx = Some(tx);
    }

    fn emit_event(&self, level: EventLevel, code: i32, msg: impl Into<String>) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(ClientEvent {
                level,
                code,
                message: msg.into(),
            });
        }
    }

    /// Disconnect from the VPN server
    pub async fn disconnect(&mut self) -> Result<()> {
        if !self.is_connected {
            return Ok(());
        }

        info!("Disconnecting from VPN server");
        self.set_state(ConnectionState::Disconnecting);

        // Stop dataplane first so its worker threads stop reading/writing
        if let Some(dp) = self.dataplane.take() {
            dp.shutdown();
        }

        // Stop session
        if let Some(mut session) = self.session.take() {
            session.stop().await?;
        }

        // Close connection
        if let Some(connection) = self.connection.take() {
            connection.close()?;
        }

        // Abort auxiliary tasks
        for handle in self.aux_tasks.drain(..) {
            handle.abort();
        }

        // Tear down virtual adapter (utun)
        #[cfg(feature = "adapter")]
        if let Some(mut adp) = self.adapter.take() {
            let _ = adp.destroy().await;
        }

        self.is_connected = false;
        // Reset connection-scoped flags
        self.bridge_ready = false;
        self.dhcp_spawned = false;
        self.set_state(ConnectionState::Idle);
        info!("VPN disconnected");
        Ok(())
    }

    /// Check if the client is connected
    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    /// Get connection statistics
    pub fn get_stats(&self) -> Option<SessionStats> {
        self.session.as_ref().map(|session| {
            let stats = session.get_stats();
            SessionStats {
                total_bytes_sent: stats.total_send_size,
                total_bytes_received: stats.total_recv_size,
                connection_time: stats.created_time,
                is_connected: stats.is_connected,
                protocol: stats.protocol.clone(),
            }
        })
    }

    /// Run the VPN client until interrupted
    pub async fn run_until_interrupted(&mut self) -> Result<()> {
        // Connect to server
        self.connect().await?;

        // Set up signal handling
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
        // Cross-platform fallback (also works on macOS)
        let mut ctrl_c = std::pin::pin!(tokio::signal::ctrl_c());

        info!("VPN client running. Press Ctrl+C to disconnect.");

        // Main event loop
        loop {
            tokio::select! {
                // Handle SIGTERM
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, shutting down...");
                    break;
                },

                // Handle SIGINT (Ctrl+C)
                _ = sigint.recv() => {
                    info!("Received SIGINT, shutting down...");
                    break;
                },

                // Fallback Ctrl+C
                _ = &mut ctrl_c => {
                    info!("Received Ctrl+C, shutting down...");
                    break;
                },

                // Keep alive check
                _ = sleep(Duration::from_secs(30)) => {
                    if self.is_connected {
                        if let Err(e) = self.keep_alive_check().await {
                            error!("Keep alive check failed: {}", e);
                            break;
                        }
                    }
                },
            }
        }

        // Disconnect gracefully with a timeout; if it hangs, abort tasks and proceed
        match timeout(Duration::from_secs(8), self.disconnect()).await {
            Ok(res) => {
                res?;
            }
            Err(_) => {
                warn!("Graceful disconnect timed out; forcing shutdown");
                // Best-effort: abort background tasks to avoid lingering
                for handle in self.aux_tasks.drain(..) {
                    handle.abort();
                }
            }
        }
        Ok(())
    }

    /// Establish connection to the server
    async fn establish_connection(&self) -> Result<SecureConnection> {
        let timeout_duration = Duration::from_secs(self.config.connection.timeout as u64);

        let connection = SecureConnection::connect(
            &self.config.host,
            self.config.port,
            self.config.connection.skip_tls_verify,
            timeout_duration,
            self.sni_host.as_deref(),
        )?;

        Ok(connection)
    }

    /// Perform authentication handshake with the server
    async fn perform_authentication(
        &mut self,
        connection: &mut SecureConnection,
        client_auth: &ClientAuth,
        client_option: &ClientOption,
    ) -> Result<Option<(String, u16)>> {
        // Perform initial hello (watermark + immediate hello pack response)
        let _hello_pack = connection.initial_hello()?;
        let (server_ver, server_build) = connection.server_version();

        if server_ver > 0 && server_build > 0 {
            info!(
                "Server version: {}.{:?}",
                server_ver as f64 / 100.0,
                server_build
            );
            // Go/C log parity (tagged as DEBUG in text)
            info!(
                "[DEBUG] server_version version={:.2} build={}",
                server_ver as f64 / 100.0,
                server_build
            );
        }

        // Create authentication pack (primary: cedar's canonical builder)
        // Then augment with secure_password and NodeInfo/client_id fields.
        // If server rejects, we fall back to the legacy manual pack once.
        let secure_pwd: Option<[u8; 20]> = if matches!(client_auth.auth_type, AuthType::Password) {
            if let Some(sr) = connection.server_random() {
                let mut hashed = [0u8; 20];
                hashed.copy_from_slice(&client_auth.hashed_password);
                let sp = secure_password(hashed, sr);
                let mut out = [0u8; 20];
                out.copy_from_slice(&sp);
                Some(out)
            } else {
                None
            }
        } else {
            None
        };

        info!(
            "[DEBUG] auth_start username={} hub={}",
            client_auth.username, self.config.hub_name
        );

        // Build auth pack: match Go prototype closely for password auth
        let mut auth_pack = if matches!(client_auth.auth_type, AuthType::Password) {
            use cedar::constants::CEDAR_SIGNATURE_STR;
            let mut p = Pack::new();
            p.add_str("method", "login")?;
            p.add_int("version", cedar::SOFTETHER_VER)?;
            p.add_int("build", cedar::SOFTETHER_BUILD)?;
            p.add_str("client_str", CLIENT_STRING)?;
            p.add_str("hubname", &client_option.hubname)?;
            p.add_str("username", &client_auth.username)?;
            p.add_str("protocol", CEDAR_SIGNATURE_STR)?;
            p.add_int("max_connection", client_option.max_connection)?;
            p.add_int("use_encrypt", client_option.use_encrypt as u32)?;
            // Force-disable compression to match current dataplane framing (no bulk compression implemented)
            p.add_int("use_compress", 0)?;
            p.add_int("half_connection", client_option.half_connection as u32)?;
            // authtype: password
            p.add_int("authtype", 1)?;
            // secure_password from server random
            if let Some(sp) = secure_pwd.as_ref() {
                p.add_data("secure_password", sp.to_vec())?;
            }
            // client_id: default to 123 if not provided, matches Go prototype
            let cid = self.config.connection.client_id.unwrap_or(123);
            p.add_int("client_id", cid)?;
            // unique_id
            let mut unique = [0u8; 20];
            rand::rng().fill_bytes(&mut unique);
            p.add_data("unique_id", unique.to_vec())?;
            p
        } else if matches!(client_auth.auth_type, AuthType::Ticket) {
            use cedar::constants::CEDAR_SIGNATURE_STR;
            let mut p = Pack::new();
            p.add_str("method", "login")?;
            p.add_int("version", cedar::SOFTETHER_VER)?;
            p.add_int("build", cedar::SOFTETHER_BUILD)?;
            p.add_str("client_str", CLIENT_STRING)?;
            p.add_str("hubname", &client_option.hubname)?;
            p.add_str("username", &client_auth.username)?;
            p.add_str("protocol", CEDAR_SIGNATURE_STR)?;
            p.add_int("max_connection", client_option.max_connection)?;
            p.add_int("use_encrypt", client_option.use_encrypt as u32)?;
            // Force-disable compression to match current dataplane framing (no bulk compression implemented)
            p.add_int("use_compress", 0)?;
            p.add_int("half_connection", client_option.half_connection as u32)?;
            // authtype: ticket
            p.add_int("authtype", 99)?;
            // ticket bytes carried in hashed_password field
            p.add_data("ticket", client_auth.hashed_password.to_vec())?;
            let cid = self.config.connection.client_id.unwrap_or(123);
            p.add_int("client_id", cid)?;
            let mut unique = [0u8; 20];
            rand::rng().fill_bytes(&mut unique);
            p.add_data("unique_id", unique.to_vec())?;
            p
        } else {
            // Non-password: fall back to cedar helper
            cedar::handshake::build_login_pack(client_option, client_auth)
                .context("Failed to build cedar login pack")?
        };

        // Environment info (best-effort)
        let os_name = std::env::consts::OS;
        let os_ver = std::env::var("RUST_OS_VERSION").unwrap_or_default();
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| local_hostname());
        let product_name = CLIENT_STRING;
        let product_ver = CLIENT_VERSION;
        let product_build = CLIENT_BUILD;
        let _ = auth_pack.add_str("client_os_name", os_name);
        if !os_ver.is_empty() {
            let _ = auth_pack.add_str("client_os_ver", &os_ver);
        }
        let _ = auth_pack.add_str("client_hostname", &hostname);
        let _ = auth_pack.add_str("client_product_name", product_name);
        let _ = auth_pack.add_int("client_product_ver", product_ver);
        let _ = auth_pack.add_int("client_product_build", product_build);
        let _ = auth_pack.add_str("ClientOsName", os_name);
        if !os_ver.is_empty() {
            let _ = auth_pack.add_str("ClientOsVer", &os_ver);
        }
        let _ = auth_pack.add_str("ClientHostname", &hostname);
        let _ = auth_pack.add_str("ClientProductName", product_name);
        let _ = auth_pack.add_int("ClientProductVer", product_ver);
        let _ = auth_pack.add_int("ClientProductBuild", product_build);
        // Brand string left empty by default
        let _ = auth_pack.add_str("branded_ctos", "");
        // Extra fields some servers show in GUI: client_host and client_ip (best-effort)
        let _ = auth_pack.add_str("client_host", &hostname);
        if let Some(conn) = &self.connection {
            if let Some(addr) = conn.local_addr() {
                let _ = auth_pack.add_str("client_ip", &addr.ip().to_string());
            }
        }
        debug!("auth_pack_redacted: {}", redact_pack(&auth_pack));

        // Upload authentication
        // Upload authentication using the cedar-built pack (no legacy fallback)
        let welcome_pack = connection.upload_auth(auth_pack)?;

        // Validate pencore if provided by server (best-effort; don't fail connection on unknown/short blobs)
        if let Ok(pencore_bytes) = welcome_pack
            .get_data("pencore")
            .or_else(|_| welcome_pack.get_data("PenCore"))
        {
            match connection.handle_pencore(pencore_bytes) {
                Ok(()) => {
                    debug!("Validated pencore blob ({} bytes)", pencore_bytes.len());
                }
                Err(e) => {
                    warn!(
                        "Ignoring invalid pencore blob ({} bytes): {}",
                        pencore_bytes.len(),
                        e
                    );
                }
            }
        }

        // Check for redirection via either explicit host fields or Redirect flag with Ip/Port
        // 1. Legacy explicit RedirectHost
        if let Ok(redirect_host) = welcome_pack
            .get_str("RedirectHost")
            .or_else(|_| welcome_pack.get_str("redirect_host"))
        {
            let redirect_port = welcome_pack
                .get_int("RedirectPort")
                .or_else(|_| welcome_pack.get_int("redirect_port"))
                .unwrap_or(self.config.port as u32) as u16;
            self.capture_redirect_ticket(&welcome_pack);
            warn!(
                "Server requested redirection to {}:{} (host field)",
                redirect_host, redirect_port
            );
            return Ok(Some((redirect_host.to_string(), redirect_port)));
        }

        // 2. Standard Redirect flag (with Ip and Port fields)
        let do_redirect = welcome_pack
            .get_int("Redirect")
            .or_else(|_| welcome_pack.get_int("redirect"))
            .unwrap_or(0);
        if do_redirect != 0 {
            let ip = welcome_pack
                .get_str("Ip")
                .or_else(|_| welcome_pack.get_str("ip"))
                .unwrap_or("");
            let port = welcome_pack
                .get_int("Port")
                .or_else(|_| welcome_pack.get_int("port"))
                .unwrap_or(self.config.port as u32) as u16;
            if !ip.is_empty() {
                self.capture_redirect_ticket(&welcome_pack);
                info!("[INFO] redirect new_host={} new_port={}", ip, port);
                return Ok(Some((ip.to_string(), port)));
            }
        }
        // 2. Modern cluster redirect: Redirect=1 plus Ip (u32 LE) and Port
        if let Ok(rflag) = welcome_pack.get_int("Redirect") {
            if rflag == 1 {
                if let Ok(ip_raw) = welcome_pack.get_int("Ip") {
                    // SoftEther appears to send IP in little-endian u32; convert to dotted quad
                    let octets = ip_raw.to_le_bytes();
                    let ipv4 = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                    let port = welcome_pack
                        .get_int("Port")
                        .unwrap_or(self.config.port as u32) as u16;
                    self.capture_redirect_ticket(&welcome_pack);
                    warn!(
                        "Server requested redirection to {}:{} (cluster)",
                        ipv4, port
                    );
                    return Ok(Some((ipv4.to_string(), port)));
                }
            }
        }

        // Extract session information; combine into one line when both are available
        let mut sess_name_opt: Option<String> = None;
        if let Ok(session_name) = welcome_pack
            .get_str("SessionName")
            .or_else(|_| welcome_pack.get_str("session_name"))
        {
            sess_name_opt = Some(session_name.to_string());
        }
        let mut conn_name_opt: Option<String> = None;
        if let Ok(cn) = welcome_pack
            .get_str("ConnectionName")
            .or_else(|_| welcome_pack.get_str("connection_name"))
        {
            conn_name_opt = Some(cn.to_string());
        }
        match (sess_name_opt.as_deref(), conn_name_opt.as_deref()) {
            (Some(s), Some(c)) => info!(
                "[INFO] session_established session_name={} connection_name={}",
                s, c
            ),
            (Some(s), None) => info!("[INFO] session_established session_name={}", s),
            (None, Some(c)) => info!("[INFO] session_established connection_name={}", c),
            (None, None) => {}
        }

        // Parse network settings (best-effort)
        let ns = self.parse_network_settings(&welcome_pack);
        if let Some(ref ns_inner) = ns {
            if let Some(ip) = ns_inner.assigned_ipv4 {
                if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                    info!("[INFO] ip_assigned ip={}", ip);
                } else {
                    debug!("ip_assigned ip={}", ip);
                }
            }
            if let (Some(ip), Some(mask)) = (ns_inner.assigned_ipv4, ns_inner.subnet_mask) {
                let bits = Self::mask_to_prefix(mask);
                if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                    info!("[INFO] ip_assigned ip={} cidr={}", ip, bits);
                } else {
                    debug!("ip_assigned ip={} cidr={}", ip, bits);
                }
            }
            if let Some(gw) = ns_inner.gateway {
                if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                    info!("[INFO] router ip={}", gw);
                } else {
                    debug!("router ip={}", gw);
                }
            }
            for d in &ns_inner.dns_servers {
                if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                    info!("[INFO] dns server={}", d);
                } else {
                    debug!("dns server={}", d);
                }
            }
            if !ns_inner.policies.is_empty() {
                debug!("{} policy entries parsed", ns_inner.policies.len());
            }
        }
        self.network_settings = ns;
        // Notify embedders that settings are available now (JSON event 1001)
        self.emit_settings_snapshot();
        // Extract server policy max connections (best-effort from policy list)
        if let Some(ref ns_inner) = self.network_settings {
            self.server_policy_max_connections = Self::extract_policy_max_connections(ns_inner);
        }
        // Record server-reported negotiated max_connection (top-level field)
        if let Ok(m) = welcome_pack
            .get_int("max_connection")
            .or_else(|_| welcome_pack.get_int("MaxConnection"))
        {
            self.server_negotiated_max_connections = Some(m);
        }
        // User-facing: negotiated max_connection matches Go/C "server_policy max_connections"
        if let Some(neg) = self.server_negotiated_max_connections {
            info!("[INFO] server_policy max_connections={}", neg);
            if let Some(pol) = self.server_policy_max_connections {
                if pol != neg {
                    debug!("policy raw MaxConnection={} (negotiated={})", pol, neg);
                }
            }
            info!("Max number of connections: {}", neg);
        }

        // Timeout (ms) reported by server welcome
        if let Ok(tmo_ms) = welcome_pack
            .get_int("timeout")
            .or_else(|_| welcome_pack.get_int("Timeout"))
        {
            let secs = (tmo_ms as f64) / 1000.0;
            if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                info!("Timeout: {:.1} seconds", secs);
            } else {
                debug!("Timeout: {:.1} seconds", secs);
            }
        }

        // Half-connection mode advertised by server
        if let Ok(hc) = welcome_pack
            .get_int("half_connection")
            .or_else(|_| welcome_pack.get_int("HalfConnection"))
        {
            if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                info!("Half-connection: {}", hc);
            } else {
                debug!("Half-connection: {}", hc);
            }
        }

        // Capture suggested server hostname for TLS SNI (helps when redirected to raw IPs)
        if let Ok(hn) = welcome_pack
            .get_str("ServerHostname")
            .or_else(|_| welcome_pack.get_str("server_hostname"))
        {
            if !hn.is_empty() {
                self.sni_host = Some(hn.to_string());
            }
        }

        // Capture session_key for bonding additional connections
        if let Ok(sk) = welcome_pack
            .get_data("session_key")
            .or_else(|_| welcome_pack.get_data("SessionKey"))
        {
            if sk.len() == 20 {
                let mut key = [0u8; 20];
                key.copy_from_slice(sk);
                self.server_session_key = Some(key);
                // Safe truncated hex preview for debugging
                let preview = key
                    .iter()
                    .take(8)
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                debug!(
                    "Captured session_key for additional connections (first16hex={})",
                    preview
                );
                info!("[INFO] session_key preview={}… (len=20)", preview);
                // Optional: print full session key when explicitly requested (diagnostics-only)
                if std::env::var("RUST_PRINT_SESSION_KEY").ok().as_deref() == Some("1") {
                    let full = key.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                    info!("[DEBUG] session_key full={}", full);
                }
            } else {
                warn!(
                    "session_key length {} != 20, skipping additional-connect bonding",
                    sk.len()
                );
            }
        } else {
            debug!("No session_key present in welcome pack");
        }

        Ok(None)
    }

    /// Open the first bulk data link by performing an additional_connect on a fresh TLS socket
    async fn open_primary_data_link(&mut self) -> Result<()> {
        let (host, port, insecure, timeout_s, sni) = (
            self.config.host.clone(),
            self.config.port,
            self.config.connection.skip_tls_verify,
            self.config.connection.timeout as u64,
            self.sni_host.clone(),
        );
        let Some(sk) = self.server_session_key else {
            anyhow::bail!("missing session_key for data link");
        };
        let dp = self
            .dataplane
            .clone()
            .ok_or_else(|| anyhow::anyhow!("dataplane not available"))?;
        // Open a new TLS connection to the target node and perform additional_connect with per-link redirect handling
        let timeout = Duration::from_secs(timeout_s);
        let mut cur_host = host.clone();
        let mut cur_port = port;
        let mut redir_attempts = 0u8;
        // Direction of this link as determined by the server (0: both, 1: c->s, 2: s->c)
        'connect_and_register: loop {
            let mut conn =
                SecureConnection::connect(&cur_host, cur_port, insecure, timeout, sni.as_deref())?;
            let _ = conn.initial_hello()?;
            // Build and send additional_connect pack
            let mut p = Pack::new();
            p.add_str("method", "additional_connect")?;
            p.add_data("session_key", sk.to_vec())?;
            p.add_str("client_str", CLIENT_STRING)?;
            p.add_int("client_ver", CLIENT_VERSION)?;
            p.add_int("client_build", CLIENT_BUILD)?;
            p.add_int("use_encrypt", 1)?;
            // Force-disable compression on data link; our dataplane doesn't implement bulk compression
            p.add_int("use_compress", 0)?;
            p.add_int(
                "half_connection",
                if self.config.connection.half_connection {
                    1
                } else {
                    0
                },
            )?;
            p.add_int("qos", 0)?;
            let resp = conn.send_pack(&p)?;
            // Handle redirect on additional_connect
            let rflag = resp
                .get_int("Redirect")
                .or_else(|_| resp.get_int("redirect"))
                .unwrap_or(0);
            if rflag != 0 {
                let mut new_host: Option<String> = None;
                if let Ok(hs) = resp
                    .get_str("RedirectHost")
                    .or_else(|_| resp.get_str("redirect_host"))
                {
                    if !hs.is_empty() {
                        new_host = Some(hs.to_string());
                    }
                }
                let new_port = resp
                    .get_int("Port")
                    .or_else(|_| resp.get_int("port"))
                    .unwrap_or(cur_port as u32) as u16;
                if new_host.is_none() {
                    if let Ok(ip_raw) = resp.get_int("Ip").or_else(|_| resp.get_int("ip")) {
                        let o = ip_raw.to_le_bytes();
                        new_host =
                            Some(std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3]).to_string());
                    }
                }
                if let Some(hh) = new_host {
                    info!(
                        "[INFO] primary_data_link redirect from={} to={}:{}",
                        cur_host, hh, new_port
                    );
                    cur_host = hh;
                    cur_port = new_port;
                    redir_attempts = redir_attempts.saturating_add(1);
                    if redir_attempts > 3 {
                        anyhow::bail!("primary_data_link too many redirects");
                    }
                    continue 'connect_and_register;
                }
            }
            if let Ok(errc) = resp.get_int("error") {
                if errc != 0 {
                    let name = Self::softether_err_name(errc as i64);
                    anyhow::bail!("additional_connect error={} ({})", errc, name);
                }
            }
            let direction = resp.get_int("direction").unwrap_or(0);
            info!(
                "[INFO] primary_data_link established host={} port={} direction={}",
                cur_host, cur_port, direction
            );
            if direction == 1 || direction == 2 {
                debug!("Server split directions across connections (half-connected)");
            }
            // Hand off TLS stream to dataplane
            let _ = conn.set_timeouts(None, None);
            let tls = conn.into_tls_stream();
            let _ = dp.register_link(tls, direction as i32);
            break;
        }
        Ok(())
    }

    /// Create client authentication structure
    pub fn create_client_auth(&self) -> Result<ClientAuth> {
        // If we possess a redirect ticket, prefer ticket auth
        if let Some(ticket) = self.redirect_ticket {
            return ClientAuth::new_ticket(&self.config.username, &ticket)
                .context("Failed to create ticket auth");
        }
        match &self.config.auth {
            AuthConfig::Anonymous => Ok(ClientAuth::new_anonymous()),
            AuthConfig::Password { hashed_password } => {
                // Expect base64 of raw 20-byte SHA1(password); we will inject directly
                let decoded = base64::prelude::BASE64_STANDARD
                    .decode(hashed_password)
                    .context("Failed to decode hashed password")?;
                if decoded.len() != 20 {
                    anyhow::bail!("Invalid password hash length");
                }
                // Build a ClientAuth with placeholder plain password then overwrite hashed_password
                let mut auth = ClientAuth::new_password(&self.config.username, "__PLACEHOLDER__")?;
                auth.plain_password.clear(); // we don't have plaintext
                auth.hashed_password.copy_from_slice(&decoded);
                auth.auth_type = AuthType::Password;
                Ok(auth)
            }
            AuthConfig::Certificate {
                cert_file,
                key_file,
            } => {
                let cert_data = std::fs::read(cert_file)
                    .with_context(|| format!("Failed to read certificate file: {}", cert_file))?;

                let key_data = std::fs::read(key_file)
                    .with_context(|| format!("Failed to read key file: {}", key_file))?;

                ClientAuth::new_certificate(&self.config.username, cert_data, key_data)
                    .context("Failed to create certificate authentication")
            }
            AuthConfig::SecureDevice {
                cert_name,
                key_name,
            } => ClientAuth::new_secure_device(&self.config.username, cert_name, key_name)
                .context("Failed to create secure device authentication"),
        }
    }

    /// Create client connection options
    fn create_client_option(&self) -> Result<ClientOption> {
        let mut option =
            ClientOption::new(&self.config.host, self.config.port, &self.config.hub_name)?
                // Force-disable compression to align with current dataplane (no bulk compression implemented)
                .with_compression(false)
                .with_udp_acceleration(self.config.connection.udp_acceleration)
                .with_max_connections(self.config.connection.max_connections);

        // HalfConnection hint
        if self.config.connection.half_connection {
            option.half_connection = true;
        }

        // Add proxy configuration if specified
        if let Some(proxy) = &self.config.connection.proxy {
            option = option.with_http_proxy(
                &proxy.host,
                proxy.port,
                proxy.username.as_deref(),
                proxy.password.as_deref(),
            )?;
        }

        // Generate host unique key
        option.generate_host_unique_key()?;

        Ok(option)
    }

    // removed: legacy create_auth_pack (unused)

    /// Perform keep-alive check
    async fn keep_alive_check(&mut self) -> Result<()> {
        if let Some(session) = &mut self.session {
            session.update_last_comm_time();

            // Update traffic statistics
            let stats = session.get_stats();
            debug!(
                "Session stats - Sent: {} bytes, Received: {} bytes",
                stats.total_send_size, stats.total_recv_size
            );
        }

        // Send a lightweight PACK keep-alive (noop) every ~50 seconds on control channel
        // Only until a dataplane link is established, to avoid control-channel read contention.
        let dp_links = self
            .dataplane
            .as_ref()
            .map(|dp| dp.summary().total_links)
            .unwrap_or(0);
        if dp_links == 0 {
            if let Some(conn) = &mut self.connection {
                let now = get_tick64();
                if self.last_noop_sent == 0
                    || now.saturating_sub(self.last_noop_sent) >= Session::KEEP_ALIVE_INTERVAL
                {
                    if let Err(e) = conn.send_noop() {
                        warn!("Keep-alive (noop) send failed: {}", e);
                    } else {
                        debug!("Keep-alive (noop) sent");
                        self.last_noop_sent = now;
                    }
                }
            }
        }

        // When tunneling mode is active, dataplane handles frequent link keep-alives

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Idle,
    Connecting,
    Established,
    Disconnecting,
}

/// Public-facing client state for embedders/FFI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    Idle = 0,
    Connecting = 1,
    Established = 2,
    Disconnecting = 3,
}

impl From<ConnectionState> for ClientState {
    fn from(s: ConnectionState) -> Self {
        match s {
            ConnectionState::Idle => ClientState::Idle,
            ConnectionState::Connecting => ClientState::Connecting,
            ConnectionState::Established => ClientState::Established,
            ConnectionState::Disconnecting => ClientState::Disconnecting,
        }
    }
}

/// Event level for embedders
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLevel {
    Info = 0,
    Warn = 1,
    Error = 2,
}

/// Event payload for embedders
#[derive(Debug, Clone)]
pub struct ClientEvent {
    pub level: EventLevel,
    pub code: i32,
    pub message: String,
}

impl VpnClient {
    fn emit_settings_snapshot(&self) {
        if let Some(tx) = &self.event_tx {
            let s = settings_json_with_kind(self.get_network_settings().as_ref(), true);
            let _ = tx.send(ClientEvent {
                level: EventLevel::Info,
                code: 1001,
                message: s,
            });
        }
    }
    fn set_state(&mut self, s: ConnectionState) {
        if self.state != s {
            debug!("connection_state: {:?} -> {:?}", self.state, s);
            self.state = s;
            if let Some(tx) = &self.state_tx {
                let _ = tx.send(ClientState::from(s));
            }
            // Also emit an informational event for state change
            let code = match s {
                ConnectionState::Idle => 100,
                ConnectionState::Connecting => 101,
                ConnectionState::Established => 102,
                ConnectionState::Disconnecting => 103,
            };
            self.emit_event(EventLevel::Info, code, format!("state: {:?}", s));
        }
    }
}

/// Resolve all IPv4 addresses for a hostname. Returns dotted-quad strings.
#[allow(dead_code)]
fn resolve_all_ips(host: &str, port: u16) -> Vec<String> {
    let mut out = Vec::new();
    let addr = format!("{}:{}", host, port);
    if let Ok(iter) = addr.to_socket_addrs() {
        for sa in iter {
            if let SocketAddr::V4(v4) = sa {
                out.push(v4.ip().to_string());
            }
        }
    }
    out
}

/// Expand a list of endpoints (hostnames or IPs) into unique IPv4 addresses, preserving order loosely.
#[allow(dead_code)]
fn expand_endpoints(endpoints: &[String], port: u16) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in endpoints {
        // If already an IPv4 address string, keep it; else resolve
        if e.parse::<std::net::Ipv4Addr>().is_ok() {
            if !out.contains(e) {
                out.push(e.clone());
            }
        } else {
            for ip in resolve_all_ips(e, port) {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

// ===== macOS interface monitor and DHCP kick (UX parity with Go client) =====
#[cfg(target_os = "macos")]
async fn monitor_darwin_interfaces(names: &[String]) {
    use log::info;
    use tokio::time::{sleep, Duration, Instant};

    let cleaned: Vec<String> = names.iter().filter(|n| !n.is_empty()).cloned().collect();
    if cleaned.is_empty() {
        return;
    }

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut printed_ip = false;
    let mut printed_router = false;

    while Instant::now() < deadline {
        sleep(Duration::from_millis(500)).await;

        for n in &cleaned {
            // Get interface info
            let v = quick_ipv4_info(n).await;

            // Print IP if valid
            if !v.ip.is_empty() && !v.ip.starts_with("169.254.") {
                if !printed_ip {
                    let bits = mask_to_cidr(&v.subnet_mask);
                    if bits > 0 {
                        info!("IP Address {}/{}", v.ip, bits);
                    } else {
                        info!("IP Address {}", v.ip);
                    }
                    printed_ip = true;
                }
            }

            // Print router if present
            if !v.router.is_empty() && !printed_router {
                info!("Router {}", v.router);
                printed_router = true;
            }

            // We intentionally avoid printing DNS/Connected here to prevent confusion
            // with system DNS or pre-VPN resolvers.
        }
    }

    // Timeout reached: only report IP; skip DNS/Connected to avoid duplicates
    if printed_ip {
        info!("Connected");
    }
}

#[cfg(target_os = "macos")]
async fn kick_dhcp_until_ip(iface: &str, timeout: std::time::Duration) {
    use tokio::time::{sleep, Duration, Instant};

    let deadline = Instant::now() + timeout;
    let mut last_kick = Instant::now();
    let kick_interval = Duration::from_secs(5);
    let mut attempts: u32 = 0;
    let max_attempts: u32 = 6; // stop after ~30 seconds total kicks

    // initial kick
    let _ = invoke_dhcp_by_name(iface).await;

    while Instant::now() < deadline {
        sleep(Duration::from_millis(500)).await;
        let v = quick_ipv4_info(iface).await;
        if !v.ip.is_empty() && !v.ip.starts_with("169.254.") {
            return;
        }
        if attempts < max_attempts
            && Instant::now().saturating_duration_since(last_kick) >= kick_interval
        {
            let _ = invoke_dhcp_by_name(iface).await;
            last_kick = Instant::now();
            attempts = attempts.saturating_add(1);
        }
        if attempts >= max_attempts {
            break;
        }
    }
}

#[cfg(target_os = "macos")]
async fn invoke_dhcp_by_name(iface: &str) -> anyhow::Result<()> {
    use tokio::process::Command;
    let _ = Command::new("ipconfig")
        .arg("set")
        .arg(iface)
        .arg("DHCP")
        .output()
        .await?;
    Ok(())
}

#[cfg(target_os = "macos")]
struct IfaceInfo {
    ip: String,
    subnet_mask: String,
    router: String,
}

#[cfg(target_os = "macos")]
async fn quick_ipv4_info(iface: &str) -> IfaceInfo {
    use tokio::process::Command;
    let mut info = IfaceInfo {
        ip: String::new(),
        subnet_mask: String::new(),
        router: String::new(),
    };
    if let Ok(out) = Command::new("ipconfig")
        .arg("getifaddr")
        .arg(iface)
        .output()
        .await
    {
        if out.status.success() {
            info.ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    // Fallback: parse ifconfig <iface> when ipconfig returns empty
    if info.ip.is_empty() {
        if let Ok(out) = Command::new("ifconfig").arg(iface).output().await {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                for line in s.lines() {
                    let l = line.trim();
                    // inet 10.0.0.12 netmask 0xffffff00 broadcast 10.0.0.255
                    if l.starts_with("inet ") {
                        let parts: Vec<&str> = l.split_whitespace().collect();
                        if parts.len() >= 2 {
                            info.ip = parts[1].to_string();
                        }
                        // Convert hex netmask to dotted-decimal if present
                        if let Some(idx) = parts.iter().position(|p| *p == "netmask") {
                            if let Some(hexmask) = parts.get(idx + 1) {
                                if hexmask.starts_with("0x") && hexmask.len() == 10 {
                                    if let Ok(v) = u32::from_str_radix(&hexmask[2..], 16) {
                                        let b = v.to_be_bytes();
                                        info.subnet_mask =
                                            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if let Ok(out) = Command::new("ipconfig")
        .arg("getoption")
        .arg(iface)
        .arg("subnet_mask")
        .output()
        .await
    {
        if out.status.success() {
            info.subnet_mask = String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    if let Ok(out) = Command::new("ipconfig")
        .arg("getoption")
        .arg(iface)
        .arg("router")
        .output()
        .await
    {
        if out.status.success() {
            info.router = String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    info
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
async fn get_all_dns_servers(_iface: &str) -> anyhow::Result<Vec<String>> {
    use tokio::process::Command;
    let out = Command::new("bash")
        .arg("-c")
        .arg(r#"scutil --dns | awk '/nameserver\[[0-9]+\]/{print $3}'"#)
        .output()
        .await?;
    if !out.status.success() {
        return Ok(vec![]);
    }
    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

#[cfg(target_os = "macos")]
// removed: get_default_router (avoid printing non-VPN default router as tunnel router)
#[cfg(target_os = "macos")]
fn mask_to_cidr(mask: &str) -> i32 {
    if mask.is_empty() {
        return 0;
    }
    let parts: Vec<&str> = mask.split('.').collect();
    if parts.len() != 4 {
        return 0;
    }
    let mut bytes = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if let Ok(n) = p.parse::<u8>() {
            bytes[i] = n;
        } else {
            return 0;
        }
    }
    let (ones, _) = std::net::Ipv4Addr::from(bytes)
        .octets()
        .into_iter()
        .fold((0u32, 0u32), |(acc, _), b| {
            (acc + (b as u8).count_ones(), 0)
        });
    ones as i32
}

impl VpnClient {
    fn capture_redirect_ticket(&mut self, pack: &Pack) {
        if let Ok(ticket) = pack.get_data("Ticket").or_else(|_| pack.get_data("ticket")) {
            if ticket.len() == 20 {
                let mut t = [0u8; 20];
                t.copy_from_slice(ticket);
                self.redirect_ticket = Some(t);
                info!("Captured redirect ticket for re-auth");
            }
        }
    }

    /// Count 1-bits in IPv4 mask to CIDR prefix length
    fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
        let octets = mask.octets();
        (octets[0].count_ones()
            + octets[1].count_ones()
            + octets[2].count_ones()
            + octets[3].count_ones()) as u8
    }

    /// Log a concise adapter and network summary once configured
    fn log_adapter_summary(&self) {
        #[cfg(feature = "adapter")]
        if let Some(ref adp) = self.adapter {
            if let Some(ref ns) = self.network_settings {
                if let Some(ip) = ns.assigned_ipv4 {
                    let bits = ns.subnet_mask.map(Self::mask_to_prefix).unwrap_or(32);
                    let gw = ns
                        .gateway
                        .map(|g| g.to_string())
                        .unwrap_or_else(|| "".to_string());
                    let dns_join = if ns.dns_servers.is_empty() {
                        "".to_string()
                    } else {
                        ns.dns_servers
                            .iter()
                            .map(|d| d.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    };
                    info!(
                        "[INFO] adapter name={} ip={}/{} gateway={} dns=[{}]",
                        adp.name(),
                        ip,
                        bits,
                        gw,
                        dns_join
                    );
                    return;
                }
            }
            // Fallback: adapter exists but we don't have IP yet
            info!("[INFO] adapter name={} (awaiting IP/DNS)", adp.name());
        }
    }

    /// Try to extract max_connections policy from parsed policies
    fn extract_policy_max_connections(ns: &NetworkSettings) -> Option<u32> {
        // Accept several common variants (case-insensitive contains)
        for (k, v) in &ns.policies {
            let kk = k.to_ascii_lowercase();
            if kk.contains("max_connection")
                || kk.contains("maxconnections")
                || kk.contains("maxconnection")
                || kk.contains("max-connection")
            {
                return Some(*v);
            }
        }
        None
    }

    /// Spawn scaffolded auxiliary link tasks up to min(server policy, config)
    fn spawn_additional_links(&mut self) {
        let cfg_max = self.config.connection.max_connections.max(1);
        let pol_max = self.server_policy_max_connections.unwrap_or(cfg_max);
        let negotiated = self.server_negotiated_max_connections.unwrap_or(cfg_max);
        let desired = cfg_max.min(pol_max).min(negotiated);
        if desired <= 1 {
            debug!("Additional links not requested (desired={})", desired);
            return;
        }
        let to_spawn = desired - 1; // minus the primary link
        info!(
            "Planning to spawn {} additional link(s) (policy={}, negotiated={}, config={})",
            to_spawn, pol_max, negotiated, cfg_max
        );

        // Require a valid session key from server to bond additional connections
        let Some(session_key) = self.server_session_key else {
            warn!("Server session_key unavailable; skipping bonded additional connections");
            return;
        };

        // Pin aux links to the same endpoint as the primary connection to avoid farm/session mismatches.
        // The server may redirect individual aux connections if needed.
        let base_host = self.config.host.clone();
        let port = self.config.port;
        let mgr = self.connection_manager.clone();
        let pool = self.connection_pool.clone();
        let dp = self.dataplane.clone();
        // Build round-robin list of ports from welcome pack if any
        let ports_rr: Vec<u16> = self
            .network_settings
            .as_ref()
            .map(|ns| {
                if ns.ports.is_empty() {
                    vec![port]
                } else {
                    ns.ports.clone()
                }
            })
            .unwrap_or_else(|| vec![port]);

        for i in 0..to_spawn {
            let name = format!("aux_link_{}", i + 1);
            let chosen_port = ports_rr[i as usize % ports_rr.len()];
            // Use the same host as the primary endpoint; allow server-side redirect to rebalance if required
            let chosen_host = base_host.clone();
            info!(
                "[INFO] additional_link starting name={} host={} port={} transport=tcp",
                name, chosen_host, chosen_port
            );
            let h = chosen_host;
            let insecure = self.config.connection.skip_tls_verify;
            let timeout_s = self.config.connection.timeout as u64;
            let client_str = CLIENT_STRING.to_string();
            let client_ver = CLIENT_VERSION;
            let client_build = CLIENT_BUILD;
            let sk = session_key; // copy for move
            let dirs = self.aux_directions.clone();
            let mgr2 = mgr.clone();
            let pool2 = pool.clone();
            let dp2 = dp.clone();
            // Force-disable compression to match dataplane framing (same as primary link)
            let use_compress = false;
            let half_conn = self.config.connection.half_connection;
            let sni = self.sni_host.clone();
            let start_stagger_ms = 250u64 * (i as u64);
            let handle = tokio::spawn(async move {
                // Stagger starts slightly to avoid server-side burst
                if start_stagger_ms > 0 {
                    sleep(Duration::from_millis(start_stagger_ms)).await;
                }
                // Establish TLS and perform additional_connect with per-link redirect handling
                let timeout = Duration::from_secs(timeout_s);
                let mut cur_host = h.clone();
                let mut cur_port = chosen_port;
                let mut redir_attempts = 0u8;
                let mut attempts: u32 = 0;
                let max_attempts: u32 = 8;
                let mut backoff_ms: u64 = 200;
                'connect_and_register: loop {
                    if attempts >= max_attempts {
                        warn!(
                            "additional_link giving up after {} attempts name={} host={} port={}",
                            attempts, name, cur_host, cur_port
                        );
                        break;
                    }
                    attempts = attempts.saturating_add(1);
                    let conn_res = SecureConnection::connect(
                        &cur_host,
                        cur_port,
                        insecure,
                        timeout,
                        sni.as_deref(),
                    );
                    let mut conn = match conn_res {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(
                                "additional_link connect failed attempt={} name={} host={} port={} err={}",
                                attempts, name, cur_host, cur_port, e
                            );
                            sleep(Duration::from_millis(backoff_ms)).await;
                            backoff_ms = (backoff_ms * 2).min(3000);
                            continue 'connect_and_register;
                        }
                    };
                    if let Err(e) = conn.initial_hello() {
                        warn!(
                            "additional_link hello failed attempt={} name={} host={} err={}",
                            attempts, name, cur_host, e
                        );
                        sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(3000);
                        continue 'connect_and_register;
                    }
                    // Build additional_connect pack each attempt
                    let mut p = Pack::new();
                    if let Err(e) = (|| -> anyhow::Result<()> {
                        p.add_str("method", "additional_connect")?;
                        p.add_data("session_key", sk.to_vec())?;
                        p.add_str("client_str", &client_str)?;
                        p.add_int("client_ver", client_ver)?;
                        p.add_int("client_build", client_build)?;
                        p.add_int("use_encrypt", 1)?;
                        p.add_int("use_compress", use_compress as u32)?;
                        p.add_int("half_connection", if half_conn { 1 } else { 0 })?;
                        p.add_int("qos", 0)?;
                        Ok(())
                    })() {
                        warn!("additional_link pack build failed name={} err={}", name, e);
                        break;
                    }

                    match conn.send_pack(&p) {
                        Ok(resp) => {
                            // Check for redirect on additional_connect
                            let rflag = resp
                                .get_int("Redirect")
                                .or_else(|_| resp.get_int("redirect"))
                                .unwrap_or(0);
                            if rflag != 0 {
                                // Prefer RedirectHost; else Ip (u32 LE) + Port
                                let mut new_host: Option<String> = None;
                                if let Ok(hs) = resp
                                    .get_str("RedirectHost")
                                    .or_else(|_| resp.get_str("redirect_host"))
                                {
                                    if !hs.is_empty() {
                                        new_host = Some(hs.to_string());
                                    }
                                }
                                let new_port = resp
                                    .get_int("Port")
                                    .or_else(|_| resp.get_int("port"))
                                    .unwrap_or(cur_port as u32)
                                    as u16;
                                if new_host.is_none() {
                                    if let Ok(ip_raw) =
                                        resp.get_int("Ip").or_else(|_| resp.get_int("ip"))
                                    {
                                        let o = ip_raw.to_le_bytes();
                                        new_host = Some(
                                            std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3])
                                                .to_string(),
                                        );
                                    }
                                }
                                if let Some(hh) = new_host {
                                    info!(
                                        "[INFO] additional_link redirect name={} from={} to={}:{}",
                                        name, cur_host, hh, new_port
                                    );
                                    cur_host = hh;
                                    cur_port = new_port;
                                    redir_attempts = redir_attempts.saturating_add(1);
                                    if redir_attempts > 3 {
                                        warn!("additional_link too many redirects name={} host={} port={}", name, cur_host, cur_port);
                                        break;
                                    }
                                    // retry with new target
                                    continue 'connect_and_register;
                                }
                            }
                            if let Ok(errc) = resp.get_int("error") {
                                if errc != 0 {
                                    let en = VpnClient::softether_err_name(errc as i64);
                                    warn!(
                                        "additional_connect error={} ({}) attempt={} name={} host={} port={}",
                                        errc, en, attempts, name, cur_host, cur_port

                                    );
                                    // Retry some transient errors like ERR_SESSION_TIMEOUT
                                    if errc == 13 {
                                        // ERR_SESSION_TIMEOUT
                                        sleep(Duration::from_millis(backoff_ms)).await;
                                        backoff_ms = (backoff_ms * 2).min(3000);
                                        continue 'connect_and_register;
                                    }
                                    // Fatal: don't retry
                                    break;
                                }
                            }
                            let direction = resp.get_int("direction").unwrap_or(0);
                            info!("[INFO] additional_link established name={} host={} port={} direction={}", name, cur_host, cur_port, direction);
                            if direction == 1 || direction == 2 {
                                debug!(
                                    "Server split directions across connections (half-connected)"
                                );
                            }
                            // Record direction
                            {
                                let mut g = dirs.lock().unwrap();
                                g.push(direction as i32);
                            }
                            // Register with the connection manager for global summary
                            let _bond_handle = mgr2.register_bond(direction as i32);
                            // Disable timeouts so idle sockets are not closed by client side
                            let _ = conn.set_timeouts(None, None);
                            // Hand off the TLS stream into dataplane/pool
                            let tls = conn.into_tls_stream();
                            if let Some(dp) = dp2.as_ref() {
                                let _ = dp.register_link(tls, direction as i32);
                            } else {
                                let _ = pool2.register_link(tls, direction as i32);
                            }
                            // Hold the connection open
                            loop {
                                sleep(Duration::from_secs(60)).await;
                            }
                        }
                        Err(e) => {
                            warn!(
                                "additional_link auth failed name={} host={} port={} err={}",
                                name, cur_host, cur_port, e
                            );
                            break;
                        }
                    }
                }
            });
            self.aux_tasks.push(handle);
        }
    }

    /// Periodically log a connections summary (primary + additional directions)
    fn start_connections_summary_logger(&mut self) {
        let mgr = self.connection_manager.clone();
        let dp_opt = self.dataplane.as_ref().cloned();
        let handle = tokio::spawn(async move {
            use tokio::time::{sleep, Duration};
            loop {
                sleep(Duration::from_secs(30)).await;
                // Prefer the connection manager's bookkeeping when available
                let s = mgr.summary();
                let total = 1 + s.total;
                let extra = if let Some(ref dp) = dp_opt {
                    let dps = dp.summary();
                    format!(
                        " tx_bytes={}, rx_bytes={}, dp_links={}",
                        dps.total_tx, dps.total_rx, dps.total_links
                    )
                } else {
                    String::new()
                };
                if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                    info!("[INFO] connections summary: total={} primary=1 additional={} split={{c2s:{}, s2c:{}, both:{}}}{}", total, s.total, s.c2s, s.s2c, s.both, extra);
                } else {
                    debug!("connections summary: total={} primary=1 additional={} split={{c2s:{}, s2c:{}, both:{}}}{}", total, s.total, s.c2s, s.s2c, s.both, extra);
                }
            }
        });
        self.aux_tasks.push(handle);
    }

    /// Start the utun adapter and bi-directional bridging between the adapter and the session/dataplane
    async fn start_adapter_and_bridge(&mut self) -> Result<()> {
        #[cfg(not(feature = "adapter"))]
        {
            // No adapter bridging when the adapter feature is disabled
            self.bridge_ready = false;
            return Ok(());
        }
        // Ensure adapter exists
        #[cfg(feature = "adapter")]
        if self.adapter.is_none() {
            let name = self.config.client.interface_name.clone();
            self.adapter = Some(VirtualAdapter::new(name, None));
            if let Some(adp) = &mut self.adapter {
                adp.create().await?;
            }
        }

        // Get IO handle (macOS) – only when adapter feature is enabled
        #[cfg(all(target_os = "macos", feature = "adapter"))]
        let io = {
            let adp = self.adapter.as_ref().expect("adapter");
            adp.io_handle()?
        };

        // Prefer bridging via dataplane if available to avoid taking session.packet_rx
        let dp_opt = self.dataplane.clone();
        if dp_opt.is_none() {
            warn!("Dataplane not initialized; skipping adapter bridging");
            return Ok(());
        }
        let dp = dp_opt.unwrap();
        // Create adapter<->dataplane channels
        let (adp_to_dp_tx, adp_to_dp_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (dp_to_adp_tx, mut dp_to_adp_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        // Register with dataplane
        dp.set_adapter_tx(adp_to_dp_rx); // adapter -> session/dataplane
        dp.set_adapter_rx(dp_to_adp_tx); // session/dataplane -> adapter

        // Task: adapter -> session (read packets from utun and send into session)
        #[cfg(all(target_os = "macos", feature = "adapter"))]
        {
            let io_r = io.clone();
            let tx = adp_to_dp_tx.clone();
            // Generate a stable locally-administered MAC used when wrapping DHCP IP packets into Ethernet frames
            let mut mac = [0u8; 6];
            rand::rng().fill_bytes(&mut mac);
            mac[0] = (mac[0] & 0b1111_1110) | 0b0000_0010; // locally administered, unicast
            let src_mac = mac;
            // Generate a locally-administered MAC for use as source in wrapped Ethernet frames
            fn ip_to_eth_if_dhcp(ip: &[u8], src_mac: [u8; 6]) -> Option<Vec<u8>> {
                if ip.len() < 20 {
                    return None;
                }
                let ver_ihl = ip[0];
                if (ver_ihl >> 4) != 4 {
                    return None;
                } // IPv4 only
                let ihl = (ver_ihl & 0x0f) as usize * 4;
                if ihl < 20 || ip.len() < ihl + 8 {
                    return None;
                }
                let proto = ip[9];
                if proto != 17 {
                    return None;
                } // UDP only
                let src_port = u16::from_be_bytes([ip[ihl], ip[ihl + 1]]);
                let dst_port = u16::from_be_bytes([ip[ihl + 2], ip[ihl + 3]]);
                let _dst_ip = &ip[16..20];
                let is_dhcp =
                    (src_port == 67 || src_port == 68) || (dst_port == 67 || dst_port == 68);
                if !is_dhcp {
                    return None;
                }
                let mut frame = Vec::with_capacity(14 + ip.len());
                // dest mac: broadcast for DHCP
                frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
                frame.extend_from_slice(&src_mac);
                frame.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType IPv4
                frame.extend_from_slice(ip);
                Some(frame)
            }
            let h = tokio::spawn(async move {
                loop {
                    match io_r.read().await {
                        Ok(Some(frame)) => {
                            // frame from utun is an IP packet; wrap to Ethernet only for DHCP to allow server-side DHCP to work
                            if let Some(eth) = ip_to_eth_if_dhcp(&frame, src_mac) {
                                let _ = tx.send(eth);
                            } else {
                                // Non-DHCP IP packets cannot be expressed on Ethernet without ARP/neighbor; drop here
                            }
                        }
                        Ok(None) => {
                            // timeout; loop to check for shutdown
                            continue;
                        }
                        Err(e) => {
                            warn!("adapter->session read error: {}", e);
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                    }
                }
            });
            self.aux_tasks.push(h);
        }

        // Task: session -> adapter (read frames emitted by session and write to utun)
        #[cfg(all(target_os = "macos", feature = "adapter"))]
        {
            let io_w = io.clone();
            // Helper: strip Ethernet header if IPv4 and return IP payload
            fn eth_to_ipv4(frame: &[u8]) -> Option<Vec<u8>> {
                if frame.len() < 14 {
                    return None;
                }
                let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
                if ether_type != 0x0800 {
                    return None;
                }
                Some(frame[14..].to_vec())
            }
            let h = tokio::spawn(async move {
                while let Some(frame) = dp_to_adp_rx.recv().await {
                    // Convert SoftEther L2 frame to utun L3 IP packet when possible
                    if let Some(ipv4) = eth_to_ipv4(&frame) {
                        if let Err(e) = io_w.write(&ipv4).await {
                            warn!("session->adapter write error: {}", e);
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                    } else {
                        // Drop non-IPv4 frames (e.g., ARP) as utun can't carry them
                        // Optionally: add logging at debug level
                        // debug!("Dropped non-IPv4 Ethernet frame len={}", frame.len());
                    }
                }
            });
            self.aux_tasks.push(h);
        }

        // Mark bridge as ready once channels/tasks are established
        self.bridge_ready = true;
        Ok(())
    }

    /// Parse network settings and policy values from the welcome/auth response pack.
    fn parse_network_settings(&self, pack: &Pack) -> Option<NetworkSettings> {
        let mut ns = NetworkSettings::default();

        // Assigned IPv4 address (SoftEther packs use u32; appears little-endian for typical servers)
        if let Ok(ip_raw) = pack
            .get_int("ClientIpAddress")
            .or_else(|_| pack.get_int("client_ip_address"))
        {
            let octets = ip_raw.to_le_bytes();
            ns.assigned_ipv4 = Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
        }

        // Subnet mask
        if let Ok(mask_raw) = pack
            .get_int("ClientIpSubnetMask")
            .or_else(|_| pack.get_int("ClientSubnetMask"))
        {
            let o = mask_raw.to_le_bytes();
            ns.subnet_mask = Some(Ipv4Addr::new(o[0], o[1], o[2], o[3]));
        }

        // Gateway
        if let Ok(gw_raw) = pack
            .get_int("ClientGatewayAddress")
            .or_else(|_| pack.get_int("ClientGateway"))
        {
            let o = gw_raw.to_le_bytes();
            ns.gateway = Some(Ipv4Addr::new(o[0], o[1], o[2], o[3]));
        }

        // DNS servers: attempt common field name patterns
        for key in [
            "DnsServerAddress",
            "DnsServerAddress2",
            "DnsServer1",
            "DnsServer2",
        ]
        .iter()
        {
            if let Ok(dns_raw) = pack.get_int(key) {
                let o = dns_raw.to_le_bytes();
                ns.dns_servers.push(Ipv4Addr::new(o[0], o[1], o[2], o[3]));
            }
        }

        // Collect multi-port list if present (element name 'port')
        for el in &pack.elements {
            if el.name.eq_ignore_ascii_case("port") {
                for v in &el.values {
                    let p = v.int_value as u16;
                    if p != 0 {
                        ns.ports.push(p);
                    }
                }
            }
        }

        // Policies: element names prefixed with "policy:" in server debug logs. We record all ints with that prefix.
        for el in &pack.elements {
            if el.name.starts_with("policy:") && el.value_type == mayaqua::pack::ValueType::Int {
                if let Some(first) = el.values.first() {
                    ns.policies.push((el.name.clone(), first.int_value));
                }
            }
        }

        if ns.assigned_ipv4.is_none() && ns.dns_servers.is_empty() && ns.policies.is_empty() {
            return None; // nothing meaningful parsed
        }
        Some(ns)
    }

    /// Apply parsed network settings to a platform virtual adapter (macOS / Linux only for now)
    async fn apply_network_settings(&mut self) -> Result<()> {
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            return Ok(()); // other platforms not yet implemented
        }

        // On macOS, creating a utun interface requires root privileges. Proactively warn if not root.
        #[cfg(target_os = "macos")]
        {
            let euid = unsafe { libc::geteuid() };
            if euid != 0 {
                // Give an actionable hint so users can actually see interface info logs.
                warn!(
                    "Insufficient privileges to create utun (need root). Run the binary with sudo: sudo target/debug/softether-vpn-client --config config.json connect"
                );
            }
        }

        let ns = match &self.network_settings {
            Some(n) => n.clone(),
            None => {
                #[cfg(feature = "adapter")]
                {
                    // Even if we couldn't parse settings, ensure adapter exists and start macOS monitor best-effort
                    if self.adapter.is_none() {
                        let name = self.config.client.interface_name.clone();
                        self.adapter = Some(VirtualAdapter::new(name, None));
                        if let Some(adp) = &mut self.adapter {
                            adp.create().await?;
                        }
                    }
                }
                #[cfg(all(target_os = "macos", feature = "adapter"))]
                {
                    #[cfg(feature = "adapter")]
                    if self.bridge_ready && !self.dhcp_spawned {
                        if let Some(adp) = &self.adapter {
                            let ifname = adp.name().to_string();
                            // Kick DHCP and start monitor to surface IP/DNS when it appears
                            let ifname2 = ifname.clone();
                            let h1 = tokio::spawn(async move {
                                kick_dhcp_until_ip(&ifname, Duration::from_secs(25)).await;
                            });
                            let h2 = tokio::spawn(async move {
                                monitor_darwin_interfaces(&[ifname2]).await;
                            });
                            self.aux_tasks.push(h1);
                            self.aux_tasks.push(h2);
                            self.dhcp_spawned = true;
                        }
                    }
                }
                return Ok(());
            }
        };
        let no_routing = ns
            .policies
            .iter()
            .any(|(k, v)| k.to_ascii_lowercase().contains("norouting") && *v != 0);
        // Always ensure the adapter exists so we can configure and/or monitor
        #[cfg(feature = "adapter")]
        if self.adapter.is_none() {
            let name = self.config.client.interface_name.clone();
            self.adapter = Some(VirtualAdapter::new(name, None));
            if let Some(adp) = &mut self.adapter {
                adp.create().await?;
            }
        }
        #[cfg(feature = "adapter")]
        let adapter = self.adapter.as_ref().unwrap();

        // Configure IP/mask on the adapter when provided by server; otherwise start DHCP/monitoring on macOS
        let ip = match ns.assigned_ipv4 {
            Some(i) => i,
            None => {
                #[cfg(all(target_os = "macos", feature = "adapter"))]
                {
                    if self.bridge_ready && !self.dhcp_spawned {
                        let ifname = adapter.name().to_string();
                        let ifname2 = ifname.clone();
                        let h1 = tokio::spawn(async move {
                            kick_dhcp_until_ip(&ifname, Duration::from_secs(25)).await;
                        });
                        let h2 = tokio::spawn(async move {
                            monitor_darwin_interfaces(&[ifname2]).await;
                        });
                        self.aux_tasks.push(h1);
                        self.aux_tasks.push(h2);
                        self.dhcp_spawned = true;
                    }
                }
                return Ok(());
            }
        };
        let mask = ns
            .subnet_mask
            .unwrap_or_else(|| Ipv4Addr::new(255, 255, 255, 255));

        if no_routing {
            info!("Server policy 'NoRouting' detected; skipping default route changes");
            info!("[INFO] network_settings_applying (passive)");
        } else {
            info!("[INFO] network_settings_applying");
        }

        #[cfg(feature = "adapter")]
        adapter
            .set_ip_address(&ip.to_string(), &mask.to_string())
            .await?;

        // Parity logs similar to third-party client
        let cidr = Self::mask_to_prefix(mask);
        #[cfg(feature = "adapter")]
        info!("Interface {}: {}/{}", adapter.name(), ip, cidr);

        // Only add default route when routing is allowed
        if !no_routing {
            if let Some(gw) = ns.gateway {
                #[cfg(feature = "adapter")]
                let _ = adapter
                    .add_route("0.0.0.0/0", &gw.to_string())
                    .await
                    .map_err(|e| {
                        warn!("Failed to add default route: {}", e);
                        e
                    });
                info!("Add IPv4 default route");
            }
        }

        // Include route: subnet derived from ip & mask (informational)
        let net = std::net::Ipv4Addr::from(u32::from(ip) & u32::from(mask));
        info!("Include route: {}/{}", net, cidr);

        // Best-effort MTU set to 1500
        #[cfg(target_os = "macos")]
        {
            use tokio::process::Command;
            #[cfg(feature = "adapter")]
            let _ = Command::new("ifconfig")
                .arg(adapter.name())
                .arg("mtu")
                .arg("1500")
                .output()
                .await;
        }
        #[cfg(target_os = "linux")]
        {
            use tokio::process::Command;
            #[cfg(feature = "adapter")]
            {
                let _ = Command::new("ip")
                    .arg("link")
                    .arg("set")
                    .arg("dev")
                    .arg(adapter.name())
                    .arg("mtu")
                    .arg("1500")
                    .output()
                    .await;
            }
        }
        info!("MTU set to 1500");
        info!("[INFO] connected");

        if !ns.dns_servers.is_empty() {
            #[cfg(target_os = "linux")]
            {
                if self.config.connection.apply_dns {
                    use tokio::process::Command;
                    let content = ns
                        .dns_servers
                        .iter()
                        .map(|d| format!("nameserver {}\n", d))
                        .collect::<String>();
                    let output = Command::new("bash")
                        .arg("-c")
                        .arg(format!(
                            "printf '{}' | sudo tee /etc/resolv.conf > /dev/null",
                            content.replace("'", "'\\''")
                        ))
                        .output()
                        .await?;
                    if !output.status.success() {
                        warn!(
                            "Failed to apply DNS to /etc/resolv.conf: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                    } else {
                        info!("Applied DNS servers to /etc/resolv.conf");
                    }
                } else {
                    info!(
                        "(Linux) To apply DNS: echo -e 'nameserver {}' | sudo tee /etc/resolv.conf",
                        ns.dns_servers
                            .iter()
                            .map(|d| d.to_string())
                            .collect::<Vec<_>>()
                            .join("\\n")
                    );
                }
            }
            #[cfg(target_os = "macos")]
            {
                if self.config.connection.apply_dns {
                    // networksetup needs a service name; we try to infer it from interface name using 'networksetup -listnetworkserviceorder' (best-effort)
                    use tokio::process::Command;
                    let mut service_name: Option<String> =
                        self.config.client.macos_dns_service_name.clone();
                    if service_name.is_none() {
                        // Try a heuristic: if the interface appears in listnetworkserviceorder, suggest Wi-Fi as common
                        let list = Command::new("bash")
                            .arg("-c")
                            .arg("networksetup -listnetworkserviceorder | sed -n 's/.*Device: (\\(.*\\)).*/\\1/p'")
                            .output()
                            .await?;
                        let iface = self.config.client.interface_name.clone();
                        let services = String::from_utf8_lossy(&list.stdout);
                        if services.contains(&iface) {
                            service_name = Some("Wi-Fi".to_string());
                        }
                    }
                    if let Some(svc) = service_name {
                        let args = ns
                            .dns_servers
                            .iter()
                            .map(|d| d.to_string())
                            .collect::<Vec<_>>()
                            .join(" ");
                        let cmd = format!(
                            "networksetup -setdnsservers '{}' {}",
                            svc.replace("'", "'\\''"),
                            args
                        );
                        let out = Command::new("bash").arg("-c").arg(&cmd).output().await?;
                        if !out.status.success() {
                            warn!(
                                "Failed to apply macOS DNS: {}",
                                String::from_utf8_lossy(&out.stderr)
                            );
                        } else {
                            info!("Applied DNS servers to service '{}'", svc);
                        }
                    } else {
                        info!("(macOS) DNS servers suggested: {} (manual apply with: networksetup -setdnsservers <ServiceName> <servers> )", ns.dns_servers.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", "));
                    }
                } else {
                    info!("(macOS) DNS servers suggested: {} (manual apply with: networksetup -setdnsservers <ServiceName> <servers> )", ns.dns_servers.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", "));
                }
            }
        }

        // Spawn macOS interface/DNS monitor to mirror Go/C UX prints (best-effort)
        #[cfg(target_os = "macos")]
        {
            #[cfg(feature = "adapter")]
            {
                let ifname = adapter.name().to_string();
                let h = tokio::spawn(async move {
                    monitor_darwin_interfaces(&[ifname]).await;
                });
                self.aux_tasks.push(h);
            }
        }

        Ok(())
    }
}

/// Session statistics
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub connection_time: u64,
    pub is_connected: bool,
    pub protocol: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VpnConfig;

    #[test]
    fn test_vpn_client_creation() -> Result<()> {
        let config =
            VpnConfig::new_anonymous("test.example.com".to_string(), 443, "TEST".to_string());

        let client = VpnClient::new(config)?;
        assert!(!client.is_connected());
        assert!(client.get_stats().is_none());

        Ok(())
    }

    // removed tests that referenced legacy create_auth_pack
}
