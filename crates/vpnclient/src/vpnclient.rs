//! Main VPN client implementation
mod adapter_bridge;
mod auth;
mod connection;
mod links;
mod network_config;
mod policy;

use anyhow::Result;
use cedar::constants::{MAX_RETRY_INTERVAL_MS, MIN_RETRY_INTERVAL_MS};
use cedar::{ConnectionManager, ConnectionPool, DataPlane, EngineConfig, SessionManager};
#[cfg(target_os = "ios")]
use rand::RngCore;
use tracing::{debug, error, info, warn}; // for fill_bytes in iOS DHCP path
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
use cedar::{Session, SessionConfig};
// use mayaqua::Pack; // not needed here post-refactor
use std::time::Duration;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::config::{AuthConfig, VpnConfig};
use crate::dhcp::DhcpClient;
// use crate::dhcp::Lease as DhcpLease;
use crate::network::SecureConnection;
#[cfg(feature = "adapter")]
use adapter::VirtualAdapter;
use config as shared_config;
// use mayaqua::get_tick64; // moved to connection module
use mayaqua::crypto::softether_password_hash; // SHA-0(password + UPPER(username))
                                              // use std::net::Ipv4Addr; // only used in network module

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
    #[allow(dead_code)]
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

use crate::types::{mask_to_prefix, network_settings_from_lease, settings_json_with_kind};
use crate::types::{ClientEvent, ClientState, EventLevel, NetworkSettings, SessionStats};

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

                    // Fallback: after 6s without success, nudge macOS DHCP in parallel
                    let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
                    let ifname_kick = ifname.clone();
                    let fallback = tokio::spawn(async move {
                        let delay = Duration::from_secs(6);
                        let timed_out = tokio::time::timeout(delay, &mut cancel_rx).await.is_err();
                        if timed_out {
                            crate::vpnclient::network_config::kick_dhcp_until_ip(
                                &ifname_kick,
                                Duration::from_secs(20),
                            ).await;
                        }
                    });
                    let lease = dhcp
                        .run_once(&ifname, Duration::from_secs(30))
                        .await
                        .ok()
                        .flatten();
                    if let Some(lease) = lease {
                    let _ = cancel_tx.send(());
                    // Best-effort: avoid a dangling task if not used
                    if fallback.is_finished() == false {
                        self.aux_tasks.push(fallback);
                    }
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

    // auth-related methods moved to vpnclient/auth.rs
    // connection keepalive/establish moved to vpnclient/connection.rs
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Idle,
    Connecting,
    Established,
    Disconnecting,
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

// endpoint helpers moved to vpnclient/connection.rs

// macOS helpers moved to vpnclient/network_config.rs

impl VpnClient {
    // moved to vpnclient/auth.rs: capture_redirect_ticket

    /// Log a concise adapter and network summary once configured
    fn log_adapter_summary(&self) {
        #[cfg(feature = "adapter")]
        if let Some(ref adp) = self.adapter {
            if let Some(ref ns) = self.network_settings {
                if let Some(ip) = ns.assigned_ipv4 {
                    let bits = ns.subnet_mask.map(mask_to_prefix).unwrap_or(32);
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

    // policy helpers moved to vpnclient/policy.rs

    // network parsing/apply moved to vpnclient/network_config.rs
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
