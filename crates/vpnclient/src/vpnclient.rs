//! Main VPN client implementation
// Deprecated VpnConfig removed; unified RuntimeConfig in use

use anyhow::Result;
use cedar::constants::{MAX_RETRY_INTERVAL_MS, MIN_RETRY_INTERVAL_MS};
use cedar::{ConnectionManager, ConnectionPool, DataPlane, EngineConfig, SessionManager};
#[cfg(target_os = "ios")]
use rand::RngCore;
use tracing::{debug, error, info, warn}; // for fill_bytes in iOS DHCP path
#[cfg(unix)]
pub(crate) fn local_hostname() -> String {
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
pub(crate) fn local_hostname() -> String {
    "unknown".to_string()
}
use cedar::{Session, SessionConfig};
// use mayaqua::Pack; // not needed here post-refactor
use std::time::Duration;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::config::RuntimeConfig;
// use crate::dhcp::Lease as DhcpLease;
use crate::network::SecureConnection;
use crate::shared_config as shared_config;
// use mayaqua::get_tick64; // moved to connection module
// softether_password_hash now handled in RuntimeConfig conversion
                                              // use std::net::Ipv4Addr; // only used in network module

/// SoftEther VPN Client
pub struct VpnClient {
    pub(crate) config: RuntimeConfig,
    pub(crate) connection: Option<SecureConnection>,
    pub(crate) session: Option<Session>,
    pub(crate) session_manager: SessionManager,
    #[allow(dead_code)]
    pub(crate) connection_manager: ConnectionManager,
    #[allow(dead_code)]
    pub(crate) connection_pool: ConnectionPool,
    pub(crate) dataplane: Option<DataPlane>,
    pub(crate) is_connected: bool,
    pub redirect_ticket: Option<[u8; 20]>,
    pub(crate) network_settings: Option<NetworkSettings>,
    // Newly integrated raw TUN device (replaces old adapter abstraction)
    pub(crate) tun: Option<tun_rs::SyncDevice>,
    pub(crate) server_policy_max_connections: Option<u32>,
    pub(crate) server_negotiated_max_connections: Option<u32>,
    pub(crate) aux_tasks: Vec<JoinHandle<()>>,
    pub(crate) server_session_key: Option<[u8; 20]>,
    pub(crate) aux_directions: std::sync::Arc<std::sync::Mutex<Vec<i32>>>,
    pub(crate) endpoints_rr: Vec<String>,
    pub(crate) sni_host: Option<String>,
    state: ConnectionState,
    pub(crate) last_noop_sent: u64,
    #[allow(dead_code)]
    pub(crate) server_timeout_ms: Option<u32>,
    pub(crate) dhcp_spawned: bool,
    pub(crate) state_tx: Option<mpsc::UnboundedSender<ClientState>>,
    pub(crate) event_tx: Option<mpsc::UnboundedSender<ClientEvent>>,
}

use crate::types::settings_json_with_kind;
use crate::types::{ClientEvent, ClientState, EventLevel, NetworkSettings, SessionStats};
use tun_rs::DeviceBuilder;

impl VpnClient {
    /// Best-effort mapping of common SoftEther error codes to names for logs
    pub(crate) fn softether_err_name(code: i64) -> &'static str {
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
        let runtime = RuntimeConfig::try_from(cc)?; // performs validation & hashing
        Self::new_runtime(runtime)
    }
    /// Create a new VPN client with the given configuration
    #[allow(deprecated)]
    pub fn new_runtime(runtime: RuntimeConfig) -> Result<Self> {
        // Prepare RR endpoints list before moving config
        let endpoints_rr = vec![runtime.host.clone()];
        Ok(Self {
            config: runtime,
            connection: None,
            session: None,
            session_manager: SessionManager::new(EngineConfig::default()),
            connection_manager: ConnectionManager::new(),
            connection_pool: ConnectionPool::new(),
            dataplane: None,
            is_connected: false,
            redirect_ticket: None,
            network_settings: None,
            tun: None,
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
                            format!("connect attempt {attempt} failed: {e}"),
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
                            format!("timeout on attempt {attempt}"),
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
            // Create a TUN device if not already created
            if self.tun.is_none() {
                match DeviceBuilder::new()
                    .name(self.config.client.interface_name.clone())
                    .mtu(1500)
                    .build_sync() {
                        Ok(dev) => {
                            info!("Created TUN interface: {}", self.config.client.interface_name);
                            self.tun = Some(dev);
                        }
                        Err(e) => {
                            warn!("Failed to create TUN interface: {}", e);
                        }
                    }
            }
            // Apply DHCP timing from config via environment overrides consumed by dhcp.rs
            std::env::set_var(
                "RUST_DHCP_SETTLE_MS",
                self.config.client.dhcp_settle_ms.to_string(),
            );
            std::env::set_var(
                "RUST_DHCP_DISCOVER_INITIAL_MS",
                self.config.client.dhcp_initial_ms.to_string(),
            );
            std::env::set_var(
                "RUST_DHCP_DISCOVER_MAX_MS",
                self.config.client.dhcp_max_ms.to_string(),
            );
            std::env::set_var(
                "RUST_DHCP_JITTER_PCT",
                format!("{}", self.config.client.dhcp_jitter_pct),
            );
            self.emit_event(EventLevel::Info, 220, "tunnel opened");
            // Establish the first bulk data link via additional_connect before bridging/DHCP
            if let Err(e) = self.open_primary_data_link().await {
                error!("Failed to establish primary data link: {}", e);
                return Err(e);
            }
            // Create adapter and start bridging so DHCP can flow
            // Bridging via old adapter removed; future: integrate direct tun-rs dataplane if needed
            // If server did not push IP settings, attempt an in-tunnel DHCP negotiation (all platforms supporting rand/tun)
            if self
                .network_settings
                .as_ref()
                .and_then(|n| n.assigned_ipv4)
                .is_none()
            {
                if let Some(dp) = self.dataplane.clone() {
                    // wait briefly for at least one TX-capable link
                    let start = std::time::Instant::now();
                    while dp.summary().total_links == 0 && start.elapsed() < Duration::from_secs(3) {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    let mut mac = [0u8; 6];
                    #[allow(unused_mut)]
                    let mut rng = rand::rng();
                    use rand::RngCore;
                    rng.fill_bytes(&mut mac);
                    mac[0] = (mac[0] & 0b1111_1110) | 0b0000_0010; // locally administered unicast
                    let mut dhcp = crate::dhcp::DhcpClient::new(dp, mac);
                    info!("Attempting DHCP over tunnel");
                    match dhcp.run_once(&self.config.client.interface_name, Duration::from_secs(30)).await {
                        Ok(Some(lease)) => {
                            self.network_settings = Some(crate::types::network_settings_from_lease(&lease));
                            self.emit_settings_snapshot();
                            info!("DHCP lease acquired: {}", lease.client_ip);
                        }
                        Ok(None) => warn!("No DHCP offer/ack within timeout"),
                        Err(e) => warn!("DHCP negotiation failed: {e}"),
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

        // Tear down TUN interface (best-effort)
        if let Some(_tun) = self.tun.take() {
            #[cfg(target_os = "linux")]
            {
                use tokio::process::Command;
                let _ = Command::new("ip")
                    .arg("link")
                    .arg("set")
                    .arg(self.config.client.interface_name.clone())
                    .arg("down")
                    .output()
                    .await;
            }
            #[cfg(target_os = "macos")]
            {
                use tokio::process::Command;
                let _ = Command::new("ifconfig")
                    .arg(self.config.client.interface_name.clone())
                    .arg("down")
                    .output()
                    .await;
            }
        }

        // Abort auxiliary tasks
        for handle in self.aux_tasks.drain(..) {
            handle.abort();
        }

        // Tear down virtual adapter (utun)
    // No adapter teardown needed after removing adapter integration

        self.is_connected = false;
        // Reset connection-scoped flags
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
    pub(crate) fn emit_settings_snapshot(&self) {
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
            self.emit_event(EventLevel::Info, code, format!("state: {s:?}"));
        }
    }
}

// endpoint helpers moved to vpnclient/connection.rs

// macOS helpers moved to vpnclient/network_config.rs

impl VpnClient {
    // moved to vpnclient/auth.rs: capture_redirect_ticket

    /// Log a concise adapter and network summary once configured
    fn log_adapter_summary(&self) {
    // Adapter summary removed; retain network settings logs via existing events
    }

    // policy helpers moved to vpnclient/policy.rs

    // network parsing/apply moved to vpnclient/network_config.rs
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vpn_client_creation() -> Result<()> {
        let shared = crate::shared_config::ClientConfig {
            server: "test.example.com".into(),
            port: 443,
            hub: "TEST".into(),
            username: "anonymous".into(),
            password: None,
            password_hash: None,
            skip_tls_verify: false,
            use_compress: false,
            use_encrypt: true,
            max_connections: 1,
            udp_port: None,
        };
        let client = VpnClient::from_shared_config(shared)?;
        assert!(!client.is_connected());
        assert!(client.get_stats().is_none());

        Ok(())
    }

    // removed tests that referenced legacy create_auth_pack
}
