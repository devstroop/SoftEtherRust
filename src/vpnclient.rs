//! Main VPN client implementation

use anyhow::Result;
use cedar::constants::{MAX_RETRY_INTERVAL_MS, MIN_RETRY_INTERVAL_MS};
use cedar::{ClientAuth, ClientOption};
use cedar::{ConnectionManager, ConnectionPool, DataPlane, EngineConfig, SessionManager};
#[cfg(target_os = "ios")]
use rand::RngCore;
use std::hash::Hasher;
use tracing::{debug, info, warn};
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
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::config::{AuthConfig, VpnConfig};
#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::dhcp::DhcpClient;
use crate::dhcp::Lease as DhcpLease;
use crate::network::SecureConnection;
use crate::shared_config;
#[cfg(feature = "adapter")]
use adapter::VirtualAdapter;
// use mayaqua::get_tick64; // moved to connection module
use mayaqua::crypto::softether_password_hash; // SHA-0(password + UPPER(username))
                                              // use std::net::Ipv4Addr; // only used in network module

/// SoftEther VPN Client
///
/// This struct encapsulates the VPN client configuration and provides methods for establishing
/// and managing VPN connections to SoftEther VPN servers.
///
/// Architecture Notes:
///   - Uses composition over inheritance for modularity
///   - Separates configuration from operational logic
///   - Provides clean interface for connection management
///   - Integrates with async runtime for concurrent operations
///
/// Thread Safety:
///   - Not thread-safe by design (single connection per client)
///   - Multiple clients can be created for concurrent connections
///   - Internal components handle their own thread safety
pub struct VpnClient {
    pub(crate) config: VpnConfig,
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
    #[cfg(feature = "adapter")]
    pub(crate) adapter: Option<VirtualAdapter>,
    // Server policy constraints (best-effort parsed from welcome/auth)
    pub(crate) server_policy_max_connections: Option<u32>,
    // Server-negotiated max_connection reported in welcome (often echo of requested <= policy)
    pub(crate) server_negotiated_max_connections: Option<u32>,
    // Background tasks for auxiliary links (scaffold)
    pub(crate) aux_tasks: Vec<JoinHandle<()>>,
    // Server-provided session key (20 bytes) used for additional connections bonding
    pub(crate) server_session_key: Option<[u8; 20]>,
    // Server-assigned session name (e.g., "SID-DEVSTROOP-37") used for session identification
    pub(crate) server_session_name: Option<String>,
    // Directions recorded for additional links (0: both or RX/TX per server; 1: client->server, 2: server->client per SoftEther)
    pub(crate) aux_directions: std::sync::Arc<std::sync::Mutex<Vec<i32>>>,
    // Round-robin endpoint list (hosts) to spread additional links across farm IPs
    pub(crate) endpoints_rr: Vec<String>,
    // TLS SNI host to use for certificate verification when connecting to an IP after redirect
    pub(crate) sni_host: Option<String>,
    // Connection state tracking and keep-alive
    pub(crate) state: ConnectionState,
    // Server-reported timeout (ms) for HTTP keep-alive / control channel guidance
    #[allow(dead_code)]
    pub(crate) server_timeout_ms: Option<u32>,
    // True once adapter<->dataplane bridging is fully set up
    pub(crate) bridge_ready: bool,
    // Prevent duplicate DHCP/monitor spawning across code paths
    pub(crate) dhcp_spawned: bool,
    // Optional state notification channel for embedders/FFI
    state_tx: Option<mpsc::UnboundedSender<ClientState>>,
    // Optional event channel for embedders/FFI
    event_tx: Option<mpsc::UnboundedSender<ClientEvent>>,
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::types::network_settings_from_lease;
use crate::types::{mask_to_prefix, settings_json_with_kind};
use crate::types::{ClientEvent, ClientState, EventLevel, NetworkSettings};

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
    ///
    /// This method creates a VPN client instance from the shared configuration format,
    /// handling authentication setup and parameter mapping.
    ///
    /// Parameters:
    ///   - cc: Validated client configuration containing server details, credentials, and options
    ///
    /// Returns:
    ///   - Result<Self>: Initialized client instance ready for connection
    ///
    /// Authentication Notes:
    ///   - Supports both pre-hashed passwords and plain text passwords
    ///   - Automatically derives SHA-0 hash for plain text passwords
    ///   - Falls back to anonymous authentication if no credentials provided
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
        // Set NAT traversal mode
        v.connection.nat_traversal = cc.nat_traversal;
        // udp_port not wired in legacy config yet; reserved for future use
        Self::new(v)
    }
    /// Create a new VPN client with the given configuration
    ///
    /// This is the primary constructor for creating VPN client instances.
    /// It validates the configuration and initializes all internal components.
    ///
    /// Parameters:
    ///   - config: Complete VPN client configuration
    ///
    /// Returns:
    ///   - Result<Self>: Initialized client instance ready for connection
    ///
    /// Initialization Notes:
    ///   - Validates configuration before creating client
    ///   - Sets up round-robin endpoint list for load balancing
    ///   - Initializes all internal state to default values
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
            server_session_name: None,
            aux_directions: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            endpoints_rr,
            sni_host: None,
            state: ConnectionState::Idle,
            server_timeout_ms: None,
            bridge_ready: false,
            dhcp_spawned: false,
            state_tx: None,
            event_tx: None,
        })
    }

    /// Connect to the VPN server
    ///
    /// This is the primary entry point for initiating the VPN connection process.
    /// It handles the complete connection lifecycle including authentication, session establishment,
    /// and network configuration.
    ///
    /// Connection Flow:
    ///   1. Establish connection with retry logic and exponential backoff
    ///   2. Handle authentication and server redirects
    ///   3. Create and configure session with proper parameters
    ///   4. Set up dataplane for data transmission
    ///   5. Handle mode-specific logic (SecureNAT vs LocalBridge)
    ///
    /// Error Handling:
    ///   - All connection errors are logged with context
    ///   - Supports server redirects with attempt limiting
    ///   - Maintains error chain for debugging
    ///
    /// Returns:
    ///   - Result<()>: Success or detailed error information
    pub async fn connect(&mut self) -> Result<()> {
        info!(
            "Starting VPN connection to {}",
            self.config.server_address()
        );

        self.set_state(ConnectionState::Connecting);
        let mut redirect_count = 0u8;

        loop {
            if redirect_count > 1 {
                anyhow::bail!("Too many redirects");
            }

            // Create authentication and client options
            let client_auth = self.create_client_auth()?;
            let client_option = self.create_client_option()?;

            // Establish connection with retry logic
            let mut connection = self.establish_connection_with_retry().await?;

            // Handle authentication and redirects
            if let Some((new_host, new_port)) = self
                .perform_authentication(&mut connection, &client_auth, &client_option)
                .await?
            {
                redirect_count += 1;
                self.handle_redirect(new_host, new_port, redirect_count);
                continue;
            }

            // Create and set up session
            let session = self.create_session(&client_auth, &client_option)?;

            // Set up dataplane and complete initialization
            self.setup_dataplane_and_session(session, connection)
                .await?;

            // Handle mode-specific logic
            if self.session.as_ref().unwrap().force_nat_traversal {
                return self.handle_secure_nat_mode().await;
            } else {
                return self.handle_local_bridge_mode().await;
            }
        }
    }

    /// Handle server redirect
    fn handle_redirect(&mut self, new_host: String, new_port: u16, redirect_count: u8) {
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
    }

    /// Establish connection to server with exponential backoff retry logic
    async fn establish_connection_with_retry(&mut self) -> Result<SecureConnection> {
        let timeout_duration = Duration::from_secs(self.config.connection.timeout as u64);
        let mut attempt: u32 = 0;

        loop {
            match timeout(timeout_duration, self.establish_connection()).await {
                Ok(Ok(c)) => return Ok(c),
                Ok(Err(e)) => {
                    attempt = attempt.saturating_add(1);
                    let delay_ms = (MIN_RETRY_INTERVAL_MS as u64)
                        .saturating_mul(1u64 << (attempt.min(6)))
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
                }
            }
        }
    }

    /// Create and configure session with authentication
    fn create_session(
        &self,
        client_auth: &ClientAuth,
        client_option: &ClientOption,
    ) -> Result<Session> {
        let session_config = SessionConfig {
            timeout: self.config.connection.timeout,
            max_connection: self.config.connection.max_connections,
            keep_alive_interval: 50,
            additional_connection_interval: 1000,
            connection_disconnect_span: 12000,
            retry_interval: 15,
            qos: false,
        };

        // Use server-assigned session name if available, otherwise generate one
        let session_name = self.server_session_name.clone()
            .unwrap_or_else(|| format!("SoftEtherRustClient_{}", uuid::Uuid::new_v4()));

        let mut session = Session::new(
            session_name,
            client_option.clone(),
            client_auth.clone(),
            session_config,
        )?;
        session.force_nat_traversal = self.config.connection.nat_traversal;

        Ok(session)
    }

    /// Set up dataplane and complete session initialization
    async fn setup_dataplane_and_session(
        &mut self,
        mut session: Session,
        connection: SecureConnection,
    ) -> Result<()> {
        session.start().await?;
        debug!(
            "[DEBUG] session_established (local) session_name={}",
            session.name
        );

        // Create dataplane bound to the session's packet channels
        let half_connection = self.config.connection.half_connection;
        let dp = DataPlane::new(&mut session, half_connection);
        if dp.is_none() {
            warn!("Failed to initialize dataplane; using connection manager only");
        }

        // Store session and connection state
        self.dataplane = dp;
        self.session = Some(session);
        self.connection = Some(connection);
        self.session_manager.mark_established();
        self.is_connected = true;
        self.set_state(ConnectionState::Established);

        // Set DHCP timing environment variables
        self.configure_dhcp_timing();

        info!("SoftEther tunnel opened");
        self.emit_event(EventLevel::Info, 220, "tunnel opened");

        // Establish the first bulk data link
        self.open_primary_data_link().await?;

        Ok(())
    }

    /// Configure DHCP timing via environment variables
    fn configure_dhcp_timing(&self) {
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
    }

    /// Handle SecureNAT mode (server handles DHCP)
    async fn handle_secure_nat_mode(&mut self) -> Result<()> {
        info!("Operating in SecureNAT mode - server handles network configuration");
        self.spawn_additional_links();
        self.start_connections_summary_logger();
        info!("VPN connection established successfully");
        Ok(())
    }

    /// Handle LocalBridge mode (client handles network configuration)
    ///
    /// In LocalBridge mode, the client is responsible for creating virtual network adapters,
    /// performing DHCP over the tunnel, and configuring the local network stack.
    ///
    /// Process Flow:
    ///   1. Generate deterministic MAC address for adapter
    ///   2. Create virtual adapter and establish bridging
    ///   3. Attempt DHCP over the VPN tunnel
    ///   4. Apply network settings (IP, routes, DNS)
    ///   5. Log adapter configuration summary
    ///   6. Spawn additional connection links for bonding
    ///
    /// Network Configuration:
    ///   - Creates platform-specific virtual network interface
    ///   - Performs DHCP discovery over encrypted tunnel
    ///   - Applies IP address, subnet mask, gateway, and DNS servers
    ///   - Falls back to system DHCP if tunnel DHCP fails
    ///
    /// Returns:
    ///   - Result<()>: Success or error during network configuration
    async fn handle_local_bridge_mode(&mut self) -> Result<()> {
        info!("Operating in LocalBridge mode - client handles network configuration");

        // Generate MAC address for the adapter
        let mac = self.generate_adapter_mac("feth0");
        let mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );

        // Create adapter and start bridging
        if let Err(e) = self.start_adapter_and_bridge(Some(mac_str)).await {
            warn!("Failed to start adapter bridging: {}", e);
        }
        info!(
            "start_adapter_and_bridge done, bridge_ready: {}",
            self.bridge_ready
        );

        // Attempt DHCP over tunnel if adapter exists
        if self.adapter.is_some() {
            if let Err(e) = self.attempt_tunnel_dhcp().await {
                warn!("Failed to obtain IP via tunnel DHCP: {}", e);
            }
        }

        // Apply network settings (will use tunnel DHCP results if available)
        if let Err(e) = self.apply_network_settings().await {
            warn!("Failed to apply network settings: {}", e);
        }

        // Log adapter summary and finalize connection
        self.log_adapter_summary();
        self.spawn_additional_links();
        self.start_connections_summary_logger();
        info!("VPN connection established successfully");

        Ok(())
    }

    /// Attempt DHCP over tunnel for supported platforms
    ///
    /// Performs DHCP discovery and configuration over the encrypted VPN tunnel.
    /// This allows the client to obtain IP configuration from the VPN server's DHCP server.
    ///
    /// Process Flow:
    ///   1. Check if bridging is ready and server didn't provide IP
    ///   2. Wait for dataplane links to be established
    ///   3. Generate MAC address for DHCP requests
    ///   4. Create DHCP client and attempt discovery
    ///   5. Apply lease information if successful
    ///   6. Cancel fallback DHCP if tunnel DHCP succeeds
    ///
    /// Platform Support:
    ///   - macOS: Uses NDRV/BPF adapter with system DHCP fallback
    ///   - iOS: Uses UTUN adapter for DHCP over tunnel
    ///   - Other platforms: Skipped (use SecureNAT mode)
    ///
    /// DHCP Timing:
    ///   - Uses configurable timeouts and retry intervals
    ///   - Falls back to system DHCP after configured delay
    ///   - Applies DNS servers from DHCP lease
    ///
    /// Returns:
    ///   - Result<()>: Success or error during DHCP process
    async fn attempt_tunnel_dhcp(&mut self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            if !self.bridge_ready {
                return Ok(());
            }

            if let Some(ip) = self.network_settings.as_ref().and_then(|n| n.assigned_ipv4) {
                if ip.is_private() {
                    // Server already provided IP, skip tunnel DHCP
                    return Ok(());
                }
            }

            if let (Some(dp), Some(adp)) = (self.dataplane.clone(), self.adapter.as_ref()) {
                let ifname = adp.name().to_string();

                // Ensure dataplane has links
                self.wait_for_dataplane_links(&dp).await;

                // Generate MAC and attempt DHCP
                let mac = self.generate_adapter_mac(&ifname);
                let dhcp = DhcpClient::new(dp, mac);
                debug!("Attempting DHCP over tunnel on {}", ifname);

                // Set up fallback system DHCP
                let fallback_handle = self.spawn_system_dhcp_fallback(&ifname);

                // Attempt tunnel DHCP
                if let Some(lease) = dhcp
                    .run_once(&ifname, Duration::from_secs(30))
                    .await
                    .ok()
                    .flatten()
                {
                    // Cancel fallback and apply lease
                    if let Some(tx) = fallback_handle {
                        let _ = tx.send(());
                    }

                    self.network_settings = Some(network_settings_from_lease(&lease));
                    self.emit_settings_snapshot();
                    self.apply_dhcp_dns(&lease, &ifname).await;
                    return Ok(());
                }
            }
        }

        #[cfg(target_os = "ios")]
        {
            if let Some(ip) = self.network_settings.as_ref().and_then(|n| n.assigned_ipv4) {
                if ip.is_private() {
                    return Ok(());
                }
            }

            if let Some(dp) = self.dataplane.clone() {
                self.wait_for_dataplane_links(&dp).await;

                let mut mac = [0u8; 6];
                rand::rng().fill_bytes(&mut mac);
                mac[0] = (mac[0] & 0b1111_1110) | 0b0000_0010;

                let dhcp = DhcpClient::new(dp, mac);
                debug!("Attempting DHCP over tunnel (iOS)");

                if let Some(lease) = dhcp
                    .run_once("utun", Duration::from_secs(30))
                    .await
                    .ok()
                    .flatten()
                {
                    self.network_settings = Some(network_settings_from_lease(&lease));
                    self.emit_settings_snapshot();
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    /// Wait for dataplane to have active links
    async fn wait_for_dataplane_links(&self, dp: &DataPlane) {
        let start = std::time::Instant::now();
        while dp.summary().total_links == 0 && start.elapsed() < Duration::from_secs(3) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Generate MAC address for adapter
    ///
    /// Creates a deterministic, locally-administered MAC address for the virtual network adapter.
    /// The MAC address is derived from the interface name to ensure consistency across sessions.
    ///
    /// Parameters:
    ///   - ifname: Interface name to use as entropy for MAC generation
    ///
    /// Returns:
    ///   - [u8; 6]: MAC address bytes with locally-administered bit set
    ///
    /// MAC Address Properties:
    ///   - Locally administered (second bit of first byte set)
    ///   - Unicast (first bit of first byte cleared)
    ///   - Deterministic based on interface name hash
    ///   - Unique per interface to avoid conflicts
    pub(crate) fn generate_adapter_mac(&self, ifname: &str) -> [u8; 6] {
        let mut mac = [0u8; 6];
        let mut h = std::collections::hash_map::DefaultHasher::new();
        use std::hash::Hash;
        ifname.hash(&mut h);
        let v = h.finish();
        mac.copy_from_slice(&[
            (v as u8) | 0x02,
            ((v >> 8) as u8),
            ((v >> 16) as u8),
            ((v >> 24) as u8),
            ((v >> 32) as u8),
            ((v >> 40) as u8),
        ]);
        mac[0] = (mac[0] & 0b1111_1110) | 0b0000_0010; // locally administered, unicast
        mac
    }

    /// Spawn system DHCP fallback task
    fn spawn_system_dhcp_fallback(
        &mut self,
        ifname: &str,
    ) -> Option<tokio::sync::oneshot::Sender<()>> {
        #[cfg(target_os = "macos")]
        {
            let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
            let ifname_kick = ifname.to_string();
            let kick_after = self.config.client.dhcp_fallback_after_ms;
            let kick_timeout = self.config.client.dhcp_kick_timeout_ms;

            let fallback = tokio::spawn(async move {
                let delay = Duration::from_millis(kick_after);
                let timed_out = tokio::time::timeout(delay, &mut cancel_rx).await.is_err();
                if timed_out {
                    crate::network_config::kick_dhcp_until_ip(
                        &ifname_kick,
                        Duration::from_millis(kick_timeout),
                    )
                    .await;
                }
            });

            self.aux_tasks.push(fallback);
            Some(cancel_tx)
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    /// Apply DNS settings from DHCP lease
    async fn apply_dhcp_dns(&self, _lease: &DhcpLease, ifname: &str) {
        #[cfg(target_os = "macos")]
        if self.config.connection.apply_dns {
            use tokio::process::Command;

            if let Some(ref ns2) = self.network_settings {
                if !ns2.dns_servers.is_empty() {
                    let mut service_name: Option<String> =
                        self.config.client.macos_dns_service_name.clone();
                    if service_name.is_none() {
                        // Try to detect service name
                        let list = Command::new("bash")
                            .arg("-c")
                            .arg("networksetup -listnetworkserviceorder | sed -n 's/.*Device: (\\(.*\\)).*/\\1/p'")
                            .output()
                            .await
                            .ok();
                        if let Some(out) = list {
                            let services = String::from_utf8_lossy(&out.stdout);
                            if services.contains(ifname) {
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
                        if let Ok(out) = Command::new("bash").arg("-c").arg(&cmd).output().await {
                            if out.status.success() {
                                debug!("Applied DNS servers to service '{}'", svc);
                            } else {
                                warn!(
                                    "Failed to apply macOS DNS: {}",
                                    String::from_utf8_lossy(&out.stderr)
                                );
                            }
                        }
                    } else {
                        debug!(
                            "(macOS) DNS servers suggested: {} (manual apply with: networksetup -setdnsservers <ServiceName> <servers> )",
                            ns2.dns_servers.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", ")
                        );
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Idle,
    Connecting,
    Established,
}

impl From<ConnectionState> for ClientState {
    fn from(s: ConnectionState) -> Self {
        match s {
            ConnectionState::Idle => ClientState::Idle,
            ConnectionState::Connecting => ClientState::Connecting,
            ConnectionState::Established => ClientState::Established,
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
            };
            self.emit_event(EventLevel::Info, code, format!("state: {s:?}"));
        }
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

    /// Expose current network settings (assigned IP, DNS, etc.) for embedders/FFI.
    pub fn get_network_settings(&self) -> Option<NetworkSettings> {
        self.network_settings.clone()
    }

    /// Get access to the dataplane for sending/receiving frames
    pub fn dataplane(&self) -> Option<&DataPlane> {
        self.dataplane.as_ref()
    }

    /// Disconnect from the VPN server and clean up resources
    ///
    /// Performs graceful shutdown of the VPN connection, stopping all active components
    /// and releasing system resources.
    ///
    /// Cleanup Process:
    ///   1. Stop and close the session
    ///   2. Close network connections
    ///   3. Destroy virtual adapters
    ///   4. Clear network settings
    ///   5. Cancel auxiliary tasks
    ///   6. Update connection state
    ///
    /// Resource Management:
    ///   - Ensures all file descriptors are closed
    ///   - Stops background tasks and timers
    ///   - Releases network interfaces
    ///   - Cleans up session state
    ///
    /// Returns:
    ///   - Result<()>: Success or error during disconnect
    pub async fn disconnect(&mut self) -> Result<()> {
        if !self.is_connected {
            return Ok(());
        }

        info!("Disconnecting from VPN server");

        // Close session and connection
        if let Some(mut session) = self.session.take() {
            session.stop().await?;
        }
        self.connection = None;
        self.dataplane = None;
        self.adapter = None;
        self.network_settings = None;

        // Cancel auxiliary tasks
        for task in self.aux_tasks.drain(..) {
            task.abort();
        }

        self.is_connected = false;
        self.set_state(ConnectionState::Idle);
        self.session_manager.mark_disconnected();

        info!("VPN disconnected successfully");
        Ok(())
    }

    /// Connect to VPN and run until interrupted (for command-line usage)
    pub async fn run_until_interrupted(&mut self) -> Result<()> {
        // Connect first
        self.connect().await?;

        // Wait for interruption signal
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigint = signal(SignalKind::interrupt())?;
            let mut sigterm = signal(SignalKind::terminate())?;

            tokio::select! {
                _ = sigint.recv() => {
                    info!("Received SIGINT, disconnecting...");
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, disconnecting...");
                }
            }
        }

        #[cfg(windows)]
        {
            use tokio::signal;
            let mut sigint = signal::ctrl_c();
            sigint.recv().await;
            info!("Received Ctrl+C, disconnecting...");
        }

        // Disconnect cleanly
        self.disconnect().await
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
                    debug!(
                        "[DEBUG] adapter name={} ip={}/{} gateway={} dns=[{}]",
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
            debug!("[DEBUG] adapter name={} (awaiting IP/DNS)", adp.name());
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
}
