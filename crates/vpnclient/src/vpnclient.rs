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
use std::time::{Duration, Instant};
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
    pub(crate) dhcp_mac: Option<[u8;6]>,
    pub(crate) dhcp_xid: Option<u32>,
    pub(crate) dhcp_metrics: Arc<DhcpMetrics>,
    pub(crate) actual_interface_name: Option<String>,
    // Idempotence: last applied network settings signature
    pub(crate) last_net_apply_sig: Option<u64>,
    // Tracking: record applied resources for safe teardown
    pub(crate) applied_resources: Option<AppliedResources>,
    metrics_shutdown_tx: Option<mpsc::UnboundedSender<()>>,
    initial_interface_snapshot_emitted: bool,
    cached_lease_reused: bool,
    lease_acquired_at: Option<u64>,
    lease_acquired_at_atomic: Arc<AtomicU64>,
    dhcpv6_lease: std::sync::Arc<std::sync::Mutex<Option<crate::dhcpv6::LeaseV6>>>,
}

use crate::types::settings_json_with_kind;
use crate::types::{ClientEvent, ClientState, EventLevel, NetworkSettings, SessionStats};
use tun_rs::DeviceBuilder;
use crate::dhcp::Lease as DhcpLease;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct DhcpMetrics {
    renew_attempts: AtomicU64,
    renew_success: AtomicU64,
    rebind_attempts: AtomicU64,
    rebind_success: AtomicU64,
    rediscover_attempts: AtomicU64,
    rediscover_success: AtomicU64,
    failures: AtomicU64,
    v6_renew_attempts: AtomicU64,
    v6_renew_success: AtomicU64,
    v6_rebind_attempts: AtomicU64,
    v6_rebind_success: AtomicU64,
    v6_rediscover_attempts: AtomicU64,
    v6_rediscover_success: AtomicU64,
    v6_failures: AtomicU64,
}

#[derive(Default, Debug, Clone)]
pub struct AppliedResources {
    pub interface_name: String,
    pub ipv4_addr: Option<(Ipv4Addr, u8)>,
    pub ipv6_addr: Option<(Ipv6Addr, u8)>,
    pub routes_added: Vec<String>,
    pub original_dns: Option<Vec<std::net::IpAddr>>,
    pub dns_modified: bool,
    pub dns_service_name: Option<String>,
    pub net_apply_sig: Option<u64>,
}

impl DhcpMetrics {
    fn new() -> Self { Self { renew_attempts: 0.into(), renew_success: 0.into(), rebind_attempts: 0.into(), rebind_success: 0.into(), rediscover_attempts: 0.into(), rediscover_success: 0.into(), failures: 0.into(), v6_renew_attempts: 0.into(), v6_renew_success: 0.into(), v6_rebind_attempts: 0.into(), v6_rebind_success: 0.into(), v6_rediscover_attempts: 0.into(), v6_rediscover_success: 0.into(), v6_failures: 0.into() } }
    #[allow(dead_code)]
    pub fn snapshot(&self) -> (u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64) { (
        self.renew_attempts.load(Ordering::Relaxed),
        self.renew_success.load(Ordering::Relaxed),
        self.rebind_attempts.load(Ordering::Relaxed),
        self.rebind_success.load(Ordering::Relaxed),
        self.rediscover_attempts.load(Ordering::Relaxed),
        self.rediscover_success.load(Ordering::Relaxed),
        self.failures.load(Ordering::Relaxed),
        self.v6_renew_attempts.load(Ordering::Relaxed),
        self.v6_renew_success.load(Ordering::Relaxed),
        self.v6_rebind_attempts.load(Ordering::Relaxed),
        self.v6_rebind_success.load(Ordering::Relaxed),
        self.v6_rediscover_attempts.load(Ordering::Relaxed),
        self.v6_rediscover_success.load(Ordering::Relaxed),
        self.v6_failures.load(Ordering::Relaxed),
    ) }
}

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
            dhcp_mac: None,
            dhcp_xid: None,
            dhcp_metrics: Arc::new(DhcpMetrics::new()),
            actual_interface_name: None,
            last_net_apply_sig: None,
            applied_resources: None,
            metrics_shutdown_tx: None,
            initial_interface_snapshot_emitted: false,
            cached_lease_reused: false,
            lease_acquired_at: None,
            lease_acquired_at_atomic: Arc::new(AtomicU64::new(0)),
            dhcpv6_lease: std::sync::Arc::new(std::sync::Mutex::new(None)),
        })
    }
    

    /// Connect to the VPN server
    pub async fn connect(&mut self) -> Result<()> {
    // Feature flags visibility: log connect-time feature state
    let nat = if self.config.connection.nat_traversal { "on" } else { "off" };
    let udp = if self.config.connection.udp_acceleration { "on" } else { "off" };
    self.emit_event(EventLevel::Info, 406, format!("transport: udp_accel={} nat_traversal={}", udp, nat));
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
                #[cfg(target_os = "macos")]
                {
                    if self.config.client.interface_name == "auto" {
                        match DeviceBuilder::new().mtu(1500).build_sync() {
                            Ok(dev)=>{ if let Ok(n)=dev.name(){ self.actual_interface_name=Some(n.clone()); info!("Created TUN interface: {} (auto-assigned, forced)", n); self.emit_event(EventLevel::Info,221,format!("interface: {}", n)); } self.tun=Some(dev);} Err(e)=>warn!("Failed to create TUN interface (auto-assigned, forced): {}", e)
                        }
                    } else {
                        let requested = self.config.client.interface_name.clone();
                        let mut created=false; let mut tried=Vec::new();
                        if requested.starts_with("utun") {
                            let base_index = requested[4..].parse::<u32>().unwrap_or(0);
                            for idx in base_index..=base_index+32 {
                                let cand=format!("utun{}", idx); tried.push(cand.clone());
                                match DeviceBuilder::new().name(cand.clone()).mtu(1500).build_sync(){
                                    Ok(dev)=>{ if let Ok(actual)=dev.name(){ self.actual_interface_name=Some(actual.clone()); info!("Created TUN interface: {} (after probing)", actual); self.emit_event(EventLevel::Info,221,format!("interface: {}", actual)); } self.tun=Some(dev); created=true; break; }
                                    Err(e)=>{ if let Some(raw)=e.raw_os_error(){ if raw!=16 { warn!("Failed to create TUN interface {}: {}", cand, e); break; }} }
                                }
                            }
                            if !created { info!("All probed utun names busy (tried: {:?}); falling back to auto-assignment", tried); }
                        } else { info!("Interface name '{}' not macOS-style; using system auto-assignment", requested); }
                        if !created && self.tun.is_none(){
                            match DeviceBuilder::new().mtu(1500).build_sync(){
                                Ok(dev)=>{ if let Ok(actual)=dev.name(){ self.actual_interface_name=Some(actual.clone()); info!("Created TUN interface: {} (auto-assigned)", actual); self.emit_event(EventLevel::Info,221,format!("interface: {}", actual)); } else { info!("Created TUN interface (auto-assigned)"); } self.tun=Some(dev); }
                                Err(e)=>warn!("Failed to create TUN interface (auto-assigned): {}", e)
                            }
                        }
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    if self.config.client.interface_name == "auto" {
                        match DeviceBuilder::new().mtu(1500).build_sync(){
                            Ok(dev)=>{ if let Ok(n)=dev.name(){ self.actual_interface_name=Some(n.clone()); info!("Created TUN interface: {} (auto-assigned, forced)", n); self.emit_event(EventLevel::Info,221,format!("interface: {}", n)); } self.tun=Some(dev);} Err(e)=>warn!("Failed to create TUN interface (auto-assigned, forced): {}", e)
                        }
                    } else {
                        let ifname=self.config.client.interface_name.clone();
                        match DeviceBuilder::new().name(ifname.clone()).mtu(1500).build_sync(){
                            Ok(dev)=>{ if let Ok(n)=dev.name(){ self.actual_interface_name=Some(n.clone()); } info!("Created TUN interface: {}", ifname); self.emit_event(EventLevel::Info,221,format!("interface: {}", ifname)); self.tun=Some(dev);} Err(e)=>warn!("Failed to create TUN interface: {}", e)
                        }
                    }
                }
            }
            // Apply DHCP timing from config via environment overrides consumed by dhcp.rs
            std::env::set_var("RUST_DHCP_SETTLE_MS", self.config.client.dhcp_settle_ms.to_string());
            std::env::set_var("RUST_DHCP_DISCOVER_INITIAL_MS", self.config.client.dhcp_initial_ms.to_string());
            std::env::set_var("RUST_DHCP_DISCOVER_MAX_MS", self.config.client.dhcp_max_ms.to_string());
            std::env::set_var("RUST_DHCP_JITTER_PCT", format!("{}", self.config.client.dhcp_jitter_pct));
            self.emit_event(EventLevel::Info, 220, "tunnel opened");

            // If static network provided in runtime config, apply it pre-DHCP and emit a snapshot.
            if self.network_settings.is_none() {
                if let Some(ns) = self.config.static_network.clone() {
                    // Preserve any v6 static fields already computed from config.rs
                    self.network_settings = Some(ns.clone());
                    // Emit initial server snapshot including v6 if present
                    self.emit_server_interface_snapshot();
                }
            }

            // If DHCPv4 disabled and no server-provided settings but static IP config exists, synthesize NetworkSettings now.
            if !self.config.client.enable_in_tunnel_dhcp && self.network_settings.is_none() {
                // Static IP config path now handled during RuntimeConfig build (network_settings may still be None until applied)
            }
            // Start periodic DHCP metrics emission (configurable interval) if DHCP enabled
            if self.config.client.enable_in_tunnel_dhcp {
                let tx = self.event_tx.clone();
                let metrics = self.dhcp_metrics.clone();
                let interval = 300u64; // fixed metrics interval
                let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
                self.metrics_shutdown_tx = Some(shutdown_tx);
                self.aux_tasks.push(tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(interval)) => {},
                            _ = shutdown_rx.recv() => { break; }
                        }
                        if let Some(tx)=&tx {
                            let (r_a,r_s,rb_a,rb_s,rd_a,rd_s,f,v6_r_a,v6_r_s,v6_rb_a,v6_rb_s,v6_rd_a,v6_rd_s,v6_f)= metrics.snapshot();
                            #[derive(serde::Serialize)] struct Metrics<'a>{kind:&'a str, renew_attempts:u64, renew_success:u64, rebind_attempts:u64, rebind_success:u64, rediscover_attempts:u64, rediscover_success:u64, failures:u64, v6_renew_attempts:u64, v6_renew_success:u64, v6_rebind_attempts:u64, v6_rebind_success:u64, v6_rediscover_attempts:u64, v6_rediscover_success:u64, v6_failures:u64}
                            if let Ok(json)=serde_json::to_string(&Metrics{kind:"dhcp_metrics", renew_attempts:r_a, renew_success:r_s, rebind_attempts:rb_a, rebind_success:rb_s, rediscover_attempts:rd_a, rediscover_success:rd_s, failures:f, v6_renew_attempts:v6_r_a, v6_renew_success:v6_r_s, v6_rebind_attempts:v6_rb_a, v6_rebind_success:v6_rb_s, v6_rediscover_attempts:v6_rd_a, v6_rediscover_success:v6_rd_s, v6_failures:v6_f}) { let _=tx.send(ClientEvent{ level: EventLevel::Info, code:2211, message: json}); }
                        }
                    }
                }));
            }
            // Establish the first bulk data link via additional_connect before bridging/DHCP
            if let Err(e) = self.open_primary_data_link().await { error!("Failed to establish primary data link: {}", e); return Err(e); }
            // Early placeholder snapshot if we already know there will be no server settings and DHCP disabled
            if self.network_settings.is_none() && !self.config.client.enable_in_tunnel_dhcp { self.emit_placeholder_interface_snapshot(); }
            // Bridging / DHCP flow: if no IPv4 settings and DHCP enabled, perform acquisition
            if self.config.client.enable_in_tunnel_dhcp && self.network_settings.as_ref().and_then(|n| n.assigned_ipv4).is_none() {
                if let Some(dp)=self.dataplane.clone() {
                    self.emit_event(EventLevel::Info, 299, "dhcp acquisition attempt");
                    let start=std::time::Instant::now();
                    while dp.summary().total_links==0 && start.elapsed() < Duration::from_secs(3) { tokio::time::sleep(Duration::from_millis(100)).await; }
                    if self.dhcp_mac.is_none(){
                        tracing::warn!("dhcp_mac not initialized; using deterministic client MAC");
                        self.dhcp_mac=Some(self.config.client.mac_address);
                    }
                    let mac=self.dhcp_mac.unwrap_or(self.config.client.mac_address);
                    let dp_clone=dp.clone();
                    let mut dhcp=crate::dhcp::DhcpClient::new(dp_clone.clone(), mac);
                    info!("Attempting DHCP over tunnel");
                    let iface_for_dhcp=self.actual_interface_name.as_ref().unwrap_or(&self.config.client.interface_name).clone();
                    if let Some(xid)=self.dhcp_xid { dhcp=crate::dhcp::DhcpClient::new_with_xid(dp_clone, mac, xid); }
                    match dhcp.run_once(&iface_for_dhcp, Duration::from_secs(30), None).await {
                        Ok(Some(lease))=>{
                            self.network_settings=Some(crate::types::network_settings_from_lease(&lease));
                            self.emit_settings_snapshot();
                            info!("DHCP lease acquired: {}", lease.client_ip);
                            self.dhcp_mac=Some(mac);
                            self.dhcp_xid=Some(dhcp.xid());
                            let now_acq=current_unix_secs();
                            self.lease_acquired_at=Some(now_acq);
                            self.lease_acquired_at_atomic.store(now_acq, Ordering::Relaxed);
                            self.maybe_emit_interface_snapshot(&lease, &iface_for_dhcp, true);
                            if let Some(lt)=lease.lease_time { let xid=self.dhcp_xid; self.spawn_dhcp_renew_task(lease, lt, iface_for_dhcp.clone(), xid); self.spawn_lease_health_monitor(lt.as_secs()); }
                        }
                        Ok(None)=>warn!("No DHCP offer/ack within timeout"),
                        Err(e)=>warn!("DHCP negotiation failed: {e}"),
                    }
                }
            }

            // DHCPv6 acquisition (independent) if enabled
            if self.config.client.enable_in_tunnel_dhcpv6 {
                if let Some(dp) = self.dataplane.clone() {
                    // Preload cached v6 lease for immediate snapshot if still valid
                    // Previously loaded cached v6 lease snapshot from disk; now only runtime renew events will emit snapshots.
                    let event_tx = self.event_tx.clone();
                    let iface_name = self.actual_interface_name.clone().unwrap_or(self.config.client.interface_name.clone());
                    let _auto_iface = self.config.client.interface_name == "auto"; // retained for potential logging
                    let verbose = false;
                    // lease cache removed
                    let shared_v6 = self.dhcpv6_lease.clone();
                    let metrics_clone = self.dhcp_metrics.clone();
                    self.aux_tasks.push(tokio::spawn(async move {
                        use rand::RngCore;
                        let mut mac=[0u8;6]; rand::rng().fill_bytes(&mut mac); mac[0]=(mac[0]&0b1111_1110)|0b0000_0010;
                        let mut client = crate::dhcpv6::DhcpV6Client::new(dp.clone(), mac);
                        match client.run_once(std::time::Duration::from_secs(25)).await {
                            Ok(Some(mut lease)) => {
                                lease.acquired_at=Some(current_unix_secs());
                                // persistence removed
                                if let Ok(mut g)=shared_v6.lock() { *g=Some(lease.clone()); }
                                if let Some(tx)=&event_tx { let json = serde_json::json!({
                                    "kind":"interface_snapshot","name":iface_name,
                                    "ipv4":serde_json::Value::Null,
                                    "router":serde_json::Value::Null,
                                    "dns":[],
                                    "lease_seconds_total":0,
                                    "lease_seconds_remaining":0,
                                    "renew_elapsed_secs":0,
                                    "t1_epoch":0,"t2_epoch":0,"expiry_epoch":0,
                                    "mtu":1500,"xid":serde_json::Value::Null,"cache_reused":false,
                                    "initial":false,"verbose":verbose,
                                    "ipv6":lease.addr.map(|a|a.to_string()),
                                    "dns6": if lease.dns_servers.is_empty(){ None } else { Some(lease.dns_servers.iter().map(|d|d.to_string()).collect::<Vec<_>>()) }
                                }); let _=tx.send(ClientEvent{ level: EventLevel::Info, code:2221, message: json.to_string()}); }
                                if let Some(pref)=lease.preferred_lifetime { if pref.as_secs()>0 { spawn_dhcpv6_renew_loop(client, lease, shared_v6.clone(), event_tx.clone(), iface_name.clone(), verbose, metrics_clone.clone()); } }
                            }
                            Ok(None) => { if let Some(tx)=&event_tx { let _=tx.send(ClientEvent{ level: EventLevel::Warn, code:310, message:"dhcpv6 timeout".into()}); } }
                            Err(e) => { if let Some(tx)=&event_tx { let _=tx.send(ClientEvent{ level: EventLevel::Warn, code:310, message: format!("dhcpv6 error: {e}" )}); } }
                        }
                    }));
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
            // Periodic interface snapshot (hourly by default) if DHCP lease or server settings present
            let period = 0u64; // periodic interface snapshot disabled (event-driven only)
            if period >= 60 {
                let event_tx = self.event_tx.clone();
                let iface_name = self.actual_interface_name.clone().unwrap_or(self.config.client.interface_name.clone());
                let verbose = false;
                let v6_shared = self.dhcpv6_lease.clone();
                self.aux_tasks.push(tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(period)).await;
                        // Load from lease cache if exists
                        // Without persisted lease, emit IPv6-only snapshot if present
                        if let Ok(g)=v6_shared.lock() { if let Some(v6l)=g.as_ref() { if let Some(tx)=&event_tx { let ipv6=v6l.addr.map(|a|a.to_string()); let dns6= if v6l.dns_servers.is_empty(){ None } else { Some(v6l.dns_servers.iter().take(if verbose {8}else{4}).map(|d|d.to_string()).collect::<Vec<_>>()) }; let snap=serde_json::json!({"kind":"interface_snapshot","name":iface_name,"ipv4":serde_json::Value::Null,"router":serde_json::Value::Null,"dns":[],"lease_seconds_total":0,"lease_seconds_remaining":0,"renew_elapsed_secs":0,"t1_epoch":0,"t2_epoch":0,"expiry_epoch":0,"mtu":1500,"xid":serde_json::Value::Null,"cache_reused":false,"initial":false,"verbose":verbose,"ipv6":ipv6,"dns6":dns6}); let _=tx.send(ClientEvent{ level: EventLevel::Info, code:2221, message: snap.to_string()}); } } }
                    }
                }));
            }
            info!("VPN connection established successfully");
            // If still no snapshot (no server IP and no DHCP lease) emit placeholder now
            if !self.initial_interface_snapshot_emitted && self.network_settings.as_ref().and_then(|n| n.assigned_ipv4).is_none() && self.dhcp_xid.is_none() {
                self.emit_placeholder_interface_snapshot();
            }
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

    // Signal periodic metrics task (if running) to terminate early for clean shutdown
    if let Some(tx)=self.metrics_shutdown_tx.take() { let _=tx.send(()); }

    // Stop dataplane first so its worker threads stop reading/writing
        if let Some(dp) = self.dataplane.take() {
            dp.shutdown();
        }

        // Emit final DHCP metrics snapshot (code 222) including last interface snapshot if available
    if self.config.client.enable_in_tunnel_dhcp {
            if let Some(tx)=&self.event_tx {
        let (r_a,r_s,rb_a,rb_s,rd_a,rd_s,f,v6_r_a,v6_r_s,v6_rb_a,v6_rb_s,v6_rd_a,v6_rd_s,v6_f)= self.dhcp_metrics.snapshot();
        #[derive(serde::Serialize)] struct Final<'a>{kind:&'a str,final_snapshot:bool,renew_attempts:u64,renew_success:u64,rebind_attempts:u64,rebind_success:u64,rediscover_attempts:u64,rediscover_success:u64,failures:u64,v6_renew_attempts:u64,v6_renew_success:u64,v6_rebind_attempts:u64,v6_rebind_success:u64,v6_rediscover_attempts:u64,v6_rediscover_success:u64,v6_failures:u64,interface:Option<serde_json::Value>}
                let mut interface_json=None;
                if let Some(ns)=&self.network_settings { // reconstruct minimal lease-like snapshot if we have network settings
                    // We no longer retain original lease struct here; only include IP summary
                    #[derive(serde::Serialize)] struct MiniIface<'a>{name:&'a str,ipv4:Option<String>,dns:Option<Vec<String>>}
                    let name = self.actual_interface_name.as_deref().unwrap_or(&self.config.client.interface_name);
                    let ipv4 = ns.assigned_ipv4.map(|ip| format!("{}", ip));
                    let dns = if !ns.dns_servers.is_empty() { Some(ns.dns_servers.iter().map(|d| d.to_string()).collect()) } else { None };
                    if let Ok(v)=serde_json::to_value(MiniIface{name,ipv4,dns}) { interface_json=Some(v); }
                }
        if let Ok(json)=serde_json::to_string(&Final{kind:"dhcp_metrics",final_snapshot:true,renew_attempts:r_a,renew_success:r_s,rebind_attempts:rb_a,rebind_success:rb_s,rediscover_attempts:rd_a,rediscover_success:rd_s,failures:f,v6_renew_attempts:v6_r_a,v6_renew_success:v6_r_s,v6_rebind_attempts:v6_rb_a,v6_rebind_success:v6_rb_s,v6_rediscover_attempts:v6_rd_a,v6_rediscover_success:v6_rd_s,v6_failures:v6_f,interface:interface_json}) {
                    let _=tx.send(ClientEvent{ level: EventLevel::Info, code:222, message: json});
                }
            }
        }

        // Stop session
        if let Some(mut session) = self.session.take() {
            session.stop().await?;
        }

        // Close connection
        if let Some(connection) = self.connection.take() {
            connection.close()?;
        }

        // Restore DNS if we changed it
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Some(applied) = self.applied_resources.as_ref() {
            if applied.dns_modified {
                #[cfg(target_os = "linux")]
                {
                    use tokio::process::Command;
                    if let Some(orig) = &applied.original_dns {
                        let content = orig
                            .iter()
                            .map(|ip| format!("nameserver {}\n", ip))
                            .collect::<String>();
                        let _ = Command::new("bash")
                            .arg("-c")
                            .arg(format!(
                                "printf '{}' | sudo tee /etc/resolv.conf > /dev/null",
                                content.replace("'", "'\\''")
                            ))
                            .output()
                            .await;
                        self.emit_event(EventLevel::Info, 3301, "dns_restore: linux resolv.conf restored from snapshot");
                    } else {
                        let _ = Command::new("bash")
                            .arg("-c")
                            .arg("echo -n '' | sudo tee /etc/resolv.conf > /dev/null")
                            .output()
                            .await;
                        self.emit_event(EventLevel::Info, 3302, "dns_restore: linux no snapshot; cleared resolv.conf");
                    }
                }
                #[cfg(target_os = "macos")]
                {
                    use tokio::process::Command;
                    if let Some(svc) = &applied.dns_service_name {
                        if let Some(orig) = &applied.original_dns {
                            if orig.is_empty() {
                                let _ = Command::new("networksetup")
                                    .arg("-setdnsservers")
                                    .arg(svc)
                                    .arg("Empty")
                                    .output()
                                    .await;
                                self.emit_event(EventLevel::Info, 3301, format!("dns_restore: macos restored '{}' to Empty", svc));
                            } else {
                                let args = orig.iter().map(|i| i.to_string()).collect::<Vec<_>>();
                                let cmd = format!(
                                    "networksetup -setdnsservers '{}' {}",
                                    svc.replace("'", "'\\''"),
                                    args.join(" ")
                                );
                                let _ = Command::new("bash").arg("-c").arg(&cmd).output().await;
                                self.emit_event(EventLevel::Info, 3301, format!("dns_restore: macos restored '{}' to {}", svc, args.join(",")));
                            }
                        } else {
                            let _ = Command::new("networksetup")
                                .arg("-setdnsservers")
                                .arg(svc)
                                .arg("Empty")
                                .output()
                                .await;
                            self.emit_event(EventLevel::Info, 3302, format!("dns_restore: macos no snapshot for '{}'; set to Empty", svc));
                        }
                    } else {
                        // Fallback: clear all services to Empty
                        let out = Command::new("networksetup")
                            .arg("-listallnetworkservices")
                            .output()
                            .await?;
                        if out.status.success() {
                            let s = String::from_utf8_lossy(&out.stdout);
                            for line in s.lines() {
                                let svc = line.trim();
                                if svc.is_empty() || svc.starts_with("An asterisk (*)") {
                                    continue;
                                }
                                let _ = Command::new("networksetup")
                                    .arg("-setdnsservers")
                                    .arg(svc)
                                    .arg("Empty")
                                    .output()
                                    .await;
                                self.emit_event(EventLevel::Info, 3302, format!("dns_restore: macos fallback; set '{}' to Empty", svc));
                            }
                        }
                    }
                }
            }
        }

        // Tear down TUN interface using tracked resources when available
        if let Some(_tun) = self.tun.take() {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                use tokio::process::Command;
                if let Some(resources) = self.applied_resources.take() {
                    let ifname = resources.interface_name;
                    // Remove routes in reverse order
                    for r in resources.routes_added.iter().rev() {
                        #[cfg(target_os = "linux")]
                        {
                            if let Some(gw) = r.strip_prefix("v4 default via ") {
                                let _ = Command::new("ip")
                                    .arg("route")
                                    .arg("del")
                                    .arg("default")
                                    .arg("via")
                                    .arg(gw.trim())
                                    .arg("dev")
                                    .arg(&ifname)
                                    .output()
                                    .await;
                                continue;
                            }
                            if let Some(gw6) = r.strip_prefix("v6 default via ") {
                                let _ = Command::new("ip")
                                    .arg("-6")
                                    .arg("route")
                                    .arg("del")
                                    .arg("default")
                                    .arg("via")
                                    .arg(gw6.trim())
                                    .arg("dev")
                                    .arg(&ifname)
                                    .output()
                                    .await;
                                continue;
                            }
                        }
                        #[cfg(target_os = "macos")]
                        {
                            if let Some(gw) = r.strip_prefix("v4 default via ") {
                                let _ = Command::new("route")
                                    .arg("delete")
                                    .arg("default")
                                    .arg(gw.trim())
                                    .output()
                                    .await;
                                continue;
                            }
                            if r.starts_with("v6 default via ") {
                                let _ = Command::new("route")
                                    .arg("delete")
                                    .arg("-inet6")
                                    .arg("default")
                                    .output()
                                    .await;
                                continue;
                            }
                        }
                    }
                    // Remove IP addresses (IPv4, IPv6)
                    if let Some((ip, _pfx)) = resources.ipv4_addr {
                        #[cfg(target_os = "linux")]
                        {
                            let _ = Command::new("ip")
                                .arg("addr")
                                .arg("del")
                                .arg(format!("{}/{}", ip, pfx))
                                .arg("dev")
                                .arg(&ifname)
                                .output()
                                .await;
                        }
                        #[cfg(target_os = "macos")]
                        {
                            let _ = Command::new("ifconfig")
                                .arg(&ifname)
                                .arg("inet")
                                .arg(ip.to_string())
                                .arg("-alias")
                                .output()
                                .await;
                        }
                    }
                    if let Some((ip6, _pfx6)) = resources.ipv6_addr {
                        #[cfg(target_os = "linux")]
                        {
                            let _ = Command::new("ip")
                                .arg("-6")
                                .arg("addr")
                                .arg("del")
                                .arg(format!("{}/{}", ip6, pfx6))
                                .arg("dev")
                                .arg(&ifname)
                                .output()
                                .await;
                        }
                        #[cfg(target_os = "macos")]
                        {
                            let _ = Command::new("ifconfig")
                                .arg(&ifname)
                                .arg("inet6")
                                .arg(ip6.to_string())
                                .arg("-alias")
                                .output()
                                .await;
                        }
                    }
                    // Bring iface down last
                    #[cfg(target_os = "linux")]
                    {
                        let _ = Command::new("ip")
                            .arg("link")
                            .arg("set")
                            .arg(&ifname)
                            .arg("down")
                            .output()
                            .await;
                    }
                    #[cfg(target_os = "macos")]
                    {
                        let _ = Command::new("ifconfig")
                            .arg(&ifname)
                            .arg("down")
                            .output()
                            .await;
                    }
                } else {
                    // Fallback: no tracker; do best-effort like before
                    let ifname = self
                        .actual_interface_name
                        .as_deref()
                        .unwrap_or(&self.config.client.interface_name)
                        .to_string();
                    #[cfg(target_os = "linux")]
                    { let _ = Command::new("ip").arg("link").arg("set").arg(&ifname).arg("down").output().await; }
                    #[cfg(target_os = "macos")]
                    { let _ = Command::new("ifconfig").arg(&ifname).arg("down").output().await; }
                }
            }
        }

    // Tracker was consumed above when present

        // Abort auxiliary tasks
        for handle in self.aux_tasks.drain(..) {
            handle.abort();
        }

    // Tear down virtual adapter (utun)
    // No adapter teardown needed after removing adapter integration

    self.is_connected = false;
    // Reset last applied signature after teardown so future applies aren't skipped
    self.last_net_apply_sig = None;
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
            // encryption always on (field removed)
            max_connections: 1,
            nat_traversal: None,
            udp_acceleration: None,
            // mac address now implicit deterministic; no user fields
            static_ip: None,
            ip_version: crate::shared_config::IpVersionPreference::Auto,
        };
        let client = VpnClient::from_shared_config(shared)?;
        assert!(!client.is_connected());
        assert!(client.get_stats().is_none());

        Ok(())
    }

    // removed tests that referenced legacy create_auth_pack
}

fn current_unix_secs() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() }

fn spawn_dhcpv6_renew_loop(mut client: crate::dhcpv6::DhcpV6Client, mut lease: crate::dhcpv6::LeaseV6, shared: std::sync::Arc<std::sync::Mutex<Option<crate::dhcpv6::LeaseV6>>>, event_tx: Option<tokio::sync::mpsc::UnboundedSender<ClientEvent>>, iface: String, verbose: bool, metrics: Arc<DhcpMetrics>) {
    let handle = tokio::spawn(async move {
        loop {
            let now = current_unix_secs();
            let pref = lease.preferred_lifetime.unwrap_or_else(|| Duration::from_secs(0));
            if pref.as_secs()==0 { break; }
            let t1 = lease.t1.unwrap_or(pref/2);
            let t2 = lease.t2.unwrap_or(pref*4/5);
            let acquired = lease.acquired_at.unwrap_or(now);
            let t1_deadline = acquired + t1.as_secs();
            let t2_deadline = acquired + t2.as_secs();
            let valid_deadline = acquired + lease.valid_lifetime.unwrap_or(pref).as_secs();
            let sleep_secs = t1_deadline.saturating_sub(now);
            tokio::time::sleep(Duration::from_secs(sleep_secs.max(1))).await;
            // RENEW phase
            if let Some(tx)=&event_tx { let _=tx.send(ClientEvent{ level: EventLevel::Info, code:320, message:"dhcpv6 renew attempt".into()}); }
            metrics.v6_renew_attempts.fetch_add(1, Ordering::Relaxed);
            if let Ok(frame)=client.build_renew(&lease) { client.send_frame(frame); }
            if let Ok(Some(reply))=client.wait_for(dhcproto::v6::MessageType::Reply, Instant::now()+Duration::from_secs(5)).await {
                lease = client.lease_from_reply(&reply); lease.acquired_at=Some(current_unix_secs());
                let _=shared.lock().map(|mut g| *g=Some(lease.clone()));
                metrics.v6_renew_success.fetch_add(1, Ordering::Relaxed);
                if let Some(tx)=&event_tx { let js=serde_json::json!({"kind":"interface_snapshot","name":iface,"ipv4":serde_json::Value::Null,"router":serde_json::Value::Null,"dns":[],"lease_seconds_total":0,"lease_seconds_remaining":0,"renew_elapsed_secs":0,"t1_epoch":0,"t2_epoch":0,"expiry_epoch":0,"mtu":1500,"xid":serde_json::Value::Null,"cache_reused":false,"initial":false,"verbose":verbose,"ipv6":lease.addr.map(|a|a.to_string()),"dns6": if lease.dns_servers.is_empty(){ None } else { Some(lease.dns_servers.iter().map(|d|d.to_string()).collect::<Vec<_>>()) }}); let _=tx.send(ClientEvent{ level: EventLevel::Info, code:321, message: js.to_string()}); }
                continue;
            } else { if let Some(tx)=&event_tx { let _=tx.send(ClientEvent{ level: EventLevel::Warn, code:322, message:"dhcpv6 renew failed".into()}); } }
            // If renew failed, sleep until T2 then REBIND
            let now2=current_unix_secs();
            let sleep_to_t2 = t2_deadline.saturating_sub(now2);
            if sleep_to_t2>0 { tokio::time::sleep(Duration::from_secs(sleep_to_t2)).await; }
            if let Some(tx)=&event_tx { let _=tx.send(ClientEvent{ level: EventLevel::Info, code:323, message:"dhcpv6 rebind attempt".into()}); }
            metrics.v6_rebind_attempts.fetch_add(1, Ordering::Relaxed);
            if let Ok(frame)=client.build_rebind(&lease) { client.send_frame(frame); }
            if let Ok(Some(reply))=client.wait_for(dhcproto::v6::MessageType::Reply, Instant::now()+Duration::from_secs(6)).await {
                lease = client.lease_from_reply(&reply); lease.acquired_at=Some(current_unix_secs());
                let _=shared.lock().map(|mut g| *g=Some(lease.clone()));
                metrics.v6_rebind_success.fetch_add(1, Ordering::Relaxed);
                if let Some(tx)=&event_tx { let js=serde_json::json!({"kind":"interface_snapshot","name":iface,"ipv4":serde_json::Value::Null,"router":serde_json::Value::Null,"dns":[],"lease_seconds_total":0,"lease_seconds_remaining":0,"renew_elapsed_secs":0,"t1_epoch":0,"t2_epoch":0,"expiry_epoch":0,"mtu":1500,"xid":serde_json::Value::Null,"cache_reused":false,"initial":false,"verbose":verbose,"ipv6":lease.addr.map(|a|a.to_string()),"dns6": if lease.dns_servers.is_empty(){ None } else { Some(lease.dns_servers.iter().map(|d|d.to_string()).collect::<Vec<_>>()) }}); let _=tx.send(ClientEvent{ level: EventLevel::Info, code:324, message: js.to_string()}); }
                continue;
            } else { if let Some(tx)=&event_tx { let _=tx.send(ClientEvent{ level: EventLevel::Warn, code:325, message:"dhcpv6 rebind failed".into()}); } }
            // If still failed and past valid lifetime, exit
            let now_end=current_unix_secs();
            if now_end > valid_deadline { if let Some(tx)=&event_tx { let _=tx.send(ClientEvent{ level: EventLevel::Warn, code:311, message:"dhcpv6 lease expired".into()}); } break; }
            // Rediscover (SOLICIT) fallback before expiry
            if let Some(tx)=&event_tx { let _=tx.send(ClientEvent{ level: EventLevel::Warn, code:326, message:"dhcpv6 rediscover attempt".into()}); }
            metrics.v6_rediscover_attempts.fetch_add(1, Ordering::Relaxed);
            // Recreate client with new xid for fresh SOLICIT
            let mac_duid = client.duid.clone();
            let iaid = client.iaid;
            let dp_clone = client.dataplane();
            let mut new_client = crate::dhcpv6::DhcpV6Client::new_with_ids(dp_clone, [0,0,0,0,0,0], mac_duid.clone(), iaid);
            if let Ok(Some(new_lease)) = new_client.run_once(Duration::from_secs(15)).await { lease=new_lease; let _=shared.lock().map(|mut g| *g=Some(lease.clone())); metrics.v6_rediscover_success.fetch_add(1, Ordering::Relaxed); if let Some(tx)=&event_tx { let js=serde_json::json!({"kind":"interface_snapshot","name":iface,"ipv4":serde_json::Value::Null,"router":serde_json::Value::Null,"dns":[],"lease_seconds_total":0,"lease_seconds_remaining":0,"renew_elapsed_secs":0,"t1_epoch":0,"t2_epoch":0,"expiry_epoch":0,"mtu":1500,"xid":serde_json::Value::Null,"cache_reused":false,"initial":false,"verbose":verbose,"ipv6":lease.addr.map(|a|a.to_string()),"dns6": if lease.dns_servers.is_empty(){ None } else { Some(lease.dns_servers.iter().map(|d|d.to_string()).collect::<Vec<_>>()) }}); let _=tx.send(ClientEvent{ level: EventLevel::Info, code:327, message: js.to_string()}); }
                client = new_client; continue; } else { metrics.v6_failures.fetch_add(1, Ordering::Relaxed); if let Some(tx)=&event_tx { let _=tx.send(ClientEvent{ level: EventLevel::Error, code:328, message:"dhcpv6 rediscover failed".into()}); } }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    // We do not store handle; loop ends on expiry.
    let _ = handle;
}

impl VpnClient {
    fn spawn_dhcp_renew_task(&mut self, lease: DhcpLease, _lease_time: std::time::Duration, iface: String, xid_initial: Option<u32>) {
    // persistence removed; no path
        let dp = self.dataplane.clone();
        let jitter_pct = self.config.client.dhcp_renewal_jitter_pct.min(50);
        let mac = self.dhcp_mac;
        let event_tx = self.event_tx.clone();
        let stored_xid = xid_initial.or(self.dhcp_xid);
        let metrics = self.dhcp_metrics.clone();
    let cache_reused = self.cached_lease_reused;
    // interface_auto removed
    // health threshold handled externally by monitor
    let acquired_at_atomic = self.lease_acquired_at_atomic.clone();
        let handle = tokio::spawn(async move {
            if let (Some(dp_root), Some(mut cur_lt)) = (dp, lease.lease_time) {
                let mut current_lease = lease;
                let mac_use = mac.unwrap_or_else(|| { let mut m=[0u8;6]; use rand::RngCore; let mut r=rand::rng(); r.fill_bytes(&mut m); m[0]=(m[0]&0b1111_1110)|0b0000_0010; m });
                let xid = stored_xid.unwrap_or_else(|| { use rand::RngCore; let mut xb=[0u8;4]; rand::rng().fill_bytes(&mut xb); u32::from_be_bytes(xb) });
        let mut last_sig: Option<(std::net::Ipv4Addr, Option<std::net::Ipv4Addr>, Option<std::net::Ipv4Addr>, Vec<std::net::Ipv4Addr>)> = None;
                loop {
                    let base = cur_lt / 2;
                    let jitter_bound = (base.as_millis() as u64 * jitter_pct as u64 / 100).max(1);
                    let jitter_ms: u64 = rand::random_range(0..=jitter_bound);
                    let wait = base + std::time::Duration::from_millis(jitter_ms);
                    tokio::time::sleep(wait).await;
                    // Health checked by monitor task (spawn_lease_health_monitor); we still update acquired_at on success below.
                    let mut renewed = false;
                    for cycle in 0..3 { // renew cycles with backoff
                        let backoff = if cycle==0 {Duration::from_secs(0)} else { Duration::from_secs(2u64.pow(cycle as u32)) };
                        if backoff.as_secs()>0 { tokio::time::sleep(backoff).await; }
                        if let Some(tx)=&event_tx { let _= tx.send(ClientEvent{ level: EventLevel::Info, code:300, message: format!("dhcp renew attempt (T1) cycle={}",cycle)}); }
                        metrics.renew_attempts.fetch_add(1, Ordering::Relaxed);
                        let mut client = crate::dhcp::DhcpClient::new_with_xid(dp_root.clone(), mac_use, xid);
                        if let Ok(Some(frame)) = client.build_renew_unicast(&current_lease) { client.send_frame(frame); }
                        if let Ok(Some(ack)) = client.wait_for(dhcproto::v4::MessageType::Ack, Instant::now()+Duration::from_secs(5), None, &iface).await {
                            if let Ok(newl) = client.lease_from_ack(&ack) { current_lease = newl; renewed = true; }
                        }
                        if !renewed {
                            if let Ok(frame) = client.build_renew_broadcast(&current_lease) { client.send_frame(frame); }
                            if let Ok(Some(ack)) = client.wait_for(dhcproto::v4::MessageType::Ack, Instant::now()+Duration::from_secs(5), None, &iface).await {
                                if let Ok(newl) = client.lease_from_ack(&ack) { current_lease = newl; renewed = true; }
                            }
                        }
                        if renewed { break; }
                    }
                    if renewed {
                        metrics.renew_success.fetch_add(1, Ordering::Relaxed);
                        if let Some(tx)=&event_tx { let _= tx.send(ClientEvent{ level: EventLevel::Info, code:301, message: "dhcp renew success".into()}); }
                        // persistence removed
                        acquired_at_atomic.store(current_unix_secs(), Ordering::Relaxed);
                            // mark last renew success time
                            if let Some(tx)=&event_tx { let _= tx.send(ClientEvent{ level: EventLevel::Info, code:3001, message: format!("renew_elapsed_reset" )}); }
                        let sig = (current_lease.client_ip, current_lease.subnet_mask, current_lease.router, current_lease.dns_servers.clone());
                        if last_sig.as_ref().map(|s| s != &sig).unwrap_or(true) {
                            if let Some(tx)=&event_tx { if let Some(json)=interface_snapshot_json(&current_lease, &iface, Some(xid), cache_reused, false, None, false, false, None) { let _=tx.send(ClientEvent{ level: EventLevel::Info, code:2221, message: json}); } }
                            last_sig=Some(sig);
                        }
                        if let Some(lt)=current_lease.lease_time { cur_lt = lt; continue; } else { break; }
                    }
                    if let Some(tx)=&event_tx { let _= tx.send(ClientEvent{ level: EventLevel::Warn, code:302, message: "dhcp renew failed; rebind phase".into()}); }
                    // Rebind at 87.5%
                    let rebind_point = (cur_lt.as_secs_f64()*0.875) as u64;
                    let elapsed = (cur_lt/2 + std::time::Duration::from_millis(jitter_ms)).as_secs();
                    if rebind_point > elapsed { tokio::time::sleep(Duration::from_secs(rebind_point - elapsed)).await; }
                    metrics.rebind_attempts.fetch_add(1, Ordering::Relaxed);
                    if let Some(tx)=&event_tx { let _= tx.send(ClientEvent{ level: EventLevel::Info, code:303, message: "dhcp rebind attempt".into()}); }
                    let mut rebinder = crate::dhcp::DhcpClient::new_with_xid(dp_root.clone(), mac_use, xid);
                    if let Ok(frame) = rebinder.build_rebind(&current_lease) { rebinder.send_frame(frame); }
                    let mut rebind_ok=false;
                    if let Ok(Some(ack)) = rebinder.wait_for(dhcproto::v4::MessageType::Ack, Instant::now()+Duration::from_secs(8), None, &iface).await {
                        if let Ok(newl) = rebinder.lease_from_ack(&ack) { current_lease = newl; rebind_ok=true; }
                    }
                    if rebind_ok {
                        metrics.rebind_success.fetch_add(1, Ordering::Relaxed);
                        if let Some(tx)=&event_tx { let _= tx.send(ClientEvent{ level: EventLevel::Info, code:304, message: "dhcp rebind success".into()}); }
                        // persistence removed
                        acquired_at_atomic.store(current_unix_secs(), Ordering::Relaxed);
                            if let Some(tx)=&event_tx { let _= tx.send(ClientEvent{ level: EventLevel::Info, code:3001, message: "renew_elapsed_reset".into()}); }
                        let sig = (current_lease.client_ip, current_lease.subnet_mask, current_lease.router, current_lease.dns_servers.clone());
                        if last_sig.as_ref().map(|s| s != &sig).unwrap_or(true) {
                            if let Some(tx)=&event_tx { if let Some(json)=interface_snapshot_json(&current_lease, &iface, Some(xid), cache_reused, false, None, false, false, None) { let _=tx.send(ClientEvent{ level: EventLevel::Info, code:2221, message: json}); } }
                            last_sig=Some(sig);
                        }
                        if let Some(lt)=current_lease.lease_time { cur_lt = lt; continue; } else { break; }
                    }
                    if let Some(tx)=&event_tx { let _= tx.send(ClientEvent{ level: EventLevel::Warn, code:305, message: "dhcp rebind failed; rediscover".into()}); }
                    metrics.rediscover_attempts.fetch_add(1, Ordering::Relaxed);
                    let mut discover_client = crate::dhcp::DhcpClient::new_with_xid(dp_root.clone(), mac_use, xid);
                    match discover_client.run_once(&iface, Duration::from_secs(20), None).await {
                        Ok(Some(newl)) => { metrics.rediscover_success.fetch_add(1, Ordering::Relaxed); if let Some(tx)=&event_tx { let _= tx.send(ClientEvent{ level: EventLevel::Info, code:306, message: "dhcp rediscover success".into()}); } current_lease=newl; acquired_at_atomic.store(current_unix_secs(), Ordering::Relaxed); if let Some(lt)=current_lease.lease_time { cur_lt=lt; let sig = (current_lease.client_ip, current_lease.subnet_mask, current_lease.router, current_lease.dns_servers.clone()); if last_sig.as_ref().map(|s| s != &sig).unwrap_or(true) { if let Some(tx)=&event_tx { if let Some(json)=interface_snapshot_json(&current_lease, &iface, Some(xid), cache_reused, false, None, false, false, None) { let _=tx.send(ClientEvent{ level: EventLevel::Info, code:2221, message: json}); } } last_sig=Some(sig); } continue; } else { break; } }
                        _ => { metrics.failures.fetch_add(1, Ordering::Relaxed); if let Some(tx)=&event_tx { let _= tx.send(ClientEvent{ level: EventLevel::Error, code:307, message: "dhcp rediscover failed".into()}); } break; }
                    }
                }
            }
        });
        self.aux_tasks.push(handle);
    }
}

// Build and emit interface snapshot JSON (returns Some(json) or None if insufficient data)
fn interface_snapshot_json(lease: &DhcpLease, iface: &str, xid: Option<u32>, cache_reused: bool, initial: bool, acquired_at: Option<u64>, redact: bool, verbose: bool, v6: Option<&crate::dhcpv6::LeaseV6>) -> Option<String> {
    use serde::Serialize;
    let lt = lease.lease_time?; // need lease time to add timing detail; skip if absent
    let now = current_unix_secs();
    let total = lt.as_secs();
    let remaining = if let Some(start)=acquired_at { total.saturating_sub(now.saturating_sub(start)) } else { total };
    let renew_elapsed = if let Some(start)=acquired_at { now.saturating_sub(start) } else { 0 };
    let t1 = now + total/2;
    let t2 = now + (total * 7 / 8);
    let expiry = now + total;
    #[derive(Serialize)] struct Snap<'a>{kind:&'a str,name:&'a str,ipv4:String,router:Option<String>,dns:Vec<String>,lease_seconds_total:u64,lease_seconds_remaining:u64,renew_elapsed_secs:u64,t1_epoch:u64,t2_epoch:u64,expiry_epoch:u64,mtu:Option<u32>,xid:Option<u32>,cache_reused:bool,initial:bool,verbose:bool,ipv6:Option<String>,dns6:Option<Vec<String>>,ipv6_preferred_remaining:Option<u64>,ipv6_valid_remaining:Option<u64>}
    let redact_token = "***".to_string();
    let ipv4 = if redact { redact_token.clone() } else if let Some(mask)=lease.subnet_mask { format!("{}/{}", lease.client_ip, mask_to_prefix(mask)) } else { lease.client_ip.to_string() };
    let dns: Vec<String> = if redact { vec![redact_token.clone()] } else { lease.dns_servers.iter().take(if verbose { 8 } else { 4 }).map(|d| d.to_string()).collect() };
    let router = if redact { Some(redact_token) } else { lease.router.map(|r| r.to_string()) };
    let (ipv6, dns6, ipv6_pref_rem, ipv6_valid_rem) = if let Some(v6l)=v6 { let now_u=current_unix_secs(); let ipv6=v6l.addr.map(|a| if redact { "***".into() } else { a.to_string() }); let dns6= if v6l.dns_servers.is_empty(){ None } else { Some(if redact { vec!["***".into()] } else { v6l.dns_servers.iter().take(if verbose {8}else{4}).map(|d|d.to_string()).collect() }) }; let pref_rem = v6l.preferred_lifetime.and_then(|d| v6l.acquired_at.map(|acq| d.as_secs().saturating_sub(now_u.saturating_sub(acq)))); let valid_rem = v6l.valid_lifetime.and_then(|d| v6l.acquired_at.map(|acq| d.as_secs().saturating_sub(now_u.saturating_sub(acq)))); (ipv6, dns6, pref_rem, valid_rem) } else { (None,None,None,None) };
    let snap = Snap{kind:"interface_snapshot", name:iface, ipv4, router, dns, lease_seconds_total: total, lease_seconds_remaining: remaining, renew_elapsed_secs: renew_elapsed, t1_epoch: t1, t2_epoch: t2, expiry_epoch: expiry, mtu: Some(1500), xid, cache_reused, initial, verbose, ipv6, dns6, ipv6_preferred_remaining: ipv6_pref_rem, ipv6_valid_remaining: ipv6_valid_rem};
    serde_json::to_string(&snap).ok()
}

fn mask_to_prefix(mask: std::net::Ipv4Addr) -> u32 { u32::from(mask.octets()[0]).count_ones() + u32::from(mask.octets()[1]).count_ones() + u32::from(mask.octets()[2]).count_ones() + u32::from(mask.octets()[3]).count_ones() }

impl VpnClient {
    fn maybe_emit_interface_snapshot(&mut self, lease: &DhcpLease, iface: &str, initial: bool) {
        if let Some(tx)=&self.event_tx {
            if initial && self.initial_interface_snapshot_emitted { return; }
            // attempt to refresh acquired_at from cache (for accurate remaining / renew elapsed)
            let acquired_at = self.lease_acquired_at;
            // persistence removed
            let v6_guard = self.dhcpv6_lease.lock().ok();
            let v6_ref = v6_guard.as_ref().and_then(|g| g.as_ref());
            if let Some(json)=interface_snapshot_json(lease, iface, self.dhcp_xid, self.cached_lease_reused, initial, acquired_at, false, false, v6_ref) {
                let code = if initial { 2220 } else { 2221 };
                let _=tx.send(ClientEvent{ level: EventLevel::Info, code, message: json.clone() });
                if initial { self.initial_interface_snapshot_emitted = true; }
                // Health warning emission
                // Lease health warnings removed (config knob eliminated)
            }
        }
    }
}

impl VpnClient {
    /// Expose a public snapshot of DHCP metrics for callers (API level)
    pub fn dhcp_metrics_snapshot(&self) -> Option<(u64,u64,u64,u64,u64,u64,u64)> {
        if self.config.client.enable_in_tunnel_dhcp { let (a,b,c,d,e,f,g,_,_,_,_,_,_,_)= self.dhcp_metrics.snapshot(); Some((a,b,c,d,e,f,g)) } else { None }
    }
    /// Extended snapshot including IPv6 metrics.
    pub fn dhcp_metrics_snapshot_v6(&self) -> Option<(u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64)> {
        if self.config.client.enable_in_tunnel_dhcp { Some(self.dhcp_metrics.snapshot()) } else { None }
    }

    /// Return the current interface snapshot (recomputed from cached lease) if available.
    pub fn current_interface_snapshot(&self) -> Option<String> {
    None
    }
    /// Emit interface snapshot for server-assigned (non-DHCP) settings if not already emitted.
    pub fn emit_server_interface_snapshot(&mut self) {
        if self.initial_interface_snapshot_emitted { return; }
        if let Some(ns)=&self.network_settings {
            if self.config.client.enable_in_tunnel_dhcp && self.dhcp_xid.is_some() { return; }
            if let Some(ip)=ns.assigned_ipv4 {
                let mask = ns.subnet_mask.unwrap_or(std::net::Ipv4Addr::new(255,255,255,255));
                let prefix = mask_to_prefix(mask);
                let iface = self.actual_interface_name.as_deref().unwrap_or(&self.config.client.interface_name);
                let redact = false;
                let verbose = false;
                let mut dns: Vec<String> = if redact { vec!["***".into()] } else { ns.dns_servers.iter().map(|d| d.to_string()).collect() };
                if !verbose { dns.truncate(4); } else { dns.truncate(8); }
                let router = ns.gateway.map(|g| if redact { "***".into() } else { g.to_string() });
                let ipv4 = if redact { "***".into() } else { format!("{}/{}", ip, prefix) };
                // Attach v6 if present in settings
                let ipv6 = ns.assigned_ipv6.map(|a| if redact { "***".into() } else { a.to_string() });
                let mut dns6: Option<Vec<String>> = None;
                if !ns.dns_servers_v6.is_empty() { dns6 = Some(if redact { vec!["***".into()] } else { ns.dns_servers_v6.iter().map(|d| d.to_string()).collect() }); }
                #[derive(serde::Serialize)] struct Snap<'a>{kind:&'a str,name:&'a str,ipv4:String,router:Option<String>,dns:Vec<String>,lease_seconds_total:u64,lease_seconds_remaining:u64,renew_elapsed_secs:u64,t1_epoch:u64,t2_epoch:u64,expiry_epoch:u64,mtu:Option<u32>,xid:Option<u32>,cache_reused:bool,initial:bool,verbose:bool,ipv6:Option<String>,dns6:Option<Vec<String>>}
                let now=current_unix_secs();
                let snap=Snap{kind:"interface_snapshot",name:iface,ipv4,router,dns,lease_seconds_total:0,lease_seconds_remaining:0,renew_elapsed_secs:0,t1_epoch:now,t2_epoch:now,expiry_epoch:now,mtu:Some(1500),xid:None,cache_reused:false,initial:true,verbose,ipv6,dns6};
                if let Ok(js)=serde_json::to_string(&snap){ self.emit_event(EventLevel::Info,2220,js); self.initial_interface_snapshot_emitted=true; }
            }
        }
    }
    /// Emit a placeholder interface snapshot when no IP information is available (no server assignment, no DHCP lease).
    fn emit_placeholder_interface_snapshot(&mut self) {
        if self.initial_interface_snapshot_emitted { return; }
        let iface = self.actual_interface_name.as_deref().unwrap_or(&self.config.client.interface_name);
    let redact = false;
    let verbose = false;
    #[derive(serde::Serialize)] struct Snap<'a>{kind:&'a str,name:&'a str,ipv4:Option<String>,router:Option<String>,dns:Vec<String>,lease_seconds_total:u64,lease_seconds_remaining:u64,renew_elapsed_secs:u64,t1_epoch:u64,t2_epoch:u64,expiry_epoch:u64,mtu:Option<u32>,xid:Option<u32>,cache_reused:bool,initial:bool,verbose:bool,ipv6:Option<String>,dns6:Option<Vec<String>>}
        let now = current_unix_secs();
        let dns: Vec<String> = if redact { vec!["***".into()] } else { vec![] };
        // Try to incorporate IPv6 info if a v6 lease is already present (e.g. acquired before v4 or only v6 enabled)
        let (ipv6,dns6) = {
            let guard = self.dhcpv6_lease.lock().ok();
            if let Some(g)=guard.as_ref() { if let Some(v6l)=g.as_ref() { let ipv6=v6l.addr.map(|a| if redact {"***".into()} else {a.to_string()}); let dns6 = if v6l.dns_servers.is_empty(){ None } else { Some(if redact { vec!["***".into()] } else { v6l.dns_servers.iter().take(if verbose {8}else{4}).map(|d|d.to_string()).collect() }) }; (ipv6,dns6) } else { (None,None) } } else { (None,None) }
        };
    let snap = Snap{kind:"interface_snapshot", name:iface, ipv4:None, router:None, dns, lease_seconds_total:0, lease_seconds_remaining:0, renew_elapsed_secs:0, t1_epoch:now, t2_epoch:now, expiry_epoch:now, mtu:Some(1500), xid:self.dhcp_xid, cache_reused:false, initial:true, verbose, ipv6, dns6};
        if let Ok(js)=serde_json::to_string(&snap){
            info!("Emitting placeholder interface snapshot (no IP info yet)");
            self.emit_event(EventLevel::Info,2220,js);
            self.initial_interface_snapshot_emitted=true;
        }
    }
    fn spawn_lease_health_monitor(&mut self, _lease_total_secs: u64) { /* no-op after persistence removal */ }
}
