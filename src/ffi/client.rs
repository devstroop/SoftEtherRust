//! FFI client implementation.
//!
//! This module provides C-callable functions for the VPN client with actual
//! connection logic wired to the SoftEther protocol implementation.

use std::ffi::{c_char, c_int, CStr};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;

use super::callbacks::*;
use super::types::*;
use crate::client::{ConnectionManager, VpnConnection};
use crate::packet::{DhcpClient, DhcpConfig, DhcpState};
use crate::protocol::{
    decompress, is_compressed, AuthPack, AuthResult, AuthType, ConnectionOptions, HelloResponse,
    HttpCodec, HttpRequest, Pack, RedirectInfo, TunnelCodec, CONTENT_TYPE_PACK,
    CONTENT_TYPE_SIGNATURE, SIGNATURE_TARGET, VPN_SIGNATURE, VPN_TARGET,
};

/// Channel capacity for packet queues
const PACKET_QUEUE_SIZE: usize = 256;

/// Internal client state.
struct FfiClient {
    /// Configuration
    config: crate::config::VpnConfig,
    /// Callbacks
    callbacks: SoftEtherCallbacks,
    /// Connection state (for FFI layer - may be stale)
    state: SoftEtherState,
    /// Atomic state shared with async task
    atomic_state: Arc<AtomicU8>,
    /// Session info (after connection)
    session: Option<SoftEtherSession>,
    /// Statistics
    stats: FfiStats,
    /// Tokio runtime
    runtime: Option<tokio::runtime::Runtime>,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Channel to send packets TO the VPN
    tx_sender: Option<mpsc::Sender<Vec<u8>>>,
}

/// Thread-safe statistics
struct FfiStats {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    uptime_start: AtomicU64,
}

impl Default for FfiStats {
    fn default() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            uptime_start: AtomicU64::new(0),
        }
    }
}

impl FfiClient {
    fn new(config: crate::config::VpnConfig, callbacks: SoftEtherCallbacks) -> Self {
        Self {
            config,
            callbacks,
            state: SoftEtherState::Disconnected,
            atomic_state: Arc::new(AtomicU8::new(SoftEtherState::Disconnected as u8)),
            session: None,
            stats: FfiStats::default(),
            runtime: None,
            running: Arc::new(AtomicBool::new(false)),
            tx_sender: None,
        }
    }

    fn set_state(&mut self, state: SoftEtherState) {
        self.state = state;
        self.atomic_state.store(state as u8, Ordering::SeqCst);
    }

    fn get_atomic_state(&self) -> SoftEtherState {
        match self.atomic_state.load(Ordering::SeqCst) {
            0 => SoftEtherState::Disconnected,
            1 => SoftEtherState::Connecting,
            2 => SoftEtherState::Handshaking,
            3 => SoftEtherState::Authenticating,
            4 => SoftEtherState::EstablishingTunnel,
            5 => SoftEtherState::Connected,
            6 => SoftEtherState::Disconnecting,
            _ => SoftEtherState::Error,
        }
    }

    #[allow(dead_code)]
    fn notify_state(&self, state: SoftEtherState) {
        if let Some(cb) = self.callbacks.on_state_changed {
            cb(self.callbacks.context, state);
        }
    }

    #[allow(dead_code)]
    fn notify_connected(&self, session: &SoftEtherSession) {
        if let Some(cb) = self.callbacks.on_connected {
            cb(self.callbacks.context, session);
        }
    }

    fn notify_disconnected(&self, result: SoftEtherResult) {
        if let Some(cb) = self.callbacks.on_disconnected {
            cb(self.callbacks.context, result);
        }
    }

    fn to_stats(&self) -> SoftEtherStats {
        let uptime_start = self.stats.uptime_start.load(Ordering::Relaxed);
        let uptime = if uptime_start > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now.saturating_sub(uptime_start)
        } else {
            0
        };

        SoftEtherStats {
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.stats.packets_sent.load(Ordering::Relaxed),
            packets_received: self.stats.packets_received.load(Ordering::Relaxed),
            uptime_secs: uptime,
            active_connections: 1,
            reconnect_count: 0,
        }
    }
}

// Thread-safe wrapper
type ClientHandle = Arc<Mutex<FfiClient>>;

/// Convert a C string to a Rust string.
unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_string())
}

// =============================================================================
// FFI Functions - C ABI
// =============================================================================

/// Create a new SoftEther VPN client.
///
/// # Safety
/// - `config` must be a valid pointer to a `SoftEtherConfig` struct.
/// - `callbacks` must be a valid pointer to a `SoftEtherCallbacks` struct or null.
/// - String pointers in config must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn softether_create(
    config: *const SoftEtherConfig,
    callbacks: *const SoftEtherCallbacks,
) -> SoftEtherHandle {
    if config.is_null() {
        return SOFTETHER_HANDLE_NULL;
    }

    let config = &*config;
    if !config.is_valid() {
        return SOFTETHER_HANDLE_NULL;
    }

    // Parse configuration
    let server = match cstr_to_string(config.server) {
        Some(s) => s,
        None => return SOFTETHER_HANDLE_NULL,
    };
    let hub = match cstr_to_string(config.hub) {
        Some(s) => s,
        None => return SOFTETHER_HANDLE_NULL,
    };
    let username = match cstr_to_string(config.username) {
        Some(s) => s,
        None => return SOFTETHER_HANDLE_NULL,
    };
    let password_hash = match cstr_to_string(config.password_hash) {
        Some(s) => s,
        None => return SOFTETHER_HANDLE_NULL,
    };

    // Parse optional routing strings
    let ipv4_include_str = cstr_to_string(config.ipv4_include).unwrap_or_default();
    let ipv4_exclude_str = cstr_to_string(config.ipv4_exclude).unwrap_or_default();

    // Parse CIDR lists (comma-separated)
    let ipv4_include: Vec<String> = if ipv4_include_str.is_empty() {
        vec![]
    } else {
        ipv4_include_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    let ipv4_exclude: Vec<String> = if ipv4_exclude_str.is_empty() {
        vec![]
    } else {
        ipv4_exclude_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    // Create VPN config with all options
    let vpn_config = crate::config::VpnConfig {
        server,
        port: config.port as u16,
        hub,
        username,
        password_hash,
        skip_tls_verify: config.skip_tls_verify != 0,
        max_connections: config.max_connections.clamp(1, 32) as u8,
        timeout_seconds: config.timeout_seconds.max(5) as u64,
        mtu: config.mtu.clamp(576, 1500) as u16,
        use_encrypt: config.use_encrypt != 0,
        use_compress: config.use_compress != 0,
        udp_accel: config.udp_accel != 0,
        qos: config.qos != 0,
        nat_traversal: config.nat_traversal != 0,
        monitor_mode: config.monitor_mode != 0,
        routing: crate::config::RoutingConfig {
            default_route: config.default_route != 0,
            accept_pushed_routes: config.accept_pushed_routes != 0,
            ipv4_include,
            ipv4_exclude,
            ipv6_include: Vec::new(),
            ipv6_exclude: Vec::new(),
        },
    };

    // Parse callbacks
    let cbs = if callbacks.is_null() {
        SoftEtherCallbacks::default()
    } else {
        (*callbacks).clone()
    };

    // Create client
    let client = FfiClient::new(vpn_config, cbs);
    let handle: ClientHandle = Arc::new(Mutex::new(client));

    // Convert to raw pointer
    Arc::into_raw(handle) as SoftEtherHandle
}

/// Destroy a SoftEther VPN client.
///
/// # Safety
/// - `handle` must be a valid handle returned by `softether_create` or null.
/// - The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn softether_destroy(handle: SoftEtherHandle) {
    if handle.is_null() {
        return;
    }

    let client = Arc::from_raw(handle as *const Mutex<FfiClient>);

    {
        if let Ok(mut guard) = client.lock() {
            guard.running.store(false, Ordering::SeqCst);
            if guard.state == SoftEtherState::Connected {
                guard.state = SoftEtherState::Disconnecting;
                guard.state = SoftEtherState::Disconnected;
            }
        }
    }

    drop(client);
}

/// Connect to the VPN server.
///
/// # Safety
/// - `handle` must be a valid handle returned by `softether_create`.
#[no_mangle]
pub unsafe extern "C" fn softether_connect(handle: SoftEtherHandle) -> SoftEtherResult {
    if handle.is_null() {
        return SoftEtherResult::InvalidParam;
    }

    let client_arc = Arc::from_raw(handle as *const Mutex<FfiClient>);
    // Don't drop - we'll convert back at the end
    let client_arc_clone = client_arc.clone();
    std::mem::forget(client_arc);

    let mut guard = match client_arc_clone.lock() {
        Ok(g) => g,
        Err(_) => return SoftEtherResult::InternalError,
    };

    if guard.state != SoftEtherState::Disconnected {
        return SoftEtherResult::AlreadyConnected;
    }

    // Create tokio runtime
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => {
            return SoftEtherResult::InternalError;
        }
    };

    guard.set_state(SoftEtherState::Connecting);
    guard.notify_state(SoftEtherState::Connecting);
    guard.running.store(true, Ordering::SeqCst);

    // Create packet channel for TX (iOS -> VPN)
    let (tx_send, tx_recv) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE_SIZE);
    guard.tx_sender = Some(tx_send);

    // Clone what we need for the async task
    let config = guard.config.clone();
    let running = guard.running.clone();
    let callbacks = guard.callbacks.clone();
    let atomic_state = guard.atomic_state.clone();

    // Log that we're starting the async task
    if let Some(cb) = callbacks.on_log {
        if let Ok(cstr) = std::ffi::CString::new("Starting async connection task...") {
            cb(callbacks.context, 1, cstr.as_ptr());
        }
    }

    // Spawn the connection task
    runtime.spawn(async move {
        // Log inside the spawned task
        if let Some(cb) = callbacks.on_log {
            if let Ok(cstr) =
                std::ffi::CString::new("Async task started, calling connect_and_run...")
            {
                cb(callbacks.context, 1, cstr.as_ptr());
            }
        }

        let result = connect_and_run(
            config,
            running.clone(),
            callbacks.clone(),
            tx_recv,
            atomic_state,
        )
        .await;

        // Notify disconnection
        running.store(false, Ordering::SeqCst);

        let disconnect_result = match result {
            Ok(()) => {
                if let Some(cb) = callbacks.on_log {
                    if let Ok(cstr) = std::ffi::CString::new("Connection ended normally") {
                        cb(callbacks.context, 1, cstr.as_ptr());
                    }
                }
                SoftEtherResult::Ok
            }
            Err(ref e) => {
                if let Some(cb) = callbacks.on_log {
                    if let Ok(cstr) = std::ffi::CString::new(format!("Connection error: {}", e)) {
                        cb(callbacks.context, 3, cstr.as_ptr());
                    }
                }
                match e {
                    crate::error::Error::AuthenticationFailed(_) => SoftEtherResult::AuthFailed,
                    crate::error::Error::ConnectionFailed(_) => SoftEtherResult::ConnectionFailed,
                    crate::error::Error::Timeout => SoftEtherResult::Timeout,
                    crate::error::Error::UserAlreadyLoggedIn => SoftEtherResult::AuthFailed,
                    _ => SoftEtherResult::InternalError,
                }
            }
        };

        if let Some(cb) = callbacks.on_state_changed {
            cb(callbacks.context, SoftEtherState::Disconnected);
        }
        if let Some(cb) = callbacks.on_disconnected {
            cb(callbacks.context, disconnect_result);
        }
    });

    // Store runtime
    guard.runtime = Some(runtime);

    SoftEtherResult::Ok
}

/// Helper to update atomic state and notify callback
fn update_state(
    atomic_state: &Arc<AtomicU8>,
    callbacks: &SoftEtherCallbacks,
    state: SoftEtherState,
) {
    atomic_state.store(state as u8, Ordering::SeqCst);
    if let Some(cb) = callbacks.on_state_changed {
        cb(callbacks.context, state);
    }
}

/// The main connection and tunnel loop
async fn connect_and_run(
    config: crate::config::VpnConfig,
    running: Arc<AtomicBool>,
    callbacks: SoftEtherCallbacks,
    mut tx_recv: mpsc::Receiver<Vec<u8>>,
    atomic_state: Arc<AtomicU8>,
) -> crate::error::Result<()> {
    // Log helper - must clone callbacks for local use
    fn log_message(callbacks: &SoftEtherCallbacks, level: i32, msg: &str) {
        if let Some(cb) = callbacks.on_log {
            if let Ok(cstr) = std::ffi::CString::new(msg) {
                cb(callbacks.context, level, cstr.as_ptr());
            }
        }
    }

    log_message(&callbacks, 1, "[RUST] connect_and_run started");
    log_message(
        &callbacks,
        1,
        &format!("[RUST] Connecting to {}:{}", config.server, config.port),
    );
    log_message(
        &callbacks,
        1,
        &format!("[RUST] Hub: {}, User: {}", config.hub, config.username),
    );
    log_message(
        &callbacks,
        1,
        &format!("[RUST] Skip TLS verify: {}", config.skip_tls_verify),
    );

    // Resolve server IP
    log_message(&callbacks, 1, "[RUST] Resolving server IP...");
    let server_ip = match resolve_server_ip(&config.server) {
        Ok(ip) => {
            log_message(&callbacks, 1, &format!("[RUST] Resolved server IP: {}", ip));
            ip
        }
        Err(e) => {
            log_message(
                &callbacks,
                3,
                &format!("[RUST] DNS resolution failed: {}", e),
            );
            return Err(e);
        }
    };

    // Connect TCP with socket protection
    log_message(&callbacks, 1, "[RUST] Establishing TCP/TLS connection...");

    // Create socket protection closure
    // Note: We wrap the raw pointer to make it Send-safe for the closure
    let protect_cb = callbacks.protect_socket;
    let protect_ctx = callbacks.context as usize; // Convert to usize (Send-safe)
    let protect_fn = move |fd: i32| -> bool {
        if let Some(cb) = protect_cb {
            let result = cb(protect_ctx as *mut std::ffi::c_void, fd);
            return result;
        }
        true // No protection needed if callback not set
    };

    let mut conn = match VpnConnection::connect_with_protect(&config, protect_fn).await {
        Ok(c) => {
            log_message(
                &callbacks,
                1,
                "[RUST] TCP/TLS connection established (protected)",
            );
            c
        }
        Err(e) => {
            log_message(
                &callbacks,
                3,
                &format!("[RUST] TCP/TLS connection failed: {}", e),
            );
            return Err(e);
        }
    };

    // Notify state: Handshaking
    log_message(&callbacks, 1, "[RUST] Starting HTTP handshake...");
    update_state(&atomic_state, &callbacks, SoftEtherState::Handshaking);

    // HTTP handshake
    let hello = match perform_handshake(&mut conn, &config).await {
        Ok(h) => {
            log_message(
                &callbacks,
                1,
                &format!(
                    "[RUST] Server: {} v{} build {}",
                    h.server_string, h.server_version, h.server_build
                ),
            );
            h
        }
        Err(e) => {
            log_message(&callbacks, 3, &format!("[RUST] Handshake failed: {}", e));
            return Err(e);
        }
    };

    // Notify state: Authenticating
    log_message(&callbacks, 1, "[RUST] Starting authentication...");
    update_state(&atomic_state, &callbacks, SoftEtherState::Authenticating);

    // Authenticate
    log_message(&callbacks, 1, "[RUST] >>> About to call authenticate() <<<");
    let mut auth_result = match authenticate(&mut conn, &config, &hello, &callbacks).await {
        Ok(r) => {
            log_message(&callbacks, 1, "[RUST] Authentication successful");
            r
        }
        Err(e) => {
            log_message(
                &callbacks,
                3,
                &format!("[RUST] Authentication failed: {}", e),
            );
            return Err(e);
        }
    };

    log_message(
        &callbacks,
        1,
        &format!(
            "[RUST] Initial auth: session_key={} bytes, redirect={:?}",
            auth_result.session_key.len(),
            auth_result
                .redirect
                .as_ref()
                .map(|r| format!("{}:{}", r.ip_string(), r.port))
        ),
    );

    // Handle cluster redirect if present
    // NOTE: When redirect is present, session_key will be empty - we get it from redirect server
    let (active_conn, final_auth, actual_server_ip, actual_server_addr, actual_server_port) =
        if let Some(redirect) = auth_result.redirect.take() {
            let redirect_ip = redirect.ip_string();
            log_message(
                &callbacks,
                1,
                &format!(
                    "[RUST] Cluster redirect to {}:{}",
                    redirect_ip, redirect.port
                ),
            );

            // Send empty Pack acknowledgment before closing connection
            let ack_pack = Pack::new();
            let request = HttpRequest::post(VPN_TARGET)
                .header("Content-Type", CONTENT_TYPE_PACK)
                .header("Connection", "Keep-Alive")
                .body(ack_pack.to_bytes());
            let host = format!("{}:{}", config.server, config.port);
            let request_bytes = request.build(&host);
            let _ = conn.write_all(&request_bytes).await;

            // Small delay before closing
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(conn);

            // Connect to redirect server
            match connect_redirect(&config, &redirect, &callbacks).await {
                Ok((redirect_conn, redirect_auth)) => {
                    let new_ip = match redirect_ip.parse::<Ipv4Addr>() {
                        Ok(ip) => ip,
                        Err(_) => server_ip,
                    };
                    (
                        redirect_conn,
                        redirect_auth,
                        new_ip,
                        redirect_ip,
                        redirect.port,
                    )
                }
                Err(e) => {
                    log_message(&callbacks, 3, &format!("[RUST] Redirect failed: {}", e));
                    return Err(e);
                }
            }
        } else {
            // No redirect - check session key now
            if auth_result.session_key.is_empty() {
                log_message(
                    &callbacks,
                    3,
                    "[RUST] No session key received and no redirect",
                );
                return Err(crate::error::Error::AuthenticationFailed(
                    "No session key received".into(),
                ));
            }
            (
                conn,
                auth_result,
                server_ip,
                config.server.clone(),
                config.port,
            )
        };

    // Verify we have session key after redirect handling
    if final_auth.session_key.is_empty() {
        log_message(&callbacks, 3, "[RUST] No session key after redirect");
        return Err(crate::error::Error::AuthenticationFailed(
            "No session key received from redirect server".into(),
        ));
    }

    log_message(
        &callbacks,
        1,
        &format!(
            "[RUST] Session established: {} bytes session key",
            final_auth.session_key.len()
        ),
    );

    // Create connection manager for packet I/O
    log_message(&callbacks, 1, "[RUST] Creating connection manager...");
    let mut conn_mgr = ConnectionManager::new(
        active_conn,
        &config,
        &final_auth,
        &actual_server_addr,
        actual_server_port,
    );

    // Generate MAC address for DHCP
    let mut mac = [0u8; 6];
    crate::crypto::fill_random(&mut mac);
    mac[0] = (mac[0] | 0x02) & 0xFE; // Local/unicast

    log_message(
        &callbacks,
        1,
        &format!(
            "[RUST] Generated MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ),
    );

    // Perform DHCP to get IP configuration
    log_message(&callbacks, 1, "[RUST] Starting DHCP...");
    update_state(
        &atomic_state,
        &callbacks,
        SoftEtherState::EstablishingTunnel,
    );

    let dhcp_config = match perform_dhcp(&mut conn_mgr, mac, &callbacks, config.use_compress).await
    {
        Ok(config) => {
            log_message(
                &callbacks,
                1,
                &format!(
                    "[RUST] DHCP complete: IP={}, Gateway={:?}, DNS={:?}",
                    config.ip, config.gateway, config.dns1
                ),
            );
            config
        }
        Err(e) => {
            log_message(&callbacks, 3, &format!("[RUST] DHCP failed: {}", e));
            return Err(e);
        }
    };

    // Create session info from DHCP config (include MAC for Kotlin to use)
    let session = create_session_from_dhcp(&dhcp_config, actual_server_ip, mac);

    // Notify connected with session info
    log_message(&callbacks, 1, "[RUST] Notifying Android of connection...");
    if let Some(cb) = callbacks.on_connected {
        cb(callbacks.context, &session);
    }
    update_state(&atomic_state, &callbacks, SoftEtherState::Connected);

    log_message(
        &callbacks,
        1,
        &format!(
            "[RUST] Connected! IP: {}, Server: {}",
            dhcp_config.ip, actual_server_ip
        ),
    );

    // Run the packet loop
    log_message(&callbacks, 1, "[RUST] Starting packet loop...");
    run_packet_loop(
        &mut conn_mgr,
        running,
        callbacks,
        &mut tx_recv,
        mac,
        dhcp_config,
    )
    .await
}

/// Create session info from DHCP config
fn create_session_from_dhcp(
    dhcp: &DhcpConfig,
    server_ip: Ipv4Addr,
    mac: [u8; 6],
) -> SoftEtherSession {
    let mut server_ip_str = [0 as std::ffi::c_char; 64];
    let ip_string = format!("{}", server_ip);
    for (i, b) in ip_string.bytes().enumerate() {
        if i < 63 {
            server_ip_str[i] = b as std::ffi::c_char;
        }
    }

    fn ip_to_u32(ip: Ipv4Addr) -> u32 {
        let octets = ip.octets();
        ((octets[0] as u32) << 24)
            | ((octets[1] as u32) << 16)
            | ((octets[2] as u32) << 8)
            | (octets[3] as u32)
    }

    SoftEtherSession {
        ip_address: ip_to_u32(dhcp.ip),
        subnet_mask: ip_to_u32(dhcp.netmask),
        gateway: dhcp.gateway.map(ip_to_u32).unwrap_or(0),
        dns1: dhcp.dns1.map(ip_to_u32).unwrap_or(0),
        dns2: dhcp.dns2.map(ip_to_u32).unwrap_or(0),
        connected_server_ip: server_ip_str,
        server_version: 0,
        server_build: 0,
        mac_address: mac,
        gateway_mac: [0; 6], // Will be learned dynamically
    }
}

/// Connect to redirect server after cluster redirect
async fn connect_redirect(
    config: &crate::config::VpnConfig,
    redirect: &RedirectInfo,
    callbacks: &SoftEtherCallbacks,
) -> crate::error::Result<(VpnConnection, AuthResult)> {
    fn log_msg(callbacks: &SoftEtherCallbacks, level: i32, msg: &str) {
        if let Some(cb) = callbacks.on_log {
            if let Ok(cstr) = std::ffi::CString::new(msg) {
                cb(callbacks.context, level, cstr.as_ptr());
            }
        }
    }

    let redirect_server = redirect.ip_string();
    let redirect_port = redirect.port;

    log_msg(
        callbacks,
        1,
        &format!(
            "[RUST] Connecting to cluster server {}:{}",
            redirect_server, redirect_port
        ),
    );

    // Create a modified config for the redirect server
    let mut redirect_config = config.clone();
    redirect_config.server = redirect_server.clone();
    redirect_config.port = redirect_port;

    // Connect to redirect server with socket protection
    let protect_cb = callbacks.protect_socket;
    let protect_ctx = callbacks.context as usize; // Convert to usize (Send-safe)
    let protect_fn = move |fd: i32| -> bool {
        if let Some(cb) = protect_cb {
            return cb(protect_ctx as *mut std::ffi::c_void, fd);
        }
        true
    };

    let mut conn = VpnConnection::connect_with_protect(&redirect_config, protect_fn).await?;

    // Perform handshake
    let hello = perform_handshake(&mut conn, &redirect_config).await?;
    log_msg(
        callbacks,
        1,
        &format!(
            "[RUST] Redirect server hello: v{} build {}",
            hello.server_version, hello.server_build
        ),
    );

    // Build connection options
    let options = ConnectionOptions {
        max_connections: config.max_connections,
        use_encrypt: config.use_encrypt,
        use_compress: config.use_compress,
        udp_accel: false,
        bridge_mode: false,
        monitor_mode: false,
        qos: config.qos,
    };

    // Build ticket auth pack
    let auth_pack = AuthPack::new_ticket(
        &config.hub,
        &config.username,
        &hello.random,
        &redirect.ticket,
        &options,
        None,
    );

    let request = HttpRequest::post(VPN_TARGET)
        .header("Content-Type", CONTENT_TYPE_PACK)
        .header("Connection", "Keep-Alive")
        .body(auth_pack.to_bytes());

    let host = format!("{}:{}", redirect_server, redirect_port);
    let request_bytes = request.build(&host);

    log_msg(callbacks, 1, "[RUST] Sending ticket authentication");
    conn.write_all(&request_bytes).await?;

    // Read response
    let mut codec = HttpCodec::new();
    let mut buf = vec![0u8; 8192];

    loop {
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            return Err(crate::error::Error::ConnectionFailed(
                "Connection closed during redirect auth".into(),
            ));
        }

        if let Some(response) = codec.feed(&buf[..n])? {
            if response.status_code != 200 {
                return Err(crate::error::Error::AuthenticationFailed(format!(
                    "Redirect server returned status {}",
                    response.status_code
                )));
            }

            if !response.body.is_empty() {
                let pack = Pack::deserialize(&response.body)?;
                let result = AuthResult::from_pack(&pack)?;

                if result.error > 0 {
                    return Err(crate::error::Error::AuthenticationFailed(format!(
                        "Redirect auth error: {}",
                        result.error
                    )));
                }

                log_msg(
                    callbacks,
                    1,
                    &format!(
                        "[RUST] Redirect auth success, session key: {} bytes",
                        result.session_key.len()
                    ),
                );
                return Ok((conn, result));
            } else {
                return Err(crate::error::Error::ServerError(
                    "Empty redirect auth response".into(),
                ));
            }
        }
    }
}

/// Perform DHCP through the tunnel to get IP configuration
async fn perform_dhcp(
    conn_mgr: &mut ConnectionManager,
    mac: [u8; 6],
    callbacks: &SoftEtherCallbacks,
    use_compress: bool,
) -> crate::error::Result<DhcpConfig> {
    use tokio::time::timeout;

    fn log_msg(callbacks: &SoftEtherCallbacks, level: i32, msg: &str) {
        if let Some(cb) = callbacks.on_log {
            if let Ok(cstr) = std::ffi::CString::new(msg) {
                cb(callbacks.context, level, cstr.as_ptr());
            }
        }
    }

    let mut dhcp = DhcpClient::new(mac);
    let mut codec = TunnelCodec::new();
    let mut buf = vec![0u8; 65536];
    let mut send_buf = vec![0u8; 2048];

    let deadline = std::time::Instant::now() + Duration::from_secs(30);

    // Send DHCP DISCOVER
    let discover = dhcp.build_discover();
    log_msg(
        callbacks,
        1,
        &format!("[RUST] Sending DHCP DISCOVER ({} bytes)", discover.len()),
    );
    send_frame(conn_mgr, &discover, &mut send_buf, use_compress).await?;

    // Wait for OFFER/ACK
    loop {
        if std::time::Instant::now() > deadline {
            return Err(crate::error::Error::TimeoutMessage(
                "DHCP timeout - no response received".into(),
            ));
        }

        match timeout(Duration::from_secs(3), conn_mgr.read_any(&mut buf)).await {
            Ok(Ok((_conn_idx, n))) if n > 0 => {
                // Decode tunnel frames
                let frames = codec.feed(&buf[..n])?;
                for frame in frames {
                    if frame.is_keepalive() {
                        continue;
                    }
                    if let Some(packets) = frame.packets() {
                        for packet in packets {
                            // Decompress if needed
                            let packet_data: Vec<u8> = if is_compressed(packet) {
                                match decompress(packet) {
                                    Ok(decompressed) => decompressed,
                                    Err(_) => continue,
                                }
                            } else {
                                packet.to_vec()
                            };

                            // Check if this is a DHCP response
                            if is_dhcp_response(&packet_data) {
                                log_msg(callbacks, 1, "[RUST] DHCP response received");
                                if dhcp.process_response(&packet_data) {
                                    // Got ACK
                                    return Ok(dhcp.config().clone());
                                } else if dhcp.state() == DhcpState::DiscoverSent {
                                    // Got OFFER, send REQUEST
                                    if let Some(request) = dhcp.build_request() {
                                        log_msg(callbacks, 1, "[RUST] Sending DHCP REQUEST");
                                        send_frame(conn_mgr, &request, &mut send_buf, use_compress)
                                            .await?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(Ok(_)) => {
                // Zero bytes - continue
            }
            Ok(Err(e)) => {
                log_msg(
                    callbacks,
                    2,
                    &format!("[RUST] Read error during DHCP: {}", e),
                );
            }
            Err(_) => {
                // Timeout, retry
                if dhcp.state() == DhcpState::DiscoverSent {
                    log_msg(callbacks, 2, "[RUST] DHCP timeout, retrying DISCOVER");
                    let discover = dhcp.build_discover();
                    send_frame(conn_mgr, &discover, &mut send_buf, use_compress).await?;
                } else if dhcp.state() == DhcpState::RequestSent {
                    log_msg(callbacks, 2, "[RUST] DHCP timeout, retrying REQUEST");
                    if let Some(request) = dhcp.build_request() {
                        send_frame(conn_mgr, &request, &mut send_buf, use_compress).await?;
                    }
                }
            }
        }
    }
}

/// Check if an Ethernet frame is a DHCP response (UDP dst port 68)
fn is_dhcp_response(frame: &[u8]) -> bool {
    // Minimum: Ethernet(14) + IP(20) + UDP(8) + DHCP minimal
    if frame.len() < 42 {
        return false;
    }
    // Check EtherType is IPv4
    if frame[12] != 0x08 || frame[13] != 0x00 {
        return false;
    }
    // Check IP protocol is UDP (17)
    if frame[23] != 17 {
        return false;
    }
    // Check UDP destination port is 68 (DHCP client)
    let dst_port = u16::from_be_bytes([frame[36], frame[37]]);
    dst_port == 68
}

/// Send an Ethernet frame through the tunnel
async fn send_frame(
    conn_mgr: &mut ConnectionManager,
    frame: &[u8],
    buf: &mut [u8],
    use_compress: bool,
) -> crate::error::Result<()> {
    use crate::protocol::compress;

    let data_to_send: std::borrow::Cow<[u8]> = if use_compress {
        match compress(frame) {
            Ok(compressed) => std::borrow::Cow::Owned(compressed),
            Err(_) => std::borrow::Cow::Borrowed(frame),
        }
    } else {
        std::borrow::Cow::Borrowed(frame)
    };

    let total_len = 4 + 4 + data_to_send.len();
    if buf.len() < total_len {
        return Err(crate::error::Error::Protocol(
            "Send buffer too small".into(),
        ));
    }

    buf[0..4].copy_from_slice(&1u32.to_be_bytes());
    buf[4..8].copy_from_slice(&(data_to_send.len() as u32).to_be_bytes());
    buf[8..8 + data_to_send.len()].copy_from_slice(&data_to_send);

    conn_mgr
        .write_all(&buf[..total_len])
        .await
        .map_err(crate::error::Error::Io)?;
    Ok(())
}

/// Run the main packet forwarding loop
async fn run_packet_loop(
    conn_mgr: &mut ConnectionManager,
    running: Arc<AtomicBool>,
    callbacks: SoftEtherCallbacks,
    tx_recv: &mut mpsc::Receiver<Vec<u8>>,
    _mac: [u8; 6],
    _dhcp_config: DhcpConfig,
) -> crate::error::Result<()> {
    fn log_msg(callbacks: &SoftEtherCallbacks, level: i32, msg: &str) {
        if let Some(cb) = callbacks.on_log {
            if let Ok(cstr) = std::ffi::CString::new(msg) {
                cb(callbacks.context, level, cstr.as_ptr());
            }
        }
    }

    let mut tunnel_codec = TunnelCodec::new();
    let mut read_buf = vec![0u8; 65536];
    let mut keepalive_interval = tokio::time::interval(Duration::from_secs(3));
    let mut tx_packet_count: u64 = 0;
    let mut rx_packet_count: u64 = 0;
    let mut keepalive_count: u64 = 0;

    log_msg(
        &callbacks,
        1,
        "[RUST] Packet loop started, waiting for traffic...",
    );

    // Send first keepalive immediately
    {
        keepalive_count += 1;
        let keepalive = tunnel_codec.encode_keepalive();
        conn_mgr
            .write_all(&keepalive)
            .await
            .map_err(crate::error::Error::Io)?;
        log_msg(
            &callbacks,
            0,
            &format!(
                "[RUST] Keepalive #{} sent ({} bytes)",
                keepalive_count,
                keepalive.len()
            ),
        );
    }

    while running.load(Ordering::SeqCst) {
        tokio::select! {
            biased;  // Ensures branches are checked in order - keepalive gets priority

            // Keepalive - check first to ensure it fires
            _ = keepalive_interval.tick() => {
                keepalive_count += 1;
                let keepalive = tunnel_codec.encode_keepalive();
                match conn_mgr.write_all(&keepalive).await {
                    Ok(()) => {
                        log_msg(&callbacks, 0, &format!("[RUST] Keepalive #{} sent ({} bytes)", keepalive_count, keepalive.len()));
                    }
                    Err(e) => {
                        log_msg(&callbacks, 3, &format!("[RUST] Keepalive send failed: {}", e));
                        return Err(crate::error::Error::Io(e));
                    }
                }
            }

            // Packets from Android to send to VPN
            Some(frame_data) = tx_recv.recv() => {
                // frame_data is already Ethernet frames, concatenated with length prefixes
                // Parse and send
                let frames = parse_length_prefixed_packets(&frame_data);
                if !frames.is_empty() {
                    tx_packet_count += frames.len() as u64;
                    if tx_packet_count <= 5 || tx_packet_count % 100 == 0 {
                        log_msg(&callbacks, 0, &format!("[RUST] TX: {} frames (total: {})", frames.len(), tx_packet_count));
                    }
                    let encoded = tunnel_codec.encode(&frames.iter().map(|f| f.as_slice()).collect::<Vec<_>>());
                    conn_mgr.write_all(&encoded).await.map_err(crate::error::Error::Io)?;
                }
            }

            // Data from VPN to send to Android - with timeout to ensure keepalive can fire
            result = tokio::time::timeout(Duration::from_secs(1), conn_mgr.read_any(&mut read_buf)) => {
                match result {
                    Ok(Ok((_conn_idx, n))) if n > 0 => {
                        // Decode tunnel frames - returns Vec<Bytes>
                        if let Ok(frames) = tunnel_codec.decode(&read_buf[..n]) {
                            if !frames.is_empty() {
                                rx_packet_count += frames.len() as u64;
                                if rx_packet_count <= 5 || rx_packet_count % 100 == 0 {
                                    log_msg(&callbacks, 0, &format!("[RUST] RX: {} frames (total: {})", frames.len(), rx_packet_count));
                                }

                                // Build length-prefixed buffer for callback
                                let mut buffer = Vec::with_capacity(n + frames.len() * 2);
                                for frame in &frames {
                                    // Decompress if needed
                                    let frame_data: Vec<u8> = if is_compressed(frame) {
                                        match decompress(frame) {
                                            Ok(d) => d,
                                            Err(_) => frame.to_vec(),
                                        }
                                    } else {
                                        frame.to_vec()
                                    };

                                    let len = frame_data.len() as u16;
                                    buffer.extend_from_slice(&len.to_be_bytes());
                                    buffer.extend_from_slice(&frame_data);
                                }

                                // Call Android callback
                                if let Some(cb) = callbacks.on_packets_received {
                                    cb(callbacks.context, buffer.as_ptr(), buffer.len(), frames.len() as u32);
                                }
                            }
                        }
                    }
                    Ok(Ok(_)) => {
                        // Connection closed (zero bytes)
                        log_msg(&callbacks, 2, "[RUST] Connection closed by server");
                        break;
                    }
                    Ok(Err(e)) => {
                        log_msg(&callbacks, 3, &format!("[RUST] Read error: {}", e));
                        return Err(crate::error::Error::Io(e));
                    }
                    Err(_) => {
                        // Timeout - this is fine, just loop again to check keepalive
                    }
                }
            }
        }
    }

    log_msg(&callbacks, 1, "[RUST] Packet loop ended");
    Ok(())
}

/// Parse length-prefixed packets from a buffer
fn parse_length_prefixed_packets(data: &[u8]) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    let mut offset = 0;

    while offset + 2 <= data.len() {
        let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + len <= data.len() {
            result.push(data[offset..offset + len].to_vec());
            offset += len;
        } else {
            break;
        }
    }

    result
}

/// Perform HTTP handshake
async fn perform_handshake(
    conn: &mut VpnConnection,
    config: &crate::config::VpnConfig,
) -> crate::error::Result<HelloResponse> {
    let request = HttpRequest::post(SIGNATURE_TARGET)
        .header("Content-Type", CONTENT_TYPE_SIGNATURE)
        .header("Connection", "Keep-Alive")
        .body(VPN_SIGNATURE);

    let host = format!("{}:{}", config.server, config.port);
    let request_bytes = request.build(&host);

    conn.write_all(&request_bytes).await?;

    let mut codec = HttpCodec::new();
    let mut buf = vec![0u8; 4096];

    loop {
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            return Err(crate::error::Error::ConnectionFailed(
                "Connection closed during handshake".into(),
            ));
        }

        if let Some(response) = codec.feed(&buf[..n])? {
            if response.status_code != 200 {
                return Err(crate::error::Error::ServerError(format!(
                    "Server returned status {}",
                    response.status_code
                )));
            }

            if !response.body.is_empty() {
                let pack = crate::protocol::Pack::deserialize(&response.body)?;
                return HelloResponse::from_pack(&pack);
            } else {
                return Err(crate::error::Error::ServerError(
                    "Empty response body".into(),
                ));
            }
        }
    }
}

/// Authenticate with the server
async fn authenticate(
    conn: &mut VpnConnection,
    config: &crate::config::VpnConfig,
    hello: &HelloResponse,
    callbacks: &SoftEtherCallbacks,
) -> crate::error::Result<AuthResult> {
    // Log helper
    fn log_msg(callbacks: &SoftEtherCallbacks, level: i32, msg: &str) {
        if let Some(cb) = callbacks.on_log {
            if let Ok(cstr) = std::ffi::CString::new(msg) {
                cb(callbacks.context, level, cstr.as_ptr());
            }
        }
    }

    // IMMEDIATE log at function entry
    log_msg(
        callbacks,
        1,
        "[RUST] >>> ENTERED authenticate() function <<<",
    );
    log_msg(
        callbacks,
        1,
        &format!(
            "[RUST] hello.use_secure_password = {}",
            hello.use_secure_password
        ),
    );

    let auth_type = if hello.use_secure_password {
        log_msg(callbacks, 1, "[RUST] Using SecurePassword auth type");
        AuthType::SecurePassword
    } else {
        log_msg(callbacks, 1, "[RUST] Using Password auth type");
        AuthType::Password
    };

    let options = ConnectionOptions {
        max_connections: config.max_connections,
        use_encrypt: config.use_encrypt,
        use_compress: config.use_compress,
        udp_accel: false,
        bridge_mode: false,
        monitor_mode: false,
        qos: true,
    };

    log_msg(
        callbacks,
        1,
        &format!(
            "[RUST] Password hash length: {}",
            config.password_hash.len()
        ),
    );

    // Decode password hash - it might be base64 or hex
    let password_hash_bytes: [u8; 20] =
        if config.password_hash.len() == 28 && config.password_hash.ends_with('=') {
            // Base64 encoded
            log_msg(callbacks, 1, "[RUST] Decoding base64 password hash");
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&config.password_hash)
                .map_err(|e| {
                    log_msg(callbacks, 3, &format!("[RUST] Base64 decode error: {}", e));
                    crate::error::Error::Config(format!("Invalid base64 password hash: {}", e))
                })?;

            if decoded.len() != 20 {
                log_msg(
                    callbacks,
                    3,
                    &format!("[RUST] Hash length wrong: {} bytes", decoded.len()),
                );
                return Err(crate::error::Error::Config(format!(
                    "Password hash must be 20 bytes, got {}",
                    decoded.len()
                )));
            }
            log_msg(callbacks, 1, "[RUST] Base64 hash decoded successfully");
            decoded.try_into().unwrap()
        } else if config.password_hash.len() == 40 {
            // Hex encoded
            log_msg(callbacks, 1, "[RUST] Decoding hex password hash");
            let decoded = hex::decode(&config.password_hash).map_err(|e| {
                log_msg(callbacks, 3, &format!("[RUST] Hex decode error: {}", e));
                crate::error::Error::Config(format!("Invalid hex password hash: {}", e))
            })?;
            log_msg(callbacks, 1, "[RUST] Hex hash decoded successfully");
            decoded.try_into().unwrap()
        } else {
            log_msg(
                callbacks,
                3,
                &format!(
                    "[RUST] Invalid hash format: len={}",
                    config.password_hash.len()
                ),
            );
            return Err(crate::error::Error::Config(
                "Password hash must be 20 bytes as base64 (28 chars) or hex (40 chars)".into(),
            ));
        };

    log_msg(callbacks, 1, "[RUST] Building auth pack...");
    let auth_pack = AuthPack::new(
        &config.hub,
        &config.username,
        &password_hash_bytes,
        auth_type,
        &hello.random,
        &options,
        None,
    );

    let request = HttpRequest::post(VPN_TARGET)
        .header("Content-Type", CONTENT_TYPE_PACK)
        .header("Connection", "Keep-Alive")
        .body(auth_pack.to_bytes());

    let host = format!("{}:{}", config.server, config.port);
    let request_bytes = request.build(&host);

    log_msg(
        callbacks,
        1,
        &format!(
            "[RUST] Sending auth request ({} bytes)...",
            request_bytes.len()
        ),
    );
    conn.write_all(&request_bytes).await?;

    let mut codec = HttpCodec::new();
    let mut buf = vec![0u8; 8192];

    log_msg(callbacks, 1, "[RUST] Waiting for auth response...");
    loop {
        let n = conn.read(&mut buf).await?;
        log_msg(callbacks, 1, &format!("[RUST] Received {} bytes", n));
        if n == 0 {
            log_msg(callbacks, 3, "[RUST] Connection closed during auth");
            return Err(crate::error::Error::ConnectionFailed(
                "Connection closed during authentication".into(),
            ));
        }

        if let Some(response) = codec.feed(&buf[..n])? {
            log_msg(
                callbacks,
                1,
                &format!("[RUST] HTTP response status: {}", response.status_code),
            );
            if response.status_code != 200 {
                log_msg(
                    callbacks,
                    3,
                    &format!("[RUST] Auth failed: HTTP {}", response.status_code),
                );
                return Err(crate::error::Error::AuthenticationFailed(format!(
                    "Server returned status {}",
                    response.status_code
                )));
            }

            if !response.body.is_empty() {
                log_msg(
                    callbacks,
                    1,
                    &format!("[RUST] Response body: {} bytes", response.body.len()),
                );
                let pack = crate::protocol::Pack::deserialize(&response.body)?;
                let result = AuthResult::from_pack(&pack)?;

                if result.error > 0 {
                    log_msg(
                        callbacks,
                        3,
                        &format!("[RUST] Auth error code: {}", result.error),
                    );
                    if result.error == 20 {
                        return Err(crate::error::Error::UserAlreadyLoggedIn);
                    }
                    return Err(crate::error::Error::AuthenticationFailed(format!(
                        "Authentication error code: {}",
                        result.error
                    )));
                }

                log_msg(
                    callbacks,
                    1,
                    &format!(
                        "[RUST] Auth success! Session key: {} bytes",
                        result.session_key.len()
                    ),
                );
                return Ok(result);
            } else {
                log_msg(callbacks, 3, "[RUST] Empty auth response body");
                return Err(crate::error::Error::ServerError(
                    "Empty authentication response".into(),
                ));
            }
        }
    }
}

/// Resolve hostname to IPv4
fn resolve_server_ip(server: &str) -> crate::error::Result<Ipv4Addr> {
    if let Ok(ip) = server.parse::<Ipv4Addr>() {
        return Ok(ip);
    }

    use std::net::ToSocketAddrs;
    let addr_str = format!("{}:443", server);
    match addr_str.to_socket_addrs() {
        Ok(mut addrs) => {
            for addr in addrs.by_ref() {
                if let std::net::SocketAddr::V4(v4) = addr {
                    return Ok(*v4.ip());
                }
            }
            Err(crate::error::Error::ConnectionFailed(format!(
                "No IPv4 address found for {}",
                server
            )))
        }
        Err(e) => Err(crate::error::Error::ConnectionFailed(format!(
            "Failed to resolve {}: {}",
            server, e
        ))),
    }
}

/// Disconnect from the VPN server.
///
/// # Safety
/// - `handle` must be a valid handle returned by `softether_create`.
#[no_mangle]
pub unsafe extern "C" fn softether_disconnect(handle: SoftEtherHandle) -> SoftEtherResult {
    if handle.is_null() {
        return SoftEtherResult::InvalidParam;
    }

    let client = &*(handle as *const Mutex<FfiClient>);
    let mut guard = match client.lock() {
        Ok(g) => g,
        Err(_) => return SoftEtherResult::InternalError,
    };

    if guard.state == SoftEtherState::Disconnected {
        return SoftEtherResult::Ok;
    }

    guard.running.store(false, Ordering::SeqCst);
    guard.state = SoftEtherState::Disconnecting;
    guard.notify_state(SoftEtherState::Disconnecting);

    // Drop the channel to signal shutdown
    guard.tx_sender = None;

    guard.state = SoftEtherState::Disconnected;
    guard.notify_state(SoftEtherState::Disconnected);
    guard.notify_disconnected(SoftEtherResult::Ok);

    SoftEtherResult::Ok
}

/// Get current connection state.
///
/// # Safety
/// - `handle` must be a valid handle returned by `softether_create` or null.
#[no_mangle]
pub unsafe extern "C" fn softether_get_state(handle: SoftEtherHandle) -> SoftEtherState {
    if handle.is_null() {
        return SoftEtherState::Disconnected;
    }

    let client = &*(handle as *const Mutex<FfiClient>);
    match client.lock() {
        Ok(guard) => guard.get_atomic_state(),
        Err(_) => SoftEtherState::Disconnected,
    }
}

/// Get session information.
///
/// # Safety
/// - `handle` must be a valid handle returned by `softether_create`.
/// - `session` must be a valid pointer to a `SoftEtherSession` struct.
#[no_mangle]
pub unsafe extern "C" fn softether_get_session(
    handle: SoftEtherHandle,
    session: *mut SoftEtherSession,
) -> SoftEtherResult {
    if handle.is_null() || session.is_null() {
        return SoftEtherResult::InvalidParam;
    }

    let client = &*(handle as *const Mutex<FfiClient>);
    let guard = match client.lock() {
        Ok(g) => g,
        Err(_) => return SoftEtherResult::InternalError,
    };

    match &guard.session {
        Some(s) => {
            *session = s.clone();
            SoftEtherResult::Ok
        }
        None => SoftEtherResult::NotConnected,
    }
}

/// Get connection statistics.
///
/// # Safety
/// - `handle` must be a valid handle returned by `softether_create`.
/// - `stats` must be a valid pointer to a `SoftEtherStats` struct.
#[no_mangle]
pub unsafe extern "C" fn softether_get_stats(
    handle: SoftEtherHandle,
    stats: *mut SoftEtherStats,
) -> SoftEtherResult {
    if handle.is_null() || stats.is_null() {
        return SoftEtherResult::InvalidParam;
    }

    let client = &*(handle as *const Mutex<FfiClient>);
    let guard = match client.lock() {
        Ok(g) => g,
        Err(_) => return SoftEtherResult::InternalError,
    };

    *stats = guard.to_stats();
    SoftEtherResult::Ok
}

/// Send packets to the VPN server.
///
/// # Safety
/// - `handle` must be a valid handle returned by `softether_create`.
/// - `packets` must be a valid pointer to a buffer of `total_size` bytes.
/// - The buffer contains length-prefixed packets.
#[no_mangle]
pub unsafe extern "C" fn softether_send_packets(
    handle: SoftEtherHandle,
    packets: *const u8,
    total_size: usize,
    count: c_int,
) -> c_int {
    if handle.is_null() || packets.is_null() || count <= 0 {
        return SoftEtherResult::InvalidParam as c_int;
    }

    let client = &*(handle as *const Mutex<FfiClient>);
    let guard = match client.lock() {
        Ok(g) => g,
        Err(_) => return SoftEtherResult::InternalError as c_int,
    };

    // Check atomic state (updated by async task) instead of stale guard.state
    if guard.get_atomic_state() != SoftEtherState::Connected {
        return SoftEtherResult::NotConnected as c_int;
    }

    // Copy packet data and send through channel
    let packet_data = std::slice::from_raw_parts(packets, total_size).to_vec();

    if let Some(tx) = &guard.tx_sender {
        match tx.try_send(packet_data) {
            Ok(()) => count,
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Queue full, drop packets
                0
            }
            Err(mpsc::error::TrySendError::Closed(_)) => SoftEtherResult::NotConnected as c_int,
        }
    } else {
        SoftEtherResult::NotConnected as c_int
    }
}

/// Receive packets from the VPN server (polling mode).
///
/// # Safety
/// - `handle` must be a valid handle returned by `softether_create`.
/// - `count` must be a valid pointer to a c_int.
#[no_mangle]
pub unsafe extern "C" fn softether_receive_packets(
    handle: SoftEtherHandle,
    _buffer: *mut u8,
    _buffer_size: usize,
    count: *mut c_int,
) -> c_int {
    if handle.is_null() || count.is_null() {
        return SoftEtherResult::InvalidParam as c_int;
    }

    // Polling mode not used - we use callbacks instead
    *count = 0;
    0
}

/// Get library version.
#[no_mangle]
pub extern "C" fn softether_version() -> *const c_char {
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

/// Hash a password for SoftEther authentication.
///
/// # Safety
/// - `password` and `username` must be valid null-terminated C strings.
/// - `output` must be a valid pointer to a buffer of at least 20 bytes.
#[no_mangle]
pub unsafe extern "C" fn softether_hash_password(
    password: *const c_char,
    username: *const c_char,
    output: *mut u8,
) -> SoftEtherResult {
    if password.is_null() || username.is_null() || output.is_null() {
        return SoftEtherResult::InvalidParam;
    }

    let password_str = match cstr_to_string(password) {
        Some(s) => s,
        None => return SoftEtherResult::InvalidParam,
    };

    let username_str = match cstr_to_string(username) {
        Some(s) => s,
        None => return SoftEtherResult::InvalidParam,
    };

    let hash = crate::crypto::hash_password(&password_str, &username_str);
    std::ptr::copy_nonoverlapping(hash.as_ptr(), output, 20);

    SoftEtherResult::Ok
}

/// Encode binary data as Base64.
///
/// # Safety
/// - `input` must be a valid pointer to a buffer of `input_len` bytes.
/// - `output` must be a valid pointer to a buffer of `output_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn softether_base64_encode(
    input: *const u8,
    input_len: usize,
    output: *mut c_char,
    output_len: usize,
) -> c_int {
    use base64::Engine;

    if input.is_null() || output.is_null() || output_len == 0 {
        return SoftEtherResult::InvalidParam as c_int;
    }

    let input_slice = std::slice::from_raw_parts(input, input_len);
    let encoded = base64::engine::general_purpose::STANDARD.encode(input_slice);

    if encoded.len() + 1 > output_len {
        return SoftEtherResult::InvalidParam as c_int;
    }

    std::ptr::copy_nonoverlapping(encoded.as_ptr(), output as *mut u8, encoded.len());
    *output.add(encoded.len()) = 0;

    encoded.len() as c_int
}

// Clone implementations
impl Clone for SoftEtherSession {
    fn clone(&self) -> Self {
        Self {
            ip_address: self.ip_address,
            subnet_mask: self.subnet_mask,
            gateway: self.gateway,
            dns1: self.dns1,
            dns2: self.dns2,
            connected_server_ip: self.connected_server_ip,
            server_version: self.server_version,
            server_build: self.server_build,
            mac_address: self.mac_address,
            gateway_mac: self.gateway_mac,
        }
    }
}

impl Clone for SoftEtherStats {
    fn clone(&self) -> Self {
        Self {
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            packets_sent: self.packets_sent,
            packets_received: self.packets_received,
            uptime_secs: self.uptime_secs,
            active_connections: self.active_connections,
            reconnect_count: self.reconnect_count,
        }
    }
}

impl Clone for SoftEtherCallbacks {
    fn clone(&self) -> Self {
        Self {
            context: self.context,
            on_state_changed: self.on_state_changed,
            on_connected: self.on_connected,
            on_disconnected: self.on_disconnected,
            on_packets_received: self.on_packets_received,
            on_log: self.on_log,
            protect_socket: self.protect_socket,
        }
    }
}
