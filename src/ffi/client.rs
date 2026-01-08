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
use crate::crypto::{Rc4KeyPair, TunnelEncryption};
use crate::packet::{
    ArpHandler, DhcpClient, DhcpConfig, DhcpState, Dhcpv6Client, Dhcpv6Config, Dhcpv6State,
};
use crate::protocol::{
    decompress, is_compressed, AuthPack, AuthResult, AuthType, ConnectionOptions, HelloResponse,
    HttpCodec, HttpRequest, Pack, RedirectInfo, TunnelCodec, CONTENT_TYPE_PACK,
    CONTENT_TYPE_SIGNATURE, SIGNATURE_TARGET, VPN_SIGNATURE, VPN_TARGET,
};

/// Channel capacity for packet queues - larger buffer for better throughput
const PACKET_QUEUE_SIZE: usize = 128;

/// Maximum retries for "User Already Logged In" errors
const MAX_USER_IN_USE_RETRIES: u32 = 5;
/// Delay between retries in seconds
const RETRY_DELAY_SECS: u64 = 10;

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
    /// Statistics (Arc for sharing with async task)
    stats: Arc<FfiStats>,
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
    packets_dropped: AtomicU64,
    uptime_start: AtomicU64,
}

impl Default for FfiStats {
    fn default() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
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
            stats: Arc::new(FfiStats::default()),
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
            packets_dropped: self.stats.packets_dropped.load(Ordering::Relaxed),
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
        return NULL_HANDLE;
    }

    let config = &*config;
    if !config.is_valid() {
        return NULL_HANDLE;
    }

    // Parse configuration
    let server = match cstr_to_string(config.server) {
        Some(s) => s,
        None => return NULL_HANDLE,
    };
    let hub = match cstr_to_string(config.hub) {
        Some(s) => s,
        None => return NULL_HANDLE,
    };
    let username = match cstr_to_string(config.username) {
        Some(s) => s,
        None => return NULL_HANDLE,
    };
    let password_hash = match cstr_to_string(config.password_hash) {
        Some(s) => s,
        None => return NULL_HANDLE,
    };

    // Parse optional routing strings
    let ipv4_include_str = cstr_to_string(config.ipv4_include).unwrap_or_default();
    let ipv4_exclude_str = cstr_to_string(config.ipv4_exclude).unwrap_or_default();
    let ipv6_include_str = cstr_to_string(config.ipv6_include).unwrap_or_default();
    let ipv6_exclude_str = cstr_to_string(config.ipv6_exclude).unwrap_or_default();

    // Helper to parse comma-separated CIDR lists
    let parse_cidr_list = |s: &str| -> Vec<String> {
        if s.is_empty() {
            vec![]
        } else {
            s.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }
    };

    let ipv4_include = parse_cidr_list(&ipv4_include_str);
    let ipv4_exclude = parse_cidr_list(&ipv4_exclude_str);
    let ipv6_include = parse_cidr_list(&ipv6_include_str);
    let ipv6_exclude = parse_cidr_list(&ipv6_exclude_str);

    // Parse optional certificate pinning fields
    let custom_ca_pem = if config.custom_ca_pem.is_null() {
        None
    } else {
        let pem = CStr::from_ptr(config.custom_ca_pem)
            .to_string_lossy()
            .into_owned();
        if pem.is_empty() {
            None
        } else {
            Some(pem)
        }
    };

    let cert_fingerprint_sha256 = if config.cert_fingerprint_sha256.is_null() {
        None
    } else {
        let fp = CStr::from_ptr(config.cert_fingerprint_sha256)
            .to_string_lossy()
            .into_owned();
        if fp.is_empty() {
            None
        } else {
            Some(fp)
        }
    };

    // Parse static IP configuration
    let static_ip = {
        let ipv4_address = cstr_to_string(config.static_ipv4_address);
        let ipv4_netmask = cstr_to_string(config.static_ipv4_netmask);
        let ipv4_gateway = cstr_to_string(config.static_ipv4_gateway);
        let ipv4_dns1 = cstr_to_string(config.static_ipv4_dns1);
        let ipv4_dns2 = cstr_to_string(config.static_ipv4_dns2);
        let ipv6_address = cstr_to_string(config.static_ipv6_address);
        let ipv6_prefix_len =
            if config.static_ipv6_prefix_len > 0 && config.static_ipv6_prefix_len <= 128 {
                Some(config.static_ipv6_prefix_len as u8)
            } else {
                None
            };
        let ipv6_gateway = cstr_to_string(config.static_ipv6_gateway);
        let ipv6_dns1 = cstr_to_string(config.static_ipv6_dns1);
        let ipv6_dns2 = cstr_to_string(config.static_ipv6_dns2);

        // Only create StaticIpConfig if at least one field is set
        if ipv4_address.is_some() || ipv6_address.is_some() {
            Some(crate::config::StaticIpConfig {
                ipv4_address,
                ipv4_netmask,
                ipv4_gateway,
                ipv4_dns1,
                ipv4_dns2,
                ipv6_address,
                ipv6_prefix_len,
                ipv6_gateway,
                ipv6_dns1,
                ipv6_dns2,
            })
        } else {
            None
        }
    };

    // Create VPN config with all options
    let vpn_config = crate::config::VpnConfig {
        server,
        port: config.port as u16,
        hub,
        username,
        password_hash,
        skip_tls_verify: config.skip_tls_verify != 0,
        custom_ca_pem,
        cert_fingerprint_sha256,
        max_connections: config.max_connections.clamp(1, 32) as u8,
        timeout_seconds: config.timeout_seconds.max(5) as u64,
        mtu: config.mtu.clamp(576, 1500) as u16,
        // Always force encryption on - non-encrypted mode is not properly supported
        // (server would switch to plain TCP which our TLS connection can't handle)
        use_encrypt: true,
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
            ipv6_include,
            ipv6_exclude,
        },
        static_ip,
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
    // Use single thread for mobile battery efficiency - VPN workload is I/O bound
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
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
    let stats = guard.stats.clone();

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
            stats,
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
                    if let Ok(cstr) = std::ffi::CString::new(format!("Connection error: {e}")) {
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

/// The main connection and tunnel loop with retry support for UserAlreadyLoggedIn
async fn connect_and_run(
    config: crate::config::VpnConfig,
    running: Arc<AtomicBool>,
    callbacks: SoftEtherCallbacks,
    mut tx_recv: mpsc::Receiver<Vec<u8>>,
    atomic_state: Arc<AtomicU8>,
    stats: Arc<FfiStats>,
) -> crate::error::Result<()> {
    // Log helper - must clone callbacks for local use
    fn log_message(callbacks: &SoftEtherCallbacks, level: i32, msg: &str) {
        if let Some(cb) = callbacks.on_log {
            if let Ok(cstr) = std::ffi::CString::new(msg) {
                cb(callbacks.context, level, cstr.as_ptr());
            }
        }
    }

    // Retry loop for UserAlreadyLoggedIn errors
    for attempt in 1..=MAX_USER_IN_USE_RETRIES {
        match connect_and_run_inner(
            &config,
            running.clone(),
            &callbacks,
            &mut tx_recv,
            &atomic_state,
            &stats,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(crate::error::Error::UserAlreadyLoggedIn) => {
                if attempt < MAX_USER_IN_USE_RETRIES {
                    log_message(
                        &callbacks,
                        2,
                        &format!(
                            "[RUST] User already logged in. Waiting {RETRY_DELAY_SECS}s for old session to expire... (attempt {attempt}/{MAX_USER_IN_USE_RETRIES})"
                        ),
                    );
                    update_state(&atomic_state, &callbacks, SoftEtherState::Connecting);
                    tokio::time::sleep(Duration::from_secs(RETRY_DELAY_SECS)).await;
                } else {
                    log_message(
                        &callbacks,
                        3,
                        &format!(
                            "[RUST] User already logged in - max retries ({MAX_USER_IN_USE_RETRIES}) exceeded"
                        ),
                    );
                    return Err(crate::error::Error::UserAlreadyLoggedIn);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(crate::error::Error::UserAlreadyLoggedIn)
}

/// Inner connection logic (called by retry wrapper)
async fn connect_and_run_inner(
    config: &crate::config::VpnConfig,
    running: Arc<AtomicBool>,
    callbacks: &SoftEtherCallbacks,
    tx_recv: &mut mpsc::Receiver<Vec<u8>>,
    atomic_state: &Arc<AtomicU8>,
    stats: &Arc<FfiStats>,
) -> crate::error::Result<()> {
    // Log helper
    fn log_message(callbacks: &SoftEtherCallbacks, level: i32, msg: &str) {
        if let Some(cb) = callbacks.on_log {
            if let Ok(cstr) = std::ffi::CString::new(msg) {
                cb(callbacks.context, level, cstr.as_ptr());
            }
        }
    }

    log_message(callbacks, 1, "[RUST] connect_and_run started");
    log_message(
        callbacks,
        1,
        &format!("[RUST] Connecting to {}:{}", config.server, config.port),
    );
    log_message(
        callbacks,
        1,
        &format!("[RUST] Hub: {}, User: {}", config.hub, config.username),
    );
    log_message(
        callbacks,
        1,
        &format!("[RUST] Skip TLS verify: {}", config.skip_tls_verify),
    );

    // Resolve server IP
    log_message(callbacks, 1, "[RUST] Resolving server IP...");
    let server_ip = match resolve_server_ip(&config.server) {
        Ok(ip) => {
            log_message(callbacks, 1, &format!("[RUST] Resolved server IP: {ip}"));
            ip
        }
        Err(e) => {
            log_message(callbacks, 3, &format!("[RUST] DNS resolution failed: {e}"));
            return Err(e);
        }
    };

    // Connect TCP with socket protection
    log_message(callbacks, 1, "[RUST] Establishing TCP/TLS connection...");

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

    let mut conn = match VpnConnection::connect_with_protect(config, protect_fn).await {
        Ok(c) => {
            log_message(
                callbacks,
                1,
                "[RUST] TCP/TLS connection established (protected)",
            );
            c
        }
        Err(e) => {
            log_message(
                callbacks,
                3,
                &format!("[RUST] TCP/TLS connection failed: {e}"),
            );
            return Err(e);
        }
    };

    // Notify state: Handshaking
    log_message(callbacks, 1, "[RUST] Starting HTTP handshake...");
    update_state(atomic_state, callbacks, SoftEtherState::Handshaking);

    // HTTP handshake
    let hello = match perform_handshake(&mut conn, config).await {
        Ok(h) => {
            log_message(
                callbacks,
                1,
                &format!(
                    "[RUST] Server: {} v{} build {}",
                    h.server_string, h.server_version, h.server_build
                ),
            );
            h
        }
        Err(e) => {
            log_message(callbacks, 3, &format!("[RUST] Handshake failed: {e}"));
            return Err(e);
        }
    };

    // Notify state: Authenticating
    log_message(callbacks, 1, "[RUST] Starting authentication...");
    update_state(atomic_state, callbacks, SoftEtherState::Authenticating);

    // Authenticate
    log_message(callbacks, 1, "[RUST] >>> About to call authenticate() <<<");
    let mut auth_result = match authenticate(&mut conn, config, &hello, callbacks).await {
        Ok(r) => {
            log_message(callbacks, 1, "[RUST] Authentication successful");
            r
        }
        Err(e) => {
            log_message(callbacks, 3, &format!("[RUST] Authentication failed: {e}"));
            return Err(e);
        }
    };

    log_message(
        callbacks,
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
                callbacks,
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
            match connect_redirect(config, &redirect, callbacks).await {
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
                    log_message(callbacks, 3, &format!("[RUST] Redirect failed: {e}"));
                    return Err(e);
                }
            }
        } else {
            // No redirect - check session key now
            if auth_result.session_key.is_empty() {
                log_message(
                    callbacks,
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
        log_message(callbacks, 3, "[RUST] No session key after redirect");
        return Err(crate::error::Error::AuthenticationFailed(
            "No session key received from redirect server".into(),
        ));
    }

    log_message(
        callbacks,
        1,
        &format!(
            "[RUST] Session established: {} bytes session key",
            final_auth.session_key.len()
        ),
    );

    // Create connection manager for packet I/O
    log_message(callbacks, 1, "[RUST] Creating connection manager...");
    let mut conn_mgr = ConnectionManager::new(
        active_conn,
        config,
        &final_auth,
        &actual_server_addr,
        actual_server_port,
    );

    // Generate MAC address for DHCP
    let mut mac = [0u8; 6];
    crate::crypto::fill_random(&mut mac);
    mac[0] = (mac[0] | 0x02) & 0xFE; // Local/unicast

    log_message(
        callbacks,
        1,
        &format!(
            "[RUST] Generated MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ),
    );

    // Perform DHCP to get IP configuration
    log_message(callbacks, 1, "[RUST] Starting DHCP...");
    update_state(atomic_state, callbacks, SoftEtherState::EstablishingTunnel);

    // In half-connection mode, we need to temporarily enable bidirectional mode
    // on the primary connection for DHCP, since additional connections aren't
    // established yet. DHCP needs to both send and receive on the same connection.
    let original_direction = conn_mgr.enable_primary_bidirectional();

    let dhcp_config = match perform_dhcp(&mut conn_mgr, mac, callbacks, config.use_compress).await {
        Ok(config) => {
            log_message(
                callbacks,
                1,
                &format!(
                    "[RUST] DHCP complete: IP={}, Gateway={:?}, DNS={:?}",
                    config.ip, config.gateway, config.dns1
                ),
            );
            config
        }
        Err(e) => {
            // Restore direction before returning error
            if let Some(dir) = original_direction {
                conn_mgr.restore_primary_direction(dir);
            }
            log_message(callbacks, 3, &format!("[RUST] DHCP failed: {e}"));
            return Err(e);
        }
    };

    // Restore primary connection direction after DHCP
    if let Some(dir) = original_direction {
        conn_mgr.restore_primary_direction(dir);
    }

    // Establish additional connections if max_connections > 1
    if config.max_connections > 1 {
        log_message(
            callbacks,
            1,
            &format!(
                "[RUST] Multi-connection mode: establishing {} additional connections...",
                config.max_connections - 1
            ),
        );

        if let Err(e) = conn_mgr.establish_additional_connections().await {
            // Log but don't fail - we can continue with fewer connections
            log_message(
                callbacks,
                2,
                &format!("[RUST] Warning: Failed to establish all additional connections: {e}"),
            );
        }

        let stats = conn_mgr.stats();
        log_message(
            callbacks,
            1,
            &format!(
                "[RUST] Connection pool: {}/{} connections active (half-connection mode: {})",
                stats.healthy_connections,
                config.max_connections,
                if conn_mgr.is_half_connection() {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
        );
    }

    // Try DHCPv6 for IPv6 address (optional - doesn't fail if server doesn't support it)
    log_message(callbacks, 1, "[RUST] Attempting DHCPv6 for IPv6 address...");
    let dhcpv6_config = perform_dhcpv6(&mut conn_mgr, mac, callbacks, config.use_compress).await;
    if dhcpv6_config.is_some() {
        log_message(
            callbacks,
            1,
            "[RUST] DHCPv6 successful - dual-stack configured",
        );
    } else {
        log_message(callbacks, 1, "[RUST] DHCPv6 not available - IPv4 only");
    }

    // Create session info from DHCP config (include MAC for Kotlin to use)
    let session =
        create_session_from_dhcp(&dhcp_config, dhcpv6_config.as_ref(), actual_server_ip, server_ip, mac);

    // Notify connected with session info
    log_message(callbacks, 1, "[RUST] Notifying Android of connection...");
    if let Some(cb) = callbacks.on_connected {
        cb(callbacks.context, &session);
    }
    update_state(atomic_state, callbacks, SoftEtherState::Connected);

    log_message(
        callbacks,
        1,
        &format!(
            "[RUST] Connected! IP: {}, Server: {}",
            dhcp_config.ip, actual_server_ip
        ),
    );

    // Log RC4 encryption status
    if final_auth.rc4_key_pair.is_some() {
        log_message(
            callbacks,
            1,
            "[RUST] RC4 tunnel encryption enabled (UseFastRC4 mode)",
        );
    } else if config.use_encrypt {
        log_message(
            callbacks,
            1,
            "[RUST] Using TLS-layer encryption (UseSSLDataEncryption mode)",
        );
    } else {
        log_message(callbacks, 1, "[RUST] Encryption disabled");
    }

    // Initialize UDP acceleration if server supports it
    let mut udp_accel = if let Some(ref udp_response) = final_auth.udp_accel_response {
        match crate::net::UdpAccel::new(None, true, false) {
            Ok(mut accel) => {
                if let Err(e) = accel.init_from_response(udp_response) {
                    log_message(
                        callbacks,
                        2,
                        &format!("[RUST] Failed to initialize UDP acceleration: {e}"),
                    );
                    None
                } else {
                    log_message(
                        callbacks,
                        1,
                        &format!(
                            "[RUST] UDP acceleration initialized: version={}, server={}:{}",
                            accel.version, udp_response.server_ip, udp_response.server_port
                        ),
                    );
                    Some(accel)
                }
            }
            Err(e) => {
                log_message(
                    callbacks,
                    2,
                    &format!("[RUST] Failed to create UDP socket: {e}"),
                );
                None
            }
        }
    } else {
        None
    };

    // Run the packet loop
    log_message(callbacks, 1, "[RUST] Starting packet loop...");
    run_packet_loop(
        &mut conn_mgr,
        running,
        callbacks.clone(),
        tx_recv,
        mac,
        dhcp_config,
        final_auth.rc4_key_pair.as_ref(),
        config.qos,
        config.use_compress,
        udp_accel.as_mut(),
        stats,
    )
    .await
}

/// Create session info from DHCP and optional DHCPv6 config
fn create_session_from_dhcp(
    dhcp: &DhcpConfig,
    dhcpv6: Option<&Dhcpv6Config>,
    server_ip: Ipv4Addr,
    original_server_ip: Ipv4Addr,
    mac: [u8; 6],
) -> SoftEtherSession {
    let mut server_ip_str = [0 as std::ffi::c_char; 64];
    let ip_string = format!("{server_ip}");
    for (i, b) in ip_string.bytes().enumerate() {
        if i < 63 {
            server_ip_str[i] = b as std::ffi::c_char;
        }
    }

    let mut original_ip_str = [0 as std::ffi::c_char; 64];
    let orig_ip_string = format!("{original_server_ip}");
    for (i, b) in orig_ip_string.bytes().enumerate() {
        if i < 63 {
            original_ip_str[i] = b as std::ffi::c_char;
        }
    }

    fn ip_to_u32(ip: Ipv4Addr) -> u32 {
        let octets = ip.octets();
        ((octets[0] as u32) << 24)
            | ((octets[1] as u32) << 16)
            | ((octets[2] as u32) << 8)
            | (octets[3] as u32)
    }

    // Extract IPv6 info if available
    let (ipv6_address, ipv6_prefix_len, dns1_v6, dns2_v6) = if let Some(v6) = dhcpv6 {
        (
            v6.ip.octets(),
            v6.prefix_len,
            v6.dns1.map(|ip| ip.octets()).unwrap_or([0; 16]),
            v6.dns2.map(|ip| ip.octets()).unwrap_or([0; 16]),
        )
    } else {
        ([0; 16], 0, [0; 16], [0; 16])
    };

    SoftEtherSession {
        ip_address: ip_to_u32(dhcp.ip),
        subnet_mask: ip_to_u32(dhcp.netmask),
        gateway: dhcp.gateway.map(ip_to_u32).unwrap_or(0),
        dns1: dhcp.dns1.map(ip_to_u32).unwrap_or(0),
        dns2: dhcp.dns2.map(ip_to_u32).unwrap_or(0),
        connected_server_ip: server_ip_str,
        original_server_ip: original_ip_str,
        server_version: 0,
        server_build: 0,
        mac_address: mac,
        gateway_mac: [0; 6], // Will be learned dynamically
        ipv6_address,
        ipv6_prefix_len,
        _padding: [0; 3],
        dns1_v6,
        dns2_v6,
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
        &format!("[RUST] Connecting to cluster server {redirect_server}:{redirect_port}"),
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

    let host = format!("{redirect_server}:{redirect_port}");
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
                log_msg(callbacks, 2, &format!("[RUST] Read error during DHCP: {e}"));
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

// Use shared DHCP response checkers from packet module
use crate::packet::{is_dhcp_response, is_dhcpv6_response};

/// Perform DHCPv6 through the tunnel to get IPv6 configuration
/// This is optional and may fail if the server doesn't support DHCPv6
async fn perform_dhcpv6(
    conn_mgr: &mut ConnectionManager,
    mac: [u8; 6],
    callbacks: &SoftEtherCallbacks,
    use_compress: bool,
) -> Option<Dhcpv6Config> {
    use tokio::time::timeout;

    fn log_msg(callbacks: &SoftEtherCallbacks, level: i32, msg: &str) {
        if let Some(cb) = callbacks.on_log {
            if let Ok(cstr) = std::ffi::CString::new(msg) {
                cb(callbacks.context, level, cstr.as_ptr());
            }
        }
    }

    let mut dhcpv6 = Dhcpv6Client::new(mac);
    let mut codec = TunnelCodec::new();
    let mut buf = vec![0u8; 65536];
    let mut send_buf = vec![0u8; 2048];

    // DHCPv6 has shorter timeout - it's optional
    let deadline = std::time::Instant::now() + Duration::from_secs(10);

    // Send DHCPv6 SOLICIT
    let solicit = dhcpv6.build_solicit();
    log_msg(
        callbacks,
        1,
        &format!("[RUST] Sending DHCPv6 SOLICIT ({} bytes)", solicit.len()),
    );
    if send_frame(conn_mgr, &solicit, &mut send_buf, use_compress)
        .await
        .is_err()
    {
        log_msg(callbacks, 2, "[RUST] Failed to send DHCPv6 SOLICIT");
        return None;
    }

    // Wait for ADVERTISE/REPLY
    loop {
        if std::time::Instant::now() > deadline {
            log_msg(
                callbacks,
                2,
                "[RUST] DHCPv6 timeout - server may not support IPv6",
            );
            return None;
        }

        match timeout(Duration::from_secs(2), conn_mgr.read_any(&mut buf)).await {
            Ok(Ok((_conn_idx, n))) if n > 0 => {
                // Decode tunnel frames
                if let Ok(frames) = codec.feed(&buf[..n]) {
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

                                // Check if this is a DHCPv6 response
                                if is_dhcpv6_response(&packet_data) {
                                    log_msg(callbacks, 1, "[RUST] DHCPv6 response received");
                                    if dhcpv6.process_response(&packet_data) {
                                        // Got REPLY with address
                                        let config = dhcpv6.config().clone();
                                        log_msg(
                                            callbacks,
                                            1,
                                            &format!(
                                                "[RUST] DHCPv6 complete: IP={}, DNS={:?}",
                                                config.ip, config.dns1
                                            ),
                                        );
                                        return Some(config);
                                    } else if dhcpv6.state() == Dhcpv6State::SolicitSent {
                                        // Got ADVERTISE, send REQUEST
                                        if let Some(request) = dhcpv6.build_request() {
                                            log_msg(callbacks, 1, "[RUST] Sending DHCPv6 REQUEST");
                                            if send_frame(
                                                conn_mgr,
                                                &request,
                                                &mut send_buf,
                                                use_compress,
                                            )
                                            .await
                                            .is_err()
                                            {
                                                log_msg(
                                                    callbacks,
                                                    2,
                                                    "[RUST] Failed to send DHCPv6 REQUEST",
                                                );
                                                return None;
                                            }
                                        }
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
            Ok(Err(_)) => {
                // Read error - give up on DHCPv6
                return None;
            }
            Err(_) => {
                // Timeout, retry
                if dhcpv6.state() == Dhcpv6State::SolicitSent {
                    log_msg(callbacks, 2, "[RUST] DHCPv6 timeout, retrying SOLICIT");
                    let solicit = dhcpv6.build_solicit();
                    if send_frame(conn_mgr, &solicit, &mut send_buf, use_compress)
                        .await
                        .is_err()
                    {
                        return None;
                    }
                } else if dhcpv6.state() == Dhcpv6State::RequestSent {
                    log_msg(callbacks, 2, "[RUST] DHCPv6 timeout, retrying REQUEST");
                    if let Some(request) = dhcpv6.build_request() {
                        if send_frame(conn_mgr, &request, &mut send_buf, use_compress)
                            .await
                            .is_err()
                        {
                            return None;
                        }
                    }
                }
            }
        }
    }
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

/// Run the main packet forwarding loop with ARP handling, QoS, and optional UDP acceleration.
#[allow(clippy::too_many_arguments)]
async fn run_packet_loop(
    conn_mgr: &mut ConnectionManager,
    running: Arc<AtomicBool>,
    callbacks: SoftEtherCallbacks,
    tx_recv: &mut mpsc::Receiver<Vec<u8>>,
    mac: [u8; 6],
    dhcp_config: DhcpConfig,
    rc4_key_pair: Option<&Rc4KeyPair>,
    qos_enabled: bool,
    use_compress: bool,
    mut udp_accel: Option<&mut crate::net::UdpAccel>,
    stats: &Arc<FfiStats>,
) -> crate::error::Result<()> {
    use crate::packet::is_priority_packet;
    use crate::protocol::compress;
    fn log_msg(callbacks: &SoftEtherCallbacks, level: i32, msg: &str) {
        if let Some(cb) = callbacks.on_log {
            if let Ok(cstr) = std::ffi::CString::new(msg) {
                cb(callbacks.context, level, cstr.as_ptr());
            }
        }
    }

    let mut tunnel_codec = TunnelCodec::new();
    let mut read_buf = vec![0u8; 65536];
    let _udp_recv_buf = vec![0u8; 65536];
    let keepalive_interval_secs = 5u64;

    // Set up ARP handler for gateway MAC learning
    let mut arp = ArpHandler::new(mac);
    let gateway = dhcp_config.gateway.unwrap_or(dhcp_config.ip);
    arp.configure(dhcp_config.ip, gateway);

    log_msg(
        &callbacks,
        1,
        &format!(
            "[RUST] ARP configured: my_ip={}, gateway_ip={}",
            dhcp_config.ip, gateway
        ),
    );

    // Create RC4 encryption state if keys are provided
    let mut encryption = rc4_key_pair.map(TunnelEncryption::new);

    // Log compression/encryption state
    log_msg(&callbacks, 1, &format!("[RUST] Compression: {}, Encryption: {}", 
        if use_compress { "enabled" } else { "disabled" },
        if encryption.is_some() { "RC4" } else { "TLS-only" }));

    // Send gratuitous ARP to announce our presence
    let garp = arp.build_gratuitous_arp();
    let garp_bytes = garp.to_vec();
    let garp_data: Vec<u8> = if use_compress {
        compress(&garp_bytes).unwrap_or_else(|_| garp_bytes.clone())
    } else {
        garp_bytes
    };
    let encoded_garp = tunnel_codec.encode(&[&garp_data]);
    let garp_to_send: Vec<u8> = if let Some(ref mut enc) = encryption {
        let mut data = encoded_garp.to_vec();
        enc.encrypt(&mut data);
        data
    } else {
        encoded_garp.to_vec()
    };
    conn_mgr
        .write_all(&garp_to_send)
        .await
        .map_err(crate::error::Error::Io)?;
    log_msg(&callbacks, 1, "[RUST] Sent gratuitous ARP");

    // Send ARP request for gateway MAC
    let gateway_arp = arp.build_gateway_request();
    let gateway_arp_bytes = gateway_arp.to_vec();
    let gateway_arp_data: Vec<u8> = if use_compress {
        compress(&gateway_arp_bytes).unwrap_or_else(|_| gateway_arp_bytes.clone())
    } else {
        gateway_arp_bytes
    };
    let encoded_gw = tunnel_codec.encode(&[&gateway_arp_data]);
    let gw_to_send: Vec<u8> = if let Some(ref mut enc) = encryption {
        let mut data = encoded_gw.to_vec();
        enc.encrypt(&mut data);
        data
    } else {
        encoded_gw.to_vec()
    };
    conn_mgr
        .write_all(&gw_to_send)
        .await
        .map_err(crate::error::Error::Io)?;
    log_msg(&callbacks, 1, "[RUST] Sent gateway ARP request");

    log_msg(&callbacks, 1, "[RUST] Packet loop started");

    // Track UDP acceleration state
    let mut udp_ready_logged = false;
    let mut last_udp_keepalive = std::time::Instant::now();
    let udp_keepalive_interval = Duration::from_secs(2);

    // Start UDP acceleration if available - send initial keepalives
    if let Some(ref mut ua) = udp_accel {
        log_msg(
            &callbacks,
            1,
            "[RUST] Sending initial UDP keepalives to establish path...",
        );
        // Send a few keepalives to trigger server response
        for _ in 0..3 {
            if let Err(e) = ua.send_keepalive().await {
                log_msg(
                    &callbacks,
                    2,
                    &format!("[RUST] UDP initial keepalive failed: {e}"),
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // Send first keepalive immediately (encrypt if RC4 is enabled)
    let keepalive = tunnel_codec.encode_keepalive();
    let first_keepalive: Vec<u8> = if let Some(ref mut enc) = encryption {
        let mut data = keepalive.to_vec();
        enc.encrypt(&mut data);
        data
    } else {
        keepalive.to_vec()
    };
    conn_mgr
        .write_all(&first_keepalive)
        .await
        .map_err(crate::error::Error::Io)?;
    let mut last_keepalive = std::time::Instant::now();
    let mut loop_count = 0u64;

    while running.load(Ordering::SeqCst) {
        loop_count += 1;
        
        // Only log loop iteration periodically to avoid log spam
        if loop_count == 1 {
            log_msg(&callbacks, 1, "[RUST] Packet loop started");
        }
        
        // Check if we need to send keepalive (TCP)
        if last_keepalive.elapsed() >= Duration::from_secs(keepalive_interval_secs) {
            // Encrypt keepalive if RC4 is enabled
            let keepalive = tunnel_codec.encode_keepalive();
            let to_send: Vec<u8> = if let Some(ref mut enc) = encryption {
                let mut data = keepalive.to_vec();
                enc.encrypt(&mut data);
                data
            } else {
                keepalive.to_vec()
            };
            if let Err(e) = conn_mgr.write_all(&to_send).await {
                log_msg(&callbacks, 3, &format!("[RUST] Keepalive failed: {e}"));
                return Err(crate::error::Error::Io(e));
            }
            last_keepalive = std::time::Instant::now();
        }

        // Send UDP keepalives if UDP acceleration is active
        if let Some(ref mut ua) = udp_accel {
            if ua.is_send_ready() {
                if !udp_ready_logged {
                    log_msg(&callbacks, 1, "[RUST] UDP acceleration path is now active!");
                    udp_ready_logged = true;
                }
                if last_udp_keepalive.elapsed() >= udp_keepalive_interval {
                    if let Err(e) = ua.send_keepalive().await {
                        log_msg(&callbacks, 2, &format!("[RUST] UDP keepalive failed: {e}"));
                    }
                    last_udp_keepalive = std::time::Instant::now();
                }
            } else {
                udp_ready_logged = false; // Reset if UDP becomes inactive
            }
        }

        tokio::select! {
            biased;

            // Packets from mobile app to send to VPN server
            Some(frame_data) = tx_recv.recv() => {
                let frames = parse_length_prefixed_packets(&frame_data);
                if !frames.is_empty() {
                    // Rewrite destination MAC to use learned gateway MAC if available
                    let gateway_mac = arp.gateway_mac_or_broadcast();
                    let mut modified_frames: Vec<Vec<u8>> = frames.into_iter().map(|mut frame| {
                        if frame.len() >= 14 {
                            // Replace destination MAC (first 6 bytes)
                            frame[0..6].copy_from_slice(&gateway_mac);
                        }
                        frame
                    }).collect();

                    // QoS: Sort priority packets to front if enabled
                    // This ensures VoIP/real-time packets are sent first
                    if qos_enabled && modified_frames.len() > 1 {
                        modified_frames.sort_by(|a, b| {
                            let a_prio = is_priority_packet(a);
                            let b_prio = is_priority_packet(b);
                            // Priority packets (true) should come first
                            b_prio.cmp(&a_prio)
                        });
                    }

                    // Calculate bytes being sent for stats
                    let total_bytes: usize = modified_frames.iter().map(|f| f.len()).sum();
                    let packet_count = modified_frames.len() as u64;

                    // Try UDP acceleration first if ready
                    let mut sent_via_udp = false;
                    if let Some(ref mut ua) = udp_accel {
                        if ua.is_send_ready() {
                            // Send each frame via UDP (no tunnel framing needed)
                            for frame in &modified_frames {
                                if let Err(e) = ua.send(frame, false).await {
                                    log_msg(&callbacks, 2, &format!("[RUST] UDP send failed: {e}"));
                                    break;
                                }
                            }
                            sent_via_udp = true;
                        }
                    }

                    // Fallback to TCP if UDP not ready or not available
                    if !sent_via_udp {
                        // Compress frames if enabled
                        let frames_to_encode: Vec<Vec<u8>> = if use_compress {
                            modified_frames.iter().map(|f| {
                                compress(f).unwrap_or_else(|_| f.clone())
                            }).collect()
                        } else {
                            modified_frames
                        };

                        // Encode frames into tunnel format
                        let encoded = tunnel_codec.encode(&frames_to_encode.iter().map(|f| f.as_slice()).collect::<Vec<_>>());

                        // Encrypt if RC4 is enabled, otherwise send as-is
                        let to_send: Vec<u8> = if let Some(ref mut enc) = encryption {
                            let mut data = encoded.to_vec();
                            enc.encrypt(&mut data);
                            data
                        } else {
                            encoded.to_vec()
                        };

                        // Write to TCP - don't use timeout, let TCP flow control handle backpressure
                        if let Err(e) = conn_mgr.write_all(&to_send).await {
                            log_msg(&callbacks, 3, &format!("[RUST] TX error: {}", e));
                            return Err(crate::error::Error::Io(e));
                        }
                    }

                    // Update send statistics
                    stats.packets_sent.fetch_add(packet_count, Ordering::Relaxed);
                    stats.bytes_sent.fetch_add(total_bytes as u64, Ordering::Relaxed);
                }
            }

            // UDP receive (if UDP acceleration is available)
            result = async {
                if let Some(ref ua) = udp_accel {
                    ua.try_recv().await
                } else {
                    // No UDP - just wait forever (will be cancelled by other branches)
                    std::future::pending::<crate::error::Result<Option<(Vec<u8>, std::net::SocketAddr)>>>().await
                }
            } => {
                if let Ok(Some((raw_data, src_addr))) = result {
                    // Process the received UDP packet through the accelerator
                    if let Some(ref mut ua) = udp_accel {
                        if let Some((frame_data, _compressed)) = ua.process_recv(&raw_data, src_addr) {
                            // Process received UDP frame
                            // Build length-prefixed buffer for callback
                            let mut buffer = Vec::with_capacity(frame_data.len() + 2);

                    // Process ARP packets for gateway MAC learning
                    if frame_data.len() >= 14 {
                        let ethertype = u16::from_be_bytes([frame_data[12], frame_data[13]]);
                        if ethertype == 0x0806 {
                            let had_mac = arp.has_gateway_mac();
                            arp.process_arp(&frame_data);
                            if !had_mac {
                                if let Some(gw_mac) = arp.gateway_mac() {
                                    log_msg(&callbacks, 1, &format!(
                                        "[RUST] Learned gateway MAC (UDP): {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                        gw_mac[0], gw_mac[1], gw_mac[2], gw_mac[3], gw_mac[4], gw_mac[5]
                                    ));
                                }
                            }
                        }
                    }

                    // Update receive statistics
                    stats.packets_received.fetch_add(1, Ordering::Relaxed);
                    stats.bytes_received.fetch_add(frame_data.len() as u64, Ordering::Relaxed);

                    let len = frame_data.len() as u16;
                    buffer.extend_from_slice(&len.to_be_bytes());
                    buffer.extend_from_slice(&frame_data);

                    if let Some(cb) = callbacks.on_packets_received {
                        cb(callbacks.context, buffer.as_ptr(), buffer.len(), 1);
                    }
                        }
                    }
                }
            }

            // Data from VPN server to send to mobile app (TCP)
            result = tokio::time::timeout(Duration::from_millis(500), conn_mgr.read_any(&mut read_buf)) => {
                match result {
                    Ok(Ok((_conn_idx, n))) if n > 0 => {
                        // Decrypt if RC4 is enabled
                        if let Some(ref mut enc) = encryption {
                            enc.decrypt(&mut read_buf[..n]);
                        }

                        match tunnel_codec.decode(&read_buf[..n]) {
                            Ok(frames) => {
                            if !frames.is_empty() {
                                // Build length-prefixed buffer for callback
                                let mut buffer = Vec::with_capacity(n + frames.len() * 2);
                                let mut total_bytes: u64 = 0;
                                for (_frame_idx, frame) in frames.iter().enumerate() {
                                    // Decompress if needed
                                    let frame_data: Vec<u8> = if is_compressed(frame) {
                                        match decompress(frame) {
                                            Ok(d) => d,
                                            Err(_) => frame.to_vec(),
                                        }
                                    } else {
                                        frame.to_vec()
                                    };

                                    // Process ARP packets for gateway MAC learning
                                    if frame_data.len() >= 14 {
                                        let ethertype = u16::from_be_bytes([frame_data[12], frame_data[13]]);
                                        if ethertype == 0x0806 {
                                            // This is an ARP packet - process it
                                            let had_mac = arp.has_gateway_mac();
                                            arp.process_arp(&frame_data);
                                            // Log if we just learned gateway MAC
                                            if !had_mac {
                                                if let Some(gw_mac) = arp.gateway_mac() {
                                                    log_msg(&callbacks, 1, &format!(
                                                        "[RUST] Learned gateway MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                                        gw_mac[0], gw_mac[1], gw_mac[2], gw_mac[3], gw_mac[4], gw_mac[5]
                                                    ));
                                                }
                                            }
                                        }
                                    }

                                    total_bytes += frame_data.len() as u64;
                                    let len = frame_data.len() as u16;
                                    buffer.extend_from_slice(&len.to_be_bytes());
                                    buffer.extend_from_slice(&frame_data);
                                }

                                // Update receive statistics
                                stats.packets_received.fetch_add(frames.len() as u64, Ordering::Relaxed);
                                stats.bytes_received.fetch_add(total_bytes, Ordering::Relaxed);

                                if let Some(cb) = callbacks.on_packets_received {
                                    cb(callbacks.context, buffer.as_ptr(), buffer.len(), frames.len() as u32);
                                }
                            }
                            }
                            Err(e) => {
                                log_msg(&callbacks, 3, &format!("[RUST] RX decode error: {:?}", e));
                            }
                        }
                    }
                    Ok(Ok(_)) => {
                        log_msg(&callbacks, 2, "[RUST] Connection closed by server");
                        break;
                    }
                    Ok(Err(e)) => {
                        log_msg(&callbacks, 3, &format!("[RUST] Read error: {e}"));
                        return Err(crate::error::Error::Io(e));
                    }
                    Err(_) => {
                        // Timeout - this is normal, no need to log
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
        udp_accel: config.udp_accel,
        bridge_mode: false,
        monitor_mode: config.monitor_mode,
        qos: config.qos,
    };

    // Setup UDP acceleration if enabled
    let udp_accel = if config.udp_accel {
        log_msg(callbacks, 1, "[RUST] Creating UDP acceleration socket...");
        match crate::net::UdpAccel::new(None, true, false) {
            Ok(accel) => {
                log_msg(
                    callbacks,
                    1,
                    &format!(
                        "[RUST] UDP accel created: port={}, version={}",
                        accel.my_port, accel.version
                    ),
                );
                Some(accel)
            }
            Err(e) => {
                log_msg(
                    callbacks,
                    2,
                    &format!("[RUST] Failed to create UDP accel: {e}, continuing without it"),
                );
                None
            }
        }
    } else {
        None
    };

    // Build UDP accel params if we have a socket
    let udp_accel_params = udp_accel
        .as_ref()
        .map(crate::net::UdpAccelAuthParams::from_udp_accel);

    log_msg(
        callbacks,
        1,
        &format!(
            "[RUST] Password hash length: {}",
            config.password_hash.len()
        ),
    );

    // Decode password hash - hex format only (40 chars = 20 bytes)
    if config.password_hash.len() != 40 {
        log_msg(
            callbacks,
            3,
            &format!(
                "[RUST] Invalid hash format: len={}, expected 40 hex chars",
                config.password_hash.len()
            ),
        );
        return Err(crate::error::Error::Config(format!(
            "Password hash must be 40 hex characters, got {}",
            config.password_hash.len()
        )));
    }

    log_msg(callbacks, 1, "[RUST] Decoding hex password hash");
    let password_hash_bytes: [u8; 20] = hex::decode(&config.password_hash)
        .map_err(|e| {
            log_msg(callbacks, 3, &format!("[RUST] Hex decode error: {e}"));
            crate::error::Error::Config(format!("Invalid hex password hash: {e}"))
        })?
        .try_into()
        .map_err(|_| crate::error::Error::Config("Hash decode produced wrong length".into()))?;
    log_msg(callbacks, 1, "[RUST] Hex hash decoded successfully");

    log_msg(callbacks, 1, "[RUST] Building auth pack...");
    let auth_pack = AuthPack::new(
        &config.hub,
        &config.username,
        &password_hash_bytes,
        auth_type,
        &hello.random,
        &options,
        udp_accel_params.as_ref(),
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
        log_msg(callbacks, 1, &format!("[RUST] Received {n} bytes"));
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

                // Resolve remote IP for UDP accel parsing
                let remote_ip = if config.udp_accel {
                    resolve_server_ip(&config.server)
                        .map(std::net::IpAddr::V4)
                        .ok()
                } else {
                    None
                };

                let result = AuthResult::from_pack_with_remote(&pack, remote_ip)?;

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

                // Log UDP acceleration status
                if config.udp_accel {
                    if let Some(ref udp_response) = result.udp_accel_response {
                        log_msg(
                            callbacks,
                            1,
                            &format!(
                                "[RUST] Server supports UDP accel: version={}, port={}, encryption={}",
                                udp_response.version, udp_response.server_port, udp_response.use_encryption
                            ),
                        );
                    } else {
                        log_msg(
                            callbacks,
                            2,
                            "[RUST] Server does not support UDP acceleration",
                        );
                    }
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
    let addr_str = format!("{server}:443");
    match addr_str.to_socket_addrs() {
        Ok(mut addrs) => {
            for addr in addrs.by_ref() {
                if let std::net::SocketAddr::V4(v4) = addr {
                    return Ok(*v4.ip());
                }
            }
            Err(crate::error::Error::ConnectionFailed(format!(
                "No IPv4 address found for {server}"
            )))
        }
        Err(e) => Err(crate::error::Error::ConnectionFailed(format!(
            "Failed to resolve {server}: {e}"
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
            Err(mpsc::error::TrySendError::Full(dropped_data)) => {
                // Queue full - backpressure signal
                // Count packets in the dropped data for stats
                let mut dropped_count = 0u64;
                let mut offset = 0;
                while offset + 2 <= dropped_data.len() {
                    let len = u16::from_be_bytes([dropped_data[offset], dropped_data[offset + 1]])
                        as usize;
                    dropped_count += 1;
                    offset += 2 + len;
                }
                guard
                    .stats
                    .packets_dropped
                    .fetch_add(dropped_count, Ordering::Relaxed);
                // Return QueueFull to signal caller should retry/backoff
                SoftEtherResult::QueueFull as c_int
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
            original_server_ip: self.original_server_ip,
            server_version: self.server_version,
            server_build: self.server_build,
            mac_address: self.mac_address,
            gateway_mac: self.gateway_mac,
            ipv6_address: self.ipv6_address,
            ipv6_prefix_len: self.ipv6_prefix_len,
            _padding: self._padding,
            dns1_v6: self.dns1_v6,
            dns2_v6: self.dns2_v6,
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
            packets_dropped: self.packets_dropped,
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
            exclude_ip: self.exclude_ip,
        }
    }
}
