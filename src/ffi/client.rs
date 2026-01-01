//! FFI client implementation.
//!
//! This module provides C-callable functions for the VPN client with actual
//! connection logic wired to the SoftEther protocol implementation.

use std::ffi::{c_char, c_int, CStr};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;

use super::callbacks::*;
use super::types::*;
use crate::client::{ConnectionManager, VpnConnection};
use crate::protocol::{
    AuthPack, AuthResult, AuthType, ConnectionOptions, HelloResponse, HttpCodec, HttpRequest,
    TunnelCodec, CONTENT_TYPE_PACK, CONTENT_TYPE_SIGNATURE, SIGNATURE_TARGET, VPN_SIGNATURE,
    VPN_TARGET,
};

/// Channel capacity for packet queues
const PACKET_QUEUE_SIZE: usize = 256;

/// Internal client state.
struct FfiClient {
    /// Configuration
    config: crate::config::VpnConfig,
    /// Callbacks
    callbacks: SoftEtherCallbacks,
    /// Connection state
    state: SoftEtherState,
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
            session: None,
            stats: FfiStats::default(),
            runtime: None,
            running: Arc::new(AtomicBool::new(false)),
            tx_sender: None,
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

    // Create VPN config
    // Note: skip_tls_verify should be TRUE for self-signed certs (common in SoftEther)
    // The Swift side sends use_tls=1 for secure connection, but we need to skip verification
    // for self-signed certificates which SoftEther commonly uses
    let vpn_config = crate::config::VpnConfig {
        server,
        port: config.port as u16,
        hub,
        username,
        password_hash,
        skip_tls_verify: true, // Always skip for now - SoftEther uses self-signed certs
        max_connections: config.max_connections.clamp(1, 32) as u8,
        use_compress: config.use_compress != 0,
        timeout_seconds: config.connect_timeout_secs.max(5) as u64,
        mtu: 1400,
        ..Default::default()
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

    guard.state = SoftEtherState::Connecting;
    guard.notify_state(SoftEtherState::Connecting);
    guard.running.store(true, Ordering::SeqCst);

    // Create packet channel for TX (iOS -> VPN)
    let (tx_send, tx_recv) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE_SIZE);
    guard.tx_sender = Some(tx_send);

    // Clone what we need for the async task
    let config = guard.config.clone();
    let running = guard.running.clone();
    let callbacks = guard.callbacks.clone();

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

        let result = connect_and_run(config, running.clone(), callbacks.clone(), tx_recv).await;

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

/// The main connection and tunnel loop
async fn connect_and_run(
    config: crate::config::VpnConfig,
    running: Arc<AtomicBool>,
    callbacks: SoftEtherCallbacks,
    mut tx_recv: mpsc::Receiver<Vec<u8>>,
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

    // Connect TCP
    log_message(&callbacks, 1, "[RUST] Establishing TCP/TLS connection...");
    let mut conn = match VpnConnection::connect(&config).await {
        Ok(c) => {
            log_message(&callbacks, 1, "[RUST] TCP/TLS connection established");
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
    if let Some(cb) = callbacks.on_state_changed {
        cb(callbacks.context, SoftEtherState::Handshaking);
    }

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
    if let Some(cb) = callbacks.on_state_changed {
        cb(callbacks.context, SoftEtherState::Authenticating);
    }

    // Authenticate
    log_message(&callbacks, 1, "[RUST] >>> About to call authenticate() <<<");
    let auth_result = match authenticate(&mut conn, &config, &hello, &callbacks).await {
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

    if auth_result.session_key.is_empty() {
        log_message(&callbacks, 3, "[RUST] No session key received");
        return Err(crate::error::Error::AuthenticationFailed(
            "No session key received".into(),
        ));
    }

    log_message(
        &callbacks,
        1,
        &format!(
            "[RUST] Session key received ({} bytes)",
            auth_result.session_key.len()
        ),
    );

    // Handle cluster redirect if present
    let (active_conn, final_auth, actual_server_ip) = if let Some(redirect) = &auth_result.redirect
    {
        let redirect_ip = redirect.ip_string();
        log_message(
            &callbacks,
            1,
            &format!(
                "[RUST] Cluster redirect to {}:{}",
                redirect_ip, redirect.port
            ),
        );

        // TODO: Implement full redirect handling
        // For now, just use the current connection
        (conn, auth_result, server_ip)
    } else {
        (conn, auth_result, server_ip)
    };

    // Create session info from auth result
    let session = create_session_from_auth(&final_auth, actual_server_ip);

    // Notify connected with session info
    log_message(&callbacks, 1, "[RUST] Notifying iOS of connection...");
    if let Some(cb) = callbacks.on_connected {
        cb(callbacks.context, &session);
    }
    if let Some(cb) = callbacks.on_state_changed {
        cb(callbacks.context, SoftEtherState::Connected);
    }

    log_message(
        &callbacks,
        1,
        &format!("[RUST] Connected! Server IP: {}", actual_server_ip),
    );

    // Create connection manager for packet I/O
    log_message(&callbacks, 1, "[RUST] Creating connection manager...");
    let mut conn_mgr = ConnectionManager::new(
        active_conn,
        &config,
        &final_auth,
        &config.server,
        config.port,
    );

    // Run the packet loop
    log_message(&callbacks, 1, "[RUST] Starting packet loop...");
    run_packet_loop(&mut conn_mgr, running, callbacks, &mut tx_recv).await
}

/// Create session info from auth result
fn create_session_from_auth(_auth: &AuthResult, server_ip: Ipv4Addr) -> SoftEtherSession {
    // DHCP configuration will be received later via protocol - for now return placeholder
    // The actual IP configuration is obtained via DHCP exchange in the tunnel
    let mut server_ip_str = [0 as std::ffi::c_char; 64];
    let ip_string = format!("{}", server_ip);
    for (i, b) in ip_string.bytes().enumerate() {
        if i < 63 {
            server_ip_str[i] = b as std::ffi::c_char;
        }
    }

    SoftEtherSession {
        ip_address: 0,  // Will be filled by DHCP
        subnet_mask: 0, // Will be filled by DHCP
        gateway: 0,     // Will be filled by DHCP
        dns1: 0,        // Will be filled by DHCP
        dns2: 0,        // Will be filled by DHCP
        connected_server_ip: server_ip_str,
        server_version: 0, // Not in AuthResult
        server_build: 0,   // Not in AuthResult
    }
}

/// Run the main packet forwarding loop
async fn run_packet_loop(
    conn_mgr: &mut ConnectionManager,
    running: Arc<AtomicBool>,
    callbacks: SoftEtherCallbacks,
    tx_recv: &mut mpsc::Receiver<Vec<u8>>,
) -> crate::error::Result<()> {
    let mut tunnel_codec = TunnelCodec::new();
    let mut read_buf = vec![0u8; 65536];
    let mut keepalive_interval = tokio::time::interval(Duration::from_secs(3));

    while running.load(Ordering::SeqCst) {
        tokio::select! {
            // Packets from iOS to send to VPN
            Some(frame_data) = tx_recv.recv() => {
                // frame_data is already Ethernet frames, concatenated with length prefixes
                // Parse and send
                let frames = parse_length_prefixed_packets(&frame_data);
                if !frames.is_empty() {
                    let encoded = tunnel_codec.encode(&frames.iter().map(|f| f.as_slice()).collect::<Vec<_>>());
                    conn_mgr.write_all(&encoded).await.map_err(crate::error::Error::Io)?;
                }
            }

            // Data from VPN to send to iOS (using read_any for connection manager)
            result = async {
                conn_mgr.read_any(&mut read_buf).await
            } => {
                match result {
                    Ok((_conn_idx, n)) if n > 0 => {
                        // Decode tunnel frames - returns Vec<Bytes>
                        if let Ok(frames) = tunnel_codec.decode(&read_buf[..n]) {
                            if !frames.is_empty() {
                                // Build length-prefixed buffer for callback
                                let mut buffer = Vec::with_capacity(n + frames.len() * 2);
                                for frame in &frames {
                                    let len = frame.len() as u16;
                                    buffer.extend_from_slice(&len.to_be_bytes());
                                    buffer.extend_from_slice(frame);
                                }

                                // Call iOS callback
                                if let Some(cb) = callbacks.on_packets_received {
                                    cb(callbacks.context, buffer.as_ptr(), buffer.len(), frames.len() as u32);
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        // Connection closed
                        break;
                    }
                    Err(e) => {
                        return Err(crate::error::Error::Io(e));
                    }
                }
            }

            // Keepalive
            _ = keepalive_interval.tick() => {
                let keepalive = tunnel_codec.encode_keepalive();
                conn_mgr.write_all(&keepalive).await.map_err(crate::error::Error::Io)?;
            }
        }
    }

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
            log_msg(callbacks, 3, &format!("[RUST] Hex decode error: {}", e));
            crate::error::Error::Config(format!("Invalid hex password hash: {}", e))
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
        Ok(guard) => guard.state,
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

    if guard.state != SoftEtherState::Connected {
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
        }
    }
}
