//! FFI client implementation.
//!
//! This module provides the C-callable functions for the VPN client.

use std::ffi::{c_char, c_int, CStr};
use std::sync::{Arc, Mutex};

use super::types::*;
use super::callbacks::*;

/// Internal client state.
struct FfiClient {
    // Configuration
    config: crate::config::VpnConfig,
    // Callbacks
    callbacks: SoftEtherCallbacks,
    // Connection state
    state: SoftEtherState,
    // Session info (after connection)
    session: Option<SoftEtherSession>,
    // Statistics
    stats: SoftEtherStats,
    // Tokio runtime (created on demand)
    runtime: Option<tokio::runtime::Runtime>,
    // Internal connection manager
    // connection: Option<...>,
}

impl FfiClient {
    fn new(config: crate::config::VpnConfig, callbacks: SoftEtherCallbacks) -> Self {
        Self {
            config,
            callbacks,
            state: SoftEtherState::Disconnected,
            session: None,
            stats: SoftEtherStats::default(),
            runtime: None,
        }
    }

    fn notify_state(&self, state: SoftEtherState) {
        if let Some(cb) = self.callbacks.on_state_changed {
            cb(self.callbacks.context, state);
        }
    }

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
/// # Parameters
/// - `config`: VPN configuration.
/// - `callbacks`: Optional callbacks for events.
///
/// # Returns
/// Handle to the client, or NULL on error.
///
/// # Safety
/// - `config` must point to a valid `SoftEtherConfig`.
/// - String pointers in config must be valid null-terminated UTF-8.
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
    let vpn_config = crate::config::VpnConfig {
        server,
        port: config.port as u16,
        hub,
        username,
        password_hash,
        skip_tls_verify: config.use_tls == 0, // Inverse: use_tls=0 means skip verify
        max_connections: config.max_connections.max(1).min(32) as u8,
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
/// This disconnects if connected and releases all resources.
///
/// # Parameters
/// - `handle`: Client handle from `softether_create`.
///
/// # Safety
/// - `handle` must be a valid handle from `softether_create`.
/// - `handle` must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn softether_destroy(handle: SoftEtherHandle) {
    if handle.is_null() {
        return;
    }

    // Convert back to Arc
    let client = Arc::from_raw(handle as *const Mutex<FfiClient>);
    
    // Disconnect if connected
    {
        if let Ok(mut guard) = client.lock() {
            if guard.state == SoftEtherState::Connected {
                guard.state = SoftEtherState::Disconnecting;
                // TODO: Actual disconnect
                guard.state = SoftEtherState::Disconnected;
            }
            // Runtime will be dropped with the client
        }
    }
    
    // Arc is dropped here, releasing resources
    drop(client);
}

/// Connect to the VPN server.
///
/// This is an asynchronous operation. Connection status is reported
/// via the `on_state_changed` and `on_connected` callbacks.
///
/// # Parameters
/// - `handle`: Client handle.
///
/// # Returns
/// - `SoftEtherResult::Ok` if connection started successfully.
/// - Error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn softether_connect(handle: SoftEtherHandle) -> SoftEtherResult {
    if handle.is_null() {
        return SoftEtherResult::InvalidParam;
    }

    let client = &*(handle as *const Mutex<FfiClient>);
    let mut guard = match client.lock() {
        Ok(g) => g,
        Err(_) => return SoftEtherResult::InternalError,
    };

    if guard.state != SoftEtherState::Disconnected {
        return SoftEtherResult::AlreadyConnected;
    }

    // Create tokio runtime if needed
    if guard.runtime.is_none() {
        match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(rt) => guard.runtime = Some(rt),
            Err(_) => return SoftEtherResult::InternalError,
        }
    }

    guard.state = SoftEtherState::Connecting;
    guard.notify_state(SoftEtherState::Connecting);

    // TODO: Spawn actual connection task
    // For now, this is a stub that would be filled in with actual connection logic
    // using the existing crate::client module

    SoftEtherResult::Ok
}

/// Disconnect from the VPN server.
///
/// # Parameters
/// - `handle`: Client handle.
///
/// # Returns
/// - `SoftEtherResult::Ok` on success.
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

    guard.state = SoftEtherState::Disconnecting;
    guard.notify_state(SoftEtherState::Disconnecting);

    // TODO: Actual disconnect

    guard.state = SoftEtherState::Disconnected;
    guard.notify_state(SoftEtherState::Disconnected);
    guard.notify_disconnected(SoftEtherResult::Ok);

    SoftEtherResult::Ok
}

/// Get current connection state.
///
/// # Parameters
/// - `handle`: Client handle.
///
/// # Returns
/// Current state, or `Disconnected` if handle is invalid.
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
/// # Parameters
/// - `handle`: Client handle.
/// - `session`: Output pointer for session info.
///
/// # Returns
/// - `SoftEtherResult::Ok` if session info was copied.
/// - `SoftEtherResult::NotConnected` if not connected.
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
/// # Parameters
/// - `handle`: Client handle.
/// - `stats`: Output pointer for statistics.
///
/// # Returns
/// - `SoftEtherResult::Ok` on success.
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

    *stats = guard.stats.clone();
    SoftEtherResult::Ok
}

/// Send packets to the VPN server.
///
/// # Parameters
/// - `handle`: Client handle.
/// - `packets`: Packet buffer (format: [len:u16][data]...).
/// - `total_size`: Total size of packet data.
/// - `count`: Number of packets.
///
/// # Returns
/// - Number of packets sent on success.
/// - Negative error code on failure.
#[no_mangle]
pub unsafe extern "C" fn softether_send_packets(
    handle: SoftEtherHandle,
    packets: *const u8,
    _total_size: usize,
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

    // TODO: Parse packets and send through connection
    // For now, return count as if all packets were sent
    count
}

/// Receive packets from the VPN server.
///
/// This is a non-blocking call. If no packets are available, returns 0.
/// For best performance, use the `on_packets_received` callback instead.
///
/// # Parameters
/// - `handle`: Client handle.
/// - `buffer`: Output buffer for packets (format: [len:u16][data]...).
/// - `buffer_size`: Size of output buffer.
/// - `count`: Output pointer for number of packets received.
///
/// # Returns
/// - Number of bytes written to buffer on success.
/// - Negative error code on failure.
#[no_mangle]
pub unsafe extern "C" fn softether_receive_packets(
    handle: SoftEtherHandle,
    buffer: *mut u8,
    _buffer_size: usize,
    count: *mut c_int,
) -> c_int {
    if handle.is_null() || buffer.is_null() || count.is_null() {
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

    // TODO: Receive packets from connection
    // For now, return 0 (no packets)
    *count = 0;
    0
}

/// Get library version.
///
/// # Returns
/// Version string (null-terminated UTF-8).
#[no_mangle]
pub extern "C" fn softether_version() -> *const c_char {
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

// Clone implementation for SoftEtherSession
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

// Clone implementation for SoftEtherStats
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

// Clone implementation for SoftEtherCallbacks
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
