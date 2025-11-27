//! FFI bindings for iOS NetworkExtension integration
//!
//! This module provides C-compatible functions for embedding the Rust SoftEther client
//! into iOS apps via NetworkExtension Packet Tunnel Provider.

mod config_ffi;
pub use config_ffi::*;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

use vpnclient::shared_config::ClientConfig;
use vpnclient::types::ClientState;
use vpnclient::VpnClient;

/// Opaque handle to VPN client instance
pub struct SoftEtherClient {
    runtime: Runtime,
    client: Arc<Mutex<Option<VpnClient>>>,
    rx_callback: Arc<Mutex<Option<RxCallback>>>,
    state_callback: Arc<Mutex<Option<StateCallback>>>,
    event_callback: Arc<Mutex<Option<EventCallback>>>,
}

type RxCallback = Box<dyn Fn(&[u8]) + Send + Sync>;
type StateCallback = Box<dyn Fn(u32) + Send + Sync>;
type EventCallback = Box<dyn Fn(u32, i32, &str) + Send + Sync>;

/// Create a new SoftEther VPN client from JSON configuration
///
/// # Safety
/// - `config_json` must be a valid null-terminated UTF-8 string
/// - Caller must call `softether_client_free` to release resources
#[no_mangle]
pub unsafe extern "C" fn softether_client_create(config_json: *const c_char) -> *mut SoftEtherClient {
    if config_json.is_null() {
        eprintln!("❌ FFI: config_json is null");
        return ptr::null_mut();
    }

    let config_str = match CStr::from_ptr(config_json).to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ FFI: Invalid UTF-8 in config: {}", e);
            return ptr::null_mut();
        }
    };

    let config: ClientConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ FFI: Failed to parse config JSON: {}", e);
            return ptr::null_mut();
        }
    };

    // Initialize tracing for iOS logs
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .with_thread_ids(false)
        .try_init();

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("❌ FFI: Failed to create Tokio runtime: {}", e);
            return ptr::null_mut();
        }
    };

    let client = match VpnClient::from_shared_config(config) {
        Ok(c) => Arc::new(Mutex::new(Some(c))),
        Err(e) => {
            eprintln!("❌ FFI: Failed to create VPN client: {}", e);
            return ptr::null_mut();
        }
    };

    let handle = Box::new(SoftEtherClient {
        runtime,
        client,
        rx_callback: Arc::new(Mutex::new(None)),
        state_callback: Arc::new(Mutex::new(None)),
        event_callback: Arc::new(Mutex::new(None)),
    });

    tracing::info!("✅ FFI: SoftEther client created");
    Box::into_raw(handle)
}

/// Create a new SoftEther VPN client from C struct configuration (RECOMMENDED)
///
/// This is the preferred way to create clients - avoids JSON parsing overhead
/// and provides compile-time type safety.
///
/// # Safety
/// - `config` must point to a valid SoftEtherConfig struct
/// - All string pointers in config must be valid null-terminated UTF-8
/// - Caller must call `softether_client_free` to release resources
///
/// # Example
/// ```swift
/// var connConfig = softether_config_connection_default()
/// connConfig.max_connections = 8
/// connConfig.skip_tls_verify = true
///
/// var clientConfig = softether_config_client_default()
///
/// let config = SoftEtherConfig(
///     host: strdup("vpn.example.com"),
///     port: 443,
///     hub_name: strdup("VPN"),
///     username: strdup("user"),
///     hashed_password: strdup("..."),
///     connection: connConfig,
///     client: clientConfig
/// )
/// let client = softether_client_create_v2(&config)
/// ```
#[no_mangle]
pub unsafe extern "C" fn softether_client_create_v2(config: *const SoftEtherConfig) -> *mut SoftEtherClient {
    if config.is_null() {
        eprintln!("❌ FFI: config is null");
        return ptr::null_mut();
    }

    let client_config = match (*config).to_client_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ FFI: Failed to convert config: {}", e);
            return ptr::null_mut();
        }
    };

    // Initialize tracing for iOS logs
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .with_thread_ids(false)
        .try_init();

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("❌ FFI: Failed to create Tokio runtime: {}", e);
            return ptr::null_mut();
        }
    };

    let client = match VpnClient::from_shared_config(client_config) {
        Ok(c) => Arc::new(Mutex::new(Some(c))),
        Err(e) => {
            eprintln!("❌ FFI: Failed to create VPN client: {}", e);
            return ptr::null_mut();
        }
    };

    let handle = Box::new(SoftEtherClient {
        runtime,
        client,
        rx_callback: Arc::new(Mutex::new(None)),
        state_callback: Arc::new(Mutex::new(None)),
        event_callback: Arc::new(Mutex::new(None)),
    });

    tracing::info!("✅ FFI: SoftEther client created (v2 struct config)");
    Box::into_raw(handle)
}

/// Set callback for receiving packets from VPN server (Server→iOS direction)
///
/// # Safety
/// - `handle` must be a valid pointer from `softether_client_create`
/// - `callback` will be called from Rust thread, must be thread-safe
/// - `user_data` is passed through unchanged
#[no_mangle]
pub unsafe extern "C" fn softether_client_set_rx_callback(
    handle: *mut SoftEtherClient,
    callback: Option<extern "C" fn(*const u8, u32, *mut c_void)>,
    user_data: *mut c_void,
) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let client_handle = &mut *handle;

    if let Some(cb) = callback {
        let user_data_val = user_data as usize;
        let rx_cb: RxCallback = Box::new(move |data: &[u8]| {
            let ptr = data.as_ptr();
            let len = data.len() as u32;
            let ud = user_data_val as *mut c_void;
            cb(ptr, len, ud);
        });
        *client_handle.rx_callback.blocking_lock() = Some(rx_cb);
        tracing::debug!("✅ FFI: RX callback registered");
    } else {
        *client_handle.rx_callback.blocking_lock() = None;
        tracing::debug!("FFI: RX callback cleared");
    }

    0
}

/// Set callback for connection state changes
///
/// # Safety
/// - `handle` must be a valid pointer from `softether_client_create`
/// - `callback` receives state as u32: 0=disconnected, 1=connecting, 2=connected
#[no_mangle]
pub unsafe extern "C" fn softether_client_set_state_callback(
    handle: *mut SoftEtherClient,
    callback: Option<extern "C" fn(u32, *mut c_void)>,
    user_data: *mut c_void,
) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let client_handle = &mut *handle;

    if let Some(cb) = callback {
        let user_data_val = user_data as usize;
        let state_cb: StateCallback = Box::new(move |state: u32| {
            let ud = user_data_val as *mut c_void;
            cb(state, ud);
        });
        *client_handle.state_callback.blocking_lock() = Some(state_cb);
        tracing::debug!("✅ FFI: State callback registered");
    } else {
        *client_handle.state_callback.blocking_lock() = None;
    }

    0
}

/// Set callback for events (logs, errors, network settings)
///
/// # Safety
/// - `handle` must be a valid pointer from `softether_client_create`
/// - `callback` receives: level (0=info, 1=warn, 2=error), code, message
/// - Special code 1001: message is JSON network settings snapshot
#[no_mangle]
pub unsafe extern "C" fn softether_client_set_event_callback(
    handle: *mut SoftEtherClient,
    callback: Option<extern "C" fn(u32, i32, *const c_char, *mut c_void)>,
    user_data: *mut c_void,
) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let client_handle = &mut *handle;

    if let Some(cb) = callback {
        let user_data_val = user_data as usize;
        let event_cb: EventCallback = Box::new(move |level: u32, code: i32, msg: &str| {
            if let Ok(c_msg) = CString::new(msg) {
                let ud = user_data_val as *mut c_void;
                cb(level, code, c_msg.as_ptr(), ud);
            }
        });
        *client_handle.event_callback.blocking_lock() = Some(event_cb);
        tracing::debug!("✅ FFI: Event callback registered");
    } else {
        *client_handle.event_callback.blocking_lock() = None;
    }

    0
}

/// Connect to VPN server (blocks until connection completes)
///
/// # Safety
/// - `handle` must be a valid pointer from `softether_client_create`
/// - Returns 0 on success, -1 on error, -2 on timeout
#[no_mangle]
pub unsafe extern "C" fn softether_client_connect(handle: *mut SoftEtherClient) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let client_handle = &mut *handle;

    tracing::info!("🚀 FFI: Starting VPN connection (blocking until complete)...");

    let client_arc = client_handle.client.clone();
    let state_cb = client_handle.state_callback.clone();
    let event_cb = client_handle.event_callback.clone();
    let rx_cb = client_handle.rx_callback.clone();

    // Use block_on instead of spawn - wait for connection to complete
    let result = client_handle.runtime.block_on(async move {
        // Lock client for connection
        let mut client_guard = client_arc.lock().await;
        let client_opt = client_guard.as_mut();
        
        if client_opt.is_none() {
            tracing::error!("❌ FFI: Client already consumed or invalid");
            return -1;
        }

        let client = client_opt.unwrap();

        // Wire up callbacks to client events
        let (state_tx, mut state_rx) = tokio::sync::mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
        
        client.set_state_callback(state_tx);
        client.set_event_callback(event_tx);

        // Spawn state/event forwarding tasks (these continue in background)
        let state_cb_clone = state_cb.clone();
        tokio::spawn(async move {
            while let Some(state) = state_rx.recv().await {
                // Serialize callback invocation to prevent concurrent Swift calls
                if let Some(cb) = state_cb_clone.lock().await.as_ref() {
                    let state_val = match state {
                        ClientState::Disconnected => 0,
                        ClientState::Connecting => 1,
                        ClientState::Established => 2,
                        ClientState::Disconnecting => 3,
                    };
                    // Execute callback in blocking context to ensure serial execution
                    tokio::task::block_in_place(|| {
                        cb(state_val);
                    });
                }
            }
        });

        let event_cb_clone = event_cb.clone();
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                // Serialize callback invocation to prevent concurrent Swift calls
                if let Some(cb) = event_cb_clone.lock().await.as_ref() {
                    let level = match event.level {
                        vpnclient::types::EventLevel::Info => 0,
                        vpnclient::types::EventLevel::Warn => 1,
                        vpnclient::types::EventLevel::Error => 2,
                    };
                    // Execute callback in blocking context to ensure serial execution
                    tokio::task::block_in_place(|| {
                        cb(level, event.code, &event.message);
                    });
                }
            }
        });

        // Connect with 60-second timeout
        let connect_result = tokio::time::timeout(std::time::Duration::from_secs(60), client.connect()).await;
        
        // Process connection result and wire up callbacks
        let final_result = match connect_result {
            Ok(Ok(_)) => {
                tracing::info!("✅ FFI: VPN connected successfully");

                // Wire up RX callback to dataplane
                if let Some(dp) = client.dataplane() {
                    let (dp_rx_tx, mut dp_rx_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                    dp.set_adapter_rx(dp_rx_tx);

                    let rx_cb_clone = rx_cb.clone();
                    tokio::spawn(async move {
                        while let Some(frame) = dp_rx_rx.recv().await {
                            if let Some(cb) = rx_cb_clone.lock().await.as_ref() {
                                cb(&frame);
                            }
                        }
                    });
                }

                // Emit network settings as event code 1001
                if let Some(settings) = client.get_network_settings() {
                    if let Ok(json) = serde_json::to_string(&settings) {
                        if let Some(cb) = event_cb.lock().await.as_ref() {
                            cb(0, 1001, &json);
                        }
                    }
                }

                0 // Success
            }
            Ok(Err(e)) => {
                tracing::error!("❌ FFI: VPN connection failed: {}", e);
                if let Some(cb) = event_cb.lock().await.as_ref() {
                    cb(2, -1, &format!("Connection failed: {}", e));
                }
                -1 // Connection error
            }
            Err(_) => {
                tracing::error!("⏱️  FFI: VPN connection timeout (60s)");
                if let Some(cb) = event_cb.lock().await.as_ref() {
                    cb(2, -2, "Connection timeout after 60 seconds");
                }
                -2 // Timeout
            }
        };

        // CRITICAL: Explicitly drop the mutex guard BEFORE returning
        // This ensures the client lock is released and iOS extension won't crash
        drop(client_guard);
        tracing::debug!("🔓 FFI: Client lock released");

        final_result
    });

    result
}

/// Send packet to VPN server (iOS→Server direction)
///
/// # Safety
/// - `handle` must be a valid pointer from `softether_client_create`
/// - `data` must point to valid memory of `len` bytes
#[no_mangle]
pub unsafe extern "C" fn softether_client_send_frame(
    handle: *mut SoftEtherClient,
    data: *const u8,
    len: u32,
) -> c_int {
    if handle.is_null() || data.is_null() || len == 0 {
        return -1;
    }
    let client_handle = &mut *handle;

    let frame = std::slice::from_raw_parts(data, len as usize).to_vec();

    let client_arc = client_handle.client.clone();
    client_handle.runtime.spawn(async move {
        let client_guard = client_arc.lock().await;
        if let Some(client) = client_guard.as_ref() {
            if let Some(dp) = client.dataplane() {
                if !dp.send_frame(frame) {
                    tracing::warn!("⚠️  FFI: Failed to send frame to dataplane");
                }
            }
        }
    });

    0
}

/// Get network settings as JSON string (IPv4, DNS, routes)
///
/// # Safety
/// - `handle` must be a valid pointer from `softether_client_create`
/// - Returns allocated C string, caller must call `softether_free_string`
#[no_mangle]
pub unsafe extern "C" fn softether_client_get_network_settings_json(
    handle: *mut SoftEtherClient,
) -> *mut c_char {
    if handle.is_null() {
        return ptr::null_mut();
    }
    let client_handle = &*handle;

    let client_arc = client_handle.client.clone();
    let result = client_handle.runtime.block_on(async {
        let client_guard = client_arc.lock().await;
        if let Some(client) = client_guard.as_ref() {
            if let Some(settings) = client.get_network_settings() {
                return serde_json::to_string(&settings).ok();
            }
        }
        None
    });

    match result {
        Some(json) => match CString::new(json) {
            Ok(c_str) => c_str.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

/// Free string allocated by softether_client_get_network_settings_json
///
/// # Safety
/// - `s` must be a pointer previously returned by `softether_client_get_network_settings_json`
#[no_mangle]
pub unsafe extern "C" fn softether_free_string(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

/// Disconnect from VPN server
///
/// # Safety
/// - `handle` must be a valid pointer from `softether_client_create`
#[no_mangle]
pub unsafe extern "C" fn softether_client_disconnect(handle: *mut SoftEtherClient) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let client_handle = &mut *handle;

    tracing::info!("🛑 FFI: Disconnecting VPN...");

    let client_arc = client_handle.client.clone();
    client_handle.runtime.block_on(async {
        let mut client_guard = client_arc.lock().await;
        if let Some(client) = client_guard.as_mut() {
            let _ = client.disconnect().await;
        }
    });

    0
}

/// Free VPN client resources
///
/// # Safety
/// - `handle` must be a valid pointer from `softether_client_create`
/// - Must not be used after calling this function
#[no_mangle]
pub unsafe extern "C" fn softether_client_free(handle: *mut SoftEtherClient) {
    if !handle.is_null() {
        let _ = Box::from_raw(handle);
        tracing::info!("♻️  FFI: SoftEther client freed");
    }
}

// =============================================================================
// Connection Statistics and Info
// =============================================================================

/// C-compatible connection info struct
#[repr(C)]
pub struct ConnectionInfo {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connected_time_ms: u64,
    pub is_connected: u8, // boolean: 0=false, 1=true
}

/// Get connection statistics
///
/// # Safety
/// - `handle` must be a valid pointer from `softether_client_create`
/// - `info` must point to valid writable memory
/// - Returns 0 on success, -1 on error
#[no_mangle]
pub unsafe extern "C" fn softether_client_get_connection_info(
    handle: *mut SoftEtherClient,
    info: *mut ConnectionInfo,
) -> c_int {
    if handle.is_null() || info.is_null() {
        return -1;
    }
    let client_handle = &*handle;

    let client_arc = client_handle.client.clone();
    let result = client_handle.runtime.block_on(async {
        let client_guard = client_arc.lock().await;
        if let Some(client) = client_guard.as_ref() {
            if let Some(stats) = client.get_connection_stats() {
                return Some(ConnectionInfo {
                    bytes_sent: stats.total_bytes_sent,
                    bytes_received: stats.total_bytes_received,
                    connected_time_ms: stats.connection_time,
                    is_connected: if stats.is_connected { 1 } else { 0 },
                });
            }
        }
        None
    });

    match result {
        Some(conn_info) => {
            *info = conn_info;
            0
        }
        None => -1,
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Generate SoftEther password hash (SHA-0 based)
///
/// # Safety
/// - `username` and `password` must be valid null-terminated UTF-8 strings
/// - `output` must point to writable buffer of at least `output_len` bytes
/// - Returns 0 on success, -1 on error
/// 
/// The output will be a base64-encoded SHA-0 hash suitable for authentication.
#[no_mangle]
pub unsafe extern "C" fn softether_generate_password_hash(
    username: *const c_char,
    password: *const c_char,
    output: *mut c_char,
    output_len: usize,
) -> c_int {
    if username.is_null() || password.is_null() || output.is_null() || output_len == 0 {
        return -1;
    }

    let username_str = match CStr::from_ptr(username).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let password_str = match CStr::from_ptr(password).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    // Use mayaqua's password hashing function (returns [u8; 20])
    let hash_bytes = mayaqua::crypto::softether_password_hash(password_str, username_str);
    
    // Base64 encode the hash
    use base64::Engine as _;
    let hash_b64 = base64::prelude::BASE64_STANDARD.encode(&hash_bytes);
    
    // Copy to output buffer
    let hash_str_bytes = hash_b64.as_bytes();
    if hash_str_bytes.len() + 1 > output_len {
        return -1; // Buffer too small
    }

    ptr::copy_nonoverlapping(hash_str_bytes.as_ptr() as *const c_char, output, hash_str_bytes.len());
    *output.add(hash_str_bytes.len()) = 0; // Null terminator

    0
}

/// Get library version string
///
/// # Safety
/// - Returns a static string pointer, no need to free
#[no_mangle]
pub unsafe extern "C" fn softether_get_library_version() -> *const c_char {
    static VERSION: &str = concat!(
        "SoftEther VPN Client Rust FFI v",
        env!("CARGO_PKG_VERSION"),
        " (Build ",
        "9807", // CLIENT_BUILD from vpnclient crate
        ")"
    );
    VERSION.as_ptr() as *const c_char
}

/// Get SoftEther core version (client version/build used for server negotiation)
///
/// # Safety
/// - Returns a static string pointer, no need to free
#[no_mangle]
pub unsafe extern "C" fn softether_get_core_version() -> *const c_char {
    static CORE_VERSION: &str = "4.44/9807"; // CLIENT_VERSION.CLIENT_BUILD
    CORE_VERSION.as_ptr() as *const c_char
}

// =============================================================================
// VirtualTapRust FFI Re-exports
// =============================================================================
// Re-export all VirtualTapRust FFI functions so they're available in a single library

pub use virtual_tap_rust::ffi::*;
