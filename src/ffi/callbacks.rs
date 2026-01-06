//! FFI callbacks for event notifications.
//!
//! Mobile apps can register callbacks to receive events from the VPN client.

use super::types::{SoftEtherResult, SoftEtherSession, SoftEtherState};
use std::ffi::c_void;

/// Callback for state changes.
///
/// # Parameters
/// - `context`: User-provided context pointer.
/// - `state`: New connection state.
pub type StateCallback = Option<extern "C" fn(context: *mut c_void, state: SoftEtherState)>;

/// Callback for connection established.
///
/// # Parameters
/// - `context`: User-provided context pointer.
/// - `session`: Session information (IP, gateway, DNS, etc.).
pub type ConnectedCallback =
    Option<extern "C" fn(context: *mut c_void, session: *const SoftEtherSession)>;

/// Callback for disconnection.
///
/// # Parameters
/// - `context`: User-provided context pointer.
/// - `result`: Reason for disconnection (Ok = clean disconnect, error code otherwise).
pub type DisconnectedCallback =
    Option<extern "C" fn(context: *mut c_void, result: SoftEtherResult)>;

/// Callback for received packets.
///
/// This is called when packets are received from the VPN server.
/// The callback should copy the packet data if needed, as the buffer
/// may be reused after the callback returns.
///
/// # Parameters
/// - `context`: User-provided context pointer.
/// - `packets`: Pointer to packet data (format: [len:u16][data]...).
/// - `total_size`: Total size of packet data.
/// - `packet_count`: Number of packets.
///
/// # Note
/// This callback is called from the I/O thread. Keep processing minimal
/// and queue packets for processing on another thread if needed.
pub type PacketsReceivedCallback = Option<
    extern "C" fn(context: *mut c_void, packets: *const u8, total_size: usize, packet_count: u32),
>;

/// Callback for log messages.
///
/// # Parameters
/// - `context`: User-provided context pointer.
/// - `level`: Log level (0=debug, 1=info, 2=warn, 3=error).
/// - `message`: Null-terminated UTF-8 log message.
pub type LogCallback =
    Option<extern "C" fn(context: *mut c_void, level: i32, message: *const std::ffi::c_char)>;

/// Socket protection callback type.
/// Called when a socket needs to be protected from VPN routing.
///
/// # Parameters
/// - `context`: User context pointer.
/// - `fd`: The socket file descriptor to protect.
///
/// # Returns
/// true if protection succeeded, false otherwise.
pub type ProtectSocketCallback = Option<extern "C" fn(context: *mut c_void, fd: i32) -> bool>;

/// IP exclusion callback type.
/// Called when an IP address should be excluded from VPN routing.
/// Used for cluster redirect scenarios where the VPN server IP changes.
///
/// # Parameters
/// - `context`: User context pointer.
/// - `ip`: Null-terminated IP address string (IPv4 or IPv6).
///
/// # Returns
/// true if exclusion succeeded, false otherwise.
pub type ExcludeIpCallback =
    Option<extern "C" fn(context: *mut c_void, ip: *const std::ffi::c_char) -> bool>;

/// Collection of all callbacks.
#[repr(C)]
pub struct SoftEtherCallbacks {
    /// User context pointer passed to all callbacks.
    pub context: *mut c_void,
    /// State change callback.
    pub on_state_changed: StateCallback,
    /// Connected callback.
    pub on_connected: ConnectedCallback,
    /// Disconnected callback.
    pub on_disconnected: DisconnectedCallback,
    /// Packets received callback.
    pub on_packets_received: PacketsReceivedCallback,
    /// Log callback.
    pub on_log: LogCallback,
    /// Socket protection callback (Android/iOS VPN).
    pub protect_socket: ProtectSocketCallback,
    /// IP exclusion callback for cluster redirects (Android VPN).
    pub exclude_ip: ExcludeIpCallback,
}

impl Default for SoftEtherCallbacks {
    fn default() -> Self {
        Self {
            context: std::ptr::null_mut(),
            on_state_changed: None,
            on_connected: None,
            on_disconnected: None,
            on_packets_received: None,
            on_log: None,
            protect_socket: None,
            exclude_ip: None,
        }
    }
}

// Safety: The callbacks are only called from within Rust code,
// and we ensure proper synchronization in the FFI layer.
unsafe impl Send for SoftEtherCallbacks {}
unsafe impl Sync for SoftEtherCallbacks {}

impl SoftEtherCallbacks {
    /// Log a message through the registered callback.
    /// 
    /// # Parameters
    /// - `level`: Log level (0=debug, 1=info, 2=warn, 3=error)
    /// - `msg`: The message to log
    #[inline]
    pub fn log(&self, level: i32, msg: &str) {
        if let Some(cb) = self.on_log {
            if let Ok(cstr) = std::ffi::CString::new(msg) {
                cb(self.context, level, cstr.as_ptr());
            }
        }
    }

    /// Log an info message (level 1).
    #[inline]
    pub fn log_info(&self, msg: &str) {
        self.log(1, msg);
    }

    /// Log a warning message (level 2).
    #[inline]
    pub fn log_warn(&self, msg: &str) {
        self.log(2, msg);
    }

    /// Log an error message (level 3).
    #[inline]
    pub fn log_error(&self, msg: &str) {
        self.log(3, msg);
    }
}
