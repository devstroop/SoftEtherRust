//! iOS platform bindings via ANE (Apple Network Extensions).
//!
//! This module provides iOS-specific helper functions that make Swift
//! integration cleaner and more efficient, similar to how JNI provides
//! Android-specific bindings.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     iOS App                                 │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │              Swift (SoftEtherBridge.swift)          │   │
//! │  │  - Calls ANE helper functions (this module)         │   │
//! │  │  - Simplified Swift API                             │   │
//! │  └───────────────────────┬─────────────────────────────┘   │
//! │                          │                                  │
//! │  ┌───────────────────────▼─────────────────────────────┐   │
//! │  │          ANE Layer (ios.rs - this module)            │   │
//! │  │  - softether_ios_*() functions                      │   │
//! │  │  - Swift-friendly return types                      │   │
//! │  │  - String handling helpers                          │   │
//! │  └───────────────────────┬─────────────────────────────┘   │
//! │                          │                                  │
//! │  ┌───────────────────────▼─────────────────────────────┐   │
//! │  │              C FFI (Generic)                         │   │
//! │  │  - softether_create(), connect(), etc.              │   │
//! │  └───────────────────────┬─────────────────────────────┘   │
//! │                          │                                  │
//! │  ┌───────────────────────▼─────────────────────────────┐   │
//! │  │              Rust Core                               │   │
//! │  │  - VPN protocol implementation                      │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use super::client::*;
use super::types::*;
use std::os::raw::{c_char, c_int};

/// iOS platform marker.
#[cfg(target_os = "ios")]
pub const PLATFORM: &str = "ios";

#[cfg(target_os = "macos")]
pub const PLATFORM: &str = "macos";

#[cfg(all(not(target_os = "ios"), not(target_os = "macos")))]
pub const PLATFORM: &str = "apple-unknown";

// =============================================================================
// Helper Functions for Swift
// =============================================================================

/// Get the library version string (Swift-friendly).
/// Returns a C string that Swift can consume directly.
#[no_mangle]
pub extern "C" fn softether_ios_version() -> *const c_char {
    softether_version()
}

/// Convert IPv4 address (u32 network byte order) to dotted string.
/// Buffer must be at least 16 bytes. Returns number of bytes written.
///
/// This avoids Swift having to do the conversion itself.
///
/// # Safety
/// The `buffer` pointer must be valid and point to at least `buffer_len` bytes of writable memory.
#[no_mangle]
pub unsafe extern "C" fn softether_ios_ipv4_to_string(
    ip: u32,
    buffer: *mut c_char,
    buffer_len: usize,
) -> c_int {
    if buffer.is_null() || buffer_len < 16 {
        return -1;
    }

    let a = (ip >> 24) & 0xFF;
    let b = (ip >> 16) & 0xFF;
    let c = (ip >> 8) & 0xFF;
    let d = ip & 0xFF;

    let ip_str = format!("{a}.{b}.{c}.{d}");

    if ip_str.len() + 1 > buffer_len {
        return -1;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(ip_str.as_ptr(), buffer as *mut u8, ip_str.len());
        *buffer.add(ip_str.len()) = 0;
    }

    ip_str.len() as c_int
}

/// Convert MAC address bytes to colon-separated string.
/// Buffer must be at least 18 bytes. Returns number of bytes written.
///
/// # Safety
/// The `mac` pointer must point to at least 6 bytes. The `buffer` pointer must be valid
/// and point to at least `buffer_len` bytes of writable memory.
#[no_mangle]
pub unsafe extern "C" fn softether_ios_mac_to_string(
    mac: *const u8,
    buffer: *mut c_char,
    buffer_len: usize,
) -> c_int {
    if mac.is_null() || buffer.is_null() || buffer_len < 18 {
        return -1;
    }

    let mac_bytes = unsafe { std::slice::from_raw_parts(mac, 6) };
    let mac_str = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
    );

    unsafe {
        std::ptr::copy_nonoverlapping(mac_str.as_ptr(), buffer as *mut u8, mac_str.len());
        *buffer.add(mac_str.len()) = 0;
    }

    mac_str.len() as c_int
}

/// Check if an IPv4 address is valid (not 0.0.0.0).
#[no_mangle]
pub extern "C" fn softether_ios_is_valid_ipv4(ip: u32) -> c_int {
    if ip == 0 {
        0
    } else {
        1
    }
}

/// Simplified session getter that returns a pointer to session data.
/// This avoids Swift having to construct the entire SoftEtherSession struct.
/// Returns NULL if not connected or handle is invalid.
///
/// # Safety
/// The `handle` must be a valid handle returned from `softether_create`.
#[no_mangle]
pub unsafe extern "C" fn softether_ios_get_session(
    handle: SoftEtherHandle,
) -> *const SoftEtherSession {
    if handle.is_null() {
        return std::ptr::null();
    }

    // We need a place to store the session - use thread-local storage
    thread_local! {
        static SESSION_STORAGE: std::cell::RefCell<SoftEtherSession> =
            std::cell::RefCell::new(SoftEtherSession::default());
    }

    SESSION_STORAGE.with(|storage| {
        let mut session = storage.borrow_mut();
        let result = unsafe { softether_get_session(handle, &mut *session as *mut _) };

        if result == SoftEtherResult::Ok {
            &*session as *const SoftEtherSession
        } else {
            std::ptr::null()
        }
    })
}

/// Simplified statistics getter.
///
/// # Safety
/// The `handle` must be a valid handle returned from `softether_create`.
#[no_mangle]
pub unsafe extern "C" fn softether_ios_get_stats(handle: SoftEtherHandle) -> *const SoftEtherStats {
    if handle.is_null() {
        return std::ptr::null();
    }

    thread_local! {
        static STATS_STORAGE: std::cell::RefCell<SoftEtherStats> =
            std::cell::RefCell::new(SoftEtherStats::default());
    }

    STATS_STORAGE.with(|storage| {
        let mut stats = storage.borrow_mut();
        let result = unsafe { softether_get_stats(handle, &mut *stats as *mut _) };

        if result == SoftEtherResult::Ok {
            &*stats as *const SoftEtherStats
        } else {
            std::ptr::null()
        }
    })
}

/// Format bytes as human-readable string (KB, MB, GB).
/// Buffer must be at least 32 bytes.
///
/// # Safety
/// The `buffer` pointer must be valid and point to at least `buffer_len` bytes of writable memory.
#[no_mangle]
pub unsafe extern "C" fn softether_ios_format_bytes(
    bytes: u64,
    buffer: *mut c_char,
    buffer_len: usize,
) -> c_int {
    if buffer.is_null() || buffer_len < 32 {
        return -1;
    }

    let formatted = if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    };

    if formatted.len() + 1 > buffer_len {
        return -1;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(formatted.as_ptr(), buffer as *mut u8, formatted.len());
        *buffer.add(formatted.len()) = 0;
    }

    formatted.len() as c_int
}

/// Check if the library is running on iOS (vs macOS).
#[no_mangle]
pub extern "C" fn softether_ios_is_ios() -> c_int {
    #[cfg(target_os = "ios")]
    {
        1
    }
    #[cfg(not(target_os = "ios"))]
    {
        0
    }
}

/// Check if the library is running on macOS.
#[no_mangle]
pub extern "C" fn softether_ios_is_macos() -> c_int {
    #[cfg(target_os = "macos")]
    {
        1
    }
    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

/// Get platform name.
#[no_mangle]
pub extern "C" fn softether_ios_platform() -> *const c_char {
    PLATFORM.as_ptr() as *const c_char
}

// =============================================================================
// Internal Helper Functions
// =============================================================================

/// Returns true if running on an Apple platform (iOS/macOS).
#[inline]
pub fn is_apple_platform() -> bool {
    cfg!(any(target_os = "ios", target_os = "macos"))
}

/// Returns true if running on iOS.
#[inline]
pub fn is_ios() -> bool {
    cfg!(target_os = "ios")
}

/// Returns true if running on macOS.
#[inline]
pub fn is_macos() -> bool {
    cfg!(target_os = "macos")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn test_platform_detection() {
        let _ = is_apple_platform();
        let _ = is_ios();
        let _ = is_macos();
    }

    #[test]
    fn test_ipv4_to_string() {
        let mut buffer = [0i8; 16];
        let len = unsafe {
            softether_ios_ipv4_to_string(
                0xC0A80001, // 192.168.0.1
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        assert!(len > 0);

        let result = unsafe {
            CStr::from_ptr(buffer.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        assert_eq!(result, "192.168.0.1");
    }

    #[test]
    fn test_mac_to_string() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut buffer = [0i8; 18];
        let len =
            unsafe { softether_ios_mac_to_string(mac.as_ptr(), buffer.as_mut_ptr(), buffer.len()) };
        assert!(len > 0);

        let result = unsafe {
            CStr::from_ptr(buffer.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        assert_eq!(result, "00:11:22:33:44:55");
    }

    #[test]
    fn test_format_bytes() {
        let mut buffer = [0i8; 32];

        // Test bytes
        unsafe { softether_ios_format_bytes(500, buffer.as_mut_ptr(), buffer.len()) };
        let result = unsafe { CStr::from_ptr(buffer.as_ptr()).to_str().unwrap() };
        assert!(result.contains("B"));

        // Test KB
        unsafe { softether_ios_format_bytes(2048, buffer.as_mut_ptr(), buffer.len()) };
        let result = unsafe { CStr::from_ptr(buffer.as_ptr()).to_str().unwrap() };
        assert!(result.contains("KB"));

        // Test MB
        unsafe { softether_ios_format_bytes(5 * 1024 * 1024, buffer.as_mut_ptr(), buffer.len()) };
        let result = unsafe { CStr::from_ptr(buffer.as_ptr()).to_str().unwrap() };
        assert!(result.contains("MB"));
    }
}
