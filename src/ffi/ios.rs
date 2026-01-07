//! iOS platform bindings.
//!
//! This module provides iOS-specific functionality and documentation for
//! integrating SoftEther VPN with iOS applications.
//!
//! # Architecture
//!
//! iOS uses the C FFI layer directly via Swift's C interop capabilities.
//! Unlike Android (which requires JNI bindings in Rust), Swift can call
//! C functions directly through a bridging header.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     iOS App                                 │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │              Swift (SoftEtherBridge.swift)          │   │
//! │  │  - Wraps C FFI functions                            │   │
//! │  │  - Handles callback bridging                        │   │
//! │  │  - Provides Swift-native types                      │   │
//! │  └───────────────────────┬─────────────────────────────┘   │
//! │                          │                                  │
//! │  ┌───────────────────────▼─────────────────────────────┐   │
//! │  │              C FFI (SoftEtherVPN.h)                  │   │
//! │  │  - softether_create()                               │   │
//! │  │  - softether_connect()                              │   │
//! │  │  - softether_send_packets()                         │   │
//! │  │  - softether_receive_packets()                      │   │
//! │  │  - softether_disconnect()                           │   │
//! │  │  - softether_destroy()                              │   │
//! │  └───────────────────────┬─────────────────────────────┘   │
//! │                          │                                  │
//! │  ┌───────────────────────▼─────────────────────────────┐   │
//! │  │              Rust Core (libsoftether_vpn.a)         │   │
//! │  │  - VPN protocol implementation                      │   │
//! │  │  - Async runtime (tokio)                            │   │
//! │  │  - TLS, compression, etc.                           │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! The iOS integration is done entirely in Swift. See:
//! - `SoftEtherBridge.swift` - Swift wrapper around C FFI
//! - `PacketTunnelProvider.swift` - Network Extension integration
//!
//! # Why No Rust Code Here?
//!
//! Unlike Android which requires JNI (Java Native Interface) bindings written
//! in Rust to bridge Java/Kotlin ↔ native code, iOS/macOS can call C functions
//! directly from Swift. This means:
//!
//! - **Android**: Kotlin → JNI (Rust) → C FFI → Rust Core
//! - **iOS**: Swift → C FFI (direct) → Rust Core
//!
//! The Swift wrapper (`SoftEtherBridge.swift`) handles:
//! - Converting Swift types to C types
//! - Managing callback contexts
//! - Providing a Swift-native API
//!
//! This module exists for:
//! 1. Consistency with the `android.rs` module
//! 2. Future iOS-specific Rust code if needed
//! 3. Documentation of the iOS integration architecture

// Currently, iOS-specific functionality is handled in Swift.
// This module serves as a placeholder and documentation reference.
//
// If iOS-specific Rust code is needed in the future, it can be added here.
// Examples of potential future additions:
// - iOS-specific optimizations
// - Apple-specific crypto (CommonCrypto bindings)
// - Keychain integration helpers

/// iOS platform marker.
/// This is a compile-time constant to identify iOS builds.
#[cfg(target_os = "ios")]
pub const PLATFORM: &str = "ios";

#[cfg(target_os = "macos")]
pub const PLATFORM: &str = "macos";

#[cfg(all(not(target_os = "ios"), not(target_os = "macos")))]
pub const PLATFORM: &str = "apple-unknown";

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

    #[test]
    fn test_platform_detection() {
        // At least one of these should be true during testing
        let _ = is_apple_platform();
        let _ = is_ios();
        let _ = is_macos();
    }
}
