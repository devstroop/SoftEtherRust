//! FFI (Foreign Function Interface) module for mobile platforms.
//!
//! This module provides a C-compatible ABI with platform-specific layers:
//! - Swift (iOS) via ANE (Apple Network Extensions) helpers
//! - Kotlin/Java (Android) via JNI (Java Native Interface) bindings
//! - Other platforms via direct C FFI
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                    Mobile App                             │
//! │  ┌─────────────────┐      ┌─────────────────┐            │
//! │  │   Swift (iOS)   │      │ Kotlin (Android)│            │
//! │  └────────┬────────┘      └────────┬────────┘            │
//! │           │                        │                      │
//! │  ┌────────▼────────┐      ┌────────▼────────┐            │
//! │  │  ANE (ios.rs)   │      │  JNI (android.rs)│           │
//! │  └────────┬────────┘      └────────┬────────┘            │
//! │           │                        │                      │
//! │  ┌────────▼────────────────────────▼────────┐            │
//! │  │              C FFI Layer (Generic)        │            │
//! │  │  - softether_create()                    │            │
//! │  │  - softether_connect()                   │            │
//! │  │  - softether_send_packet()               │            │
//! │  │  - softether_receive_packets()           │            │
//! │  │  - softether_disconnect()                │            │
//! │  │  - softether_destroy()                   │            │
//! │  └────────────────────┬─────────────────────┘            │
//! │                       │                                   │
//! │  ┌────────────────────▼─────────────────────┐            │
//! │  │           Rust SoftEther Core            │            │
//! │  │  - VPN protocol implementation           │            │
//! │  │  - Async runtime (tokio)                 │            │
//! │  │  - TLS, compression, etc.                │            │
//! │  └──────────────────────────────────────────┘            │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage from Swift (iOS)
//!
//! ```swift
//! // In your bridging header or Swift module
//! import SoftEtherVPN
//!
//! let config = SoftEtherConfig(
//!     server: "vpn.example.com",
//!     port: 443,
//!     hub: "VPN",
//!     username: "user",
//!     password_hash: "base64hash"
//! )
//!
//! let client = softether_create(&config)
//! softether_connect(client)
//!
//! // In packet tunnel provider:
//! // Send packets TO VPN
//! softether_send_packets(client, packets, count)
//!
//! // Receive packets FROM VPN
//! var buffer = [UInt8](repeating: 0, count: 65536)
//! let received = softether_receive_packets(client, &buffer, buffer.count)
//! ```
//!
//! # Usage from Kotlin (Android)
//!
//! ```kotlin
//! // Via JNI or direct NDK bindings
//! external fun softether_create(config: SoftEtherConfig): Long
//! external fun softether_connect(handle: Long): Int
//! external fun softether_send_packets(handle: Long, packets: ByteArray, count: Int): Int
//! external fun softether_receive_packets(handle: Long, buffer: ByteArray, bufferSize: Int): Int
//! external fun softether_disconnect(handle: Long)
//! external fun softether_destroy(handle: Long)
//! ```

mod callbacks;
mod client;
mod connection;
mod packet_loop;
mod types;

pub use callbacks::*;
pub use callbacks::log_level;
pub use client::*;
pub use types::*;

// Platform-specific modules
#[cfg(feature = "android")]
mod android;

#[cfg(feature = "android")]
pub use android::*;

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod ios;

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub use ios::*;
