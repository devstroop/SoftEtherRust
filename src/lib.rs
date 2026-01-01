//! # SoftEther Rust Client
//!
//! A high-performance SoftEther VPN client implementation in Rust.
//!
//! ## Features
//!
//! - Full SoftEther protocol support (TCP over TLS)
//! - SHA-0 authentication (legacy SoftEther compatibility)
//! - DHCP client for IP configuration
//! - ARP handling for gateway MAC discovery
//! - Async/await with Tokio runtime
//! - Cross-platform TUN device support (macOS, Linux)
//!
//! ## Example
//!
//! ```rust,no_run
//! use softether_rust::{VpnClient, VpnConfig, crypto};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Generate password hash (do this once, store the hex string)
//!     let password_hash = crypto::hash_password("password", "user");
//!     let password_hash_hex = hex::encode(password_hash);
//!
//!     let config = VpnConfig {
//!         server: "vpn.example.com".to_string(),
//!         port: 443,
//!         hub: "VPN".to_string(),
//!         username: "user".to_string(),
//!         password_hash: password_hash_hex,
//!         ..Default::default()
//!     };
//!
//!     let mut client = VpnClient::new(config);
//!     client.connect().await?;
//!     
//!     Ok(())
//! }
//! ```

pub mod adapter;
pub mod client;
pub mod config;
pub mod crypto;
pub mod error;
pub mod net;
pub mod packet;
pub mod protocol;
pub mod tunnel;

// FFI module for C/iOS/Android interop
#[cfg(feature = "ffi")]
pub mod ffi;

// Re-exports for convenience
pub use client::VpnClient;
pub use config::VpnConfig;
pub use error::{Error, Result};
