//! C API for SoftEther VPN Rust client
//! Split into smaller modules for maintainability; public C symbols unchanged.

mod utils;
mod callbacks;
mod arp;
mod client_handle;
mod api;

// No public Rust API is exposed; C API lives in api.rs with #[no_mangle] symbols.
