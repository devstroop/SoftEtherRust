//! # Mayaqua - Foundation Layer
//!
//! Core utilities and platform abstraction layer for SoftEther VPN Rust implementation.
//! Based on the original SoftEther Mayaqua kernel.

#[cfg(feature = "compress")]
pub mod compress;
pub mod crypto;
pub mod error;
pub mod fs;
pub mod http;
pub mod logging;
pub mod memory;
pub mod network;
pub mod pack;
pub mod platform;
pub mod time;

// Re-export common types and traits
pub use error::{Error, Result};
pub use http::{HttpRequest, HttpResponse};
pub use pack::{Element, Pack, Value, ValueType};
pub use time::{get_tick64, Tick64};

// Core constants from C implementation - Platform-dependent sizes
pub const MAX_VALUE_NUM: u32 = 262144; // Max VALUEs per ELEMENT
pub const MAX_ELEMENT_NAME_LEN: u32 = 63; // Element name length
pub const MAX_ELEMENT_NUM: u32 = 262144; // Max ELEMENTs per PACK

// Architecture-dependent size limits (from Pack.h)
#[cfg(target_pointer_width = "64")]
pub const MAX_VALUE_SIZE: usize = 384 * 1024 * 1024; // 384MB per VALUE on 64-bit

#[cfg(target_pointer_width = "32")]
pub const MAX_VALUE_SIZE: usize = 96 * 1024 * 1024; // 96MB per VALUE on 32-bit

#[cfg(target_pointer_width = "64")]
pub const MAX_PACK_SIZE: usize = 512 * 1024 * 1024; // 512MB PACK on 64-bit

#[cfg(target_pointer_width = "32")]
pub const MAX_PACK_SIZE: usize = 128 * 1024 * 1024; // 128MB PACK on 32-bit

// HTTP transport constants
pub const HTTP_PACK_RAND_SIZE_MAX: u32 = 1000; // Random padding size

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert!(MAX_VALUE_SIZE > 0);
        assert!(MAX_PACK_SIZE > 0);
        assert_eq!(MAX_ELEMENT_NAME_LEN, 63);
    }
}
