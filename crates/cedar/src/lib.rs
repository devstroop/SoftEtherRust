//! Cedar VPN Engine Layer
//!
//! This crate sits above `mayaqua` (foundation) and `protocol` (wire-level) and implements:
//! - Session lifecycle orchestration
//! - Multi / half connections & bonding
//! - Farm (cluster) redirection + ticket handling
//! - Authentication strategy dispatch
//! - Traffic stats, QoS skeleton
//! - Keep-alive and reconnect scaffolding
//!
//! The current commit provides the skeleton with key public types and TODO markers.

pub mod auth;
pub mod connection_mgr;
pub mod connection_pool;
pub mod dataplane;
pub mod redirect;
pub mod session_mgr;
pub mod types;
pub mod watermark;

pub mod client_auth;
pub mod client_option;
pub mod connection;
pub mod constants;
pub mod handshake;
pub mod session;
#[cfg(feature = "udp-accel")]
pub mod udp_accel;

pub use auth::*;
pub use connection_mgr::*;
pub use connection_pool::*;
pub use dataplane::*;
pub use redirect::*;
pub use session_mgr::*;
pub use types::*;
#[cfg(feature = "udp-accel")]
pub use udp_accel::*;
pub use watermark::*;

// Re-export key types exactly as before for external callers
pub use client_auth::ClientAuth;
pub use client_option::ClientOption;
pub use connection::Connection;
pub use constants::{AuthType, ConnectionStatus};
pub use handshake::build_login_pack;
pub use session::{Session, SessionConfig};

/// SoftEther protocol version constants (match Cedar.h)
pub const SOFTETHER_VER: u32 = 444;
pub const SOFTETHER_BUILD: u32 = 9807;
pub const SOFTETHER_PROTO_VER: u32 = 3;

/// Maximum protocol string lengths (from C implementation)
pub const MAX_SERVER_STR_LEN: usize = 64;
pub const MAX_CLIENT_STR_LEN: usize = 64;
pub const MAX_HOST_NAME_LEN: usize = 255;
pub const MAX_USERNAME_LEN: usize = 255;
pub const MAX_PASSWORD_LEN: usize = 255;
pub const MAX_HUBNAME_LEN: usize = 255;
pub const MAX_DEVICE_NAME_LEN: usize = 31;
pub const MAX_ACCOUNT_NAME_LEN: usize = 255;

/// SHA1 hash size
pub const SHA1_SIZE: usize = 20;

/// Protocol signatures and magic numbers
pub const KEEP_ALIVE_STRING: &str = "Internet Connection Keep Alive Packet";
pub const CONNECTION_BULK_COMPRESS_SIGNATURE: u64 = 0xDEADBEEFCAFEFACE;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(SHA1_SIZE, 20);
        assert!(MAX_USERNAME_LEN > 0);
        assert!(SOFTETHER_VER > 0);
    }
}

// Note: We intentionally do not re-export from a `protocol` crate/module here.
// The C Cedar layer sits above Mayaqua and the wire-level protocol, but in this
// Rust workspace the corresponding types are defined locally in this crate
// (client_auth, client_option, connection, session, constants, etc.).
// Upstream-facing re-exports are provided above from our own modules.
