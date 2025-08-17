//! Protocol Layer embedded under Cedar
//!
//! This module used to live in a separate `protocol` crate. It is now merged under
//! `cedar::protocol` to align with the original C layout where Cedar contains protocol.

pub mod client_auth;
pub mod client_option;
pub mod connection;
pub mod constants;
pub mod handshake;
pub mod session;

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
