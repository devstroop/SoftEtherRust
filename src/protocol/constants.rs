//! SoftEther protocol constants.

/// VPN target path for authenticated communication.
pub const VPN_TARGET: &str = "/vpnsvc/vpn.cgi";

/// Signature target path for initial connection.
pub const SIGNATURE_TARGET: &str = "/vpnsvc/connect.cgi";

/// Content type for signature requests.
pub const CONTENT_TYPE_SIGNATURE: &str = "image/jpeg";

/// Content type for Pack data.
pub const CONTENT_TYPE_PACK: &str = "application/octet-stream";

/// Client identification string.
pub const CLIENT_STRING: &str = "SoftEther (Rust) VPN Client";

/// Client version number.
pub const CLIENT_VERSION: u32 = 444;

/// Client build number.
pub const CLIENT_BUILD: u32 = 9807;

/// SHA-1/SHA-0 digest size.
pub const SHA_SIZE: usize = 20;

/// Maximum Pack value size (96 MB).
pub const MAX_VALUE_SIZE: usize = 96 * 1024 * 1024;

/// Maximum number of values per Pack element.
pub const MAX_VALUE_NUM: usize = 65536;

/// Maximum number of elements in a Pack.
pub const MAX_ELEMENTS: usize = 65536;

/// Maximum Ethernet frame size.
pub const MAX_PACKET_SIZE: usize = 1514;

/// Maximum keepalive data size.
pub const MAX_KEEPALIVE_SIZE: usize = 512;

/// Maximum blocks to receive at once.
pub const MAX_RECV_BLOCKS: usize = 512;

/// Keepalive magic number.
pub const KEEPALIVE_MAGIC: u32 = 0xFFFFFFFF;

/// UDP NAT-T port signature embedded in keepalive padding.
/// Format: [signature][port:u16 BE] at start of padding data.
pub const UDP_NAT_T_PORT_SIGNATURE: &[u8] = b"NATT_MY_PORT";

/// Connection signature.
pub const VPN_SIGNATURE: &[u8] = b"VPNCONNECT";
