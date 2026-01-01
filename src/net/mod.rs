//! Networking utilities.
//!
//! This module provides:
//! - TLS connection management
//! - TCP socket utilities
//! - UDP acceleration support

mod connection;
mod udp_accel;

pub use connection::VpnConnection;
pub use udp_accel::{
    UdpAccel, UdpAccelAuthParams, UdpAccelServerResponse,
    UDP_ACCELERATION_COMMON_KEY_SIZE_V1, UDP_ACCELERATION_COMMON_KEY_SIZE_V2,
    UDP_ACCEL_VERSION_1, UDP_ACCEL_VERSION_2, UDP_ACCEL_MAX_VERSION,
};
