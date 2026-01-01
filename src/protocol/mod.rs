//! SoftEther protocol implementation.
//!
//! This module contains:
//! - Pack: Binary serialization format
//! - HTTP: HTTP codec for handshake
//! - Auth: Authentication helpers
//! - Tunnel: Data tunnel protocol

mod auth;
mod constants;
mod http;
mod pack;
mod tunnel;

pub use auth::{AuthPack, AuthResult, AuthType, ConnectionOptions, HelloResponse, RedirectInfo};
pub use constants::*;
pub use http::{HttpCodec, HttpRequest, HttpResponse};
pub use pack::{Pack, PackValue};
pub use tunnel::{
    compress, decompress, decompress_into, is_compressed, TunnelCodec, TunnelConstants, TunnelFrame,
};
