//! SoftEther protocol implementation.
//!
//! This module contains:
//! - Pack: Binary serialization format
//! - HTTP: HTTP codec for handshake
//! - Auth: Authentication helpers
//! - Tunnel: Data tunnel protocol

mod pack;
mod http;
mod auth;
mod tunnel;
mod constants;

pub use pack::{Pack, PackValue};
pub use http::{HttpRequest, HttpResponse, HttpCodec};
pub use auth::{AuthType, AuthPack, HelloResponse, AuthResult, RedirectInfo, ConnectionOptions};
pub use tunnel::{TunnelFrame, TunnelCodec, TunnelConstants, is_compressed, decompress, decompress_into, compress};
pub use constants::*;
