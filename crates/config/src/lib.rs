//! Client configuration crate: JSON I/O and mapping to cedar types.

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod io;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(String),
    #[error("json: {0}")]
    Json(String),
    #[error("invalid: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server: String,
    pub port: u16,
    pub hub: String,
    pub username: String,
    pub password: Option<String>,
    /// Base64 of SHA-0(password + UPPER(username)), compatible with Go prototype's genpwdhash
    #[serde(default, alias = "password_hash")]
    pub password_hash: Option<String>,
    /// Skip TLS certificate verification (insecure). Default: false
    #[serde(default)]
    pub skip_tls_verify: bool,
    pub use_compress: bool,
    pub use_encrypt: bool,
    pub max_connections: u32,
    pub udp_port: Option<u16>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".into(),
            port: 443,
            hub: "DEFAULT".into(),
            username: String::new(),
            password: None,
            password_hash: None,
            skip_tls_verify: false,
            use_compress: false,
            use_encrypt: true,
            max_connections: 1,
            udp_port: None,
        }
    }
}

impl ClientConfig {
    pub fn to_client_option(&self) -> std::result::Result<cedar::ClientOption, mayaqua::Error> {
        let mut opt = cedar::ClientOption::new(&self.server, self.port, &self.hub)?;
        opt = opt.with_max_connections(self.max_connections);
        opt = opt.with_compression(self.use_compress);
        opt = opt.with_encryption(self.use_encrypt);
        if let Some(udp) = self.udp_port {
            opt.port_udp = udp;
        }
        Ok(opt)
    }

    pub fn to_client_auth(&self) -> std::result::Result<cedar::ClientAuth, mayaqua::Error> {
        if let Some(ref pass) = self.password {
            return cedar::ClientAuth::new_password(&self.username, pass);
        }
        // Prefer SHA-0(password + UPPER(username)) variant when provided
        if let Some(ref b64) = self.password_hash {
            let mut auth = cedar::ClientAuth::new_password(&self.username, "__PLACEHOLDER__")?;
            auth.plain_password.clear();
            if let Ok(bytes) = base64::prelude::BASE64_STANDARD.decode(b64) {
                if bytes.len() == 20 {
                    auth.hashed_password.copy_from_slice(&bytes);
                }
            }
            return Ok(auth);
        }
        Ok(cedar::ClientAuth::new_anonymous())
    }
}
