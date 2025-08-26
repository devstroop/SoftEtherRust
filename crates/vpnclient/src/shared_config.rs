//! Shared client configuration (migrated from former `config` crate)
//! Provides JSON I/O helpers and mapping to cedar types.

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod io {
    use super::{ConfigError, Result};
    use serde::{de::DeserializeOwned, Serialize};
    use std::path::Path;

    pub fn load_json<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T> {
        let data = mayaqua::fs::read_all(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        serde_json::from_slice(&data).map_err(|e| ConfigError::Json(e.to_string()))
    }

    pub fn save_json<T: Serialize, P: AsRef<Path>>(path: P, value: &T) -> Result<()> {
        let data = serde_json::to_vec_pretty(value).map_err(|e| ConfigError::Json(e.to_string()))?;
        mayaqua::fs::write_all_atomic(path, &data).map_err(|e| ConfigError::Io(e.to_string()))
    }
}

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
    #[serde(default)]
    pub enable_in_tunnel_dhcp: Option<bool>,
    #[serde(default)]
    pub lease_cache_path: Option<String>,
    #[serde(default)]
    pub interface_auto: Option<bool>,
    #[serde(default)]
    pub dhcp_metrics_interval_secs: Option<u64>,
    #[serde(default)]
    pub interface_snapshot_redact: Option<bool>,
    #[serde(default)]
    pub interface_snapshot_verbose: Option<bool>,
    #[serde(default)]
    pub lease_health_warn_pct: Option<u32>,
    #[serde(default)]
    pub interface_snapshot_period_secs: Option<u64>,
    #[serde(default)]
    pub enable_in_tunnel_dhcpv6: Option<bool>,
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
            enable_in_tunnel_dhcp: None,
            lease_cache_path: None,
            interface_auto: None,
            dhcp_metrics_interval_secs: None,
            interface_snapshot_redact: None,
            interface_snapshot_verbose: None,
            lease_health_warn_pct: None,
            interface_snapshot_period_secs: None,
            enable_in_tunnel_dhcpv6: None,
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
            // Construct with empty password then replace hashed bytes
            let mut auth = cedar::ClientAuth::new_password(&self.username, "")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_values() {
        let c = ClientConfig::default();
        assert_eq!(c.port, 443);
        assert_eq!(c.hub, "DEFAULT");
    }
}
