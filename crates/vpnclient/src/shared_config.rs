//! Shared client configuration (migrated from former `config` crate)
//! Provides JSON I/O helpers and mapping to cedar types.

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod io {
    use super::{ClientConfig, ConfigError, Result};
    use serde::{de::DeserializeOwned, Serialize};
    use std::path::Path;
    use serde_json::Value;

    pub fn load_json<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T> {
        let data = mayaqua::fs::read_all(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        serde_json::from_slice(&data).map_err(|e| ConfigError::Json(e.to_string()))
    }

    pub fn save_json<T: Serialize, P: AsRef<Path>>(path: P, value: &T) -> Result<()> {
        let data = serde_json::to_vec_pretty(value).map_err(|e| ConfigError::Json(e.to_string()))?;
        mayaqua::fs::write_all_atomic(path, &data).map_err(|e| ConfigError::Io(e.to_string()))
    }

    /// Load a `ClientConfig`, returning any unknown top-level keys (excluding alias forms)
    pub fn load_client_config_with_unknowns<P: AsRef<Path>>(path: P) -> Result<(ClientConfig, Vec<String>)> {
        let data = mayaqua::fs::read_all(&path).map_err(|e| ConfigError::Io(e.to_string()))?;
        let v: Value = serde_json::from_slice(&data).map_err(|e| ConfigError::Json(e.to_string()))?;
        let mut unknown = Vec::new();
        if let Some(map) = v.as_object() {
            // Known canonical keys (include legacy aliases to avoid false positives if used)
            const KNOWN: &[&str] = &[
                "server","port","hub","username","password","password_hash","skip_tls_verify","use_encrypt","use_compress","max_connections","nat_traversal","udp_acceleration","static_ip","static_ipv4","static_ipv6","ip_version","require_static_ip"
            ];
            for k in map.keys() {
                if !KNOWN.contains(&k.as_str()) { unknown.push(k.clone()); }
            }
        }
        // Now deserialize proper config struct
        let cfg: ClientConfig = serde_json::from_value(v).map_err(|e| ConfigError::Json(e.to_string()))?;
        Ok((cfg, unknown))
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

fn default_true() -> bool { true }

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
    /// Enable RC4 encryption on top of TLS (default: true, recommended for performance)
    #[serde(default = "default_true")]
    pub use_encrypt: bool,
    /// Enable data compression (default: false for compatibility)
    #[serde(default)]
    pub use_compress: bool,
    pub max_connections: u32,
    /// Enable NAT traversal (SecureNAT / NAT-T style) if supported; default false
    #[serde(default)]
    pub nat_traversal: Option<bool>,
    /// Enable UDP acceleration (datapath over UDP) if supported; default false
    #[serde(default)]
    pub udp_acceleration: Option<bool>,
    // Telemetry / cosmetic tuning fields removed.
    /// Optional static IP (IPv4 or IPv6). Field `ip` should be CIDR, e.g. "192.168.1.10/24" or "2001:db8::1/64".
    /// Applies equally to both families; same property names regardless of version.
    /// `gateway` and each entry in `dns` may be either IPv4 or IPv6 literals consistent with `ip` family.
    #[serde(default, alias = "static_ipv4", alias = "static_ipv6", skip_serializing_if = "Option::is_none")]
    pub static_ip: Option<StaticIpConfig>,
    /// Which IP version(s) to attempt for in-tunnel dynamic configuration when no static IP for that family.
    /// Values: "auto" (default) -> independently attempt v4/v6 if no static; "v4" -> only IPv4; "v6" -> only IPv6.
    #[serde(default)]
    pub ip_version: IpVersionPreference,
    /// If true, abort connection if no static_ip provided (skip DHCP attempts entirely). Default false.
    #[serde(default)]
    pub require_static_ip: bool,
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
            use_encrypt: true,
            use_compress: false,
            max_connections: 1,
            nat_traversal: None,
            udp_acceleration: None,
            static_ip: None,
            ip_version: IpVersionPreference::Auto,
            require_static_ip: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticIpConfig {
    /// CIDR string (address/prefix); prefix required to derive mask or routing info.
    pub ip: String,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub dns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IpVersionPreference { Auto, V4, V6 }

impl Default for IpVersionPreference { fn default() -> Self { IpVersionPreference::Auto } }

impl ClientConfig {
    pub fn to_client_option(&self) -> std::result::Result<cedar::ClientOption, mayaqua::Error> {
        let mut opt = cedar::ClientOption::new(&self.server, self.port, &self.hub)?;
        opt = opt.with_max_connections(self.max_connections);
        opt = opt.with_encryption(self.use_encrypt);
        opt = opt.with_compression(self.use_compress);
        Ok(opt)
    }

    pub fn to_client_auth(&self) -> std::result::Result<cedar::ClientAuth, mayaqua::Error> {
        if let Some(ref pass) = self.password { return cedar::ClientAuth::new_password(&self.username, pass); }
        if let Some(ref b64) = self.password_hash {
            let mut auth = cedar::ClientAuth::new_password(&self.username, "")?;
            auth.plain_password.clear();
            if let Ok(bytes) = base64::prelude::BASE64_STANDARD.decode(b64) { if bytes.len() == 20 { auth.hashed_password.copy_from_slice(&bytes); } }
            return Ok(auth);
        }
        Ok(cedar::ClientAuth::new_anonymous())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn default_values() {
        let c = ClientConfig::default();
        assert_eq!(c.port, 443);
        assert_eq!(c.hub, "DEFAULT");
    }

    #[test]
    fn unknown_key_detection() {
        let blob = json!({
            "server":"1.2.3.4","port":443,"hub":"DEFAULT","username":"u","max_connections":1,
            "use_compress":false,"ip_version":"auto","mystery_field":123
        });
        let val = serde_json::to_vec(&blob).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &val).unwrap();
        let (cfg, unknown) = crate::shared_config::io::load_client_config_with_unknowns(tmp.path()).unwrap();
        assert_eq!(cfg.server, "1.2.3.4");
        assert_eq!(unknown, vec!["mystery_field".to_string()]);
    }
}
