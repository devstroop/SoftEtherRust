use crate::shared_config;
use anyhow::Result;
use std::convert::TryFrom;

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub host: String,
    pub port: u16,
    pub hub_name: String,
    pub username: String,
    pub auth: AuthConfig,
    pub connection: ConnectionConfig,
    pub client: ClientRuntime,
}

impl RuntimeConfig {
    pub fn server_address(&self) -> String { format!("{}:{}", self.host, self.port) }
}

#[derive(Debug, Clone)]
pub enum AuthConfig {
    Anonymous,
    Password { hashed_password: String },
    Certificate { cert_file: String, key_file: String },
    SecureDevice { cert_name: String, key_name: String },
}

#[derive(Debug, Clone, Default)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    pub timeout: u32,
    pub max_connections: u32,
    pub skip_tls_verify: bool,
    pub half_connection: bool,
    pub udp_acceleration: bool,
    pub apply_dns: bool,
    pub proxy: Option<ProxyConfig>,
    pub client_id: Option<u32>,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            timeout: 30,
            max_connections: 1,
            skip_tls_verify: false,
            half_connection: false,
            udp_acceleration: false,
            apply_dns: true,
            proxy: None,
            client_id: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientRuntime {
    pub interface_name: String,
    pub interface_auto: bool,
    pub macos_dns_service_name: Option<String>,
    pub dhcp_settle_ms: u32,
    pub dhcp_initial_ms: u32,
    pub dhcp_max_ms: u32,
    pub dhcp_jitter_pct: u32,
    pub enable_in_tunnel_dhcp: bool,
    pub lease_cache_path: Option<String>,
    pub dhcp_renewal_jitter_pct: u32,
    pub dhcp_metrics_interval_secs: u64,
    pub interface_snapshot_redact: bool,
    pub interface_snapshot_verbose: bool,
    pub lease_health_warn_pct: u32,
}

impl Default for ClientRuntime {
    fn default() -> Self {
        Self {
            interface_name: "sevpn0".to_string(),
            interface_auto: false,
            macos_dns_service_name: None,
            dhcp_settle_ms: 3000,
            dhcp_initial_ms: 1000,
            dhcp_max_ms: 8000,
            dhcp_jitter_pct: 20,
            enable_in_tunnel_dhcp: true,
            lease_cache_path: None,
            dhcp_renewal_jitter_pct: 10,
            dhcp_metrics_interval_secs: 300,
            interface_snapshot_redact: false,
            interface_snapshot_verbose: false,
            lease_health_warn_pct: 10,
        }
    }
}

impl TryFrom<shared_config::ClientConfig> for RuntimeConfig {
    type Error = anyhow::Error;
    fn try_from(c: shared_config::ClientConfig) -> Result<Self> {
        // Determine auth: prefer hashed password if provided, else password, else anonymous
        let auth = if let Some(h) = c.password_hash.clone() {
            AuthConfig::Password { hashed_password: h }
        } else if c.password.is_some() { // password string -> convert to cedar hash first (defer to cedar login pack builder)
            // Fallback: derive SHA-0 hash the same as Go prototype if needed; presently we pass hashed later.
            // For now treat as anonymous if plain password present but no hash to avoid storing secrets in runtime config.
            AuthConfig::Anonymous
        } else {
            AuthConfig::Anonymous
        };
        let mut client_defaults = ClientRuntime::default();
    if let Some(iv) = c.dhcp_metrics_interval_secs { client_defaults.dhcp_metrics_interval_secs = iv.clamp(10, 86_400); }
    if let Some(b) = c.interface_snapshot_redact { client_defaults.interface_snapshot_redact = b; }
    if let Some(b) = c.interface_snapshot_verbose { client_defaults.interface_snapshot_verbose = b; }
    if let Some(p) = c.lease_health_warn_pct { client_defaults.lease_health_warn_pct = p.min(99).max(1); }
        Ok(Self {
            host: c.server.clone(),
            port: c.port,
            hub_name: c.hub.clone(),
            username: c.username.clone(),
            auth,
            connection: ConnectionConfig {
                timeout: 30,
                max_connections: c.max_connections,
                skip_tls_verify: c.skip_tls_verify,
                half_connection: false,
                udp_acceleration: false,
                apply_dns: true,
                proxy: None,
                client_id: None,
            },
            client: ClientRuntime { enable_in_tunnel_dhcp: c.enable_in_tunnel_dhcp.unwrap_or(true), lease_cache_path: c.lease_cache_path.clone(), interface_auto: c.interface_auto.unwrap_or(false), dhcp_metrics_interval_secs: client_defaults.dhcp_metrics_interval_secs, ..client_defaults },
        })
    }
}
