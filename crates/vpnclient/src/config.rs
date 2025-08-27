use crate::shared_config;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
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
    /// Precomputed static network settings (from shared config), if any.
    pub static_network: Option<crate::types::NetworkSettings>,
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
    pub nat_traversal: bool,
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
            nat_traversal: false,
            apply_dns: true,
            proxy: None,
            client_id: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientRuntime {
    pub interface_name: String,
    pub macos_dns_service_name: Option<String>,
    pub dhcp_settle_ms: u32,
    pub dhcp_initial_ms: u32,
    pub dhcp_max_ms: u32,
    pub dhcp_jitter_pct: u32,
    pub enable_in_tunnel_dhcp: bool,
    pub dhcp_renewal_jitter_pct: u32,
    pub enable_in_tunnel_dhcpv6: bool,
    pub mac_address: [u8;6],
}

impl Default for ClientRuntime {
    fn default() -> Self {
        Self {
            interface_name: "sevpn0".to_string(),
            macos_dns_service_name: None,
            dhcp_settle_ms: 3000,
            dhcp_initial_ms: 1000,
            dhcp_max_ms: 8000,
            dhcp_jitter_pct: 20,
            enable_in_tunnel_dhcp: true,
            dhcp_renewal_jitter_pct: 10,
            enable_in_tunnel_dhcpv6: false,
            mac_address: [0;6],
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
    let client_defaults = ClientRuntime::default();
    // Removed: metrics/snapshot/health/debug tunables (now fixed internally)
    // Always derive deterministic MAC from username|hub|server triple.
    use sha2::{Digest, Sha256};
    let mut h=Sha256::new();
    h.update(c.username.as_bytes()); h.update(b"|"); h.update(c.hub.as_bytes()); h.update(b"|"); h.update(c.server.as_bytes());
    let out=h.finalize();
    let mut mac_bytes=[0u8;6]; mac_bytes.copy_from_slice(&out[..6]);
    mac_bytes[0] = (mac_bytes[0] & 0b1111_1110) | 0b0000_0010; // locally administered unicast
        // Determine DHCP enable flags from ip_version preference + presence of static configs.
        use crate::shared_config::IpVersionPreference;
        // Detect static v4 or v6 by parsing CIDR-style string (very light parsing: split on '/').
        let mut static_v4: Option<(Ipv4Addr, u8, Option<Ipv4Addr>, Vec<Ipv4Addr>)> = None;
        let mut static_v6: Option<(Ipv6Addr, u8, Option<Ipv6Addr>, Vec<Ipv6Addr>)> = None;
        if let Some(cfg) = c.static_ip.as_ref() {
            let parts: Vec<&str> = cfg.ip.split('/').collect();
            if parts.len() != 2 { anyhow::bail!(crate::shared_config::ConfigError::Invalid("static_ip must be in CIDR form <addr>/<prefix>".into())); }
            if parts.len() == 2 { if let Ok(prefix) = parts[1].parse::<u8>() {
                if let Ok(v4) = parts[0].parse::<Ipv4Addr>() {
                    if prefix==0 || prefix>32 { anyhow::bail!(crate::shared_config::ConfigError::Invalid(format!("invalid IPv4 prefix /{}", prefix))); }
                    let gw = cfg.gateway.as_ref().and_then(|g| g.parse::<Ipv4Addr>().ok());
                    let mut dns_v4 = Vec::new();
                    for d in &cfg.dns { if let Ok(v4d)=d.parse::<Ipv4Addr>() { dns_v4.push(v4d); } else { anyhow::bail!(crate::shared_config::ConfigError::Invalid(format!("dns entry '{}' not IPv4", d))); } }
                    static_v4 = Some((v4, prefix.min(32), gw, dns_v4));
                } else if let Ok(v6) = parts[0].parse::<Ipv6Addr>() {
                    if prefix==0 || prefix>128 { anyhow::bail!(crate::shared_config::ConfigError::Invalid(format!("invalid IPv6 prefix /{}", prefix))); }
                    let gw = cfg.gateway.as_ref().and_then(|g| g.parse::<Ipv6Addr>().ok());
                    let mut dns_v6 = Vec::new();
                    for d in &cfg.dns { if let Ok(v6d)=d.parse::<Ipv6Addr>() { dns_v6.push(v6d); } else { anyhow::bail!(crate::shared_config::ConfigError::Invalid(format!("dns entry '{}' not IPv6", d))); } }
                    static_v6 = Some((v6, prefix.min(128), gw, dns_v6));
                }
            }}
            // Family mismatch checks
            if let Some(gw) = cfg.gateway.as_ref() {
                let ip_is_v4 = parts[0].parse::<Ipv4Addr>().is_ok();
                let gw_v4 = gw.parse::<Ipv4Addr>().is_ok();
                let gw_v6 = gw.parse::<Ipv6Addr>().is_ok();
                if ip_is_v4 && !gw_v4 && gw_v6 { anyhow::bail!(crate::shared_config::ConfigError::Invalid("gateway family mismatch (expected IPv4)".into())); }
                if !ip_is_v4 && !gw_v6 && gw_v4 { anyhow::bail!(crate::shared_config::ConfigError::Invalid("gateway family mismatch (expected IPv6)".into())); }
            }
        }

        let (dhcp_enabled, dhcpv6_enabled) = match c.ip_version {
            IpVersionPreference::Auto => (static_v4.is_none(), static_v6.is_none()),
            IpVersionPreference::V4 => (static_v4.is_none(), false),
            IpVersionPreference::V6 => (false, static_v6.is_none()),
        };

        // Pre-build network settings from static v4 (v6 static currently not stored in NetworkSettings structure)
    let mut static_ipv4_ns: Option<crate::types::NetworkSettings> = None;
        if let Some((ipv4, prefix, gw, dns_list)) = static_v4 {
            // Convert prefix to netmask
            let mask = if prefix==0 { Ipv4Addr::new(0,0,0,0) } else { let mask_u32 = (!0u32) << (32-prefix as u32); Ipv4Addr::from(mask_u32.to_be_bytes()) };
            let mut ns = crate::types::NetworkSettings::default();
            ns.assigned_ipv4 = Some(ipv4);
            ns.subnet_mask = Some(mask);
            ns.gateway = gw;
            ns.dns_servers.extend(dns_list);
            static_ipv4_ns = Some(ns);
        }
        if let Some((ipv6, prefix, gw6, dns6)) = static_v6 {
            // Attach to existing settings or create new
            if let Some(ns) = static_ipv4_ns.as_mut() {
                ns.assigned_ipv6 = Some(ipv6);
                ns.assigned_ipv6_prefix = Some(prefix);
                ns.ipv6_gateway = gw6;
                ns.dns_servers_v6.extend(dns6);
            } else {
                let mut ns = crate::types::NetworkSettings::default();
                ns.assigned_ipv6 = Some(ipv6);
                ns.assigned_ipv6_prefix = Some(prefix);
                ns.ipv6_gateway = gw6;
                ns.dns_servers_v6.extend(dns6);
                static_ipv4_ns = Some(ns);
            }
        }

        let runtime = Self {
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
                udp_acceleration: c.udp_acceleration.unwrap_or(false),
                nat_traversal: c.nat_traversal.unwrap_or(false),
                apply_dns: true,
                proxy: None,
                client_id: None,
            },
            client: ClientRuntime { enable_in_tunnel_dhcp: dhcp_enabled, enable_in_tunnel_dhcpv6: dhcpv6_enabled, mac_address: mac_bytes, ..client_defaults },
            static_network: static_ipv4_ns.clone(),
        };

        // If static IPv4 present, store synthesized network settings into a side-channel file for later detection.
        // Simplest: write to lease cache path if provided and no existing lease cache; marked as static.
    if let Some(_ns) = static_ipv4_ns.as_ref() { /* now purely in-memory; persistence removed */ }

    Ok(runtime)
    }
}
