use std::net::{Ipv4Addr, Ipv6Addr};

use crate::dhcp::Lease as DhcpLease;

/// Parsed network settings (assigned IP, DNS, policy flags) extracted from welcome/auth packs
#[derive(Debug, Clone, Default)]
pub struct NetworkSettings {
    pub assigned_ipv4: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub policies: Vec<(String, u32)>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub ports: Vec<u16>,
    // IPv6 additions
    pub assigned_ipv6: Option<Ipv6Addr>,
    pub assigned_ipv6_prefix: Option<u8>,
    pub ipv6_gateway: Option<Ipv6Addr>,
    pub dns_servers_v6: Vec<Ipv6Addr>,
}

/// Helper: serialize a snapshot of NetworkSettings to a compact JSON used by FFI/events.
/// If include_kind is true, a { kind: "settings", ... } wrapper is emitted to distinguish event payloads.
pub fn settings_json_with_kind(ns: Option<&NetworkSettings>, include_kind: bool) -> String {
    #[derive(serde::Serialize)]
    struct SettingsJson<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        kind: Option<&'a str>,
        assigned_ipv4: Option<String>,
        subnet_mask: Option<String>,
        gateway: Option<String>,
        dns_servers: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        assigned_ipv6: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        assigned_ipv6_prefix: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ipv6_gateway: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        dns_servers_v6: Vec<String>,
    }

    let mut json = SettingsJson {
        kind: include_kind.then_some("settings"),
        assigned_ipv4: None,
        subnet_mask: None,
        gateway: None,
        dns_servers: vec![],
        assigned_ipv6: None,
        assigned_ipv6_prefix: None,
        ipv6_gateway: None,
        dns_servers_v6: vec![],
    };
    if let Some(ns) = ns {
        if let Some(ip) = ns.assigned_ipv4 {
            json.assigned_ipv4 = Some(ip.to_string());
        }
        if let Some(m) = ns.subnet_mask {
            json.subnet_mask = Some(m.to_string());
        }
        if let Some(g) = ns.gateway {
            json.gateway = Some(g.to_string());
        }
        json.dns_servers = ns.dns_servers.iter().map(|d| d.to_string()).collect();
        if let Some(v6) = ns.assigned_ipv6 { json.assigned_ipv6 = Some(v6.to_string()); }
        if let Some(pfx) = ns.assigned_ipv6_prefix { json.assigned_ipv6_prefix = Some(pfx); }
        if let Some(g6) = ns.ipv6_gateway { json.ipv6_gateway = Some(g6.to_string()); }
        json.dns_servers_v6 = ns.dns_servers_v6.iter().map(|d| d.to_string()).collect();
    }
    serde_json::to_string(&json).unwrap_or_else(|_| "{}".to_string())
}

/// Convert a DHCP lease into NetworkSettings (IP/mask/gateway/DNS)
pub fn network_settings_from_lease(lease: &DhcpLease) -> NetworkSettings {
    let mut ns = NetworkSettings::default();
    ns.assigned_ipv4 = Some(lease.client_ip);
    ns.subnet_mask = lease.subnet_mask;
    ns.gateway = lease.router;
    ns.dns_servers.extend(lease.dns_servers.iter().copied());
    ns
}

/// Public-facing client state for embedders/FFI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    Idle = 0,
    Connecting = 1,
    Established = 2,
    Disconnecting = 3,
}

/// Event level for embedders
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLevel {
    Info = 0,
    Warn = 1,
    Error = 2,
}

/// Event payload for embedders
#[derive(Debug, Clone)]
pub struct ClientEvent {
    pub level: EventLevel,
    pub code: i32,
    pub message: String,
}

/// Session statistics
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub connection_time: u64,
    pub is_connected: bool,
    pub protocol: String,
}

/// Count 1-bits in IPv4 mask to CIDR prefix length
pub fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    let octets = mask.octets();
    (octets[0].count_ones()
        + octets[1].count_ones()
        + octets[2].count_ones()
        + octets[3].count_ones()) as u8
}
