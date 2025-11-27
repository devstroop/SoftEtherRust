use std::net::Ipv4Addr;
use serde::{Deserialize, Serialize};

/// Parsed network settings (assigned IP, DNS, policy flags) extracted from welcome/auth packs
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkSettings {
    pub assigned_ipv4: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub policies: Vec<(String, u32)>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub ports: Vec<u16>,
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
    }

    let mut json = SettingsJson {
        kind: include_kind.then_some("settings"),
        assigned_ipv4: None,
        subnet_mask: None,
        gateway: None,
        dns_servers: vec![],
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
    }
    serde_json::to_string(&json).unwrap_or_else(|_| "{}".to_string())
}



/// Internal connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Idle = 0,
    Connecting = 1,
    Established = 2,
}

/// Public-facing client state for embedders/FFI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    Disconnected = 0,
    Connecting = 1,
    Established = 2,
    Disconnecting = 3,
}

impl From<ConnectionState> for ClientState {
    fn from(state: ConnectionState) -> Self {
        match state {
            ConnectionState::Idle => ClientState::Disconnected,
            ConnectionState::Connecting => ClientState::Connecting,
            ConnectionState::Established => ClientState::Established,
        }
    }
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
