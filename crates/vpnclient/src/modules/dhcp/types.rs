// DHCP types - consolidated from the fragmented implementations
// Based on Go implementation's clean structure

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

impl Default for Lease {
    fn default() -> Self {
        Self {
            client_ip: Ipv4Addr::UNSPECIFIED,
            server_ip: None,
            gateway: None,
            subnet_mask: None,
            dns_servers: Vec::new(),
            lease_time: None,
            renewal_time: None,
            rebinding_time: None,
            domain_name: None,
            interface_mtu: None,
            broadcast_addr: None,
            classless_routes: Vec::new(),
            server_mac: None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lease {
    pub client_ip: Ipv4Addr,
    pub server_ip: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_time: Option<Duration>,
    pub renewal_time: Option<SystemTime>,
    pub rebinding_time: Option<SystemTime>,
    pub domain_name: Option<String>,
    pub interface_mtu: Option<u16>,
    pub broadcast_addr: Option<Ipv4Addr>,
    pub classless_routes: Vec<(Ipv4Addr, u8, Ipv4Addr)>, // network, prefix, gateway
    pub server_mac: Option<[u8; 6]>,
}

/// DHCPv6 lease structure (consolidating from dhcpv6.rs)
#[derive(Clone, Debug, Default)]
pub struct LeaseV6 {
    pub client_ip: Option<Ipv6Addr>,
    pub prefix_len: Option<u8>,
    pub gateway: Option<Ipv6Addr>,
    pub dns_servers: Vec<Ipv6Addr>,
    pub lease_time: Option<Duration>,
    pub t1: Option<Duration>,
    pub t2: Option<Duration>,
    pub domain_search: Vec<String>,
}

/// DHCP state tracking (simplified from complex state machines)
#[derive(Debug, Clone, PartialEq)]
pub enum DhcpState {
    Idle,
    Discovering,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    RenewingV6,
    RebindingV6,
}

/// DHCP metrics (consolidated from scattered metrics)
#[derive(Debug)]
pub struct DhcpMetrics {
    // IPv4 metrics
    pub renew_attempts: AtomicU64,
    pub renew_success: AtomicU64,
    pub rebind_attempts: AtomicU64,
    pub rebind_success: AtomicU64,
    pub rediscover_attempts: AtomicU64,
    pub rediscover_success: AtomicU64,
    pub failures: AtomicU64,
    
    // IPv6 metrics
    pub v6_renew_attempts: AtomicU64,
    pub v6_renew_success: AtomicU64,
    pub v6_rebind_attempts: AtomicU64,
    pub v6_rebind_success: AtomicU64,
    pub v6_rediscover_attempts: AtomicU64,
    pub v6_rediscover_success: AtomicU64,
    pub v6_failures: AtomicU64,
}

impl DhcpMetrics {
    pub fn new() -> Self {
        Self {
            renew_attempts: AtomicU64::new(0),
            renew_success: AtomicU64::new(0),
            rebind_attempts: AtomicU64::new(0),
            rebind_success: AtomicU64::new(0),
            rediscover_attempts: AtomicU64::new(0),
            rediscover_success: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            v6_renew_attempts: AtomicU64::new(0),
            v6_renew_success: AtomicU64::new(0),
            v6_rebind_attempts: AtomicU64::new(0),
            v6_rebind_success: AtomicU64::new(0),
            v6_rediscover_attempts: AtomicU64::new(0),
            v6_rediscover_success: AtomicU64::new(0),
            v6_failures: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
        (
            self.renew_attempts.load(Ordering::Relaxed),
            self.renew_success.load(Ordering::Relaxed),
            self.rebind_attempts.load(Ordering::Relaxed),
            self.rebind_success.load(Ordering::Relaxed),
            self.rediscover_attempts.load(Ordering::Relaxed),
            self.rediscover_success.load(Ordering::Relaxed),
            self.failures.load(Ordering::Relaxed),
            self.v6_renew_attempts.load(Ordering::Relaxed),
            self.v6_renew_success.load(Ordering::Relaxed),
            self.v6_rebind_attempts.load(Ordering::Relaxed),
            self.v6_rebind_success.load(Ordering::Relaxed),
            self.v6_rediscover_attempts.load(Ordering::Relaxed),
            self.v6_rediscover_success.load(Ordering::Relaxed),
            self.v6_failures.load(Ordering::Relaxed),
        )
    }
}

impl Default for DhcpMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// DHCP options structure (based on Go implementation)
#[derive(Debug, Clone)]
pub struct DhcpOptions {
    pub opcode: u8,
    pub client_address: u32,
    pub server_address: u32,
    pub subnet_mask: u32,
    pub gateway: u32,
    pub dns_server: u32,
    pub dns_server2: u32,
    pub lease_time: u32,
    pub requested_ip: u32,
    pub hostname: String,
}

impl Default for DhcpOptions {
    fn default() -> Self {
        Self {
            opcode: 0,
            client_address: 0,
            server_address: 0,
            subnet_mask: 0,
            gateway: 0,
            dns_server: 0,
            dns_server2: 0,
            lease_time: 0,
            requested_ip: 0,
            hostname: String::new(),
        }
    }
}

/// Convert from DHCPv4 lease to network settings (helper)
impl From<&Lease> for crate::types::NetworkSettings {
    fn from(lease: &Lease) -> Self {
        Self {
            assigned_ipv4: Some(lease.client_ip),
            subnet_mask: lease.subnet_mask,
            gateway: lease.gateway,
            dns_servers: if lease.dns_servers.is_empty() {
                None
            } else {
                Some(lease.dns_servers.iter().map(|ip| (*ip).into()).collect())
            }.unwrap_or_default(),
            ..Default::default()
        }
    }
}