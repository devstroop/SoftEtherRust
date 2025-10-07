use anyhow::Result;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::network::SecureConnection;

use super::VpnClient;

impl VpnClient {
    /// Establish a TLS-secured control connection to the server
    pub(super) async fn establish_connection(&self) -> Result<SecureConnection> {
        let timeout_duration = Duration::from_secs(self.config.connection.timeout as u64);

        eprintln!("🔌 Connecting to {}:{}", self.config.host, self.config.port);
        let connection = SecureConnection::connect(
            &self.config.host,
            self.config.port,
            self.config.connection.skip_tls_verify,
            timeout_duration,
            self.sni_host.as_deref(),
        )?;
        eprintln!("✅ Connected to {}:{}", self.config.host, self.config.port);

        Ok(connection)
    }
}

/// Resolve all IPv4 addresses for a hostname. Returns dotted-quad strings.
#[allow(dead_code)]
pub(super) fn resolve_all_ips(host: &str, port: u16) -> Vec<String> {
    let mut out = Vec::new();
    let addr = format!("{host}:{port}");
    if let Ok(iter) = addr.to_socket_addrs() {
        for sa in iter {
            if let SocketAddr::V4(v4) = sa {
                out.push(v4.ip().to_string());
            }
        }
    }
    out
}

/// Expand a list of endpoints (hostnames or IPs) into unique IPv4 addresses, preserving order loosely.
#[allow(dead_code)]
pub(super) fn expand_endpoints(endpoints: &[String], port: u16) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in endpoints {
        // If already an IPv4 address string, keep it; else resolve
        if e.parse::<std::net::Ipv4Addr>().is_ok() {
            if !out.contains(e) {
                out.push(e.clone());
            }
        } else {
            for ip in resolve_all_ips(e, port) {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}
