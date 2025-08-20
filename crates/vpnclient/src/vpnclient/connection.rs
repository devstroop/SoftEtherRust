use anyhow::Result;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::network::SecureConnection;
use cedar::Session;
use mayaqua::get_tick64;
use tracing::{debug, warn};

use super::VpnClient;

impl VpnClient {
    /// Establish a TLS-secured control connection to the server
    pub(super) async fn establish_connection(&self) -> Result<SecureConnection> {
        let timeout_duration = Duration::from_secs(self.config.connection.timeout as u64);

        let connection = SecureConnection::connect(
            &self.config.host,
            self.config.port,
            self.config.connection.skip_tls_verify,
            timeout_duration,
            self.sni_host.as_deref(),
        )?;

        Ok(connection)
    }

    /// Perform periodic keep-alive work on control channel and session
    pub(super) async fn keep_alive_check(&mut self) -> Result<()> {
        if let Some(session) = &mut self.session {
            session.update_last_comm_time();

            // Update traffic statistics
            let stats = session.get_stats();
            debug!(
                "Session stats - Sent: {} bytes, Received: {} bytes",
                stats.total_send_size, stats.total_recv_size
            );
        }

        // Send a lightweight PACK keep-alive (noop) every ~50 seconds on control channel
        // Only until a dataplane link is established, to avoid control-channel read contention.
        let dp_links = self
            .dataplane
            .as_ref()
            .map(|dp| dp.summary().total_links)
            .unwrap_or(0);
        if dp_links == 0 {
            if let Some(conn) = &mut self.connection {
                let now = get_tick64();
                if self.last_noop_sent == 0
                    || now.saturating_sub(self.last_noop_sent) >= Session::KEEP_ALIVE_INTERVAL
                {
                    if let Err(e) = conn.send_noop() {
                        warn!("Keep-alive (noop) send failed: {}", e);
                    } else {
                        debug!("Keep-alive (noop) sent");
                        self.last_noop_sent = now;
                    }
                }
            }
        }

        // When tunneling mode is active, dataplane handles frequent link keep-alives
        Ok(())
    }
}

/// Resolve all IPv4 addresses for a hostname. Returns dotted-quad strings.
#[allow(dead_code)]
pub(super) fn resolve_all_ips(host: &str, port: u16) -> Vec<String> {
    let mut out = Vec::new();
    let addr = format!("{}:{}", host, port);
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
