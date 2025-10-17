use std::time::Duration;

use anyhow::Result;
use mayaqua::Pack;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::network::SecureConnection;
use crate::{CLIENT_BUILD, CLIENT_STRING, CLIENT_VERSION};

use super::VpnClient;

impl VpnClient {
    /// Open the first bulk data link by performing an additional_connect on a fresh TLS socket
    pub(crate) async fn open_primary_data_link(&mut self) -> Result<()> {
        let (host, port, insecure, timeout_s, sni) = (
            self.config.host.clone(),
            self.config.port,
            self.config.connection.skip_tls_verify,
            self.config.connection.timeout as u64,
            self.sni_host.clone(),
        );
        let Some(sk) = self.server_session_key else {
            anyhow::bail!("missing session_key for data link");
        };
        let dp = self
            .dataplane
            .clone()
            .ok_or_else(|| anyhow::anyhow!("dataplane not available"))?;
        // Open a new TLS connection to the target node and perform additional_connect with per-link redirect handling
        let timeout = Duration::from_secs(timeout_s);
        let mut cur_host = host.clone();
        let mut cur_port = port;
        let mut redir_attempts = 0u8;
        // Direction of this link as determined by the server (0: both, 1: c->s, 2: s->c)
        'connect_and_register: loop {
            let mut conn =
                SecureConnection::connect(&cur_host, cur_port, insecure, timeout, sni.as_deref())?;
            let _ = conn.initial_hello()?;
            // Build and send additional_connect pack
            let mut p = Pack::new();
            // Match C implementation: PackAdditionalConnect + PackAddClientVersion
            // Only session_key and client version - NO use_encrypt/compress/etc.
            p.add_str("method", "additional_connect")?;
            p.add_data("session_key", sk.to_vec())?;
            p.add_str("client_str", CLIENT_STRING)?;
            p.add_int("client_ver", CLIENT_VERSION)?;
            p.add_int("client_build", CLIENT_BUILD)?;
            let resp = conn.send_pack(&p)?;
            // Handle redirect on additional_connect
            let rflag = resp
                .get_int("Redirect")
                .or_else(|_| resp.get_int("redirect"))
                .unwrap_or(0);
            if rflag != 0 {
                let mut new_host: Option<String> = None;
                if let Ok(hs) = resp
                    .get_str("RedirectHost")
                    .or_else(|_| resp.get_str("redirect_host"))
                {
                    if !hs.is_empty() {
                        new_host = Some(hs.to_string());
                    }
                }
                let new_port = resp
                    .get_int("Port")
                    .or_else(|_| resp.get_int("port"))
                    .unwrap_or(cur_port as u32) as u16;
                if new_host.is_none() {
                    if let Ok(ip_raw) = resp.get_int("Ip").or_else(|_| resp.get_int("ip")) {
                        let o = ip_raw.to_le_bytes();
                        new_host =
                            Some(std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3]).to_string());
                    }
                }
                if let Some(hh) = new_host {
                    info!(
                        "[INFO] primary_data_link redirect from={} to={}:{}",
                        cur_host, hh, new_port
                    );
                    cur_host = hh;
                    cur_port = new_port;
                    redir_attempts = redir_attempts.saturating_add(1);
                    if redir_attempts > 3 {
                        anyhow::bail!("primary_data_link too many redirects");
                    }
                    continue 'connect_and_register;
                }
            }
            if let Ok(errc) = resp.get_int("error") {
                if errc != 0 {
                    let name = super::VpnClient::softether_err_name(errc as i64);
                    anyhow::bail!("additional_connect error={} ({})", errc, name);
                }
            }
            let direction = resp.get_int("direction").unwrap_or(0);
            info!(
                "[INFO] primary_data_link established host={} port={} direction={}",
                cur_host, cur_port, direction
            );
            if direction == 1 || direction == 2 {
                debug!("Server split directions across connections (half-connected)");
            }

            // CRITICAL: Check if server is actually ready to receive data
            // Try to read with a short timeout to see if server sends anything first
            debug!("🔍 Checking if server sends initial data on data link...");
            let mut test_buf = [0u8; 4];
            let tls_ref = conn.tls_stream_ref();
            match tls_ref.get_ref().peek(&mut test_buf) {
                Ok(0) => {
                    debug!("⚠️  Server peek returned 0 bytes (socket closed?)");
                }
                Ok(n) => {
                    debug!("✅ Server has {} bytes waiting to be read (good sign)", n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    debug!("⚠️  No data from server yet (WouldBlock) - server may not be reading our packets");
                }
                Err(e) => {
                    debug!(
                        "⚠️  Server peek error: {} - may indicate connection issue",
                        e
                    );
                }
            }

            // Hand off TLS stream to dataplane
            // DO NOT set timeout - dataplane RX task needs true blocking I/O
            // The socket was already configured for blocking mode in network.rs
            let tls = conn.into_tls_stream();
            let _ = dp.register_link(tls, direction as i32);
            break;
        }
        Ok(())
    }

    /// Spawn scaffolded auxiliary link tasks up to min(server policy, config)
    pub(crate) fn spawn_additional_links(&mut self) {
        let cfg_max = self.config.connection.max_connections.max(1);
        let pol_max = self.server_policy_max_connections.unwrap_or(cfg_max);
        let negotiated = self.server_negotiated_max_connections.unwrap_or(cfg_max);
        let desired = cfg_max.min(pol_max).min(negotiated);
        if desired <= 1 {
            debug!("Additional links not requested (desired={})", desired);
            return;
        }
        let to_spawn = desired - 1; // minus the primary link
        info!(
            "Planning to spawn {} additional link(s) (policy={}, negotiated={}, config={})",
            to_spawn, pol_max, negotiated, cfg_max
        );

        // Require a valid session key from server to bond additional connections
        let Some(session_key) = self.server_session_key else {
            warn!("Server session_key unavailable; skipping bonded additional connections");
            return;
        };

        // Pin aux links to the same endpoint as the primary connection to avoid farm/session mismatches.
        // The server may redirect individual aux connections if needed.
        let base_host = self.config.host.clone();
        let port = self.config.port;
        let mgr = self.connection_manager.clone();
        let pool = self.connection_pool.clone();
        let dp = self.dataplane.clone();
        // Build round-robin list of ports from welcome pack if any
        let ports_rr: Vec<u16> = self
            .network_settings
            .as_ref()
            .map(|ns| {
                if ns.ports.is_empty() {
                    vec![port]
                } else {
                    ns.ports.clone()
                }
            })
            .unwrap_or_else(|| vec![port]);

        for i in 0..to_spawn {
            let name = format!("aux_link_{}", i + 1);
            let chosen_port = ports_rr[i as usize % ports_rr.len()];
            // Use the same host as the primary endpoint; allow server-side redirect to rebalance if required
            let chosen_host = base_host.clone();
            info!(
                "[INFO] additional_link starting name={} host={} port={} transport=tcp",
                name, chosen_host, chosen_port
            );
            let h = chosen_host;
            let insecure = self.config.connection.skip_tls_verify;
            let timeout_s = self.config.connection.timeout as u64;
            let client_str = CLIENT_STRING.to_string();
            let client_ver = CLIENT_VERSION;
            let client_build = CLIENT_BUILD;
            let sk = session_key; // copy for move
            let dirs = self.aux_directions.clone();
            let mgr2 = mgr.clone();
            let pool2 = pool.clone();
            let dp2 = dp.clone();
            // Force-disable compression to match dataplane framing (same as primary link)
            let use_compress = false;
            let half_conn = self.config.connection.half_connection;
            let sni = self.sni_host.clone();
            let start_stagger_ms = 250u64 * (i as u64);
            let handle = tokio::spawn(async move {
                // Stagger starts slightly to avoid server-side burst
                if start_stagger_ms > 0 {
                    sleep(Duration::from_millis(start_stagger_ms)).await;
                }
                // Establish TLS and perform additional_connect with per-link redirect handling
                let timeout = Duration::from_secs(timeout_s);
                let mut cur_host = h.clone();
                let mut cur_port = chosen_port;
                let mut redir_attempts = 0u8;
                let mut attempts: u32 = 0;
                let max_attempts: u32 = 8;
                let mut backoff_ms: u64 = 200;
                'connect_and_register: loop {
                    if attempts >= max_attempts {
                        warn!(
                            "additional_link giving up after {} attempts name={} host={} port={}",
                            attempts, name, cur_host, cur_port
                        );
                        break;
                    }
                    attempts = attempts.saturating_add(1);
                    let conn_res = SecureConnection::connect(
                        &cur_host,
                        cur_port,
                        insecure,
                        timeout,
                        sni.as_deref(),
                    );
                    let mut conn = match conn_res {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(
                                "additional_link connect failed attempt={} name={} host={} port={} err={}",
                                attempts, name, cur_host, cur_port, e
                            );
                            sleep(Duration::from_millis(backoff_ms)).await;
                            backoff_ms = (backoff_ms * 2).min(3000);
                            continue 'connect_and_register;
                        }
                    };
                    if let Err(e) = conn.initial_hello() {
                        warn!(
                            "additional_link hello failed attempt={} name={} host={} err={}",
                            attempts, name, cur_host, e
                        );
                        sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(3000);
                        continue 'connect_and_register;
                    }
                    // Build additional_connect pack each attempt
                    let mut p = Pack::new();
                    if let Err(e) = (|| -> anyhow::Result<()> {
                        p.add_str("method", "additional_connect")?;
                        p.add_data("session_key", sk.to_vec())?;
                        p.add_str("client_str", &client_str)?;
                        p.add_int("client_ver", client_ver)?;
                        p.add_int("client_build", client_build)?;
                        p.add_int("use_encrypt", 1)?;
                        p.add_int("use_compress", use_compress as u32)?;
                        p.add_int("half_connection", if half_conn { 1 } else { 0 })?;
                        p.add_int("qos", 0)?;
                        Ok(())
                    })() {
                        warn!("additional_link pack build failed name={} err={}", name, e);
                        break;
                    }

                    match conn.send_pack(&p) {
                        Ok(resp) => {
                            // Check for redirect on additional_connect
                            let rflag = resp
                                .get_int("Redirect")
                                .or_else(|_| resp.get_int("redirect"))
                                .unwrap_or(0);
                            if rflag != 0 {
                                // Prefer RedirectHost; else Ip (u32 LE) + Port
                                let mut new_host: Option<String> = None;
                                if let Ok(hs) = resp
                                    .get_str("RedirectHost")
                                    .or_else(|_| resp.get_str("redirect_host"))
                                {
                                    if !hs.is_empty() {
                                        new_host = Some(hs.to_string());
                                    }
                                }
                                let new_port = resp
                                    .get_int("Port")
                                    .or_else(|_| resp.get_int("port"))
                                    .unwrap_or(cur_port as u32)
                                    as u16;
                                if new_host.is_none() {
                                    if let Ok(ip_raw) =
                                        resp.get_int("Ip").or_else(|_| resp.get_int("ip"))
                                    {
                                        let o = ip_raw.to_le_bytes();
                                        new_host = Some(
                                            std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3])
                                                .to_string(),
                                        );
                                    }
                                }
                                if let Some(hh) = new_host {
                                    info!(
                                        "[INFO] additional_link redirect name={} from={} to={}:{}",
                                        name, cur_host, hh, new_port
                                    );
                                    cur_host = hh;
                                    cur_port = new_port;
                                    redir_attempts = redir_attempts.saturating_add(1);
                                    if redir_attempts > 3 {
                                        warn!("additional_link too many redirects name={} host={} port={}", name, cur_host, cur_port);
                                        break;
                                    }
                                    // retry with new target
                                    continue 'connect_and_register;
                                }
                            }
                            if let Ok(errc) = resp.get_int("error") {
                                if errc != 0 {
                                    let en = super::VpnClient::softether_err_name(errc as i64);
                                    warn!(
                                        "additional_connect error={} ({}) attempt={} name={} host={} port={}",
                                        errc, en, attempts, name, cur_host, cur_port

                                    );
                                    // Retry some transient errors like ERR_SESSION_TIMEOUT
                                    if errc == 13 {
                                        // ERR_SESSION_TIMEOUT
                                        sleep(Duration::from_millis(backoff_ms)).await;
                                        backoff_ms = (backoff_ms * 2).min(3000);
                                        continue 'connect_and_register;
                                    }
                                    // Fatal: don't retry
                                    break;
                                }
                            }
                            let direction = resp.get_int("direction").unwrap_or(0);
                            info!("[INFO] additional_link established name={} host={} port={} direction={}", name, cur_host, cur_port, direction);
                            if direction == 1 || direction == 2 {
                                debug!(
                                    "Server split directions across connections (half-connected)"
                                );
                            }
                            // Record direction
                            {
                                let mut g = dirs.lock().unwrap();
                                g.push(direction as i32);
                            }
                            // Register with the connection manager for global summary
                            let _bond_handle = mgr2.register_bond(direction as i32);
                            // DO NOT set timeout - dataplane RX tasks need true blocking I/O
                            // The socket was already configured for blocking mode in network.rs
                            // Hand off the TLS stream into dataplane/pool
                            let tls = conn.into_tls_stream();
                            if let Some(dp) = dp2.as_ref() {
                                let _ = dp.register_link(tls, direction as i32);
                            } else {
                                let _ = pool2.register_link(tls, direction as i32);
                            }
                            // Hold the connection open
                            loop {
                                sleep(Duration::from_secs(60)).await;
                            }
                        }
                        Err(e) => {
                            warn!(
                                "additional_link auth failed name={} host={} port={} err={}",
                                name, cur_host, cur_port, e
                            );
                            break;
                        }
                    }
                }
            });
            self.aux_tasks.push(handle);
        }
    }

    /// Periodically log a connections summary (primary + additional directions)
    pub(crate) fn start_connections_summary_logger(&mut self) {
        let mgr = self.connection_manager.clone();
        let dp_opt = self.dataplane.as_ref().cloned();
        let handle = tokio::spawn(async move {
            use tokio::time::{sleep, Duration};
            loop {
                sleep(Duration::from_secs(30)).await;
                // Prefer the connection manager's bookkeeping when available
                let s = mgr.summary();
                let total = 1 + s.total;
                let extra = if let Some(ref dp) = dp_opt {
                    let dps = dp.summary();
                    format!(
                        " tx_bytes={}, rx_bytes={}, dp_links={}",
                        dps.total_tx, dps.total_rx, dps.total_links
                    )
                } else {
                    String::new()
                };
                if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                    info!("[INFO] connections summary: total={} primary=1 additional={} split={{c2s:{}, s2c:{}, both:{}}}{}", total, s.total, s.c2s, s.s2c, s.both, extra);
                } else {
                    debug!("connections summary: total={} primary=1 additional={} split={{c2s:{}, s2c:{}, both:{}}}{}", total, s.total, s.c2s, s.s2c, s.both, extra);
                }
            }
        });
        self.aux_tasks.push(handle);
    }
}
