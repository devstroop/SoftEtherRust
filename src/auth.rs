use anyhow::{Context, Result};
use base64::Engine as _;
use rand::RngCore;
use tracing::{debug, info, warn};

use crate::config::AuthConfig;
use crate::network::SecureConnection;
use crate::{CLIENT_BUILD, CLIENT_STRING, CLIENT_VERSION};
use cedar::handshake::secure_password;
use cedar::{AuthType, ClientAuth, ClientOption};

use super::VpnClient;

impl VpnClient {
    pub fn create_client_auth(&self) -> Result<ClientAuth> {
        // Use ticket auth after redirect if ticket was captured
        if let Some(ticket) = self.redirect_ticket {
            info!("🎫 Using TICKET AUTH after redirect (authtype=99)");
            info!("   Ticket bytes: {:?}", &ticket[..]);
            return ClientAuth::new_ticket(&self.config.username, &ticket)
                .context("Failed to create ticket auth");
        }
        info!("🔑 Using PASSWORD AUTH (authtype=1)");
        match &self.config.auth {
            AuthConfig::Anonymous => Ok(ClientAuth::new_anonymous()),
            AuthConfig::Password { hashed_password } => {
                let decoded = base64::prelude::BASE64_STANDARD
                    .decode(hashed_password)
                    .context("Failed to decode hashed password")?;
                if decoded.len() != 20 {
                    anyhow::bail!("Invalid password hash length");
                }
                let mut auth = ClientAuth::new_password(&self.config.username, "__PLACEHOLDER__")?;
                auth.plain_password.clear();
                auth.hashed_password.copy_from_slice(&decoded);
                auth.auth_type = AuthType::Password;
                Ok(auth)
            }
            AuthConfig::Certificate {
                cert_file,
                key_file,
            } => {
                let cert_data = std::fs::read(cert_file)
                    .with_context(|| format!("Failed to read certificate file: {cert_file}"))?;
                let key_data = std::fs::read(key_file)
                    .with_context(|| format!("Failed to read key file: {key_file}"))?;
                ClientAuth::new_certificate(&self.config.username, cert_data, key_data)
                    .context("Failed to create certificate authentication")
            }
            AuthConfig::SecureDevice {
                cert_name,
                key_name,
            } => ClientAuth::new_secure_device(&self.config.username, cert_name, key_name)
                .context("Failed to create secure device authentication"),
        }
    }

    pub(crate) fn create_client_option(&self) -> Result<ClientOption> {
        let mut option =
            ClientOption::new(&self.config.host, self.config.port, &self.config.hub_name)?
                .with_compression(false)
                .with_udp_acceleration(self.config.connection.udp_acceleration)
                .with_max_connections(self.config.connection.max_connections);
        if self.config.connection.half_connection {
            option.half_connection = true;
        }
        if let Some(proxy) = &self.config.connection.proxy {
            option = option.with_http_proxy(
                &proxy.host,
                proxy.port,
                proxy.username.as_deref(),
                proxy.password.as_deref(),
            )?;
        }
        option.generate_host_unique_key()?;
        Ok(option)
    }

    pub(crate) async fn perform_authentication(
        &mut self,
        connection: &mut SecureConnection,
        client_auth: &ClientAuth,
        client_option: &ClientOption,
    ) -> Result<Option<(String, u16)>> {
        let _hello_pack = connection.initial_hello()?;
        let (server_ver, server_build) = connection.server_version();
        if server_ver > 0 && server_build > 0 {
            info!(
                "Server version: {}.{:?}",
                server_ver as f64 / 100.0,
                server_build
            );
            info!(
                "[DEBUG] server_version version={:.2} build={}",
                server_ver as f64 / 100.0,
                server_build
            );
        }

        let secure_pwd: Option<[u8; 20]> = if matches!(client_auth.auth_type, AuthType::Password) {
            if let Some(sr) = connection.server_random() {
                let mut hashed = [0u8; 20];
                hashed.copy_from_slice(&client_auth.hashed_password);
                let sp = secure_password(hashed, sr);
                let mut out = [0u8; 20];
                out.copy_from_slice(&sp);
                Some(out)
            } else {
                None
            }
        } else {
            None
        };

        info!(
            "[DEBUG] auth_start username={} hub={}",
            client_auth.username, self.config.hub_name
        );

        // Build auth pack
        let mut auth_pack = if matches!(client_auth.auth_type, AuthType::Password) {
            use cedar::constants::CEDAR_SIGNATURE_STR;
            let mut p = mayaqua::Pack::new();
            p.add_str("method", "login")?;
            p.add_int("version", cedar::SOFTETHER_VER)?;
            p.add_int("build", cedar::SOFTETHER_BUILD)?;
            p.add_str("client_str", CLIENT_STRING)?;
            p.add_str("hubname", &client_option.hubname)?;
            p.add_str("username", &client_auth.username)?;
            p.add_str("protocol", CEDAR_SIGNATURE_STR)?;
            p.add_int("max_connection", client_option.max_connection)?;
            p.add_int("use_encrypt", client_option.use_encrypt as u32)?;
            p.add_int("use_compress", 0)?;
            p.add_int("half_connection", client_option.half_connection as u32)?;
            p.add_int("authtype", 1)?;
            if let Some(sp) = secure_pwd.as_ref() {
                p.add_data("secure_password", sp.to_vec())?;
            }
            let cid = self.config.connection.client_id.unwrap_or(123);
            p.add_int("client_id", cid)?;
            let mut unique = [0u8; 20];
            rand::rng().fill_bytes(&mut unique);
            p.add_data("unique_id", unique.to_vec())?;
            p
        } else if matches!(client_auth.auth_type, AuthType::Ticket) {
            use cedar::constants::CEDAR_SIGNATURE_STR;
            let mut p = mayaqua::Pack::new();
            p.add_str("method", "login")?;
            p.add_int("version", cedar::SOFTETHER_VER)?;
            p.add_int("build", cedar::SOFTETHER_BUILD)?;
            p.add_str("client_str", CLIENT_STRING)?;
            p.add_str("hubname", &client_option.hubname)?;
            p.add_str("username", &client_auth.username)?;
            p.add_str("protocol", CEDAR_SIGNATURE_STR)?;
            p.add_int("max_connection", client_option.max_connection)?;
            p.add_int("use_encrypt", client_option.use_encrypt as u32)?;
            p.add_int("use_compress", 0)?;
            p.add_int("half_connection", client_option.half_connection as u32)?;
            p.add_int("authtype", 99)?;
            p.add_data("ticket", client_auth.hashed_password.to_vec())?;
            let cid = self.config.connection.client_id.unwrap_or(123);
            p.add_int("client_id", cid)?;
            let mut unique = [0u8; 20];
            rand::rng().fill_bytes(&mut unique);
            p.add_data("unique_id", unique.to_vec())?;
            p
        } else {
            cedar::handshake::build_login_pack(client_option, client_auth)
                .context("Failed to build cedar login pack")?
        };

        // Environment info
        let os_name = std::env::consts::OS;
        let os_ver = std::env::var("RUST_OS_VERSION").unwrap_or_default();
        let hostname =
            std::env::var("HOSTNAME").unwrap_or_else(|_| crate::vpnclient::local_hostname());
        let product_name = CLIENT_STRING;
        let product_ver = CLIENT_VERSION;
        let product_build = CLIENT_BUILD;
        let _ = auth_pack.add_str("client_os_name", os_name);
        if !os_ver.is_empty() {
            let _ = auth_pack.add_str("client_os_ver", &os_ver);
        }
        let _ = auth_pack.add_str("client_hostname", &hostname);
        let _ = auth_pack.add_str("client_product_name", product_name);
        let _ = auth_pack.add_int("client_product_ver", product_ver);
        let _ = auth_pack.add_int("client_product_build", product_build);
        let _ = auth_pack.add_str("ClientOsName", os_name);
        if !os_ver.is_empty() {
            let _ = auth_pack.add_str("ClientOsVer", &os_ver);
        }
        let _ = auth_pack.add_str("ClientHostname", &hostname);
        let _ = auth_pack.add_str("ClientProductName", product_name);
        let _ = auth_pack.add_int("ClientProductVer", product_ver);
        let _ = auth_pack.add_int("ClientProductBuild", product_build);
        let _ = auth_pack.add_str("branded_ctos", "");
        if let Some(conn) = &self.connection {
            if let Some(addr) = conn.local_addr() {
                let _ = auth_pack.add_str("client_ip", &addr.ip().to_string());
            }
        }
        debug!(
            "auth_pack_redacted: {}",
            mayaqua::logging::redact_pack(&auth_pack)
        );

        let welcome_pack = connection.upload_auth(auth_pack)?;

        // pencore
        if let Ok(pencore_bytes) = welcome_pack
            .get_data("pencore")
            .or_else(|_| welcome_pack.get_data("PenCore"))
        {
            match connection.handle_pencore(pencore_bytes) {
                Ok(()) => debug!("Validated pencore blob ({} bytes)", pencore_bytes.len()),
                Err(e) => warn!(
                    "Ignoring invalid pencore blob ({} bytes): {}",
                    pencore_bytes.len(),
                    e
                ),
            }
        }

        // Redirects
        if let Ok(redirect_host) = welcome_pack
            .get_str("RedirectHost")
            .or_else(|_| welcome_pack.get_str("redirect_host"))
        {
            let redirect_port = welcome_pack
                .get_int("RedirectPort")
                .or_else(|_| welcome_pack.get_int("redirect_port"))
                .unwrap_or(self.config.port as u32) as u16;
            self.capture_redirect_ticket(&welcome_pack);
            warn!(
                "Server requested redirection to {}:{} (host field)",
                redirect_host, redirect_port
            );
            return Ok(Some((redirect_host.to_string(), redirect_port)));
        }
        let do_redirect = welcome_pack
            .get_int("Redirect")
            .or_else(|_| welcome_pack.get_int("redirect"))
            .unwrap_or(0);
        if do_redirect != 0 {
            let ip = welcome_pack
                .get_str("Ip")
                .or_else(|_| welcome_pack.get_str("ip"))
                .unwrap_or("");
            let port = welcome_pack
                .get_int("Port")
                .or_else(|_| welcome_pack.get_int("port"))
                .unwrap_or(self.config.port as u32) as u16;
            if !ip.is_empty() {
                self.capture_redirect_ticket(&welcome_pack);
                info!("[INFO] redirect new_host={} new_port={}", ip, port);
                return Ok(Some((ip.to_string(), port)));
            }
        }
        if let Ok(rflag) = welcome_pack.get_int("Redirect") {
            if rflag == 1 {
                if let Ok(ip_raw) = welcome_pack.get_int("Ip") {
                    let octets = ip_raw.to_le_bytes();
                    let ipv4 = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                    let port = welcome_pack
                        .get_int("Port")
                        .unwrap_or(self.config.port as u32) as u16;
                    
                    // Check if server sent a ticket
                    let has_ticket = welcome_pack.get_data("Ticket")
                        .or_else(|_| welcome_pack.get_data("ticket"))
                        .is_ok();
                    debug!("🔍 Redirect packet analysis: has_ticket={}, capturing anyway", has_ticket);
                    
                    self.capture_redirect_ticket(&welcome_pack);
                    warn!(
                        "Server requested redirection to {}:{} (cluster)",
                        ipv4, port
                    );
                    
                    // CRITICAL: Send empty pack acknowledgment before disconnecting (matches C code)
                    // C code: p = NewPack(); HttpClientSend(s, p); FreePack(p);
                    let ack_pack = mayaqua::Pack::new();
                    if let Err(e) = connection.upload_auth(ack_pack) {
                        debug!("Failed to send redirect ack (non-fatal): {}", e);
                    }
                    
                    return Ok(Some((ipv4.to_string(), port)));
                }
            }
        }

        // Session info lines - capture server-assigned session name
        let server_session_name = welcome_pack
            .get_str("SessionName")
            .or_else(|_| welcome_pack.get_str("session_name"))
            .ok()
            .map(|s| s.to_string());
        
        if let Some(ref session_name) = server_session_name {
            info!("[INFO] session_established session_name={}", session_name);
            // Store it for use by the session
            self.server_session_name = Some(session_name.clone());
        }
        if let Ok(cn) = welcome_pack
            .get_str("ConnectionName")
            .or_else(|_| welcome_pack.get_str("connection_name"))
        {
            info!("[INFO] session_established connection_name={}", cn);
        }

        // network settings
        let ns = self.parse_network_settings(&welcome_pack);
        if let Some(ref ns_inner) = ns {
            if let Some(ip) = ns_inner.assigned_ipv4 {
                if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                    info!("[INFO] ip_assigned ip={}", ip);
                } else {
                    debug!("ip_assigned ip={}", ip);
                }
            }
            if let (Some(ip), Some(mask)) = (ns_inner.assigned_ipv4, ns_inner.subnet_mask) {
                let bits = crate::types::mask_to_prefix(mask);
                if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                    info!("[INFO] ip_assigned ip={} cidr={}", ip, bits);
                } else {
                    debug!("ip_assigned ip={} cidr={}", ip, bits);
                }
            }
            if let Some(gw) = ns_inner.gateway {
                if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                    info!("[INFO] router ip={}", gw);
                } else {
                    debug!("router ip={}", gw);
                }
            }
            for d in &ns_inner.dns_servers {
                if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                    info!("[INFO] dns server={}", d);
                } else {
                    debug!("dns server={}", d);
                }
            }
        }
        self.network_settings = ns;
        self.emit_settings_snapshot();
        if let Some(ref ns_inner) = self.network_settings {
            self.server_policy_max_connections =
                super::policy::extract_policy_max_connections(ns_inner);
        }
        if let Ok(m) = welcome_pack
            .get_int("max_connection")
            .or_else(|_| welcome_pack.get_int("MaxConnection"))
        {
            self.server_negotiated_max_connections = Some(m);
        }
        if let Some(neg) = self.server_negotiated_max_connections {
            info!("[INFO] server_policy max_connections={}", neg);
            info!("Max number of connections: {}", neg);
        }
        if let Ok(tmo_ms) = welcome_pack
            .get_int("timeout")
            .or_else(|_| welcome_pack.get_int("Timeout"))
        {
            let secs = (tmo_ms as f64) / 1000.0;
            if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                info!("Timeout: {:.1} seconds", secs);
            } else {
                debug!("Timeout: {:.1} seconds", secs);
            }
        }
        if let Ok(hc) = welcome_pack
            .get_int("half_connection")
            .or_else(|_| welcome_pack.get_int("HalfConnection"))
        {
            if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                info!("Half-connection: {}", hc);
            } else {
                debug!("Half-connection: {}", hc);
            }
        }
        if let Ok(hn) = welcome_pack
            .get_str("ServerHostname")
            .or_else(|_| welcome_pack.get_str("server_hostname"))
        {
            if !hn.is_empty() {
                self.sni_host = Some(hn.to_string());
            }
        }
        if let Ok(sk) = welcome_pack
            .get_data("session_key")
            .or_else(|_| welcome_pack.get_data("SessionKey"))
        {
            if sk.len() == 20 {
                let mut key = [0u8; 20];
                key.copy_from_slice(sk);
                self.server_session_key = Some(key);
                let preview = key
                    .iter()
                    .take(8)
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                debug!(
                    "Captured session_key for additional connections (first16hex={})",
                    preview
                );
                info!("[INFO] session_key preview={}… (len=20)", preview);
                if std::env::var("RUST_PRINT_SESSION_KEY").ok().as_deref() == Some("1") {
                    let full = key.iter().map(|b| format!("{b:02x}")).collect::<String>();
                    info!("[DEBUG] session_key full={}", full);
                }
            } else {
                warn!(
                    "session_key length {} != 20, skipping additional-connect bonding",
                    sk.len()
                );
            }
        } else {
            debug!("No session_key present in welcome pack");
        }
        Ok(None)
    }

    pub(crate) fn capture_redirect_ticket(&mut self, pack: &mayaqua::Pack) {
        if let Ok(ticket) = pack.get_data("Ticket").or_else(|_| pack.get_data("ticket")) {
            if ticket.len() == 20 {
                let mut t = [0u8; 20];
                t.copy_from_slice(ticket);
                self.redirect_ticket = Some(t);
                info!("Captured redirect ticket for re-auth");
            }
        }
    }
}
