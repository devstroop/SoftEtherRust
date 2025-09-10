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
    /// Helper to build a password-based login pack mimicking Kotlin & C reference clients.
    /// Expects: already performed watermark/hello so `secure_pwd` (SecurePassword) computed from server random.
    pub(crate) fn build_password_login_pack(
        &self,
        client_auth: &cedar::ClientAuth,
        client_option: &cedar::ClientOption,
        secure_pwd: Option<&[u8;20]>,
        ticket: bool,
    ) -> anyhow::Result<mayaqua::Pack> {
        use cedar::constants::CEDAR_SIGNATURE_STR;
        let mut p = mayaqua::Pack::new();
        // Toggle for emitting duplicate CamelCase variants of fields (legacy / debugging)
        let dup = std::env::var("SE_DUPLICATE_LOGIN_FIELDS").ok().as_deref() == Some("1");
        // Canonical lowercase method (server StrCmpi) + fields
        p.add_str("method", "login")?;
        p.add_int("version", cedar::SOFTETHER_VER)?;
        p.add_int("build", cedar::SOFTETHER_BUILD)?;
        p.add_str("client_str", CLIENT_STRING)?;
        p.add_str("hubname", &client_option.hubname)?;
        p.add_str("username", &client_auth.username)?;
        p.add_str("protocol", CEDAR_SIGNATURE_STR)?;
        p.add_int("max_connection", client_option.max_connection)?;
        p.add_int("use_compress", client_option.use_compress as u32)?;
        p.add_int("half_connection", client_option.half_connection as u32)?;
        // Explicit encryption flag (always 1 over TLS) – send both snake and CamelCase variants
        p.add_int("use_encrypt", 1)?;
        if dup { p.add_int("UseEncrypt", 1).ok(); }
        // Secure password or ticket handling
        if ticket {
            // Ticket auth: server expects ticket data (20 bytes). Add both forms.
            p.add_int("authtype", 99)?;
            p.add_data("ticket", client_auth.hashed_password.to_vec())?;
            if dup { p.add_data("Ticket", client_auth.hashed_password.to_vec()).ok(); }
        } else {
            p.add_int("authtype", 1)?;
            if let Some(sp) = secure_pwd { p.add_data("secure_password", sp.to_vec())?; if dup { p.add_data("SecurePassword", sp.to_vec()).ok(); } }
        }
        // Client / product metadata (duplicate in CamelCase for compatibility)
        let cid = self.config.connection.client_id.unwrap_or_else(|| rand::rng().next_u32());
        p.add_int("client_id", cid)?; if dup { p.add_int("ClientId", cid).ok(); }
        let mut unique = [0u8; 20]; rand::rng().fill_bytes(&mut unique);
        p.add_data("unique_id", unique.to_vec())?; if dup { p.add_data("UniqueId", unique.to_vec()).ok(); }
        // Random PenCore blob (0..1000 bytes like Kotlin) – add only CamelCase; server tolerant
        let pen_size = (rand::rng().next_u32() as usize) % 1000;
        if pen_size > 0 { let mut pen = vec![0u8; pen_size]; rand::rng().fill_bytes(&mut pen); p.add_data("PenCore", pen).ok(); }
        // Duplicate commonly camel-cased fields expected by property packs (optional)
        if dup {
            p.add_str("HubName", &client_option.hubname).ok();
            p.add_str("UserName", &client_auth.username).ok();
            p.add_int("MaxConnection", client_option.max_connection).ok();
            p.add_int("UseCompress", client_option.use_compress as u32).ok();
            p.add_int("HalfConnection", client_option.half_connection as u32).ok();
        }
        // Placeholder UDP flags (align Kotlin when disabled). Only advertise disabled explicitly; future: gate by config.
        // If config enables UDP acceleration, emit full set of negotiation fields similar to Kotlin client.
    if self.config.connection.udp_acceleration {
            p.add_int("use_udp_acceleration", 1).ok();
            p.add_int("UseUdpAcceleration", 1).ok(); // camel for legacy if dup
            p.add_int("udp_acceleration_version", 2).ok();
            p.add_int("udp_acceleration_max_version", 2).ok();
            // Local UDP endpoint discovery (placeholder 0.0.0.0 if not yet bound)
            // Later we can integrate real socket bind from UdpAccelerator
            p.add_int("udp_acceleration_client_ip", 0).ok();
            p.add_int("udp_acceleration_client_port", 0).ok();
            p.add_int("udp_acceleration_support_fast_disconnect_detect", 1).ok();
            // Generate a v2 client key (32 bytes like ChaCha20-Poly1305 key) placeholder random
            let mut key_v2 = [0u8; 32]; rand::rng().fill_bytes(&mut key_v2);
            p.add_data("udp_acceleration_client_key_v2", key_v2.to_vec()).ok();
        } else {
            p.add_int("UseUdpAcceleration", 0)?; // keep previous explicit disabled flag
        }
        // Note: environment info appended afterwards in perform_authentication.
        Ok(p)
    }
    pub fn create_client_auth(&self) -> Result<ClientAuth> {
        if let Some(ticket) = self.redirect_ticket {
            return ClientAuth::new_ticket(&self.config.username, &ticket)
                .context("Failed to create ticket auth");
        }
        match &self.config.auth {
            AuthConfig::Anonymous => Ok(ClientAuth::new_anonymous()),
            AuthConfig::Password { hashed_password } => {
                let decoded = base64::prelude::BASE64_STANDARD
                    .decode(hashed_password)
                    .context("Failed to decode hashed password")?;
                if decoded.len() != 20 {
                    anyhow::bail!("Invalid password hash length");
                }
                // Initialize with empty password then inject hashed form
                let mut auth = ClientAuth::new_password(&self.config.username, "")?;
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
        let mut option = ClientOption::new(&self.config.host, self.config.port, &self.config.hub_name)?
            .with_compression(false)
            .with_udp_acceleration(self.config.connection.udp_acceleration)
            .with_nat_traversal(self.config.connection.nat_traversal)
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

        // Build auth pack (unified path for password & ticket); other auth types fallback to cedar builder then augmented for parity
        let mut auth_pack = if matches!(client_auth.auth_type, AuthType::Password) {
            self.build_password_login_pack(client_auth, client_option, secure_pwd.as_ref(), false)?
        } else if matches!(client_auth.auth_type, AuthType::Ticket) {
            self.build_password_login_pack(client_auth, client_option, None, true)?
        } else {
            let mut base = cedar::handshake::build_login_pack(client_option, client_auth)
                .context("Failed to build cedar login pack")?;
            // Parity augmentation (camel-case duplicates + UseEncrypt + PenCore)
            base.add_int("UseEncrypt", 1).ok();
            base.add_int("use_encrypt", 1).ok();
            let pen_size = (rand::rng().next_u32() as usize) % 1000;
            if pen_size > 0 { let mut pen = vec![0u8; pen_size]; rand::rng().fill_bytes(&mut pen); base.add_data("PenCore", pen).ok(); }
            base
        };

        // Environment info
        let os_name = std::env::consts::OS;
        let hostname = super::local_hostname();
        let product_name = CLIENT_STRING;
        let product_ver = CLIENT_VERSION;
        let product_build = CLIENT_BUILD;
        let _ = auth_pack.add_str("client_os_name", os_name);
        let _ = auth_pack.add_str("client_hostname", &hostname);
        let _ = auth_pack.add_str("client_product_name", product_name);
        let _ = auth_pack.add_int("client_product_ver", product_ver);
        let _ = auth_pack.add_int("client_product_build", product_build);
        let _ = auth_pack.add_str("ClientOsName", os_name);
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
                    self.capture_redirect_ticket(&welcome_pack);
                    warn!(
                        "Server requested redirection to {}:{} (cluster)",
                        ipv4, port
                    );
                    return Ok(Some((ipv4.to_string(), port)));
                }
            }
        }

        // Session info lines
        if let Ok(session_name) = welcome_pack
            .get_str("SessionName")
            .or_else(|_| welcome_pack.get_str("session_name"))
        {
            info!("[INFO] session_established session_name={}", session_name);
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
        // Emit a compact policy summary for diagnostics (e.g., NoRouting, NoBroadcast)
        if let Some(ns) = &self.network_settings {
            if !ns.policies.is_empty() {
                let mut flags: Vec<String> = Vec::new();
                for (k, v) in &ns.policies {
                    let kk = k.to_ascii_lowercase();
                    if kk.contains("norouting") || kk.contains("nobroadcast") || kk.contains("nodhcp") {
                        flags.push(format!("{}={}", k, v));
                    }
                }
                if !flags.is_empty() {
                    self.emit_event(super::types::EventLevel::Info, 1201, format!("policy: {}", flags.join(" ")));
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use crate::shared_config::{ClientConfig as SharedConfig, IpVersionPreference};

    #[test]
    fn test_unified_login_pack_contains_canonical_fields() {
        let hashed = [0x11u8;20];
        let b64 = base64::engine::general_purpose::STANDARD.encode(&hashed);
        let cfg = SharedConfig { server:"example.com".into(), port:443, hub:"DEFAULT".into(), username:"user1".into(), password:None, password_hash:Some(b64), skip_tls_verify:true, use_compress:false, max_connections:1, nat_traversal:None, udp_acceleration:None, static_ip:None, ip_version:IpVersionPreference::Auto, require_static_ip:false };
        let client = VpnClient::from_shared_config(cfg).expect("client create");
        let auth = client.create_client_auth().expect("auth");
        let opt = client.create_client_option().expect("opt");
        let fake = [0x22u8;20];
        let pack = client.build_password_login_pack(&auth, &opt, Some(&fake), false).expect("pack");
        assert_eq!(pack.get_str("method").unwrap().to_ascii_lowercase(), "login");
        assert!(pack.get_data("SecurePassword").is_ok() || pack.get_data("secure_password").is_ok());
        assert!(pack.get_int("UseEncrypt").is_ok() || pack.get_int("use_encrypt").is_ok());
    }
}
