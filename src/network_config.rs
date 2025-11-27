use anyhow::Result;
use std::net::Ipv4Addr;
use tracing::{debug, info, warn};

use crate::types::{mask_to_prefix, NetworkSettings};
// use crate::types::network_settings_from_lease; // DHCP lease reflection handled elsewhere
use mayaqua::Pack;

use super::VpnClient;

impl VpnClient {
    /// Parse network settings and policy values from the welcome/auth response pack.
    pub(super) fn parse_network_settings(&self, pack: &Pack) -> Option<NetworkSettings> {
        let mut ns = NetworkSettings::default();

        // Assigned IPv4 address
        if let Ok(ip_raw) = pack
            .get_int("ClientIpAddress")
            .or_else(|_| pack.get_int("client_ip_address"))
        {
            let octets = ip_raw.to_le_bytes();
            ns.assigned_ipv4 = Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
        }

        // Subnet mask
        if let Ok(mask_raw) = pack
            .get_int("ClientIpSubnetMask")
            .or_else(|_| pack.get_int("ClientSubnetMask"))
        {
            let o = mask_raw.to_le_bytes();
            ns.subnet_mask = Some(Ipv4Addr::new(o[0], o[1], o[2], o[3]));
        }

        // Gateway
        if let Ok(gw_raw) = pack
            .get_int("ClientGatewayAddress")
            .or_else(|_| pack.get_int("ClientGateway"))
        {
            let o = gw_raw.to_le_bytes();
            ns.gateway = Some(Ipv4Addr::new(o[0], o[1], o[2], o[3]));
        }

        // DNS servers
        for key in [
            "DnsServerAddress",
            "DnsServerAddress2",
            "DnsServer1",
            "DnsServer2",
        ] {
            if let Ok(dns_raw) = pack.get_int(key) {
                let o = dns_raw.to_le_bytes();
                ns.dns_servers.push(Ipv4Addr::new(o[0], o[1], o[2], o[3]));
            }
        }

        // Collect multi-port list if present (element name 'port')
        for el in &pack.elements {
            if el.name.eq_ignore_ascii_case("port") {
                for v in &el.values {
                    let p = v.int_value as u16;
                    if p != 0 {
                        ns.ports.push(p);
                    }
                }
            }
        }

        // Policies: elements named "policy:*" with int values
        for el in &pack.elements {
            if el.name.starts_with("policy:") && el.value_type == mayaqua::pack::ValueType::Int {
                if let Some(first) = el.values.first() {
                    ns.policies.push((el.name.clone(), first.int_value));
                }
            }
        }

        if ns.assigned_ipv4.is_none() && ns.dns_servers.is_empty() && ns.policies.is_empty() {
            return None;
        }
        Some(ns)
    }
}

// Platform-specific helpers and apply logic
#[cfg(target_os = "linux")]
mod linux {
    use anyhow::Result;
    use tokio::process::Command;
    use tracing::{info, warn};

    pub(super) async fn apply_dns(servers: &[std::net::Ipv4Addr]) -> Result<()> {
        let content = servers
            .iter()
            .map(|d| format!("nameserver {}\n", d))
            .collect::<String>();
        let output = Command::new("bash")
            .arg("-c")
            .arg(format!(
                "printf '{}' | sudo tee /etc/resolv.conf > /dev/null",
                content.replace("'", "'\\''")
            ))
            .output()
            .await?;
        if !output.status.success() {
            warn!(
                "Failed to apply DNS to /etc/resolv.conf: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        } else {
            info!("Applied DNS servers to /etc/resolv.conf");
        }
        Ok(())
    }
}
#[cfg(target_os = "macos")]
mod macos {
    // use super::*;
    use tokio::process::Command;
    use tracing::{info, warn};

    #[derive(Clone)]
    pub(super) struct IfaceInfo {
        pub ip: String,
        pub subnet_mask: String,
        pub router: String,
    }

    pub(super) async fn monitor_darwin_interfaces(names: &[String]) {
        info!("Monitoring DHCP on interfaces: {}", names.join(","));
        use tokio::time::{sleep, Duration, Instant};
        let cleaned: Vec<String> = names.iter().filter(|n| !n.is_empty()).cloned().collect();
        if cleaned.is_empty() {
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut printed_ip = false;
        let mut printed_router = false;
        while Instant::now() < deadline {
            sleep(Duration::from_millis(500)).await;
            for n in &cleaned {
                let v = quick_ipv4_info(n).await;
                if !v.ip.is_empty() && !v.ip.starts_with("169.254.") && !printed_ip {
                    let bits = mask_to_cidr(&v.subnet_mask);
                    if bits > 0 {
                        info!("IP Address {}/{}", v.ip, bits);
                    } else {
                        info!("IP Address {}", v.ip);
                    }
                    printed_ip = true;
                }
                if !v.router.is_empty() && !printed_router {
                    info!("Router {}", v.router);
                    printed_router = true;
                }
            }
        }
        if printed_ip {
            info!("Connected");
        }
    }

    pub(super) async fn invoke_dhcp_by_name(iface: &str) -> anyhow::Result<()> {
        info!("Invoking DHCP on {}", iface);
        let output = Command::new("ipconfig")
            .arg("set")
            .arg(iface)
            .arg("dhcp")
            .output()
            .await?;
        if output.status.success() {
            info!("DHCP invocation succeeded on {}", iface);
        } else {
            warn!(
                "DHCP invocation failed on {}: {}",
                iface,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    pub(super) async fn kick_dhcp_until_ip(iface: &str, timeout: std::time::Duration) {
        info!("Starting DHCP kick on {}", iface);
        use tokio::time::{sleep, Duration, Instant};
        let deadline = Instant::now() + timeout;
        let mut last_kick = Instant::now();
        let kick_interval = Duration::from_secs(5);
        let mut attempts: u32 = 0;
        let max_attempts: u32 = 6; // ~30s of kicks total
                                   // initial kick
        let _ = invoke_dhcp_by_name(iface).await;
        while Instant::now() < deadline {
            sleep(Duration::from_millis(500)).await;
            let v = quick_ipv4_info(iface).await;
            if !v.ip.is_empty() && !v.ip.starts_with("169.254.") {
                return;
            }
            if attempts < max_attempts
                && Instant::now().saturating_duration_since(last_kick) >= kick_interval
            {
                let _ = invoke_dhcp_by_name(iface).await;
                last_kick = Instant::now();
                attempts = attempts.saturating_add(1);
            }
            if attempts >= max_attempts {
                break;
            }
        }
    }

    pub(super) async fn quick_ipv4_info(iface: &str) -> IfaceInfo {
        let mut info = IfaceInfo {
            ip: String::new(),
            subnet_mask: String::new(),
            router: String::new(),
        };
        if let Ok(out) = Command::new("ipconfig")
            .arg("getifaddr")
            .arg(iface)
            .output()
            .await
        {
            if out.status.success() {
                info.ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
            }
        }
        if info.ip.is_empty() {
            if let Ok(out) = Command::new("ifconfig").arg(iface).output().await {
                if out.status.success() {
                    let s = String::from_utf8_lossy(&out.stdout);
                    for line in s.lines() {
                        let l = line.trim();
                        if l.starts_with("inet ") {
                            let parts: Vec<&str> = l.split_whitespace().collect();
                            if parts.len() >= 2 {
                                info.ip = parts[1].to_string();
                            }
                            if let Some(idx) = parts.iter().position(|p| *p == "netmask") {
                                if let Some(hexmask) = parts.get(idx + 1) {
                                    if hexmask.starts_with("0x") && hexmask.len() == 10 {
                                        if let Ok(v) = u32::from_str_radix(&hexmask[2..], 16) {
                                            let b = v.to_be_bytes();
                                            info.subnet_mask =
                                                format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Ok(out) = Command::new("ipconfig")
            .arg("getoption")
            .arg(iface)
            .arg("subnet_mask")
            .output()
            .await
        {
            if out.status.success() {
                info.subnet_mask = String::from_utf8_lossy(&out.stdout).trim().to_string();
            }
        }
        if let Ok(out) = Command::new("ipconfig")
            .arg("getoption")
            .arg(iface)
            .arg("router")
            .output()
            .await
        {
            if out.status.success() {
                info.router = String::from_utf8_lossy(&out.stdout).trim().to_string();
            }
        }
        info
    }

    pub(super) fn mask_to_cidr(mask: &str) -> i32 {
        if mask.is_empty() {
            return 0;
        }
        let parts: Vec<&str> = mask.split('.').collect();
        if parts.len() != 4 {
            return 0;
        }
        let mut bytes = [0u8; 4];
        for (i, p) in parts.iter().enumerate() {
            if let Ok(n) = p.parse::<u8>() {
                bytes[i] = n;
            } else {
                return 0;
            }
        }
        let ones: u32 = std::net::Ipv4Addr::from(bytes)
            .octets()
            .into_iter()
            .map(|b| b.count_ones())
            .sum();
        ones as i32
    }
}

// Re-export helper for external callers (vpnclient.rs) without exposing the private macOS module
#[cfg(target_os = "macos")]
pub(crate) async fn kick_dhcp_until_ip(iface: &str, timeout: std::time::Duration) {
    macos::kick_dhcp_until_ip(iface, timeout).await
}

impl VpnClient {
    /// Apply parsed network settings to a platform virtual adapter
    ///
    /// This method configures the virtual network interface with IP address, routes, DNS servers,
    /// and other network settings received from the VPN server or obtained via DHCP.
    ///
    /// Process Flow:
    ///   1. Check for server-provided network settings
    ///   2. Create virtual adapter if needed
    ///   3. Apply IP address and subnet mask
    ///   4. Configure default routes (unless NoRouting policy)
    ///   5. Set DNS servers
    ///   6. Configure MTU and start monitoring
    ///
    /// Platform Support:
    ///   - macOS: Uses networksetup for DNS, ifconfig for MTU
    ///   - Linux: Uses ip command for network configuration
    ///   - Other platforms: Skipped
    ///
    /// Policies:
    ///   - Respects 'NoRouting' policy to avoid default route changes
    ///   - Applies DNS settings based on configuration
    ///
    /// DHCP Fallback:
    ///   - Spawns system DHCP when no server IP provided
    ///   - Monitors interface for IP acquisition
    ///
    /// Returns:
    ///   - Result<()>: Success or error during network configuration
    pub(super) async fn apply_network_settings(&mut self) -> Result<()> {
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            let euid = unsafe { libc::geteuid() };
            if euid != 0 {
                warn!("Insufficient privileges to create utun (need root). Run with sudo.");
            }
        }

        debug!(
            "Applying network settings, ns is_some: {}",
            self.network_settings.is_some()
        );
        debug!(
            "bridge_ready: {}, dhcp_spawned: {}",
            self.bridge_ready, self.dhcp_spawned
        );

        let ns = match &self.network_settings {
            Some(n) => n.clone(),
            None => {
                #[cfg(feature = "adapter")]
                {
                    if self.adapter.is_none() && !self.bridge_ready {
                        // Only create adapter if bridge hasn't already created one
                        let name = self.config.client.interface_name.clone();
                        let mac = self.generate_adapter_mac(&name);
                        let mac_str = format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                        );
                        self.adapter = Some(adapter::VirtualAdapter::new(name, Some(mac_str)));
                        if let Some(adp) = &mut self.adapter {
                            adp.create().await?;
                        }
                    }
                }
                #[cfg(all(target_os = "macos", feature = "adapter"))]
                {
                    if self.bridge_ready && !self.dhcp_spawned {
                        debug!("Spawning DHCP tasks for no ns case");
                        if let Some(adp) = &self.adapter {
                            let ifname = adp.name().to_string();
                            let ifname2 = ifname.clone();
                            let h1 = tokio::spawn(async move {
                                super::network_config::macos::kick_dhcp_until_ip(
                                    &ifname,
                                    std::time::Duration::from_secs(25),
                                )
                                .await;
                            });
                            let h2 = tokio::spawn(async move {
                                super::network_config::macos::monitor_darwin_interfaces(&[ifname2])
                                    .await;
                            });
                            self.aux_tasks.push(h1);
                            self.aux_tasks.push(h2);
                            self.dhcp_spawned = true;
                        }
                    }
                }
                return Ok(());
            }
        };

        let no_routing = ns
            .policies
            .iter()
            .any(|(k, v)| k.to_ascii_lowercase().contains("norouting") && *v != 0);

        #[cfg(feature = "adapter")]
        if self.adapter.is_none() && !self.bridge_ready {
            // Only create adapter if bridge hasn't already created one
            // (bridge takes ownership and moves it into Arc<Mutex<>>)
            let name = self.config.client.interface_name.clone();
            self.adapter = Some(adapter::VirtualAdapter::new(name, None));
            if let Some(adp) = &mut self.adapter {
                adp.create().await?;
            }
        }
        #[cfg(feature = "adapter")]
        let adapter = if self.bridge_ready {
            // If bridge is active, it owns the adapter - skip adapter-based config
            debug!("Bridge owns adapter, skipping adapter-based network config");
            return Ok(());
        } else {
            self.adapter.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Adapter not initialized"))?
        };

        let ip = match ns.assigned_ipv4 {
            Some(i) => i,
            None => {
                #[cfg(all(target_os = "macos", feature = "adapter"))]
                {
                    if self.bridge_ready && !self.dhcp_spawned {
                        debug!("Spawning DHCP tasks for has ns but no ip case");
                        let ifname = adapter.name().to_string();
                        let ifname2 = ifname.clone();
                        let h1 = tokio::spawn(async move {
                            super::network_config::macos::kick_dhcp_until_ip(
                                &ifname,
                                std::time::Duration::from_secs(25),
                            )
                            .await;
                        });
                        let h2 = tokio::spawn(async move {
                            super::network_config::macos::monitor_darwin_interfaces(&[ifname2])
                                .await;
                        });
                        self.aux_tasks.push(h1);
                        self.aux_tasks.push(h2);
                        self.dhcp_spawned = true;
                    }
                }
                return Ok(());
            }
        };

        let mask = ns
            .subnet_mask
            .unwrap_or_else(|| Ipv4Addr::new(255, 255, 255, 255));

        if no_routing {
            debug!("Server policy 'NoRouting' detected; skipping default route changes");
            debug!("[DEBUG] network_settings_applying (passive)");
        } else {
            info!("[INFO] network_settings_applying");
        }

        #[cfg(feature = "adapter")]
        adapter
            .set_ip_address(&ip.to_string(), &mask.to_string())
            .await?;

        let cidr = mask_to_prefix(mask);
        #[cfg(feature = "adapter")]
        debug!("Interface {}: {}/{}", adapter.name(), ip, cidr);

        if !no_routing {
            if let Some(gw) = ns.gateway {
                #[cfg(feature = "adapter")]
                let _ = adapter
                    .add_route("0.0.0.0/0", &gw.to_string())
                    .await
                    .map_err(|e| {
                        warn!("Failed to add default route: {}", e);
                        e
                    });
                debug!("Add IPv4 default route");
            }
        }

        let net = std::net::Ipv4Addr::from(u32::from(ip) & u32::from(mask));
        debug!("Include route: {}/{}", net, cidr);

        #[cfg(target_os = "macos")]
        {
            use tokio::process::Command;
            #[cfg(feature = "adapter")]
            let _ = Command::new("ifconfig")
                .arg(adapter.name())
                .arg("mtu")
                .arg("1500")
                .output()
                .await;
        }
        #[cfg(target_os = "linux")]
        {
            use tokio::process::Command;
            #[cfg(feature = "adapter")]
            let _ = Command::new("ip")
                .arg("link")
                .arg("set")
                .arg("dev")
                .arg(adapter.name())
                .arg("mtu")
                .arg("1500")
                .output()
                .await;
        }
        debug!("MTU set to 1500");
        debug!("[DEBUG] connected");

        if !ns.dns_servers.is_empty() {
            #[cfg(target_os = "linux")]
            {
                if self.config.connection.apply_dns {
                    linux::apply_dns(&ns.dns_servers).await?;
                } else {
                    info!(
                        "(Linux) To apply DNS: echo -e 'nameserver {}' | sudo tee /etc/resolv.conf",
                        ns.dns_servers
                            .iter()
                            .map(|d| d.to_string())
                            .collect::<Vec<_>>()
                            .join("\\n")
                    );
                }
            }
            #[cfg(target_os = "macos")]
            {
                if self.config.connection.apply_dns {
                    use tokio::process::Command;
                    let mut service_name: Option<String> =
                        self.config.client.macos_dns_service_name.clone();
                    if service_name.is_none() {
                        // Parse: `networksetup -listnetworkserviceorder` to map devices -> services
                        // We choose the first service bound to a physical device (en*, bridge*, awdl* ignored)
                        let out = Command::new("networksetup")
                            .arg("-listnetworkserviceorder")
                            .output()
                            .await?;
                        if out.status.success() {
                            let s = String::from_utf8_lossy(&out.stdout);
                            let mut last_service: Option<String> = None;
                            for line in s.lines() {
                                let line = line.trim();
                                // Lines look like: "(1) Wi-Fi" or "(2) USB 10/100/1000 LAN"
                                if line.starts_with('(') {
                                    // Extract service name after ") "
                                    if let Some(pos) = line.find(") ") {
                                        let name = line[pos + 2..].trim();
                                        if !name.is_empty() {
                                            last_service = Some(name.to_string());
                                        }
                                    }
                                }
                                // Following line often contains: "Hardware Port: Wi-Fi, Device: en0"
                                if line.contains("Device:") {
                                    if let Some(dev_pos) = line.find("Device:") {
                                        let dev = line[dev_pos + 7..].trim();
                                        let dev = dev.trim_end_matches(')');
                                        let dev = dev.trim();
                                        if !dev.is_empty() {
                                            // Choose first reasonable device-backed service
                                            if dev.starts_with("en") || dev.starts_with("bridge") {
                                                if let Some(svc) = last_service.clone() {
                                                    service_name = Some(svc);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if let Some(svc) = service_name {
                        let args = ns
                            .dns_servers
                            .iter()
                            .map(|d| d.to_string())
                            .collect::<Vec<_>>()
                            .join(" ");
                        let cmd = format!(
                            "networksetup -setdnsservers '{}' {}",
                            svc.replace("'", "'\\''"),
                            args
                        );
                        let out = Command::new("bash").arg("-c").arg(&cmd).output().await?;
                        if out.status.success() {
                            debug!("Applied DNS servers to service '{}'", svc);
                        } else {
                            warn!(
                                "Failed to apply macOS DNS: {}",
                                String::from_utf8_lossy(&out.stderr)
                            );
                        }
                    } else {
                        debug!("(macOS) DNS servers suggested: {} (manual apply with: networksetup -setdnsservers <ServiceName> <servers> )", ns.dns_servers.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", "));
                    }
                } else {
                    debug!("(macOS) DNS servers suggested: {} (manual apply with: networksetup -setdnsservers <ServiceName> <servers> )", ns.dns_servers.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", "));
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            #[cfg(feature = "adapter")]
            {
                let ifname = adapter.name().to_string();
                let h = tokio::spawn(async move {
                    super::network_config::macos::monitor_darwin_interfaces(&[ifname]).await;
                });
                self.aux_tasks.push(h);
            }
        }

        Ok(())
    }
}
