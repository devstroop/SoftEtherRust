use anyhow::Result;
use std::net::Ipv4Addr;
use tracing::{info, warn};

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
// Removed legacy macOS DHCP helper utilities (now unused after unified in-tunnel DHCP)

impl VpnClient {
    /// Apply parsed network settings to a platform virtual adapter (macOS / Linux only for now)
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

        let ns = match &self.network_settings {
            Some(n) => n.clone(),
            None => {
                return Ok(());
            }
        };

        let no_routing = ns
            .policies
            .iter()
            .any(|(k, v)| k.to_ascii_lowercase().contains("norouting") && *v != 0);

    // Adapter creation removed (using tun-rs directly in future work)

        let ip = match ns.assigned_ipv4 {
            Some(i) => i,
            None => {
                return Ok(());
            }
        };

        let mask = ns
            .subnet_mask
            .unwrap_or_else(|| Ipv4Addr::new(255, 255, 255, 255));

        if no_routing {
            info!("Server policy 'NoRouting' detected; skipping default route changes");
            info!("[INFO] network_settings_applying (passive)");
        } else {
            info!("[INFO] network_settings_applying");
        }

        // Configure IP on the created TUN interface (best-effort, platform specific)
        #[cfg(target_os = "linux")]
        if let Some(_tun) = self.tun.as_ref() {
            use tokio::process::Command;
            let ifname = &self.config.client.interface_name;
            // ip addr add <ip>/<cidr> dev <ifname>
            let _ = Command::new("ip")
                .arg("addr")
                .arg("add")
                .arg(format!("{}/{}", ip, mask_to_prefix(mask)))
                .arg("dev")
                .arg(ifname)
                .output()
                .await;
            let _ = Command::new("ip")
                .arg("link")
                .arg("set")
                .arg(ifname)
                .arg("up")
                .output()
                .await;
        }
        #[cfg(target_os = "macos")]
        if let Some(_tun) = self.tun.as_ref() {
            use tokio::process::Command;
            let ifname = &self.config.client.interface_name;
            // ifconfig <ifname> inet <ip> <mask> up
            let _ = Command::new("ifconfig")
                .arg(ifname)
                .arg("inet")
                .arg(ip.to_string())
                .arg(mask.to_string())
                .arg("up")
                .output()
                .await;
        }

        let cidr = mask_to_prefix(mask);
    info!("Assigned interface IP {}/{}", ip, cidr);

        if !no_routing {
            if let Some(gw) = ns.gateway {
                info!("Add IPv4 default route");
                #[cfg(target_os = "linux")]
                if let Some(_tun) = self.tun.as_ref() {
                    use tokio::process::Command;
                    let _ = Command::new("ip")
                        .arg("route")
                        .arg("add")
                        .arg("default")
                        .arg("via")
                        .arg(gw.to_string())
                        .output()
                        .await;
                }
                #[cfg(target_os = "macos")]
                if let Some(_tun) = self.tun.as_ref() {
                    use tokio::process::Command;
                    // On macOS adding a default route may require sudo; attempt silently
                    let _ = Command::new("route")
                        .arg("add")
                        .arg("default")
                        .arg(gw.to_string())
                        .output()
                        .await;
                }
            }
        }

        let net = std::net::Ipv4Addr::from(u32::from(ip) & u32::from(mask));
        info!("Include route: {}/{}", net, cidr);

        #[cfg(target_os = "macos")]
        {
            use tokio::process::Command;
            let _ = Command::new("ifconfig")
                .arg(self.config.client.interface_name.clone())
                .arg("mtu")
                .arg("1500")
                .output()
                .await;
        }
        #[cfg(target_os = "linux")]
        {
            use tokio::process::Command;
            let _ = Command::new("ip")
                .arg("link")
                .arg("set")
                .arg("dev")
                .arg(self.config.client.interface_name.clone())
                .arg("mtu")
                .arg("1500")
                .output()
                .await;
        }
        info!("MTU set to 1500");
        info!("[INFO] connected");

        // Emit a server-provided interface snapshot if DHCP not in use
        if !(self.config.client.enable_in_tunnel_dhcp && self.dhcp_xid.is_some()) {
            self.emit_server_interface_snapshot();
        }

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
                        if !out.status.success() {
                            warn!(
                                "Failed to apply macOS DNS: {}",
                                String::from_utf8_lossy(&out.stderr)
                            );
                        } else {
                            info!("Applied DNS servers to service '{}'", svc);
                        }
                    } else {
                        info!("(macOS) DNS servers suggested: {} (manual apply with: networksetup -setdnsservers <ServiceName> <servers> )", ns.dns_servers.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", "));
                    }
                } else {
                    info!("(macOS) DNS servers suggested: {} (manual apply with: networksetup -setdnsservers <ServiceName> <servers> )", ns.dns_servers.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", "));
                }
            }
        }

    // macOS interface monitoring skipped (adapter removed)

        Ok(())
    }
}
