use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr};
use tracing::{info, warn};

use crate::types::{mask_to_prefix, NetworkSettings};
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
            None => return Ok(()),
        };

        let no_routing = ns
            .policies
            .iter()
            .any(|(k, v)| k.to_ascii_lowercase().contains("norouting") && *v != 0);

        let ipv4 = ns.assigned_ipv4;
        let mask = ns
            .subnet_mask
            .unwrap_or_else(|| Ipv4Addr::new(255, 255, 255, 255));
        let ipv6 = ns.assigned_ipv6;
        let ipv6_prefix = ns.assigned_ipv6_prefix;

        if ipv4.is_none() && ipv6.is_none() {
            return Ok(());
        }

        if no_routing {
            info!("Server policy 'NoRouting' detected; skipping default route changes");
            info!("[INFO] network_settings_applying (passive)");
        } else {
            info!("[INFO] network_settings_applying");
        }

        // Idempotence signature
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        ipv4.hash(&mut hasher);
        mask.octets().hash(&mut hasher);
        ns.gateway.hash(&mut hasher);
        ipv6.hash(&mut hasher);
        ipv6_prefix.hash(&mut hasher);
        ns.ipv6_gateway.hash(&mut hasher);
        for d in &ns.dns_servers {
            d.hash(&mut hasher);
        }
        for d6 in &ns.dns_servers_v6 {
            d6.hash(&mut hasher);
        }
        hasher.write_u8(if no_routing { 1 } else { 0 });
        let desired_sig = hasher.finish();
        if let Some(prev) = self
            .applied_resources
            .as_ref()
            .and_then(|a| a.net_apply_sig)
        {
            if prev == desired_sig {
                info!("Network settings identical to last applied; skipping apply");
                return Ok(());
            }
        }
        if let Some(ref mut a) = self.applied_resources {
            a.net_apply_sig = Some(desired_sig);
        }

        // Resource tracker
        let mut applied: Option<crate::vpnclient::AppliedResources> = None;
        // Initialize tracker with current signature if an existing one isn't present
        if self.applied_resources.is_none() {
            applied = Some(crate::vpnclient::AppliedResources { interface_name: self.actual_interface_name.clone().unwrap_or_else(|| self.config.client.interface_name.clone()), net_apply_sig: Some(desired_sig), ..Default::default() });
        } else if let Some(a) = self.applied_resources.clone() { applied = Some(crate::vpnclient::AppliedResources { net_apply_sig: Some(desired_sig), ..a }); }

        // IPv4
        if let Some(ip) = ipv4 {
            #[cfg(target_os = "linux")]
            if self.actual_interface_name.is_some() || self.config.client.interface_name != "auto" {
                use tokio::process::Command;
                let ifname = &self.config.client.interface_name;
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
            if self.actual_interface_name.is_some() || self.config.client.interface_name != "auto" {
                use tokio::process::Command;
                let ifname = self
                    .actual_interface_name
                    .as_deref()
                    .unwrap_or(&self.config.client.interface_name);
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
            info!("Assigned interface IPv4 {}/{}", ip, cidr);
            let res = applied.get_or_insert_with(|| crate::vpnclient::AppliedResources {
                interface_name: self
                    .actual_interface_name
                    .clone()
                    .unwrap_or_else(|| self.config.client.interface_name.clone()),
                ..Default::default()
            });
            res.ipv4_addr = Some((ip, cidr as u8));
            if !no_routing {
                if let Some(gw) = ns.gateway {
                    // CRITICAL: Save original default gateway before changing it
                    use tokio::process::Command;
                    #[cfg(target_os = "linux")]
                    {
                        if let Ok(output) = Command::new("ip")
                            .arg("route")
                            .arg("show")
                            .arg("default")
                            .output()
                            .await
                        {
                            if let Ok(s) = String::from_utf8(output.stdout) {
                                // Parse: "default via 192.168.1.1 dev eth0"
                                if let Some(rest) = s.strip_prefix("default via ") {
                                    let parts: Vec<&str> = rest.split_whitespace().collect();
                                    if let Ok(orig_gw) = parts.get(0).unwrap_or(&"").parse::<Ipv4Addr>() {
                                        let orig_iface = parts.get(2).map(|s| s.to_string());
                                        if let Some(r) = applied.as_mut() {
                                            r.original_default_gateway = Some((orig_gw, orig_iface));
                                            info!("Saved original default gateway: {} via {:?}", orig_gw, r.original_default_gateway.as_ref().unwrap().1);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    #[cfg(target_os = "macos")]
                    {
                        if let Ok(output) = Command::new("route")
                            .arg("-n")
                            .arg("get")
                            .arg("default")
                            .output()
                            .await
                        {
                            if let Ok(s) = String::from_utf8(output.stdout) {
                                // Parse: "gateway: 192.168.1.1"
                                let mut orig_gw = None;
                                let mut orig_iface = None;
                                for line in s.lines() {
                                    if line.trim().starts_with("gateway:") {
                                        if let Some(gw_str) = line.split(':').nth(1) {
                                            if let Ok(gw) = gw_str.trim().parse::<Ipv4Addr>() {
                                                orig_gw = Some(gw);
                                            }
                                        }
                                    } else if line.trim().starts_with("interface:") {
                                        if let Some(iface) = line.split(':').nth(1) {
                                            orig_iface = Some(iface.trim().to_string());
                                        }
                                    }
                                }
                                if let (Some(gw), Some(r)) = (orig_gw, applied.as_mut()) {
                                    r.original_default_gateway = Some((gw, orig_iface.clone()));
                                    info!("Saved original default gateway: {} via {:?}", gw, orig_iface);
                                }
                            }
                        }
                    }
                    
                    #[cfg(target_os = "linux")]
                    if self.actual_interface_name.is_some() || self.config.client.interface_name != "auto" {
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
                    if self.actual_interface_name.is_some() || self.config.client.interface_name != "auto" {
                        // CRITICAL: Delete old default route first, then add VPN route
                        // (macOS allows multiple default routes, but we want VPN to be primary)
                        info!("Removing existing default route before adding VPN route");
                        let delete_result = Command::new("route")
                            .arg("delete")
                            .arg("default")
                            .output()
                            .await;
                        
                        if let Ok(output) = delete_result {
                            if !output.status.success() {
                                warn!("Failed to delete old default route (may not exist): {:?}", 
                                      String::from_utf8_lossy(&output.stderr));
                            }
                        }
                        
                        info!("Adding VPN default route via {}", gw);
                        let add_result = Command::new("route")
                            .arg("add")
                            .arg("default")
                            .arg(gw.to_string())
                            .output()
                            .await;
                            
                        if let Ok(output) = add_result {
                            if !output.status.success() {
                                warn!("Failed to add VPN default route: {:?}", 
                                      String::from_utf8_lossy(&output.stderr));
                            } else {
                                info!("Successfully changed default route to VPN gateway {}", gw);
                            }
                        }
                    }
                    if let Some(r) = applied.as_mut() {
                        r.routes_added.push(format!("v4 default via {}", gw));
                    }
                }
            }
            let net = std::net::Ipv4Addr::from(u32::from(ip) & u32::from(mask));
            info!("Include route: {}/{}", net, cidr);
        }

        // IPv6
        if self.actual_interface_name.is_some() || self.config.client.interface_name != "auto" {
            if let (Some(ip6), Some(prefix)) = (ns.assigned_ipv6, ns.assigned_ipv6_prefix) {
                #[cfg(target_os = "linux")]
                {
                    use tokio::process::Command;
                    let ifname = self
                        .actual_interface_name
                        .as_deref()
                        .unwrap_or(&self.config.client.interface_name);
                    let _ = Command::new("ip")
                        .arg("-6")
                        .arg("addr")
                        .arg("add")
                        .arg(format!("{}/{}", ip6, prefix))
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
                {
                    use tokio::process::Command;
                    let ifname = self
                        .actual_interface_name
                        .as_deref()
                        .unwrap_or(&self.config.client.interface_name);
                    let _ = Command::new("ifconfig")
                        .arg(ifname)
                        .arg("inet6")
                        .arg(ip6.to_string())
                        .arg("prefixlen")
                        .arg(prefix.to_string())
                        .arg("add")
                        .output()
                        .await;
                    let _ = Command::new("ifconfig").arg(ifname).arg("up").output().await;
                }
                info!("Assigned interface IPv6 {}/{}", ip6, prefix);
                let res = applied.get_or_insert_with(|| crate::vpnclient::AppliedResources {
                    interface_name: self
                        .actual_interface_name
                        .clone()
                        .unwrap_or_else(|| self.config.client.interface_name.clone()),
                    ..Default::default()
                });
                res.ipv6_addr = Some((ip6, prefix as u8));
            }

            if !no_routing {
                if let Some(gw6) = ns.ipv6_gateway {
                    #[cfg(target_os = "linux")]
                    {
                        use tokio::process::Command;
                        let ifname = self
                            .actual_interface_name
                            .as_deref()
                            .unwrap_or(&self.config.client.interface_name);
                        let _ = Command::new("ip")
                            .arg("-6")
                            .arg("route")
                            .arg("add")
                            .arg("default")
                            .arg("via")
                            .arg(gw6.to_string())
                            .arg("dev")
                            .arg(ifname)
                            .output()
                            .await;
                    }
                    #[cfg(target_os = "macos")]
                    {
                        use tokio::process::Command;
                        let _ = Command::new("route")
                            .arg("add")
                            .arg("-inet6")
                            .arg("default")
                            .arg(gw6.to_string())
                            .output()
                            .await;
                    }
                    if let Some(r) = applied.as_mut() {
                        r.routes_added.push(format!("v6 default via {}", gw6));
                    }
                }
            }
        }

        // MTU
        #[cfg(target_os = "macos")]
        {
            use tokio::process::Command;
            let ifname = self
                .actual_interface_name
                .as_deref()
                .unwrap_or(&self.config.client.interface_name)
                .to_string();
            let _ = Command::new("ifconfig")
                .arg(ifname)
                .arg("mtu")
                .arg("1500")
                .output()
                .await;
        }
        #[cfg(target_os = "linux")]
        {
            use tokio::process::Command;
            let ifname = self
                .actual_interface_name
                .as_deref()
                .unwrap_or(&self.config.client.interface_name);
            let _ = Command::new("ip")
                .arg("link")
                .arg("set")
                .arg("dev")
                .arg(ifname)
                .arg("mtu")
                .arg("1500")
                .output()
                .await;
        }
        info!("MTU set to 1500");
        info!("[INFO] connected");

        // Emit snapshot if DHCP not in use (or static pre-DHCP)
        if !(self.config.client.enable_in_tunnel_dhcp && self.dhcp_xid.is_some()) {
            self.emit_server_interface_snapshot();
        }

        // DNS apply
        if !ns.dns_servers.is_empty() || !ns.dns_servers_v6.is_empty() {
            #[cfg(target_os = "linux")]
            {
                if self.config.connection.apply_dns {
                    let content = ns
                        .dns_servers
                        .iter()
                        .map(|d| d.to_string())
                        .chain(ns.dns_servers_v6.iter().map(|d| d.to_string()))
                        .collect::<Vec<_>>()
                        .join(" ");
                    if let Ok(current) = tokio::fs::read_to_string("/etc/resolv.conf").await {
                        let mut prev: Vec<IpAddr> = Vec::new();
                        for line in current.lines() {
                            let l = line.trim();
                            if let Some(rest) = l.strip_prefix("nameserver ") {
                                if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                                    prev.push(ip);
                                }
                            }
                        }
                        if !prev.is_empty() {
                            let res = applied.get_or_insert_with(|| crate::vpnclient::AppliedResources {
                                interface_name: self
                                    .actual_interface_name
                                    .clone()
                                    .unwrap_or_else(|| self.config.client.interface_name.clone()),
                                ..Default::default()
                            });
                            res.original_dns = Some(prev);
                        }
                    }
                    use tokio::process::Command;
                    let out = Command::new("bash")
                        .arg("-c")
                        .arg(format!(
                            "printf '%s' | awk '{for(i=1;i<=NF;i++) print \"nameserver \"$i}' | sudo tee /etc/resolv.conf > /dev/null",
                            content.replace("'", "'\\''")
                        ))
                        .output()
                        .await?;
                    if !out.status.success() {
                        warn!(
                            "Failed to apply DNS to /etc/resolv.conf: {}",
                            String::from_utf8_lossy(&out.stderr)
                        );
                    } else {
                        info!("Applied DNS servers to /etc/resolv.conf");
                        if let Some(r) = applied.as_mut() {
                            r.dns_modified = true;
                        }
                    }
                } else {
                    info!(
                        "(Linux) To apply DNS: echo -e 'nameserver {}' | sudo tee /etc/resolv.conf",
                        ns.dns_servers
                            .iter()
                            .map(|d| d.to_string())
                            .chain(ns.dns_servers_v6.iter().map(|d| d.to_string()))
                            .collect::<Vec<_>>()
                            .join("\\n")
                    );
                }
            }
            #[cfg(target_os = "macos")]
            {
                // Check if server has NoRouting policy - if so, skip DNS changes entirely
                let has_no_routing = ns
                    .policies
                    .iter()
                    .any(|(k, v)| k.to_ascii_lowercase().contains("norouting") && *v != 0);

                if has_no_routing {
                    info!("Server policy 'NoRouting' detected; skipping DNS changes (Local Bridge Mode)");
                    if !ns.dns_servers.is_empty() || !ns.dns_servers_v6.is_empty() {
                        info!(
                            "(macOS) VPN DNS servers available but not applied in Local Bridge Mode: {} (manual apply if needed: networksetup -setdnsservers <ServiceName> {})",
                            ns.dns_servers
                                .iter()
                                .map(|d| d.to_string())
                                .chain(ns.dns_servers_v6.iter().map(|d| d.to_string()))
                                .collect::<Vec<_>>()
                                .join(", "),
                            ns.dns_servers
                                .iter()
                                .map(|d| d.to_string())
                                .chain(ns.dns_servers_v6.iter().map(|d| d.to_string()))
                                .collect::<Vec<_>>()
                                .join(" ")
                        );
                    }
                } else if self.config.connection.apply_dns {
                    use tokio::process::Command;
                    let mut service_name: Option<String> =
                        self.config.client.macos_dns_service_name.clone();
                    if service_name.is_none() {
                        // Try to find a service associated with the VPN interface
                        if let Some(vpn_interface) = &self.actual_interface_name {
                            let out = Command::new("networksetup")
                                .arg("-listnetworkserviceorder")
                                .output()
                                .await?;
                            if out.status.success() {
                                let s = String::from_utf8_lossy(&out.stdout);
                                let mut last_service: Option<String> = None;
                                for line in s.lines() {
                                    let line = line.trim();
                                    if line.starts_with('(') {
                                        if let Some(pos) = line.find(") ") {
                                            let name = line[pos + 2..].trim();
                                            if !name.is_empty() {
                                                last_service = Some(name.to_string());
                                            }
                                        }
                                    }
                                    if line.contains("Device:") {
                                        if let Some(dev_pos) = line.find("Device:") {
                                            let dev = line[dev_pos + 7..].trim();
                                            let dev = dev.trim_end_matches(')');
                                            let dev = dev.trim();
                                            if !dev.is_empty() && dev == vpn_interface {
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
                        
                        // Fallback: warn user instead of applying to physical interface
                        if service_name.is_none() {
                            warn!("Could not find network service for VPN interface; DNS not applied automatically");
                            info!(
                                "(macOS) DNS servers suggested: {} (manual apply with: networksetup -setdnsservers <ServiceName> {})",
                                ns.dns_servers
                                    .iter()
                                    .map(|d| d.to_string())
                                    .chain(ns.dns_servers_v6.iter().map(|d| d.to_string()))
                                    .collect::<Vec<_>>()
                                    .join(", "),
                                ns.dns_servers
                                    .iter()
                                    .map(|d| d.to_string())
                                    .chain(ns.dns_servers_v6.iter().map(|d| d.to_string()))
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            );
                        }
                    }
                    if let Some(svc) = service_name {
                        let all_dns = ns
                            .dns_servers
                            .iter()
                            .map(|d| d.to_string())
                            .chain(ns.dns_servers_v6.iter().map(|d| d.to_string()))
                            .collect::<Vec<_>>()
                            .join(" ");
                        // Backup
                        if let Ok(out_prev) = Command::new("bash")
                            .arg("-c")
                            .arg(format!(
                                "networksetup -getdnsservers '{}'",
                                svc.replace("'", "'\\''")
                            ))
                            .output()
                            .await
                        {
                            if out_prev.status.success() {
                                let s = String::from_utf8_lossy(&out_prev.stdout);
                                let mut prev: Vec<IpAddr> = Vec::new();
                                for line in s.lines() {
                                    let v = line.trim();
                                    if v.is_empty() {
                                        continue;
                                    }
                                    if v.starts_with("There aren't any DNS Servers set") {
                                        prev.clear();
                                        break;
                                    }
                                    if let Ok(ip) = v.parse::<IpAddr>() {
                                        prev.push(ip);
                                    }
                                }
                                if !prev.is_empty() {
                                    let res = applied.get_or_insert_with(|| crate::vpnclient::AppliedResources {
                                        interface_name: self
                                            .actual_interface_name
                                            .clone()
                                            .unwrap_or_else(|| self.config.client.interface_name.clone()),
                                        ..Default::default()
                                    });
                                    res.original_dns = Some(prev);
                                    res.dns_service_name = Some(svc.clone());
                                }
                            }
                        }
                        let cmd = format!(
                            "networksetup -setdnsservers '{}' {}",
                            svc.replace("'", "'\\''"),
                            all_dns
                        );
                        let out = Command::new("bash").arg("-c").arg(&cmd).output().await?;
                        if !out.status.success() {
                            warn!(
                                "Failed to apply macOS DNS: {}",
                                String::from_utf8_lossy(&out.stderr)
                            );
                        } else {
                            info!("Applied DNS servers to service '{}'", svc);
                            if let Some(r) = applied.as_mut() {
                                r.dns_modified = true;
                                r.dns_service_name = Some(svc.clone());
                            }
                        }
                    }
                } else {
                    info!(
                        "(macOS) DNS servers suggested: {} (manual apply with: networksetup -setdnsservers <ServiceName> {})",
                        ns.dns_servers
                            .iter()
                            .map(|d| d.to_string())
                            .chain(ns.dns_servers_v6.iter().map(|d| d.to_string()))
                            .collect::<Vec<_>>()
                            .join(", "),
                        ns.dns_servers
                            .iter()
                            .map(|d| d.to_string())
                            .chain(ns.dns_servers_v6.iter().map(|d| d.to_string()))
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                }
            }
        }

        if applied.is_some() {
            self.applied_resources = applied;
        }
        Ok(())
    }
}
