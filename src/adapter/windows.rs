//! Windows TUN device implementation using Wintun.
//!
//! This module provides a TUN adapter for Windows using the Wintun driver.
//! Wintun is a lightweight TUN driver for Windows developed by the WireGuard team.

use std::io;
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::{Arc, Mutex};

use tracing::{debug, info, warn};
use wintun::{Adapter, Session};

use super::TunAdapter;

/// Get the current default gateway from the routing table.
/// Returns None if no default gateway is found.
pub fn get_default_gateway() -> Option<Ipv4Addr> {
    // Use PowerShell to get the default gateway
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' } | Select-Object -First 1).NextHop"
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let gateway_str = String::from_utf8_lossy(&output.stdout);
    let gateway_str = gateway_str.trim();

    if gateway_str.is_empty() {
        return None;
    }

    gateway_str.parse().ok()
}

/// Get the interface index for a given adapter name.
fn get_interface_index(adapter_name: &str) -> Option<u32> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "(Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue).ifIndex",
                adapter_name
            ),
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let idx_str = String::from_utf8_lossy(&output.stdout);
    idx_str.trim().parse().ok()
}

/// Windows Wintun device.
pub struct WintunDevice {
    _adapter: Arc<Adapter>,
    session: Arc<Session>,
    name: String,
    mtu: u16,
    /// Routes added by this device (for cleanup on drop)
    routes_added: Mutex<Vec<String>>,
    /// Original default gateway (saved for host route cleanup)
    original_gateway: Mutex<Option<Ipv4Addr>>,
    /// Original DNS servers (for restoration)
    original_dns: Mutex<Option<String>>,
}

impl WintunDevice {
    /// Create a new Wintun device.
    ///
    /// The adapter will be named "SoftEther VPN" and will use Wintun driver.
    pub fn new(_unit: Option<u32>) -> io::Result<Self> {
        // Load Wintun DLL - try current directory first, then system path
        let wintun = unsafe { wintun::load() }
            .or_else(|_| unsafe { wintun::load_from_path("wintun.dll") })
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Failed to load wintun.dll: {}. Please download wintun.dll from https://wintun.net and place it in the current directory or system PATH.", e),
                )
            })?;

        // Disable wintun logging temporarily to suppress "Element not found" error
        // which is expected when the adapter doesn't exist yet
        wintun::reset_logger(&wintun);

        // Try to open an existing adapter first, otherwise create a new one
        let adapter = match Adapter::open(&wintun, "SoftEther VPN") {
            Ok(adapter) => {
                // Re-enable default logger for future messages
                wintun::set_logger(&wintun, Some(wintun::default_logger));
                debug!("Opened existing Wintun adapter");
                adapter
            }
            Err(_) => {
                // Re-enable default logger before creating adapter
                wintun::set_logger(&wintun, Some(wintun::default_logger));
                // Adapter doesn't exist yet, create a new one (this is normal on first run)
                debug!("Creating new Wintun adapter");
                Adapter::create(&wintun, "SoftEther VPN", "SoftEther Rust", None)
                    .map_err(|e| {
                        io::Error::other(
                            format!("Failed to create Wintun adapter: {}. Make sure you're running as Administrator.", e),
                        )
                    })?
            }
        };

        let name = adapter
            .get_name()
            .map_err(|e| io::Error::other(format!("Failed to get adapter name: {}", e)))?;

        // Start a session with ring buffer capacity (must be power of 2, between 128KB and 64MB)
        // Using 4MB for good performance
        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| io::Error::other(format!("Failed to start session: {}", e)))?;

        info!("Created Wintun device: {}", name);

        Ok(Self {
            _adapter: adapter,
            session: Arc::new(session),
            name,
            mtu: 1500,
            routes_added: Mutex::new(Vec::new()),
            original_gateway: Mutex::new(None),
            original_dns: Mutex::new(None),
        })
    }

    /// Get the Wintun session for packet operations.
    pub fn session(&self) -> Arc<Session> {
        self.session.clone()
    }

    /// Helper to run netsh commands
    #[allow(dead_code)]
    fn run_netsh(&self, args: &[&str]) -> io::Result<()> {
        let status = Command::new("netsh").args(args).status()?;

        if !status.success() {
            return Err(io::Error::other(format!(
                "netsh command failed: {:?}",
                args
            )));
        }

        Ok(())
    }
}

impl TunAdapter for WintunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Wintun receive_blocking waits for a packet
        match self.session.receive_blocking() {
            Ok(packet) => {
                let bytes = packet.bytes();
                let len = bytes.len().min(buf.len());
                buf[..len].copy_from_slice(&bytes[..len]);
                Ok(len)
            }
            Err(e) => Err(io::Error::other(format!("Receive failed: {}", e))),
        }
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Allocate a send packet and copy data
        let mut packet = self
            .session
            .allocate_send_packet(buf.len() as u16)
            .map_err(|e| io::Error::other(format!("Allocate failed: {}", e)))?;

        packet.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(packet);

        Ok(buf.len())
    }

    fn set_mtu(&mut self, mtu: u16) -> io::Result<()> {
        // Set MTU using netsh
        let status = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &self.name,
                &format!("mtu={}", mtu),
                "store=active",
            ])
            .status()?;

        if !status.success() {
            warn!("Failed to set MTU via netsh, trying PowerShell");
            // Try PowerShell as fallback
            let status = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "Set-NetIPInterface -InterfaceAlias '{}' -NlMtuBytes {}",
                        self.name, mtu
                    ),
                ])
                .status()?;

            if !status.success() {
                warn!("Failed to set MTU on {}, continuing anyway", self.name);
            }
        }

        self.mtu = mtu;
        debug!("Set MTU to {} on {}", mtu, self.name);
        Ok(())
    }

    fn configure(&mut self, ip: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        // Calculate prefix length from netmask
        let prefix_len: u8 = netmask.octets().iter().map(|b| b.count_ones() as u8).sum();

        // Use PowerShell to configure the IP address in a way that shows as DHCP-like
        // First remove existing IPs, then add new one
        let ps_script = format!(
            r#"
            $adapter = Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue
            if ($adapter) {{
                # Remove existing IP addresses
                Get-NetIPAddress -InterfaceAlias '{}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
                # Add new IP address
                New-NetIPAddress -InterfaceAlias '{}' -IPAddress '{}' -PrefixLength {} -SkipAsSource $false -ErrorAction Stop | Out-Null
                # Set interface to look like DHCP-configured (cosmetic)
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($adapter.InterfaceGuid)" -Name 'EnableDHCP' -Value 1 -Type DWord -ErrorAction SilentlyContinue
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($adapter.InterfaceGuid)" -Name 'DhcpIPAddress' -Value '{}' -Type String -ErrorAction SilentlyContinue
            }}
            "#,
            self.name, self.name, self.name, ip, prefix_len, ip
        );

        let status = Command::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &ps_script,
            ])
            .status()?;

        if !status.success() {
            // Fallback to simple netsh command
            let _ = Command::new("netsh")
                .args(["interface", "ip", "delete", "address", &self.name, "all"])
                .status();

            let status = Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "set",
                    "address",
                    &self.name,
                    "static",
                    &ip.to_string(),
                    &netmask.to_string(),
                ])
                .status()?;

            if !status.success() {
                return Err(io::Error::other(format!(
                    "Failed to configure {} with IP {}",
                    self.name, ip
                )));
            }
        }

        info!("Configured {} with IP {}/{}", self.name, ip, prefix_len);
        Ok(())
    }

    fn set_up(&mut self) -> io::Result<()> {
        // Enable the adapter using netsh
        let status = Command::new("netsh")
            .args(["interface", "set", "interface", &self.name, "admin=enable"])
            .status()?;

        if !status.success() {
            warn!("netsh enable failed, trying PowerShell");
            let status = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!("Enable-NetAdapter -Name '{}' -Confirm:$false", self.name),
                ])
                .status()?;

            if !status.success() {
                return Err(io::Error::other(format!(
                    "Failed to bring up {}",
                    self.name
                )));
            }
        }

        info!("Interface {} is up", self.name);
        Ok(())
    }

    fn add_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr) -> io::Result<()> {
        // Calculate prefix length from netmask
        let prefix_len: u8 = netmask.octets().iter().map(|b| b.count_ones() as u8).sum();

        let status = Command::new("route")
            .args([
                "add",
                &dest.to_string(),
                "mask",
                &netmask.to_string(),
                &gateway.to_string(),
            ])
            .status()?;

        if !status.success() {
            warn!("Failed to add route to {}/{}", dest, prefix_len);
        } else {
            debug!("Added route: {}/{} via {}", dest, prefix_len, gateway);
        }

        Ok(())
    }

    fn add_route_via_interface(&self, dest: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
        let if_index = get_interface_index(&self.name);

        let route_str = format!("{}/{}", dest, prefix_len);

        // Calculate netmask from prefix length
        let netmask_val: u32 = if prefix_len == 0 {
            0
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        let netmask = Ipv4Addr::from(netmask_val);

        // Use 'route add' command with interface index if available
        let status = if let Some(idx) = if_index {
            Command::new("route")
                .args([
                    "add",
                    &dest.to_string(),
                    "mask",
                    &netmask.to_string(),
                    "0.0.0.0",
                    "if",
                    &idx.to_string(),
                ])
                .status()?
        } else {
            // Fallback to PowerShell
            Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "New-NetRoute -DestinationPrefix '{}/{}' -InterfaceAlias '{}' -ErrorAction SilentlyContinue",
                        dest, prefix_len, self.name
                    )
                ])
                .status()?
        };

        if !status.success() {
            warn!(
                "Failed to add route to {} via interface {}",
                route_str, self.name
            );
        } else {
            info!("Added route: {} via interface {}", route_str, self.name);
            if let Ok(mut routes) = self.routes_added.lock() {
                routes.push(route_str);
            }
        }

        Ok(())
    }

    fn set_default_route(
        &self,
        _gateway: Ipv4Addr,
        vpn_server_ip: Option<Ipv4Addr>,
    ) -> io::Result<()> {
        // On Windows, we use the same split-tunnel approach as macOS:
        // Add 0.0.0.0/1 and 128.0.0.0/1 routes through the VPN interface

        // First, add a host route for the VPN server through the original gateway
        if let Some(server_ip) = vpn_server_ip {
            if let Some(orig_gateway) = get_default_gateway() {
                info!(
                    "Adding host route for VPN server {} via original gateway {}",
                    server_ip, orig_gateway
                );

                let status = Command::new("route")
                    .args([
                        "add",
                        &server_ip.to_string(),
                        "mask",
                        "255.255.255.255",
                        &orig_gateway.to_string(),
                    ])
                    .status()?;

                if status.success() {
                    if let Ok(mut gw) = self.original_gateway.lock() {
                        *gw = Some(orig_gateway);
                    }
                    if let Ok(mut routes) = self.routes_added.lock() {
                        routes.push(format!("-host {}", server_ip));
                    }
                    info!("Added host route: {} via {}", server_ip, orig_gateway);
                } else {
                    warn!("Failed to add host route for VPN server (may already exist)");
                }
            } else {
                warn!("Could not determine original default gateway - VPN traffic may not route correctly");
            }
        }

        let if_index = get_interface_index(&self.name);

        // Add route for 0.0.0.0/1 (first half of IPv4 space)
        let status1 = if let Some(idx) = if_index {
            Command::new("route")
                .args([
                    "add",
                    "0.0.0.0",
                    "mask",
                    "128.0.0.0",
                    "0.0.0.0",
                    "if",
                    &idx.to_string(),
                ])
                .status()?
        } else {
            Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias '{}' -ErrorAction SilentlyContinue",
                        self.name
                    )
                ])
                .status()?
        };

        if !status1.success() {
            return Err(io::Error::other("Failed to add route 0.0.0.0/1"));
        }
        if let Ok(mut routes) = self.routes_added.lock() {
            routes.push("0.0.0.0/1".to_string());
        }

        // Add route for 128.0.0.0/1 (second half of IPv4 space)
        let status2 = if let Some(idx) = if_index {
            Command::new("route")
                .args([
                    "add",
                    "128.0.0.0",
                    "mask",
                    "128.0.0.0",
                    "0.0.0.0",
                    "if",
                    &idx.to_string(),
                ])
                .status()?
        } else {
            Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias '{}' -ErrorAction SilentlyContinue",
                        self.name
                    )
                ])
                .status()?
        };

        if !status2.success() {
            // Rollback first route
            let _ = Command::new("route")
                .args(["delete", "0.0.0.0", "mask", "128.0.0.0"])
                .status();
            if let Ok(mut routes) = self.routes_added.lock() {
                routes.pop();
            }
            return Err(io::Error::other("Failed to add route 128.0.0.0/1"));
        }
        if let Ok(mut routes) = self.routes_added.lock() {
            routes.push("128.0.0.0/1".to_string());
        }

        info!(
            "Set default route via {} (split-tunnel: 0.0.0.0/1 + 128.0.0.0/1)",
            self.name
        );
        Ok(())
    }

    fn configure_dns(&self, dns1: Option<Ipv4Addr>, dns2: Option<Ipv4Addr>) -> io::Result<()> {
        let dns_servers: Vec<String> = [dns1, dns2]
            .iter()
            .filter_map(|&d| d.map(|ip| ip.to_string()))
            .collect();

        if dns_servers.is_empty() {
            debug!("No DNS servers to configure");
            return Ok(());
        }

        // Save current DNS configuration for restoration
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "(Get-DnsClientServerAddress -InterfaceAlias '{}' -AddressFamily IPv4).ServerAddresses -join ','",
                    self.name
                )
            ])
            .output();

        if let Ok(out) = output {
            let current_dns = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !current_dns.is_empty() {
                if let Ok(mut dns) = self.original_dns.lock() {
                    *dns = Some(current_dns);
                }
            }
        }

        // Set DNS servers using PowerShell (more reliable than netsh for modern Windows)
        let dns_str = dns_servers.join(",");
        let status = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @('{}')",
                    self.name, dns_str
                ),
            ])
            .status()?;

        if !status.success() {
            // Fallback to netsh
            let primary = &dns_servers[0];
            let status = Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "set",
                    "dns",
                    &self.name,
                    "static",
                    primary,
                ])
                .status()?;

            if status.success() {
                // Add secondary DNS if present
                if dns_servers.len() > 1 {
                    let _ = Command::new("netsh")
                        .args([
                            "interface",
                            "ip",
                            "add",
                            "dns",
                            &self.name,
                            &dns_servers[1],
                            "index=2",
                        ])
                        .status();
                }
            }
        }

        info!("Configured DNS servers: {:?}", dns_servers);
        Ok(())
    }

    fn restore_dns(&self) -> io::Result<()> {
        // Restore original DNS configuration
        if let Ok(dns) = self.original_dns.lock() {
            if let Some(original) = dns.as_ref() {
                if !original.is_empty() {
                    let _ = Command::new("powershell")
                        .args([
                            "-NoProfile",
                            "-Command",
                            &format!(
                                "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @('{}')",
                                self.name, original
                            )
                        ])
                        .status();
                } else {
                    // Reset to DHCP
                    let _ = Command::new("powershell")
                        .args([
                            "-NoProfile",
                            "-Command",
                            &format!(
                                "Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses",
                                self.name
                            )
                        ])
                        .status();
                }
            }
        }

        debug!("Restored DNS configuration");
        Ok(())
    }
}

impl Drop for WintunDevice {
    fn drop(&mut self) {
        // Restore DNS first
        let _ = self.restore_dns();

        // Clean up routes we added
        if let Ok(routes) = self.routes_added.lock() {
            for route in routes.iter() {
                debug!("Removing route: {}", route);
                if route.starts_with("-host ") {
                    let host_ip = route.strip_prefix("-host ").unwrap();
                    let _ = Command::new("route").args(["delete", host_ip]).status();
                } else if route == "0.0.0.0/1" {
                    let _ = Command::new("route")
                        .args(["delete", "0.0.0.0", "mask", "128.0.0.0"])
                        .status();
                } else if route == "128.0.0.0/1" {
                    let _ = Command::new("route")
                        .args(["delete", "128.0.0.0", "mask", "128.0.0.0"])
                        .status();
                } else {
                    // Parse CIDR notation
                    let parts: Vec<&str> = route.split('/').collect();
                    if parts.len() == 2 {
                        if let (Ok(dest), Ok(prefix_len)) =
                            (parts[0].parse::<Ipv4Addr>(), parts[1].parse::<u8>())
                        {
                            let netmask_val: u32 = if prefix_len == 0 {
                                0
                            } else {
                                !((1u32 << (32 - prefix_len)) - 1)
                            };
                            let netmask = Ipv4Addr::from(netmask_val);
                            let _ = Command::new("route")
                                .args(["delete", &dest.to_string(), "mask", &netmask.to_string()])
                                .status();
                        }
                    }
                }
            }
        }

        debug!("Closing Wintun device: {}", self.name);
    }
}
