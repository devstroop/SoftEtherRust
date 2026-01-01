//! macOS utun device implementation.

use std::ffi::CStr;
use std::io::{self};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::Command;
use std::sync::Mutex;

use libc::{
    c_char, c_int, c_void, close, connect, getsockopt, ioctl, setsockopt, sockaddr, sockaddr_ctl,
    socket, socklen_t, AF_SYSTEM, CTLIOCGINFO, PF_SYSTEM, SOCK_DGRAM, SOL_SOCKET, SO_RCVBUF,
    SO_SNDBUF, SYSPROTO_CONTROL,
};
use tracing::{debug, info, warn};

use super::TunAdapter;

/// Control info structure for utun.
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [c_char; 96],
}

/// utun control name.
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

/// utun socket option for interface name.
const UTUN_OPT_IFNAME: c_int = 2;

/// Get the current default gateway from the routing table.
/// Returns None if no default gateway is found.
pub fn get_default_gateway() -> Option<Ipv4Addr> {
    // Use netstat to get the default gateway, excluding utun interfaces
    let output = Command::new("sh")
        .args([
            "-c",
            "netstat -rn | grep '^default' | grep -v 'utun' | head -1 | awk '{print $2}'",
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

/// macOS utun device.
pub struct UtunDevice {
    fd: OwnedFd,
    name: String,
    mtu: u16,
    /// Routes added by this device (for cleanup on drop)
    routes_added: Mutex<Vec<String>>,
    /// Original default gateway (saved for host route cleanup)
    original_gateway: Mutex<Option<Ipv4Addr>>,
}

impl UtunDevice {
    /// Create a new utun device.
    ///
    /// If `unit` is `None`, the system will assign the next available unit number.
    pub fn new(unit: Option<u32>) -> io::Result<Self> {
        unsafe {
            // Create a system control socket
            let fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // Get the control ID for utun
            let mut ctl_info = CtlInfo {
                ctl_id: 0,
                ctl_name: [0; 96],
            };

            // Copy the control name
            let name_bytes = UTUN_CONTROL_NAME;
            for (i, &byte) in name_bytes.iter().enumerate() {
                ctl_info.ctl_name[i] = byte as c_char;
            }

            if ioctl(fd, CTLIOCGINFO, &mut ctl_info as *mut _ as *mut c_void) < 0 {
                close(fd);
                return Err(io::Error::last_os_error());
            }

            // Connect to the utun device
            let mut addr: sockaddr_ctl = std::mem::zeroed();
            addr.sc_len = std::mem::size_of::<sockaddr_ctl>() as u8;
            addr.sc_family = AF_SYSTEM as u8;
            addr.ss_sysaddr = 2; // AF_SYS_CONTROL
            addr.sc_id = ctl_info.ctl_id;
            addr.sc_unit = unit.unwrap_or(0); // 0 = auto-assign

            if connect(
                fd,
                &addr as *const _ as *const sockaddr,
                std::mem::size_of::<sockaddr_ctl>() as socklen_t,
            ) < 0
            {
                close(fd);
                return Err(io::Error::last_os_error());
            }

            // Get the interface name
            let mut name_buf = [0u8; 32];
            let mut name_len: socklen_t = name_buf.len() as socklen_t;

            if getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name_buf.as_mut_ptr() as *mut c_void,
                &mut name_len,
            ) < 0
            {
                close(fd);
                return Err(io::Error::last_os_error());
            }

            let name = CStr::from_bytes_until_nul(&name_buf)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid interface name"))?
                .to_string_lossy()
                .into_owned();

            // Set socket buffer sizes for better throughput
            let buf_size: c_int = 2 * 1024 * 1024; // 2MB
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_SNDBUF,
                &buf_size as *const _ as *const c_void,
                std::mem::size_of::<c_int>() as socklen_t,
            );
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVBUF,
                &buf_size as *const _ as *const c_void,
                std::mem::size_of::<c_int>() as socklen_t,
            );

            info!("Created utun device: {}", name);

            Ok(Self {
                fd: OwnedFd::from_raw_fd(fd),
                name,
                mtu: 1500,
                routes_added: Mutex::new(Vec::new()),
                original_gateway: Mutex::new(None),
            })
        }
    }

    /// Get the raw file descriptor.
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl TunAdapter for UtunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // utun on macOS prepends a 4-byte header (protocol family)
        let mut full_buf = vec![0u8; buf.len() + 4];

        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                full_buf.as_mut_ptr() as *mut c_void,
                full_buf.len(),
            )
        };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let n = n as usize;
        if n <= 4 {
            return Ok(0);
        }

        // Skip the 4-byte header
        let payload_len = n - 4;
        buf[..payload_len].copy_from_slice(&full_buf[4..n]);

        Ok(payload_len)
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // utun on macOS needs a 4-byte header with protocol family
        let mut full_buf = Vec::with_capacity(buf.len() + 4);

        // Determine protocol family from IP version
        let proto = if !buf.is_empty() && (buf[0] >> 4) == 6 {
            libc::AF_INET6 as u32
        } else {
            libc::AF_INET as u32
        };

        full_buf.extend_from_slice(&proto.to_be_bytes());
        full_buf.extend_from_slice(buf);

        let n = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                full_buf.as_ptr() as *const c_void,
                full_buf.len(),
            )
        };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        // Return the number of bytes written (excluding header)
        Ok((n as usize).saturating_sub(4))
    }

    fn set_mtu(&mut self, mtu: u16) -> io::Result<()> {
        let status = Command::new("ifconfig")
            .args([&self.name, "mtu", &mtu.to_string()])
            .status()?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to set MTU on {}", self.name),
            ));
        }

        self.mtu = mtu;
        debug!("Set MTU to {} on {}", mtu, self.name);
        Ok(())
    }

    fn configure(&mut self, ip: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        // On macOS, we need to use ifconfig to set the IP address
        // Format: ifconfig utunX inet <ip> <ip> netmask <netmask>
        let status = Command::new("ifconfig")
            .args([
                &self.name,
                "inet",
                &ip.to_string(),
                &ip.to_string(),
                "netmask",
                &netmask.to_string(),
            ])
            .status()?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to configure {} with IP {}", self.name, ip),
            ));
        }

        info!(
            "Configured {} with IP {} netmask {}",
            self.name, ip, netmask
        );
        Ok(())
    }

    fn set_up(&mut self) -> io::Result<()> {
        let status = Command::new("ifconfig").args([&self.name, "up"]).status()?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to bring up {}", self.name),
            ));
        }

        info!("Interface {} is up", self.name);
        Ok(())
    }

    fn add_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr) -> io::Result<()> {
        // Calculate prefix length from netmask
        let prefix_len = netmask.octets().iter().map(|b| b.count_ones()).sum::<u32>();

        let status = Command::new("route")
            .args([
                "-n",
                "add",
                "-net",
                &format!("{}/{}", dest, prefix_len),
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
        let route_str = format!("{}/{}", dest, prefix_len);
        let status = Command::new("route")
            .args(["-n", "add", "-net", &route_str, "-interface", &self.name])
            .status()?;

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
        // On macOS, we use the "split-tunnel" approach for default routing:
        // Instead of replacing the default route (which can break connectivity),
        // we add two more-specific routes that cover the entire IPv4 space:
        // - 0.0.0.0/1 covers 0.0.0.0 - 127.255.255.255
        // - 128.0.0.0/1 covers 128.0.0.0 - 255.255.255.255
        // These are more specific than the default route (0.0.0.0/0), so they
        // take precedence, but don't delete the original default route.

        // CRITICAL: First, add a host route for the VPN server through the original gateway
        // This prevents a routing loop where VPN traffic itself gets routed through the VPN
        if let Some(server_ip) = vpn_server_ip {
            if let Some(orig_gateway) = get_default_gateway() {
                info!(
                    "Adding host route for VPN server {} via original gateway {}",
                    server_ip, orig_gateway
                );
                let status = Command::new("route")
                    .args([
                        "-n",
                        "add",
                        "-host",
                        &server_ip.to_string(),
                        &orig_gateway.to_string(),
                    ])
                    .status()?;

                if status.success() {
                    // Save original gateway for cleanup
                    if let Ok(mut gw) = self.original_gateway.lock() {
                        *gw = Some(orig_gateway);
                    }
                    // Track the host route for cleanup
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

        // Add route for 0.0.0.0/1 (first half of IPv4 space)
        let status1 = Command::new("route")
            .args(["-n", "add", "-net", "0.0.0.0/1", "-interface", &self.name])
            .status()?;

        if !status1.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to add route 0.0.0.0/1",
            ));
        }
        if let Ok(mut routes) = self.routes_added.lock() {
            routes.push("0.0.0.0/1".to_string());
        }

        // Add route for 128.0.0.0/1 (second half of IPv4 space)
        let status2 = Command::new("route")
            .args(["-n", "add", "-net", "128.0.0.0/1", "-interface", &self.name])
            .status()?;

        if !status2.success() {
            // Rollback first route
            let _ = Command::new("route")
                .args(["-n", "delete", "-net", "0.0.0.0/1"])
                .status();
            if let Ok(mut routes) = self.routes_added.lock() {
                routes.pop();
            }
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to add route 128.0.0.0/1",
            ));
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
        // On macOS, we create a custom resolver configuration using scutil
        // This creates a "resolver" entry that takes precedence for DNS resolution

        let dns_servers: Vec<String> = [dns1, dns2]
            .iter()
            .filter_map(|&d| d.map(|ip| ip.to_string()))
            .collect();

        if dns_servers.is_empty() {
            debug!("No DNS servers to configure");
            return Ok(());
        }

        let servers_str = dns_servers.join("\n");

        // Create the resolver configuration
        let scutil_commands = format!(
            "d.init\n\
             d.add ServerAddresses * {}\n\
             d.add SupplementalMatchDomains * \"\"\n\
             set State:/Network/Service/{}/DNS\n\
             quit",
            servers_str, self.name
        );

        let output = Command::new("scutil")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    stdin.write_all(scutil_commands.as_bytes())?;
                }
                child.wait_with_output()
            });

        match output {
            Ok(out) if out.status.success() => {
                info!("Configured DNS servers: {:?}", dns_servers);
                Ok(())
            }
            Ok(out) => {
                warn!(
                    "scutil DNS configuration may have failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                // Don't fail - DNS might still work
                Ok(())
            }
            Err(e) => {
                warn!("Failed to run scutil for DNS: {}", e);
                Ok(()) // Don't fail connection over DNS config
            }
        }
    }

    fn restore_dns(&self) -> io::Result<()> {
        // Remove our DNS configuration
        let scutil_commands = format!(
            "remove State:/Network/Service/{}/DNS\n\
             quit",
            self.name
        );

        let _ = Command::new("scutil")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    stdin.write_all(scutil_commands.as_bytes())?;
                }
                child.wait()
            });

        debug!("Restored DNS configuration");
        Ok(())
    }
}

impl Drop for UtunDevice {
    fn drop(&mut self) {
        // Restore DNS first
        let _ = self.restore_dns();

        // Clean up routes we added
        if let Ok(routes) = self.routes_added.lock() {
            for route in routes.iter() {
                debug!("Removing route: {}", route);
                // Handle host routes differently
                if route.starts_with("-host ") {
                    let host_ip = route.strip_prefix("-host ").unwrap();
                    let _ = Command::new("route")
                        .args(["-n", "delete", "-host", host_ip])
                        .status();
                } else {
                    let _ = Command::new("route")
                        .args(["-n", "delete", "-net", route])
                        .status();
                }
            }
        }
        debug!("Closing utun device: {}", self.name);
    }
}
