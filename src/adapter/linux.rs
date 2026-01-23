//! Linux TUN device implementation.

use std::ffi::CStr;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::Command;
use std::sync::Mutex;

use libc::{
    c_char, c_int, c_short, c_void, close, ioctl, open, read, sockaddr_in, socket, write, AF_INET,
    IFF_NO_PI, IFF_TUN, O_RDWR, SOCK_DGRAM,
};
use tracing::{debug, info, warn};

use super::TunAdapter;

/// TUNSETIFF ioctl number.
const TUNSETIFF: libc::c_ulong = 0x400454ca;

/// SIOCSIFADDR - Set interface address.
const SIOCSIFADDR: libc::c_ulong = 0x8916;

/// SIOCSIFNETMASK - Set interface netmask.
const SIOCSIFNETMASK: libc::c_ulong = 0x891c;

/// SIOCSIFFLAGS - Set interface flags.
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;

/// SIOCGIFFLAGS - Get interface flags.
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;

/// SIOCSIFMTU - Set interface MTU.
const SIOCSIFMTU: libc::c_ulong = 0x8922;

/// IFF_UP - Interface is up.
const IFF_UP: c_short = 0x1;

/// IFF_RUNNING - Interface is running.
const IFF_RUNNING: c_short = 0x40;

/// Get the current default gateway from the routing table.
/// Returns None if no default gateway is found.
pub fn get_default_gateway() -> Option<Ipv4Addr> {
    // Use ip route to get the default gateway, excluding our TUN interfaces
    let output = Command::new("sh")
        .args([
            "-c",
            "ip route show default | grep -v 'tun' | head -1 | awk '{print $3}'",
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

/// Interface request structure.
#[repr(C)]
struct IfReq {
    ifr_name: [c_char; 16],
    ifr_flags: c_short,
    _pad: [u8; 22],
}

/// Interface request with address.
#[repr(C)]
struct IfReqAddr {
    ifr_name: [c_char; 16],
    ifr_addr: sockaddr_in,
}

/// Interface request with MTU.
#[repr(C)]
struct IfReqMtu {
    ifr_name: [c_char; 16],
    ifr_mtu: c_int,
    _pad: [u8; 20],
}

/// Linux TUN device.
pub struct TunDevice {
    fd: OwnedFd,
    name: String,
    mtu: u16,
    /// Routes added by this device (for cleanup on drop)
    routes_added: Mutex<Vec<String>>,
    /// Original default gateway (saved for host route cleanup)
    original_gateway: Mutex<Option<Ipv4Addr>>,
}

impl TunDevice {
    /// Create a new TUN device.
    ///
    /// If `name` is empty, the kernel will assign a name like "tun0".
    pub fn new(name: Option<&str>) -> io::Result<Self> {
        unsafe {
            // Open the TUN clone device
            let fd = open(b"/dev/net/tun\0".as_ptr() as *const c_char, O_RDWR);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // Set up the interface request
            let mut ifr = IfReq {
                ifr_name: [0; 16],
                ifr_flags: (IFF_TUN | IFF_NO_PI) as c_short,
                _pad: [0; 22],
            };

            // Copy the name if provided
            if let Some(name) = name {
                for (i, byte) in name.bytes().take(15).enumerate() {
                    ifr.ifr_name[i] = byte as c_char;
                }
            }

            // Create the TUN device
            if ioctl(fd, TUNSETIFF, &mut ifr as *mut _ as *mut c_void) < 0 {
                close(fd);
                return Err(io::Error::last_os_error());
            }

            // Get the actual interface name
            let name = CStr::from_ptr(ifr.ifr_name.as_ptr())
                .to_string_lossy()
                .into_owned();

            info!("Created TUN device: {}", name);

            Ok(Self {
                fd: OwnedFd::from_raw_fd(fd),
                name,
                mtu: 1420,
                routes_added: Mutex::new(Vec::new()),
                original_gateway: Mutex::new(None),
            })
        }
    }

    /// Get the raw file descriptor.
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Create a control socket for ioctl operations.
    fn control_socket() -> io::Result<RawFd> {
        unsafe {
            let fd = socket(AF_INET, SOCK_DGRAM, 0);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(fd)
        }
    }

    /// Copy interface name to a buffer.
    fn copy_name(&self, buf: &mut [c_char; 16]) {
        for (i, byte) in self.name.bytes().take(15).enumerate() {
            buf[i] = byte as c_char;
        }
    }
}

impl TunAdapter for TunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe {
            read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
            )
        };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(n as usize)
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = unsafe {
            write(
                self.fd.as_raw_fd(),
                buf.as_ptr() as *const c_void,
                buf.len(),
            )
        };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(n as usize)
    }

    fn set_mtu(&mut self, mtu: u16) -> io::Result<()> {
        unsafe {
            let sock = Self::control_socket()?;

            let mut ifr = IfReqMtu {
                ifr_name: [0; 16],
                ifr_mtu: mtu as c_int,
                _pad: [0; 20],
            };
            self.copy_name(&mut ifr.ifr_name);

            if ioctl(sock, SIOCSIFMTU, &mut ifr as *mut _ as *mut c_void) < 0 {
                close(sock);
                return Err(io::Error::last_os_error());
            }

            close(sock);
        }

        self.mtu = mtu;
        debug!("Set MTU to {} on {}", mtu, self.name);
        Ok(())
    }

    fn configure(&mut self, ip: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        unsafe {
            let sock = Self::control_socket()?;

            // Set IP address
            let mut ifr_addr = IfReqAddr {
                ifr_name: [0; 16],
                ifr_addr: std::mem::zeroed(),
            };
            self.copy_name(&mut ifr_addr.ifr_name);
            ifr_addr.ifr_addr.sin_family = AF_INET as u16;
            ifr_addr.ifr_addr.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());

            if ioctl(sock, SIOCSIFADDR, &mut ifr_addr as *mut _ as *mut c_void) < 0 {
                close(sock);
                return Err(io::Error::last_os_error());
            }

            // Set netmask
            let mut ifr_mask = IfReqAddr {
                ifr_name: [0; 16],
                ifr_addr: std::mem::zeroed(),
            };
            self.copy_name(&mut ifr_mask.ifr_name);
            ifr_mask.ifr_addr.sin_family = AF_INET as u16;
            ifr_mask.ifr_addr.sin_addr.s_addr = u32::from_ne_bytes(netmask.octets());

            if ioctl(sock, SIOCSIFNETMASK, &mut ifr_mask as *mut _ as *mut c_void) < 0 {
                close(sock);
                return Err(io::Error::last_os_error());
            }

            close(sock);
        }

        info!(
            "Configured {} with IP {} netmask {}",
            self.name, ip, netmask
        );
        Ok(())
    }

    fn set_up(&mut self) -> io::Result<()> {
        unsafe {
            let sock = Self::control_socket()?;

            // Get current flags
            let mut ifr = IfReq {
                ifr_name: [0; 16],
                ifr_flags: 0,
                _pad: [0; 22],
            };
            self.copy_name(&mut ifr.ifr_name);

            if ioctl(sock, SIOCGIFFLAGS, &mut ifr as *mut _ as *mut c_void) < 0 {
                close(sock);
                return Err(io::Error::last_os_error());
            }

            // Set UP and RUNNING flags
            ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

            if ioctl(sock, SIOCSIFFLAGS, &mut ifr as *mut _ as *mut c_void) < 0 {
                close(sock);
                return Err(io::Error::last_os_error());
            }

            close(sock);
        }

        info!("Interface {} is up", self.name);
        Ok(())
    }

    fn add_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr) -> io::Result<()> {
        // Calculate prefix length from netmask
        let prefix_len = netmask.octets().iter().map(|b| b.count_ones()).sum::<u32>();

        let status = Command::new("ip")
            .args([
                "route",
                "replace",
                &format!("{}/{}", dest, prefix_len),
                "via",
                &gateway.to_string(),
                "dev",
                &self.name,
            ])
            .status()?;

        if !status.success() {
            warn!("Failed to add/replace route to {}/{}", dest, prefix_len);
        } else {
            debug!("Added route: {}/{} via {}", dest, prefix_len, gateway);
        }

        Ok(())
    }

    fn add_route_via_interface(&self, dest: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
        let route_str = format!("{}/{}", dest, prefix_len);
        let status = Command::new("ip")
            .args(["route", "replace", &route_str, "dev", &self.name])
            .status()?;

        if !status.success() {
            warn!(
                "Failed to add/replace route to {} via interface {}",
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
        // On Linux, we use the same "split-tunnel" approach as macOS:
        // Add two more-specific routes that cover the entire IPv4 space:
        // - 0.0.0.0/1 covers 0.0.0.0 - 127.255.255.255
        // - 128.0.0.0/1 covers 128.0.0.0 - 255.255.255.255

        // CRITICAL: First, add a host route for the VPN server through the original gateway
        if let Some(server_ip) = vpn_server_ip {
            if let Some(orig_gateway) = get_default_gateway() {
                info!(
                    "Adding host route for VPN server {} via original gateway {}",
                    server_ip, orig_gateway
                );
                let status = Command::new("ip")
                    .args([
                        "route",
                        "add",
                        &server_ip.to_string(),
                        "via",
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
                        routes.push(format!("host:{}", server_ip));
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
        let status1 = Command::new("ip")
            .args(["route", "replace", "0.0.0.0/1", "dev", &self.name])
            .status()?;

        if !status1.success() {
            return Err(io::Error::other("Failed to add/replace route 0.0.0.0/1"));
        }
        if let Ok(mut routes) = self.routes_added.lock() {
            routes.push("0.0.0.0/1".to_string());
        }

        // Add route for 128.0.0.0/1 (second half of IPv4 space)
        let status2 = Command::new("ip")
            .args(["route", "replace", "128.0.0.0/1", "dev", &self.name])
            .status()?;

        if !status2.success() {
            // Rollback first route
            let _ = Command::new("ip")
                .args(["route", "del", "0.0.0.0/1"])
                .status();
            if let Ok(mut routes) = self.routes_added.lock() {
                routes.pop();
            }
            return Err(io::Error::other("Failed to add/replace route 128.0.0.0/1"));
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
        // On Linux, we modify /etc/resolv.conf or use resolvconf/systemd-resolved

        let dns_servers: Vec<String> = [dns1, dns2]
            .iter()
            .filter_map(|&d| d.map(|ip| ip.to_string()))
            .collect();

        if dns_servers.is_empty() {
            debug!("No DNS servers to configure");
            return Ok(());
        }

        // Try systemd-resolved first (modern systems)
        for dns in &dns_servers {
            let status = Command::new("resolvectl")
                .args(["dns", &self.name, dns])
                .status();

            if status.is_ok() && status.unwrap().success() {
                info!("Configured DNS {} via resolvectl", dns);
                continue;
            }

            // Fall back to systemd-resolve (older name)
            let status = Command::new("systemd-resolve")
                .args(["--interface", &self.name, "--set-dns", dns])
                .status();

            if status.is_ok() && status.unwrap().success() {
                info!("Configured DNS {} via systemd-resolve", dns);
            }
        }

        // Also set domain routing for all domains through this interface
        let _ = Command::new("resolvectl")
            .args(["domain", &self.name, "~."])
            .status();

        info!("Configured DNS servers: {:?}", dns_servers);
        Ok(())
    }

    fn restore_dns(&self) -> io::Result<()> {
        // systemd-resolved automatically removes DNS config when interface goes down
        // For resolvconf-based systems, we would need to restore the backup
        debug!("DNS configuration will be restored when interface is removed");
        Ok(())
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        // Restore DNS first
        let _ = self.restore_dns();

        // Clean up routes we added
        if let Ok(routes) = self.routes_added.lock() {
            for route in routes.iter() {
                debug!("Removing route: {}", route);
                // Handle host routes differently
                if route.starts_with("host:") {
                    let host_ip = route.strip_prefix("host:").unwrap();
                    let _ = Command::new("ip").args(["route", "del", host_ip]).status();
                } else {
                    let _ = Command::new("ip").args(["route", "del", route]).status();
                }
            }
        }
        debug!("Closing TUN device: {}", self.name);
    }
}
