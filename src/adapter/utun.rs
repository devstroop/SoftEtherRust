//! macOS utun device implementation.

use std::ffi::CStr;
use std::io::{self};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::Command;

use libc::{
    c_char, c_int, c_void, close, connect, getsockopt, ioctl, setsockopt, sockaddr,
    sockaddr_ctl, socket, socklen_t, AF_SYSTEM, CTLIOCGINFO, PF_SYSTEM, SOCK_DGRAM,
    SOL_SOCKET, SO_SNDBUF, SO_RCVBUF, SYSPROTO_CONTROL,
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

/// macOS utun device.
pub struct UtunDevice {
    fd: OwnedFd,
    name: String,
    mtu: u16,
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
            ) < 0 {
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
            ) < 0 {
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

        info!("Configured {} with IP {} netmask {}", self.name, ip, netmask);
        Ok(())
    }

    fn set_up(&mut self) -> io::Result<()> {
        let status = Command::new("ifconfig")
            .args([&self.name, "up"])
            .status()?;

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
        let prefix_len = netmask
            .octets()
            .iter()
            .map(|b| b.count_ones())
            .sum::<u32>();

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
        let status = Command::new("route")
            .args([
                "-n",
                "add",
                "-net",
                &format!("{}/{}", dest, prefix_len),
                "-interface",
                &self.name,
            ])
            .status()?;

        if !status.success() {
            warn!("Failed to add route to {}/{} via interface {}", dest, prefix_len, self.name);
        } else {
            info!("Added route: {}/{} via interface {}", dest, prefix_len, self.name);
        }

        Ok(())
    }

    fn set_default_route(&self, gateway: Ipv4Addr) -> io::Result<()> {
        // First, delete the existing default route
        let _ = Command::new("route")
            .args(["-n", "delete", "default"])
            .status();

        // Add new default route
        let status = Command::new("route")
            .args([
                "-n",
                "add",
                "default",
                &gateway.to_string(),
                "-interface",
                &self.name,
            ])
            .status()?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to set default route",
            ));
        }

        info!("Set default route via {} on {}", gateway, self.name);
        Ok(())
    }
}

impl Drop for UtunDevice {
    fn drop(&mut self) {
        debug!("Closing utun device: {}", self.name);
    }
}
