//! Linux TUN device implementation.

use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::Command;

use libc::{
    c_char, c_int, c_short, c_void, close, ioctl, open, read, write,
    sockaddr, sockaddr_in, socket, AF_INET, IFF_NO_PI, IFF_TUN,
    O_RDWR, SOCK_DGRAM,
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
                mtu: 1500,
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

        info!("Configured {} with IP {} netmask {}", self.name, ip, netmask);
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
        let prefix_len = netmask
            .octets()
            .iter()
            .map(|b| b.count_ones())
            .sum::<u32>();

        let status = Command::new("ip")
            .args([
                "route",
                "add",
                &format!("{}/{}", dest, prefix_len),
                "via",
                &gateway.to_string(),
                "dev",
                &self.name,
            ])
            .status()?;

        if !status.success() {
            warn!("Failed to add route to {}/{}", dest, prefix_len);
        } else {
            debug!("Added route: {}/{} via {}", dest, prefix_len, gateway);
        }

        Ok(())
    }

    fn set_default_route(&self, gateway: Ipv4Addr) -> io::Result<()> {
        // First, delete the existing default route
        let _ = Command::new("ip")
            .args(["route", "del", "default"])
            .status();

        // Add new default route
        let status = Command::new("ip")
            .args([
                "route",
                "add",
                "default",
                "via",
                &gateway.to_string(),
                "dev",
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

impl Drop for TunDevice {
    fn drop(&mut self) {
        debug!("Closing TUN device: {}", self.name);
    }
}
