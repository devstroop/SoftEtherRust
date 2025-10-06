//! macOS utun device implementation using kernel control interface
//!
//! This module implements native macOS TUN devices using the AF_SYSTEM socket
//! family with kernel control. This matches the Zig implementation in
//! ZigTapTun/src/platform/macos.zig

use anyhow::Result;
use log::{debug, info};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::task;

// macOS kernel control constants
const PF_SYSTEM: libc::c_int = 32;
const AF_SYS_CONTROL: u16 = 2;
const SYSPROTO_CONTROL: libc::c_int = 2;
const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
const UTUN_OPT_IFNAME: libc::c_int = 2;
const MAX_KCTL_NAME: usize = 96;

#[repr(C)]
struct ctl_info {
    ctl_id: u32,
    ctl_name: [u8; MAX_KCTL_NAME],
}

#[repr(C)]
struct sockaddr_ctl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

/// macOS utun device handle
pub struct MacOSUtun {
    fd: OwnedFd,
    name: String,
}

impl MacOSUtun {
    /// Open a new utun device
    ///
    /// Creates a native macOS utun device using the kernel control interface.
    /// The device will automatically get the next available utun number (utun0, utun1, etc.)
    ///
    /// Requires root privileges.
    pub fn open() -> Result<Self> {
        let fd = unsafe {
            // Create system socket for kernel control
            let fd = libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL);
            if fd < 0 {
                anyhow::bail!(
                    "Failed to create kernel control socket (need root): {}",
                    std::io::Error::last_os_error()
                );
            }

            // Get utun kernel control ID
            let mut info = std::mem::zeroed::<ctl_info>();
            info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);

            if libc::ioctl(fd, CTLIOCGINFO, &mut info as *mut ctl_info) < 0 {
                libc::close(fd);
                anyhow::bail!(
                    "Failed to get utun control info: {}",
                    std::io::Error::last_os_error()
                );
            }

            // Connect to utun kernel control
            // sc_unit = 0 means "allocate next available utun device"
            let mut addr = std::mem::zeroed::<sockaddr_ctl>();
            addr.sc_len = std::mem::size_of::<sockaddr_ctl>() as u8;
            addr.sc_family = 32; // AF_SYSTEM
            addr.ss_sysaddr = AF_SYS_CONTROL;
            addr.sc_id = info.ctl_id;
            addr.sc_unit = 0; // Auto-allocate next available

            if libc::connect(
                fd,
                &addr as *const sockaddr_ctl as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_ctl>() as u32,
            ) < 0
            {
                libc::close(fd);
                anyhow::bail!(
                    "Failed to connect to utun control: {}",
                    std::io::Error::last_os_error()
                );
            }

            // Get interface name
            let mut ifname = [0u8; 16];
            let mut ifname_len: libc::socklen_t = ifname.len() as u32;

            if libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                ifname.as_mut_ptr() as *mut libc::c_void,
                &mut ifname_len,
            ) < 0
            {
                libc::close(fd);
                anyhow::bail!(
                    "Failed to get utun interface name: {}",
                    std::io::Error::last_os_error()
                );
            }

            let name_str = std::str::from_utf8(&ifname[..ifname_len as usize])
                .unwrap_or("utun?")
                .trim_end_matches('\0')
                .to_string();

            info!("✓ Created utun device: {}", name_str);

            // Make non-blocking
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags >= 0 {
                let _ = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }

            (OwnedFd::from_raw_fd(fd), name_str)
        };

        Ok(Self {
            fd: fd.0,
            name: fd.1,
        })
    }

    /// Get the interface name (e.g., "utun0")
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read an IP packet from the utun device
    ///
    /// Returns the IP packet without the 4-byte protocol header.
    /// Returns None if no data is available (non-blocking).
    pub async fn read_packet(&self) -> Result<Option<Vec<u8>>> {
        let fd = self.fd.as_raw_fd();
        task::spawn_blocking(move || {
            // Poll with short timeout
            unsafe {
                let mut fds = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let rc = libc::poll(&mut fds as *mut libc::pollfd, 1, 100);
                if rc < 0 {
                    return Err(anyhow::anyhow!(
                        "utun poll error: {}",
                        std::io::Error::last_os_error()
                    ));
                } else if rc == 0 {
                    return Ok(None); // Timeout
                }
            }

            // Read from utun device
            let mut buffer = vec![0u8; 2048];
            let n = unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };

            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                return Err(anyhow::anyhow!("utun read error: {}", err));
            }
            if n == 0 {
                return Ok(None);
            }

            // utun packets include 4-byte protocol header (AF_INET or AF_INET6)
            // Strip this to get the raw IP packet
            if n < 4 {
                debug!("Short utun packet: {} bytes", n);
                return Ok(None);
            }

            buffer.truncate(n as usize);
            Ok(Some(buffer[4..].to_vec()))
        })
        .await
        .map_err(|e| anyhow::anyhow!("join error: {}", e))?
    }

    /// Write an IP packet to the utun device
    ///
    /// The 4-byte protocol header is automatically added based on IP version.
    pub async fn write_packet(&self, ip_packet: &[u8]) -> Result<()> {
        let fd = self.fd.as_raw_fd();
        let payload = ip_packet.to_vec();

        task::spawn_blocking(move || {
            // Determine protocol family from IP version
            let af_family: u32 = if !payload.is_empty() && (payload[0] & 0xF0) == 0x40 {
                2 // AF_INET (IPv4)
            } else if !payload.is_empty() && (payload[0] & 0xF0) == 0x60 {
                30 // AF_INET6 (IPv6)
            } else {
                return Err(anyhow::anyhow!("Invalid IP packet"));
            };

            // Prepend 4-byte protocol header (network byte order)
            let mut packet = Vec::with_capacity(4 + payload.len());
            packet.extend_from_slice(&af_family.to_be_bytes());
            packet.extend_from_slice(&payload);

            let n = unsafe { libc::write(fd, packet.as_ptr() as *const libc::c_void, packet.len()) };
            if n < 0 {
                return Err(anyhow::anyhow!(
                    "utun write error: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if n as usize != packet.len() {
                return Err(anyhow::anyhow!("utun write incomplete"));
            }
            Ok(())
        })
        .await
        .map_err(|e| anyhow::anyhow!("join error: {}", e))??;
        Ok(())
    }
}

impl Drop for MacOSUtun {
    fn drop(&mut self) {
        debug!("Closing utun device: {}", self.name);
        // OwnedFd will automatically close the file descriptor
    }
}
