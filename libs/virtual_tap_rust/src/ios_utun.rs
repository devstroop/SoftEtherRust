//! iOS utun device interface
//!
//! Provides safe Rust bindings to the iOS utun (userspace tunnel) device.
//! This replaces the C-based implementation with pure Rust using nix crate.

use crate::error::VTapError;
use crate::packet::EthernetFrame;
use anyhow::Result;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tracing::{debug, info, warn};

// iOS utun control constants
const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;
const SYSPROTO_CONTROL: libc::c_int = 2;
const AF_SYS_CONTROL: libc::c_int = 2;
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

/// utun device control info structure
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [libc::c_char; 96],
}

/// Socket address for system control protocol
#[repr(C)]
struct SockaddrCtl {
    sc_len: libc::c_uchar,
    sc_family: libc::c_uchar,
    ss_sysaddr: libc::c_ushort,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

/// iOS utun device
///
/// Represents a userspace tunnel device on iOS. Provides:
/// - Automatic device creation and cleanup
/// - Async packet I/O
/// - Raw access to file descriptor
pub struct IosUtunDevice {
    /// File descriptor for the utun device
    fd: OwnedFd,
    
    /// Interface name (e.g., "utun3")
    name: String,
    
    /// Unit number (e.g., 3 for "utun3")
    unit: u32,
}

impl IosUtunDevice {
    /// Create a new utun device
    ///
    /// Automatically allocates the next available utun device number.
    /// The device will be closed when dropped.
    pub fn create() -> Result<Self> {
        Self::create_with_unit(0) // 0 = auto-allocate
    }
    
    /// Create a utun device with specific unit number
    ///
    /// # Arguments
    ///
    /// * `unit` - Unit number (0 for auto-allocate, 1-255 for specific)
    pub fn create_with_unit(unit: u32) -> Result<Self> {
        info!("Creating iOS utun device (unit: {})", if unit == 0 { "auto".to_string() } else { unit.to_string() });
        
        // Create control socket
        let fd = unsafe {
            let raw_fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL);
            if raw_fd < 0 {
                return Err(VTapError::UtunCreation(
                    format!("Failed to create control socket: {}", std::io::Error::last_os_error())
                ).into());
            }
            OwnedFd::from_raw_fd(raw_fd)
        };
        
        // Get utun control ID
        let ctl_id = Self::get_utun_control_id(fd.as_raw_fd())?;
        debug!("Got utun control ID: {}", ctl_id);
        
        // Connect to utun control
        let actual_unit = Self::connect_utun_control(fd.as_raw_fd(), ctl_id, unit)?;
        let name = format!("utun{}", actual_unit);
        
        info!("Created utun device: {} (fd: {})", name, fd.as_raw_fd());
        
        Ok(Self {
            fd,
            name,
            unit: actual_unit,
        })
    }
    
    /// Get the utun control ID
    fn get_utun_control_id(fd: RawFd) -> Result<u32> {
        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        
        // Copy control name
        let name_bytes = UTUN_CONTROL_NAME;
        info.ctl_name[..name_bytes.len()].copy_from_slice(
            unsafe { std::slice::from_raw_parts(name_bytes.as_ptr() as *const i8, name_bytes.len()) }
        );
        
        unsafe {
            if libc::ioctl(fd, CTLIOCGINFO, &mut info as *mut _ as *mut libc::c_void) < 0 {
                return Err(VTapError::UtunCreation(
                    format!("Failed to get utun control info: {}", std::io::Error::last_os_error())
                ).into());
            }
        }
        
        Ok(info.ctl_id)
    }
    
    /// Connect to the utun control
    fn connect_utun_control(fd: RawFd, ctl_id: u32, requested_unit: u32) -> Result<u32> {
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYS_CONTROL as u8,
            ss_sysaddr: AF_SYS_CONTROL as u16,
            sc_id: ctl_id,
            sc_unit: requested_unit,
            sc_reserved: [0; 5],
        };
        
        unsafe {
            if libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as u32,
            ) < 0 {
                return Err(VTapError::UtunCreation(
                    format!("Failed to connect to utun control: {}", std::io::Error::last_os_error())
                ).into());
            }
        }
        
        // If auto-allocate (unit=0), get actual unit number from socket name
        let actual_unit = if requested_unit == 0 {
            Self::get_socket_unit(fd)?
        } else {
            requested_unit
        };
        
        Ok(actual_unit)
    }
    
    /// Get the actual unit number from the connected socket
    fn get_socket_unit(fd: RawFd) -> Result<u32> {
        let mut addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: 0,
            ss_sysaddr: 0,
            sc_id: 0,
            sc_unit: 0,
            sc_reserved: [0; 5],
        };
        
        let mut len = std::mem::size_of::<SockaddrCtl>() as u32;
        
        unsafe {
            if libc::getsockname(
                fd,
                &mut addr as *mut _ as *mut libc::sockaddr,
                &mut len,
            ) < 0 {
                return Err(VTapError::UtunCreation(
                    format!("Failed to get socket name: {}", std::io::Error::last_os_error())
                ).into());
            }
        }
        
        // Unit number is sc_unit - 1 (kernel adds 1)
        Ok(addr.sc_unit.saturating_sub(1))
    }
    
    /// Get the interface name
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Get the unit number
    pub fn unit(&self) -> u32 {
        self.unit
    }
    
    /// Get the raw file descriptor
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
    
    /// Read a packet from the utun device
    ///
    /// Returns None if no packet is available (non-blocking)
    pub async fn read_packet(&self) -> Result<Option<EthernetFrame>> {
        let mut buffer = vec![0u8; 65536]; // Max IP packet size
        
        // Set non-blocking mode
        unsafe {
            let flags = libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        };
        
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(err.into());
        }
        
        if n == 0 {
            return Ok(None);
        }
        
        // iOS utun prepends 4-byte protocol family
        if n < 4 {
            warn!("Received packet too short: {} bytes", n);
            return Ok(None);
        }
        
        let data = buffer[4..n as usize].to_vec();
        Ok(Some(EthernetFrame::from_ip_packet(data)?))
    }
    
    /// Write a packet to the utun device
    pub async fn write_packet(&self, frame: &EthernetFrame) -> Result<()> {
        // Extract IP packet from Ethernet frame
        let ip_packet = frame.ip_payload()?;
        
        // Prepend 4-byte protocol family (AF_INET or AF_INET6)
        let protocol_family = if ip_packet[0] >> 4 == 4 {
            libc::AF_INET as u32
        } else {
            libc::AF_INET6 as u32
        };
        
        let mut buffer = Vec::with_capacity(4 + ip_packet.len());
        buffer.extend_from_slice(&protocol_family.to_be_bytes());
        buffer.extend_from_slice(&ip_packet);
        
        let n = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                buffer.as_ptr() as *const libc::c_void,
                buffer.len(),
            )
        };
        
        if n < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        
        if n as usize != buffer.len() {
            warn!("Partial write: {} of {} bytes", n, buffer.len());
        }
        
        Ok(())
    }
}

impl Drop for IosUtunDevice {
    fn drop(&mut self) {
        info!("Closing utun device: {}", self.name);
    }
}
