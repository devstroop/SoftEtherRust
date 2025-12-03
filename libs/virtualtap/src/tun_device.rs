//! Pure Rust TUN device implementation for macOS
//! 
//! Creates utun devices using ioctl syscalls without C dependencies

use std::os::unix::io::RawFd;
use std::ffi::CString;

const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
const MAX_PACKET_SIZE: usize = 2048;

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

pub struct TunDevice {
    fd: RawFd,
    name: String,
}

impl TunDevice {
    /// Create a new TUN device (utun) on macOS
    pub fn create() -> Result<Self, String> {
        unsafe {
            // Create socket for utun
            let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
            if fd < 0 {
                return Err(format!("Failed to create socket: {}", std::io::Error::last_os_error()));
            }

            // Get control ID for utun
            let mut ctl_info = std::mem::zeroed::<CtlInfo>();
            let control_name = CString::new(UTUN_CONTROL_NAME).unwrap();
            let name_bytes = control_name.as_bytes_with_nul();
            ctl_info.ctl_name[..name_bytes.len()].copy_from_slice(name_bytes);

            const CTLIOCGINFO: libc::c_ulong = 0xc0644e03; // ioctl code for CTLIOCGINFO
            
            if libc::ioctl(fd, CTLIOCGINFO, &mut ctl_info) < 0 {
                libc::close(fd);
                return Err(format!("Failed to get control info: {}", std::io::Error::last_os_error()));
            }

            // Connect to utun control (unit 0 = let kernel pick)
            let mut addr = std::mem::zeroed::<SockaddrCtl>();
            addr.sc_len = std::mem::size_of::<SockaddrCtl>() as u8;
            addr.sc_family = libc::AF_SYSTEM as u8;
            addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
            addr.sc_id = ctl_info.ctl_id;
            addr.sc_unit = 0; // Let kernel pick unit number

            if libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as u32,
            ) < 0 {
                libc::close(fd);
                return Err(format!("Failed to connect to utun control: {}", std::io::Error::last_os_error()));
            }

            // Get the assigned unit number
            let mut unit: u32 = 0;
            let mut unit_len: libc::socklen_t = std::mem::size_of::<u32>() as u32;
            
            const SYSPROTO_CONTROL: i32 = 2;
            const UTUN_OPT_IFNAME: i32 = 2;
            
            if libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                &mut unit as *mut _ as *mut libc::c_void,
                &mut unit_len,
            ) < 0 {
                // If we can't get the name, just use unit 0
                unit = 0;
            }

            let name = format!("utun{}", unit);
            
            // Set non-blocking mode for async I/O
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            if flags >= 0 {
                let _ = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
            
            Ok(TunDevice { fd, name })
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Read an IP packet from the TUN device
    pub fn read(&self) -> Result<Option<Vec<u8>>, String> {
        let mut buffer = vec![0u8; MAX_PACKET_SIZE];
        
        unsafe {
            let n = libc::read(self.fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len());
            
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(None); // Non-blocking, no data available
                }
                return Err(format!("TUN read error: {}", err));
            }
            
            if n == 0 {
                return Ok(None);
            }

            // macOS utun prepends 4-byte protocol family header
            if n < 4 {
                return Err("Packet too short".to_string());
            }

            // Skip the 4-byte header and return the IP packet
            buffer.truncate(n as usize);
            Ok(Some(buffer[4..].to_vec()))
        }
    }

    /// Write an IP packet to the TUN device
    pub fn write(&self, packet: &[u8]) -> Result<usize, String> {
        // macOS utun requires 4-byte protocol family header
        let mut buffer = Vec::with_capacity(4 + packet.len());
        
        // Determine protocol family from IP version
        let family = if !packet.is_empty() {
            let version = (packet[0] >> 4) & 0x0F;
            match version {
                4 => libc::AF_INET as u32,
                6 => libc::AF_INET6 as u32,
                _ => return Err("Invalid IP version".to_string()),
            }
        } else {
            return Err("Empty packet".to_string());
        };

        // Prepend 4-byte family header (network byte order)
        buffer.extend_from_slice(&family.to_be_bytes());
        buffer.extend_from_slice(packet);

        unsafe {
            let n = libc::write(self.fd, buffer.as_ptr() as *const libc::c_void, buffer.len());
            
            if n < 0 {
                return Err(format!("TUN write error: {}", std::io::Error::last_os_error()));
            }

            // Return number of IP packet bytes written (excluding 4-byte header)
            Ok((n as usize).saturating_sub(4))
        }
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

unsafe impl Send for TunDevice {}
unsafe impl Sync for TunDevice {}
