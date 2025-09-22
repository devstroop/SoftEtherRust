//! Virtual network adapter management for SoftEther VPN client
//!
//! This crate provides platform-specific virtual network adapter implementations
//! for VPN connections. On macOS, it uses feth interfaces with NDRV for writing
//! and BPF for reading. On Linux, it uses TUN interfaces. On Windows, it uses TAP.
//!
//! The adapter handles:
//! - Interface creation and destruction
//! - IP address and route configuration
//! - Packet I/O operations for bridging with VPN sessions

use anyhow::Result;
use log::{debug, info, warn};

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use tokio::process::Command;

#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "macos")]
use tokio::task;

/// Virtual network adapter for VPN connections
/// 
/// Provides a unified interface for creating and managing virtual network interfaces
/// across different platforms. Handles interface lifecycle, network configuration,
/// and packet I/O operations.
pub struct VirtualAdapter {
    name: String,
    mac_address: Option<String>,
    is_created: bool,
    #[cfg(target_os = "macos")]
    ndrv_fd: Option<std::os::fd::OwnedFd>,
    #[cfg(target_os = "macos")]
    bpf_fd: Option<std::os::fd::OwnedFd>,
}

impl VirtualAdapter {
    /// Create a new virtual adapter instance
    /// 
    /// # Arguments
    /// * `name` - Interface name (e.g., "feth0", "tun0")
    /// * `mac_address` - Optional MAC address string (e.g., "00:11:22:33:44:55")
    pub fn new(name: String, mac_address: Option<String>) -> Self {
        Self {
            name,
            mac_address,
            is_created: false,
            #[cfg(target_os = "macos")]
            ndrv_fd: None,
            #[cfg(target_os = "macos")]
            bpf_fd: None,
        }
    }

    /// Create the virtual adapter interface
    /// 
    /// Creates the platform-specific virtual network interface and initializes
    /// the necessary file descriptors for packet I/O operations.
    pub async fn create(&mut self) -> Result<()> {
        debug!("Creating virtual adapter: {}", self.name);

        #[cfg(target_os = "macos")]
        {
            self.create_macos().await?;
        }
        #[cfg(target_os = "linux")]
        {
            self.create_linux().await?;
        }
        #[cfg(target_os = "windows")]
        {
            self.create_windows().await?;
        }

        self.is_created = true;
        debug!("Virtual adapter created successfully");
        Ok(())
    }

    /// Destroy the virtual adapter interface
    /// 
    /// Cleans up the virtual interface and closes any open file descriptors.
    pub async fn destroy(&mut self) -> Result<()> {
        if !self.is_created {
            return Ok(());
        }
        debug!("Destroying virtual adapter: {}", self.name);
        #[cfg(target_os = "macos")]
        {
            self.destroy_macos().await?;
        }
        #[cfg(target_os = "linux")]
        {
            self.destroy_linux().await?;
        }
        #[cfg(target_os = "windows")]
        {
            self.destroy_windows().await?;
        }
        self.is_created = false;
        debug!("Virtual adapter destroyed successfully");
        Ok(())
    }

    /// Check if the adapter is created
    pub fn is_created(&self) -> bool {
        self.is_created
    }
    
    /// Get the adapter name
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Get the MAC address
    pub fn mac_address(&self) -> Option<&String> {
        self.mac_address.as_ref()
    }

    /// Set IP address and netmask
    /// 
    /// Configures the IPv4 address and subnet mask on the virtual interface.
    /// 
    /// # Arguments
    /// * `ip` - IP address string (e.g., "192.168.1.100")
    /// * `netmask` - Netmask string (e.g., "255.255.255.0")
    pub async fn set_ip_address(&self, ip: &str, netmask: &str) -> Result<()> {
        if !self.is_created {
            anyhow::bail!("Adapter not created");
        }
        debug!("Setting IP address {}/{} on {}", ip, netmask, self.name);
        #[cfg(target_os = "macos")]
        {
            self.set_ip_address_macos(ip, netmask).await?;
        }
        #[cfg(target_os = "linux")]
        {
            self.set_ip_address_linux(ip, netmask).await?;
        }
        #[cfg(target_os = "windows")]
        {
            self.set_ip_address_windows(ip, netmask).await?;
        }
        Ok(())
    }

    /// Add a route through this adapter
    /// 
    /// Adds a routing table entry that directs traffic to the specified destination
    /// through this virtual adapter.
    /// 
    /// # Arguments
    /// * `destination` - Destination network (e.g., "192.168.1.0/24" or "0.0.0.0/0")
    /// * `gateway` - Gateway IP address
    pub async fn add_route(&self, destination: &str, gateway: &str) -> Result<()> {
        if !self.is_created {
            anyhow::bail!("Adapter not created");
        }
        debug!(
            "Adding route {} via {} on {}",
            destination, gateway, self.name
        );
        #[cfg(target_os = "macos")]
        {
            self.add_route_macos(destination, gateway).await?;
        }
        #[cfg(target_os = "linux")]
        {
            self.add_route_linux(destination, gateway).await?;
        }
        #[cfg(target_os = "windows")]
        {
            self.add_route_windows(destination, gateway).await?;
        }
        Ok(())
    }

    /// Get a cloneable I/O handle for reading/writing frames on this utun device
    #[cfg(target_os = "macos")]
    pub fn io_handle(&self) -> Result<AdapterIo> {
        if !self.is_created {
            anyhow::bail!("Adapter not created");
        }
        // For non-macOS, not supported
        #[cfg(not(target_os = "macos"))]
        anyhow::bail!("Direct I/O not supported on this platform");
        #[cfg(target_os = "macos")]
        {
            let ndrv_owned = self.ndrv_fd.as_ref().ok_or_else(|| anyhow::anyhow!("NDRV fd not initialized"))?.try_clone()?;
            let bpf_owned = self.bpf_fd.as_ref().ok_or_else(|| anyhow::anyhow!("BPF fd not initialized"))?.try_clone()?;
            Ok(AdapterIo {
                name: self.name.clone(),
                ndrv_fd: ndrv_owned,
                bpf_fd: bpf_owned,
            })
        }
    }
}

#[cfg(target_os = "macos")]
impl VirtualAdapter {
    /// Create macOS feth interface pair with NDRV and BPF setup
    /// 
    /// Creates paired feth interfaces, sets up NDRV socket for writing packets
    /// to the network interface, and BPF device for reading packets from it.
    /// This follows the same approach as the Go implementation.
    async fn create_macos(&mut self) -> Result<()> {
        // For LocalBridge mode, we need Ethernet-level interface like feth
        // Create feth interface pair like Go implementation
        let feth_name = "feth0".to_string();
        let peer_name = format!("feth{}", 1024); // Use a fixed peer for simplicity

        // Destroy existing if any
        let _ = Command::new("ifconfig")
            .arg(&feth_name)
            .arg("destroy")
            .output()
            .await;
        let _ = Command::new("ifconfig")
            .arg(&peer_name)
            .arg("destroy")
            .output()
            .await;

        // Create feth interface
        let output = Command::new("ifconfig")
            .arg(&feth_name)
            .arg("create")
            .output()
            .await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to create feth interface: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Create peer
        let output = Command::new("ifconfig")
            .arg(&peer_name)
            .arg("create")
            .output()
            .await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to create feth peer: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Peer them
        let output = Command::new("ifconfig")
            .arg(&feth_name)
            .arg("peer")
            .arg(&peer_name)
            .output()
            .await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to peer feth interfaces: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Set MAC address if provided
        if let Some(mac) = &self.mac_address {
            let output = Command::new("ifconfig")
                .arg(&feth_name)
                .arg("lladdr")
                .arg(mac)
                .output()
                .await?;
            if !output.status.success() {
                warn!(
                    "Failed to set MAC address: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        // Bring up interfaces
        let output = Command::new("ifconfig")
            .arg(&feth_name)
            .arg("up")
            .output()
            .await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to bring up feth: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let output = Command::new("ifconfig")
            .arg(&peer_name)
            .arg("up")
            .output()
            .await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to bring up feth peer: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Small delay to let interfaces settle
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Set MTU
        let _ = Command::new("ifconfig")
            .arg(&feth_name)
            .arg("mtu")
            .arg("1500")
            .output()
            .await;

        // Create NDRV socket for writing
        let ndrv_fd = unsafe {
            let fd = libc::socket(27, libc::SOCK_RAW, 0); // AF_NDRV = 27
            if fd < 0 {
                anyhow::bail!("Failed to create NDRV socket");
            }

            // Make non-blocking
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                libc::close(fd);
                anyhow::bail!("Failed to set NDRV socket non-blocking");
            }

            // Bind to peer
            let mut sockaddr = [0u8; 18];
            sockaddr[0] = 18; // len
            sockaddr[1] = 27; // family
            let name_bytes = peer_name.as_bytes();
            for (i, &b) in name_bytes.iter().enumerate() {
                if i < 16 {
                    sockaddr[2 + i] = b;
                }
            }
            // Null terminate
            if name_bytes.len() < 16 {
                sockaddr[2 + name_bytes.len()] = 0;
            }

            if libc::bind(fd, sockaddr.as_ptr() as *const libc::sockaddr, 18) < 0 {
                libc::close(fd);
                anyhow::bail!("Failed to bind NDRV socket");
            }

            // Connect to peer
            if libc::connect(fd, sockaddr.as_ptr() as *const libc::sockaddr, 18) < 0 {
                libc::close(fd);
                anyhow::bail!("Failed to connect NDRV socket");
            }

            std::os::fd::OwnedFd::from_raw_fd(fd)
        };

        // Open BPF device and bind to peer_name
        let bpf_fd = unsafe {
            // Find available BPF device
            let mut fd = -1;
            for i in 0..64 {
                let path = format!("/dev/bpf{}", i);
                let c_path = std::ffi::CString::new(path).unwrap();
                fd = libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK);
                if fd >= 0 {
                    break;
                }
            }
            if fd < 0 {
                anyhow::bail!("No available BPF device");
            }

            // Set buffer length (optional)
            let buflen = 131072u32;
            if libc::ioctl(fd, 0x80044266, &buflen) < 0 { // BIOCSBLEN
                warn!("Failed to set BPF buffer length, continuing");
            }

            // Set immediate mode
            let immediate = 1u32;
            if libc::ioctl(fd, 0x80044270, &immediate) < 0 { // BIOCIMMEDIATE
                libc::close(fd);
                anyhow::bail!("Failed to set BPF immediate mode");
            }

            // Bind BPF to the peer interface (like Go implementation)
            let peer_name = format!("feth{}", 1024);
            // Small delay to ensure interface is ready
            std::thread::sleep(std::time::Duration::from_millis(10));
            if libc::ioctl(fd, 0x8020426c, peer_name.as_ptr() as *const libc::c_void) < 0 { // BIOCSETIF
                anyhow::bail!("Failed to bind BPF to interface {}", peer_name);
            }

            // Set header complete
            let hdr_cmpl = 1u32;
            if libc::ioctl(fd, 0x80044275, &hdr_cmpl) < 0 { // BIOCSHDRCMPLT
                libc::close(fd);
                anyhow::bail!("Failed to set BPF header complete");
            }

            // Set promiscuous mode (optional)
            let promisc = 1u32;
            if libc::ioctl(fd, 0x2000426d, &promisc) < 0 { // BIOCPROMISC
                warn!("Failed to set BPF promiscuous mode, continuing");
            }

            std::os::fd::OwnedFd::from_raw_fd(fd)
        };

        self.ndrv_fd = Some(ndrv_fd);
        self.bpf_fd = Some(bpf_fd);

        // Update self.name to the actual interface name
        self.name = feth_name;
        info!("Created feth interface: {}", self.name);
        Ok(())
    }
    /// Destroy macOS feth interfaces and close file descriptors
    async fn destroy_macos(&mut self) -> Result<()> {
        // Close NDRV and BPF fds
        self.ndrv_fd = None;
        self.bpf_fd = None;

        // Destroy feth interfaces
        let peer_name = format!("feth{}", 1024);
        let _ = Command::new("ifconfig")
            .arg(&self.name)
            .arg("destroy")
            .output()
            .await;
        let _ = Command::new("ifconfig")
            .arg(&peer_name)
            .arg("destroy")
            .output()
            .await;
        self.is_created = false;
        Ok(())
    }
    async fn set_ip_address_macos(&self, ip: &str, netmask: &str) -> Result<()> {
        let output = Command::new("ifconfig")
            .arg(&self.name)
            .arg("inet")
            .arg(ip)
            .arg(ip)
            .arg("netmask")
            .arg(netmask)
            .output()
            .await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to set IP address: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }
    async fn add_route_macos(&self, destination: &str, gateway: &str) -> Result<()> {
        // macOS expects 'route add default <gw>' for default route, and for networks '-net'.
        let mut cmd = Command::new("route");
        cmd.arg("add");
        if destination == "0.0.0.0/0" || destination == "default" {
            cmd.arg("default");
        } else {
            cmd.arg("-net").arg(destination);
        }
        let output = cmd.arg(gateway).output().await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to add route: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
/// Adapter I/O handle for packet reading and writing
/// 
/// Provides async packet I/O operations for virtual network adapters.
/// On macOS, uses NDRV for writing and BPF for reading.
pub struct AdapterIo {
    name: String,
    ndrv_fd: std::os::fd::OwnedFd,
    bpf_fd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "macos")]
impl AdapterIo {
    /// Get the adapter name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read a single Ethernet frame from the BPF device
    /// 
    /// Returns the next available Ethernet frame, or None if no data is available
    /// within the timeout period. Uses blocking I/O in a dedicated thread.
    pub async fn read_frame(&self) -> Result<Option<Vec<u8>>> {
        let fd = self.bpf_fd.as_raw_fd();
        task::spawn_blocking(move || {
            // Poll the file descriptor with ~100ms timeout to avoid indefinite blocking
            unsafe {
                let mut fds = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let rc = libc::poll(&mut fds as *mut libc::pollfd, 1, 100);
                if rc < 0 {
                    return Err(anyhow::anyhow!(
                        "BPF poll error: {}",
                        std::io::Error::last_os_error()
                    ));
                } else if rc == 0 {
                    // timeout
                    return Ok(None);
                }
            }
            // Ready to read
            let mut buf = vec![0u8; 65536];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                return Err(anyhow::anyhow!(
                    "BPF read error: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if n == 0 {
                return Ok(None);
            }
            // Skip BPF header (18 bytes on macOS)
            const BPF_HDR_LEN: usize = 18;
            if n < BPF_HDR_LEN as isize {
                return Ok(None);
            }
            let frame_len = n as usize - BPF_HDR_LEN;
            buf.truncate(frame_len);
            Ok(Some(buf))
        })
        .await
        .map_err(|e| anyhow::anyhow!("join error: {}", e))?
    }

    /// Write a single Ethernet frame to the NDRV device
    /// 
    /// Sends an Ethernet frame to the network interface using the NDRV socket.
    /// Uses blocking I/O in a dedicated thread.
    pub async fn write_frame(&self, data: &[u8]) -> Result<()> {
        let fd = self.ndrv_fd.as_raw_fd();
        let payload = data.to_vec();
        task::spawn_blocking(move || {
            let n = unsafe { libc::write(fd, payload.as_ptr() as *const libc::c_void, payload.len()) };
            if n < 0 {
                return Err(anyhow::anyhow!(
                    "NDRV write error: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if n as usize != payload.len() {
                return Err(anyhow::anyhow!("NDRV write incomplete"));
            }
            Ok(())
        })
        .await
        .map_err(|e| anyhow::anyhow!("join error: {}", e))??;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl VirtualAdapter {
    async fn create_linux(&mut self) -> Result<()> {
        let output = Command::new("ip")
            .arg("tuntap")
            .arg("add")
            .arg("mode")
            .arg("tun")
            .arg("name")
            .arg(&self.name)
            .output()
            .await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to create TUN interface: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        self.is_created = true;
        Ok(())
    }
    async fn destroy_linux(&mut self) -> Result<()> {
        let output = Command::new("ip")
            .arg("link")
            .arg("delete")
            .arg(&self.name)
            .output()
            .await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to delete TUN interface: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        self.is_created = false;
        Ok(())
    }
    async fn set_ip_address_linux(&self, ip: &str, netmask: &str) -> Result<()> {
        fn dotted_to_prefix(mask: &str) -> Result<u8> {
            let parts: Vec<&str> = mask.split('.').collect();
            if parts.len() != 4 {
                anyhow::bail!("Invalid netmask format: {}", mask);
            }
            let mut bits = 0u8;
            for p in parts {
                let v: u8 = p
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid netmask octet: {}", p))?;
                bits += v.count_ones() as u8;
            }
            Ok(bits)
        }
        let prefix = if netmask.contains('.') {
            dotted_to_prefix(netmask)?
        } else {
            netmask
                .parse::<u8>()
                .map_err(|_| anyhow::anyhow!("Invalid prefix length: {}", netmask))?
        };
        let output = Command::new("ip")
            .arg("addr")
            .arg("add")
            .arg(format!("{}/{}", ip, prefix))
            .arg("dev")
            .arg(&self.name)
            .output()
            .await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to set IP address: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let up = Command::new("ip")
            .arg("link")
            .arg("set")
            .arg("dev")
            .arg(&self.name)
            .arg("up")
            .output()
            .await?;
        if !up.status.success() {
            anyhow::bail!(
                "Failed to bring interface up: {}",
                String::from_utf8_lossy(&up.stderr)
            );
        }
        Ok(())
    }
    async fn add_route_linux(&self, destination: &str, gateway: &str) -> Result<()> {
        let output = Command::new("ip")
            .arg("route")
            .arg("add")
            .arg(destination)
            .arg("via")
            .arg(gateway)
            .arg("dev")
            .arg(&self.name)
            .output()
            .await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to add route: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl VirtualAdapter {
    async fn create_windows(&mut self) -> Result<()> {
        let output = Command::new("tapinstall")
            .arg("install")
            .arg("OemVista.inf")
            .arg(&self.name)
            .output()
            .await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to create TAP-Windows adapter: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        self.is_created = true;
        Ok(())
    }
    async fn destroy_windows(&mut self) -> Result<()> {
        let output = Command::new("tapinstall")
            .arg("remove")
            .arg(&self.name)
            .output()
            .await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to remove TAP-Windows adapter: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        self.is_created = false;
        Ok(())
    }
    async fn set_ip_address_windows(&self, ip: &str, netmask: &str) -> Result<()> {
        let output = Command::new("netsh")
            .arg("interface")
            .arg("ip")
            .arg("set")
            .arg("address")
            .arg("static")
            .arg(ip)
            .arg(netmask)
            .output()
            .await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to set IP address: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }
    async fn add_route_windows(&self, destination: &str, gateway: &str) -> Result<()> {
        let output = Command::new("route")
            .arg("add")
            .arg(destination)
            .arg(gateway)
            .arg("metric")
            .arg("1")
            .output()
            .await?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to add route: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }
}
