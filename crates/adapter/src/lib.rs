//! Virtual network adapter management (crate)

use anyhow::Result;
use log::{debug, info};

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use tokio::process::Command;

#[cfg(target_os = "macos")]
use tun::Device as _; // bring trait for name()

#[cfg(target_os = "macos")]
use std::io::{Read, Write};
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "macos")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "macos")]
use tokio::task;

/// Virtual network adapter for VPN connections
pub struct VirtualAdapter {
    name: String,
    mac_address: Option<String>,
    is_created: bool,
    #[cfg(target_os = "macos")]
    dev: Option<Arc<Mutex<tun::platform::Device>>>,
}

impl VirtualAdapter {
    /// Create a new virtual adapter
    pub fn new(name: String, mac_address: Option<String>) -> Self {
        Self {
            name,
            mac_address,
            is_created: false,
            #[cfg(target_os = "macos")]
            dev: None,
        }
    }

    /// Create the virtual adapter
    pub async fn create(&mut self) -> Result<()> {
        info!("Creating virtual adapter: {}", self.name);

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

    /// Destroy the virtual adapter
    pub async fn destroy(&mut self) -> Result<()> {
        if !self.is_created {
            return Ok(());
        }
        info!("Destroying virtual adapter: {}", self.name);
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
    pub async fn set_ip_address(&self, ip: &str, netmask: &str) -> Result<()> {
        if !self.is_created {
            anyhow::bail!("Adapter not created");
        }
        info!("Setting IP address {}/{} on {}", ip, netmask, self.name);
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
    pub async fn add_route(&self, destination: &str, gateway: &str) -> Result<()> {
        if !self.is_created {
            anyhow::bail!("Adapter not created");
        }
        info!(
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
}

#[cfg(target_os = "macos")]
impl VirtualAdapter {
    async fn create_macos(&mut self) -> Result<()> {
        // Create utun using tun crate (SystemConfiguration/kern.control semantics)
        let config = tun::Configuration::default();
        // Let kernel pick the utunN name; we'll read it after open. Don't set address/netmask here on macOS.
        let dev =
            tun::create(&config).map_err(|e| anyhow::anyhow!("Failed to create utun: {}", e))?;
        let name = dev.name().ok().unwrap_or_else(|| "utun".to_string());
        self.name = name;
        // Bring interface up and set default MTU 1500
        let _ = Command::new("ifconfig")
            .arg(&self.name)
            .arg("up")
            .output()
            .await;
        let _ = Command::new("ifconfig")
            .arg(&self.name)
            .arg("mtu")
            .arg("1500")
            .output()
            .await;
        self.dev = Some(Arc::new(Mutex::new(dev)));
        self.is_created = true;
        info!("Created utun interface: {}", self.name);
        Ok(())
    }
    async fn destroy_macos(&mut self) -> Result<()> {
        // Drop the device; kernel will reclaim utun
        self.dev = None;
        let _ = Command::new("ifconfig")
            .arg(&self.name)
            .arg("down")
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

    /// Get a cloneable I/O handle for reading/writing frames on this utun device
    pub fn io_handle(&self) -> Result<AdapterIo> {
        if !self.is_created {
            anyhow::bail!("Adapter not created");
        }
        let inner = self
            .dev
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Device not initialized"))?
            .clone();
        Ok(AdapterIo {
            name: self.name.clone(),
            inner,
        })
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
pub struct AdapterIo {
    name: String,
    inner: Arc<Mutex<tun::platform::Device>>,
}

#[cfg(target_os = "macos")]
impl AdapterIo {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read a single frame from the utun device with a small timeout so it can be canceled.
    /// Returns Ok(Some(frame)) when data is available, Ok(None) on timeout (no data), or Err on hard errors.
    pub async fn read(&self) -> Result<Option<Vec<u8>>> {
        let inner = self.inner.clone();
        task::spawn_blocking(move || {
            // Poll the file descriptor with ~100ms timeout to avoid indefinite blocking
            let fd = { inner.lock().unwrap().as_raw_fd() };
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
                    // timeout
                    return Ok(None);
                }
            }
            // Ready to read
            let mut buf = vec![0u8; 65536];
            let n = {
                let mut dev = inner.lock().unwrap();
                dev.read(&mut buf)
                    .map_err(|e| anyhow::anyhow!("utun read error: {}", e))?
            };
            buf.truncate(n);
            Ok(Some(buf))
        })
        .await
        .map_err(|e| anyhow::anyhow!("join error: {}", e))?
    }

    /// Write a single frame to the utun device (blocking in a dedicated thread)
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        let inner = self.inner.clone();
        let payload = data.to_vec();
        task::spawn_blocking(move || {
            let mut dev = inner.lock().unwrap();
            dev.write_all(&payload)
                .map_err(|e| anyhow::anyhow!("utun write error: {}", e))
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
            .arg(&self.name)
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
