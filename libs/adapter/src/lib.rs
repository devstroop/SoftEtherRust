//! Virtual network adapter management for SoftEther VPN client
//!
//! This crate provides platform-specific virtual network adapter implementations
//! for VPN connections. On macOS, it uses native utun devices (Layer 3).
//! On Linux, it uses TUN interfaces. On Windows, it uses TAP.
//!
//! The adapter handles:
//! - Interface creation and destruction
//! - IP address and route configuration
//! - Packet I/O operations for bridging with VPN sessions
//! - L2/L3 protocol translation (Ethernet frames ↔ IP packets)

mod arp;
mod translator;

#[cfg(target_os = "macos")]
mod utun_macos;

pub use translator::{L2L3Translator, TranslatorOptions, TranslatorStats};

#[cfg(target_os = "macos")]
pub use utun_macos::MacOSUtun;

use anyhow::Result;
use log::{debug, info};

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use tokio::process::Command;

/// Virtual network adapter for VPN connections
///
/// Provides a unified interface for creating and managing virtual network interfaces
/// across different platforms. Handles interface lifecycle, network configuration,
/// and packet I/O operations.
pub struct VirtualAdapter {
    name: String,
    mac_address: Option<String>,
    is_created: bool,
    translator: L2L3Translator,
    #[cfg(target_os = "macos")]
    utun: Option<MacOSUtun>,
}

impl VirtualAdapter {
    /// Create a new virtual adapter instance
    ///
    /// # Arguments
    /// * `name` - Interface name (e.g., "feth0", "tun0")
    /// * `mac_address` - Optional MAC address string (e.g., "00:11:22:33:44:55")
    pub fn new(name: String, mac_address: Option<String>) -> Self {
        // Parse MAC address or use default
        let our_mac = if let Some(ref mac_str) = mac_address {
            parse_mac_address(mac_str).unwrap_or([0x5E, 0x00, 0x53, 0xFF, 0xFF, 0xFF])
        } else {
            [0x5E, 0x00, 0x53, 0xFF, 0xFF, 0xFF] // SoftEther default
        };
        
        let translator_opts = TranslatorOptions {
            our_mac,
            learn_ip: true,
            verbose: false,
        };
        
        Self {
            name,
            mac_address,
            is_created: false,
            translator: L2L3Translator::new(translator_opts),
            #[cfg(target_os = "macos")]
            utun: None,
        }
    }
    
    /// Get a reference to the L2/L3 translator
    pub fn translator(&self) -> &L2L3Translator {
        &self.translator
    }
    
    /// Get a mutable reference to the L2/L3 translator
    pub fn translator_mut(&mut self) -> &mut L2L3Translator {
        &mut self.translator
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

    /// Read an IP packet from the utun device (with L2→L3 translation)
    ///
    /// Reads an IP packet directly from the utun device. Since utun operates
    /// at Layer 3, no Ethernet header stripping is needed.
    ///
    /// Returns:
    /// - `Ok(Some(ip_packet))` - IP packet ready for processing
    /// - `Ok(None)` - No packet available
    /// - `Err(...)` - I/O error
    #[cfg(target_os = "macos")]
    pub async fn read_ip_packet(&mut self) -> Result<Option<Vec<u8>>> {
        let utun = self.utun.as_ref()
            .ok_or_else(|| anyhow::anyhow!("utun device not initialized"))?;
        
        utun.read_packet().await
    }
    
    /// Write an IP packet to the utun device (with L3→L2 translation)
    ///
    /// Writes an IP packet directly to the utun device. Since utun operates
    /// at Layer 3, no Ethernet header addition is needed.
    ///
    /// # Arguments
    /// * `ip_packet` - Raw IP packet (IPv4 or IPv6)
    #[cfg(target_os = "macos")]
    pub async fn write_ip_packet(&mut self, ip_packet: &[u8]) -> Result<()> {
        let utun = self.utun.as_ref()
            .ok_or_else(|| anyhow::anyhow!("utun device not initialized"))?;
        
        utun.write_packet(ip_packet).await
    }
}

#[cfg(target_os = "macos")]
impl VirtualAdapter {
    /// Create macOS utun device
    async fn create_macos(&mut self) -> Result<()> {
        let utun = MacOSUtun::open()?;
        self.name = utun.name().to_string();
        self.utun = Some(utun);
        info!("Created utun device: {}", self.name);
        Ok(())
    }
    
    /// Destroy macOS utun device
    async fn destroy_macos(&mut self) -> Result<()> {
        self.utun = None;
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

/// Parse a MAC address string (e.g., "00:11:22:33:44:55") into a byte array
fn parse_mac_address(mac_str: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow::anyhow!("Invalid MAC address format: {}", mac_str));
    }
    
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|e| anyhow::anyhow!("Invalid MAC address byte '{}': {}", part, e))?;
    }
    
    Ok(mac)
}
