//! TUN device adapter.
//!
//! This module provides cross-platform TUN device support
//! for routing VPN traffic.

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "macos")]
pub use macos::UtunDevice;

#[cfg(target_os = "linux")]
pub use linux::TunDevice;

#[cfg(target_os = "windows")]
pub use windows::WintunDevice;

use std::net::Ipv4Addr;

/// Platform-specific raw handle type for TUN devices.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub type TunHandle = std::os::fd::RawFd;

#[cfg(target_os = "windows")]
pub type TunHandle = std::sync::Arc<wintun::Session>;

/// Generic TUN device trait.
pub trait TunAdapter: Send + Sync {
    /// Get the device name.
    fn name(&self) -> &str;

    /// Read a packet from the device.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Write a packet to the device.
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>;

    /// Get the raw file descriptor (Unix) or handle (Windows).
    /// This is used for polling in the data loop.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn raw_fd(&self) -> std::os::fd::RawFd;

    /// Set the device MTU.
    fn set_mtu(&mut self, mtu: u16) -> std::io::Result<()>;

    /// Configure the device with an IP address.
    fn configure(&mut self, ip: Ipv4Addr, netmask: Ipv4Addr) -> std::io::Result<()>;

    /// Set the device as up.
    fn set_up(&mut self) -> std::io::Result<()>;

    /// Add a route through this device via a gateway IP.
    fn add_route(
        &self,
        dest: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Ipv4Addr,
    ) -> std::io::Result<()>;

    /// Add a route directly through this interface (no gateway IP needed).
    fn add_route_via_interface(&self, dest: Ipv4Addr, prefix_len: u8) -> std::io::Result<()>;

    /// Set as the default route.
    /// `vpn_server_ip` is used to add a host route for the VPN server through the original gateway
    /// to prevent routing loops.
    fn set_default_route(
        &self,
        gateway: Ipv4Addr,
        vpn_server_ip: Option<Ipv4Addr>,
    ) -> std::io::Result<()>;

    /// Configure DNS servers.
    /// This sets the system to use the specified DNS servers.
    fn configure_dns(&self, dns1: Option<Ipv4Addr>, dns2: Option<Ipv4Addr>) -> std::io::Result<()>;

    /// Restore original DNS configuration.
    fn restore_dns(&self) -> std::io::Result<()>;
}

/// Get the current default gateway.
/// Returns None if no default gateway is found.
pub fn get_default_gateway() -> Option<Ipv4Addr> {
    #[cfg(target_os = "macos")]
    {
        macos::get_default_gateway()
    }
    #[cfg(target_os = "linux")]
    {
        linux::get_default_gateway()
    }
    #[cfg(target_os = "windows")]
    {
        windows::get_default_gateway()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        None
    }
}
