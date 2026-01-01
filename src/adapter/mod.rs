//! TUN device adapter.
//!
//! This module provides cross-platform TUN device support
//! for routing VPN traffic.

#[cfg(target_os = "macos")]
mod utun;

#[cfg(target_os = "linux")]
mod tun_linux;

#[cfg(target_os = "macos")]
pub use utun::UtunDevice;

#[cfg(target_os = "linux")]
pub use tun_linux::TunDevice;

use std::net::Ipv4Addr;

/// Generic TUN device trait.
pub trait TunAdapter: Send + Sync {
    /// Get the device name.
    fn name(&self) -> &str;

    /// Read a packet from the device.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Write a packet to the device.
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>;

    /// Set the device MTU.
    fn set_mtu(&mut self, mtu: u16) -> std::io::Result<()>;

    /// Configure the device with an IP address.
    fn configure(&mut self, ip: Ipv4Addr, netmask: Ipv4Addr) -> std::io::Result<()>;

    /// Set the device as up.
    fn set_up(&mut self) -> std::io::Result<()>;

    /// Add a route through this device via a gateway IP.
    fn add_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr) -> std::io::Result<()>;

    /// Add a route directly through this interface (no gateway IP needed).
    fn add_route_via_interface(&self, dest: Ipv4Addr, prefix_len: u8) -> std::io::Result<()>;

    /// Set as the default route.
    /// `vpn_server_ip` is used to add a host route for the VPN server through the original gateway
    /// to prevent routing loops.
    fn set_default_route(&self, gateway: Ipv4Addr, vpn_server_ip: Option<Ipv4Addr>) -> std::io::Result<()>;

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
        utun::get_default_gateway()
    }
    #[cfg(target_os = "linux")]
    {
        tun_linux::get_default_gateway()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}
