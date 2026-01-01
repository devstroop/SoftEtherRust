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
    fn configure(&mut self, ip: std::net::Ipv4Addr, netmask: std::net::Ipv4Addr) -> std::io::Result<()>;

    /// Set the device as up.
    fn set_up(&mut self) -> std::io::Result<()>;

    /// Add a route through this device via a gateway IP.
    fn add_route(&self, dest: std::net::Ipv4Addr, netmask: std::net::Ipv4Addr, gateway: std::net::Ipv4Addr) -> std::io::Result<()>;

    /// Add a route directly through this interface (no gateway IP needed).
    fn add_route_via_interface(&self, dest: std::net::Ipv4Addr, prefix_len: u8) -> std::io::Result<()>;

    /// Set as the default route.
    fn set_default_route(&self, gateway: std::net::Ipv4Addr) -> std::io::Result<()>;
}
