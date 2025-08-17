//! Tunnel management for VPN connections

use anyhow::Result;
use tracing::{debug, info};
use tokio::process::Command;

/// VPN tunnel interface
pub struct Tunnel {
    interface_name: String,
    is_active: bool,
}

impl Tunnel {
    /// Create a new tunnel with the given interface name
    pub fn new(interface_name: String) -> Self {
        Self {
            interface_name,
            is_active: false,
        }
    }

    /// Start the tunnel
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting tunnel on interface: {}", self.interface_name);

        // Create TUN/TAP interface
        let output = Command::new("ip")
            .arg("tuntap")
            .arg("add")
            .arg("mode")
            .arg("tun")
            .arg("name")
            .arg(&self.interface_name)
            .output()
            .await?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to create TUN/TAP interface: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Configure IP address and routing
        let ip_output = Command::new("ip")
            .arg("addr")
            .arg("add")
            .arg("192.168.1.100/24")
            .arg("dev")
            .arg(&self.interface_name)
            .output()
            .await?;

        if !ip_output.status.success() {
            anyhow::bail!(
                "Failed to configure IP address: {}",
                String::from_utf8_lossy(&ip_output.stderr)
            );
        }

        let route_output = Command::new("ip")
            .arg("route")
            .arg("add")
            .arg("default")
            .arg("via")
            .arg("192.168.1.1")
            .output()
            .await?;

        if !route_output.status.success() {
            anyhow::bail!(
                "Failed to configure routing: {}",
                String::from_utf8_lossy(&route_output.stderr)
            );
        }

        self.is_active = true;
        debug!("Tunnel started successfully");

        Ok(())
    }

    /// Stop the tunnel
    pub async fn stop(&mut self) -> Result<()> {
        if !self.is_active {
            return Ok(());
        }

        info!("Stopping tunnel on interface: {}", self.interface_name);

        // Remove routes
        let route_output = Command::new("ip")
            .arg("route")
            .arg("del")
            .arg("default")
            .arg("dev")
            .arg(&self.interface_name)
            .output()
            .await?;

        if !route_output.status.success() {
            anyhow::bail!(
                "Failed to remove routes: {}",
                String::from_utf8_lossy(&route_output.stderr)
            );
        }

        // Destroy TUN/TAP interface
        let output = Command::new("ip")
            .arg("link")
            .arg("delete")
            .arg(&self.interface_name)
            .output()
            .await?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to destroy TUN/TAP interface: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        self.is_active = false;
        debug!("Tunnel stopped successfully");

        Ok(())
    }

    /// Check if the tunnel is active
    pub fn is_active(&self) -> bool {
        self.is_active
    }

    /// Get the interface name
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }
}

#[cfg(test)]
mod tests {
    // use super::*; // avoid unused import when adapter-tests feature is off
    // Requires privileged commands (ip tuntap). Enable with --features adapter-tests
    #[cfg(feature = "adapter-tests")]
    #[tokio::test]
    async fn test_tunnel_lifecycle() -> Result<()> {
        let mut tunnel = Tunnel::new("test0".to_string());

        assert!(!tunnel.is_active());
        assert_eq!(tunnel.interface_name(), "test0");

        tunnel.start().await?;
        assert!(tunnel.is_active());

        tunnel.stop().await?;
        assert!(!tunnel.is_active());

        Ok(())
    }
}
