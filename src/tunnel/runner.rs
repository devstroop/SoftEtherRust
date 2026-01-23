//! Tunnel runner - main packet processing loop.
//!
//! This module handles the actual VPN data plane:
//! - Create and configure TUN device
//! - DHCP discovery through tunnel
//! - ARP for gateway MAC discovery
//! - Bidirectional packet forwarding
//! - Multi-connection support for half-connection mode
//! - RC4 tunnel encryption (when UseFastRC4 is enabled)
//!
//! The implementation is split across several files:
//! - `runner.rs` (this file): Core TunnelRunner struct and entry points
//! - `dhcp_handler.rs`: DHCP handling for single and multi-connection modes
//! - `single_conn.rs`: Single-connection data loop (Unix + Windows)
//! - `multi_conn.rs`: Multi-connection data loop (half-connection mode)
//! - `packet_processor.rs`: Shared packet processing utilities

use std::net::Ipv4Addr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use tracing::{debug, info};

use crate::adapter::TunAdapter;
#[cfg(target_os = "linux")]
use crate::adapter::TunDevice;
#[cfg(target_os = "macos")]
use crate::adapter::UtunDevice;
#[cfg(target_os = "windows")]
use crate::adapter::WintunDevice;
use crate::client::{ConnectionManager, VpnConnection};
use crate::crypto::{Rc4KeyPair, TunnelEncryption};
use crate::error::{Error, Result};
use crate::packet::DhcpConfig;

/// Configuration for the tunnel runner.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// Keepalive interval in seconds.
    pub keepalive_interval: u64,
    /// DHCP timeout in seconds.
    pub dhcp_timeout: u64,
    /// TUN device MTU.
    pub mtu: u16,
    /// Whether to set default route (all traffic through VPN).
    pub default_route: bool,
    /// Routes to add automatically (CIDR prefix lengths).
    /// If empty, will auto-detect from DHCP and add VPN subnet route.
    pub routes: Vec<RouteConfig>,
    /// Whether to compress outgoing packets (must match auth setting).
    pub use_compress: bool,
    /// VPN server IP address (used for host route when default_route is true).
    pub vpn_server_ip: Option<Ipv4Addr>,
    /// RC4 key pair for tunnel encryption (UseFastRC4 mode).
    /// If None, either encryption is disabled or UseSSLDataEncryption is used (TLS handles it).
    pub rc4_key_pair: Option<Rc4KeyPair>,
}

/// Route configuration.
#[derive(Debug, Clone)]
pub struct RouteConfig {
    /// Destination network.
    pub dest: Ipv4Addr,
    /// Prefix length (e.g., 16 for /16).
    pub prefix_len: u8,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            keepalive_interval: 5,
            dhcp_timeout: 30,
            mtu: 1420,
            default_route: false,
            routes: Vec::new(),
            use_compress: false,
            vpn_server_ip: None,
            rc4_key_pair: None,
        }
    }
}

/// Generate a random MAC address with local/unicast bits set.
fn generate_mac() -> [u8; 6] {
    let mut mac = [0u8; 6];
    crate::crypto::fill_random(&mut mac);
    // Set local bit, clear multicast bit
    mac[0] = (mac[0] | 0x02) & 0xFE;
    mac
}

/// Tunnel runner handles the VPN data loop.
pub struct TunnelRunner {
    pub(super) config: TunnelConfig,
    pub(super) mac: [u8; 6],
    pub(super) running: Arc<AtomicBool>,
}

impl TunnelRunner {
    /// Create a new tunnel runner.
    pub fn new(config: TunnelConfig) -> Self {
        // Note: TLS encryption is ALWAYS active. RC4 is optional defense-in-depth.
        if config.rc4_key_pair.is_some() {
            info!("RC4 defense-in-depth enabled (TLS + RC4)");
        } else {
            debug!("RC4 defense-in-depth disabled (TLS encryption still active)");
        }

        Self {
            config,
            mac: generate_mac(),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Create encryption state if RC4 keys are configured.
    pub(super) fn create_encryption(&self) -> Option<TunnelEncryption> {
        self.config.rc4_key_pair.as_ref().map(TunnelEncryption::new)
    }

    /// Check if RC4 encryption is enabled.
    #[inline]
    pub fn is_encrypted(&self) -> bool {
        self.config.rc4_key_pair.is_some()
    }

    /// Get the running flag for external control.
    pub fn running(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }

    /// Run the tunnel data loop.
    ///
    /// This is the main entry point after authentication.
    /// It will:
    /// 1. Perform DHCP through the tunnel
    /// 2. Create and configure a TUN device
    /// 3. Run the packet forwarding loop
    pub async fn run(&mut self, conn: &mut VpnConnection) -> Result<()> {
        debug!(mac = %format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]),
            "Tunnel runner initialized");
        info!("Starting VPN tunnel");

        // Step 1: Perform DHCP to get IP configuration
        let dhcp_config = self.perform_dhcp(conn).await?;
        info!(ip = %dhcp_config.ip, gateway = ?dhcp_config.gateway, dns = ?dhcp_config.dns1,
            "DHCP configuration received");

        // Step 2: Create TUN device
        #[cfg(target_os = "macos")]
        let mut tun = UtunDevice::new(None)
            .map_err(|e| Error::TunDevice(format!("Failed to create TUN: {e}")))?;
        #[cfg(target_os = "linux")]
        let mut tun = TunDevice::new(None)
            .map_err(|e| Error::TunDevice(format!("Failed to create TUN: {}", e)))?;
        #[cfg(target_os = "windows")]
        let mut tun = WintunDevice::new(None)
            .map_err(|e| Error::TunDevice(format!("Failed to create TUN: {}", e)))?;
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        return Err(Error::TunDevice(
            "TUN device not supported on this platform".to_string(),
        ));

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        {
            debug!(device = %tun.name(), "TUN device created");

            // Step 3: Configure TUN device
            tun.configure(dhcp_config.ip, dhcp_config.netmask)
                .map_err(|e| Error::TunDevice(format!("Failed to configure TUN: {e}")))?;
            tun.set_up()
                .map_err(|e| Error::TunDevice(format!("Failed to bring up TUN: {e}")))?;
            tun.set_mtu(self.config.mtu)
                .map_err(|e| Error::TunDevice(format!("Failed to set MTU: {e}")))?;

            // Step 4: Set up routes
            self.configure_routes(&tun, &dhcp_config)?;

            info!(device = %tun.name(), ip = %dhcp_config.ip, mtu = self.config.mtu,
            "TUN interface configured");

            // Step 5: Run the data loop
            self.run_data_loop(conn, &mut tun, &dhcp_config).await
        }
    }

    /// Run the tunnel with multi-connection support.
    ///
    /// This is similar to `run()` but uses a ConnectionManager that can handle
    /// multiple TCP connections in half-connection mode.
    pub async fn run_multi(&mut self, conn_mgr: &mut ConnectionManager) -> Result<()> {
        debug!(mac = %format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]),
            "Tunnel runner initialized (multi-connection)");
        info!("Starting VPN tunnel with multiple connections");

        // Step 1: Establish additional connections BEFORE DHCP
        // In half-connection mode, the server won't respond until all connections are established
        if conn_mgr.needs_more_connections() {
            conn_mgr.establish_additional_connections().await?;
        }

        // Step 2: Perform DHCP to get IP configuration
        let dhcp_config = self.perform_dhcp_multi(conn_mgr).await?;
        info!(ip = %dhcp_config.ip, gateway = ?dhcp_config.gateway, dns = ?dhcp_config.dns1,
            "DHCP configuration received");

        // Additional connections already established above
        if conn_mgr.needs_more_connections() {
            conn_mgr.establish_additional_connections().await?;
        }

        // Step 3: Create TUN device
        #[cfg(target_os = "macos")]
        let mut tun = UtunDevice::new(None)
            .map_err(|e| Error::TunDevice(format!("Failed to create TUN: {e}")))?;
        #[cfg(target_os = "linux")]
        let mut tun = TunDevice::new(None)
            .map_err(|e| Error::TunDevice(format!("Failed to create TUN: {}", e)))?;
        #[cfg(target_os = "windows")]
        let mut tun = WintunDevice::new(None)
            .map_err(|e| Error::TunDevice(format!("Failed to create TUN: {}", e)))?;
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        return Err(Error::TunDevice(
            "TUN device not supported on this platform".to_string(),
        ));

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        {
            debug!(device = %tun.name(), "TUN device created");

            // Step 4: Configure TUN device
            tun.configure(dhcp_config.ip, dhcp_config.netmask)
                .map_err(|e| Error::TunDevice(format!("Failed to configure TUN: {e}")))?;
            tun.set_up()
                .map_err(|e| Error::TunDevice(format!("Failed to bring up TUN: {e}")))?;
            tun.set_mtu(self.config.mtu)
                .map_err(|e| Error::TunDevice(format!("Failed to set MTU: {e}")))?;

            // Step 5: Set up routes
            self.configure_routes(&tun, &dhcp_config)?;

            info!(device = %tun.name(), ip = %dhcp_config.ip, mtu = self.config.mtu,
            "TUN interface configured");

            // Step 6: Run the data loop with multi-connection support
            self.run_data_loop_multi(conn_mgr, &mut tun, &dhcp_config)
                .await
        }
    }

    /// Configure routes for VPN traffic.
    ///
    /// This sets up routing so traffic to the VPN subnet goes through the TUN device.
    fn configure_routes(&self, tun: &impl TunAdapter, dhcp_config: &DhcpConfig) -> Result<()> {
        // CRITICAL: If default route is requested, add the VPN server host route FIRST
        // This ensures the VPN connection itself doesn't get routed through the VPN
        if self.config.default_route {
            if let Some(gateway) = dhcp_config.gateway {
                // set_default_route adds the host route first internally, then the split-tunnel routes
                tun.set_default_route(gateway, self.config.vpn_server_ip)
                    .map_err(|e| Error::TunDevice(format!("Failed to set default route: {e}")))?;
            }
        }

        // If explicit routes are configured, use those
        if !self.config.routes.is_empty() {
            for route in &self.config.routes {
                tun.add_route_via_interface(route.dest, route.prefix_len)
                    .map_err(|e| Error::TunDevice(format!("Failed to add route: {e}")))?;
            }
        } else {
            // Auto-detect VPN subnet from DHCP config (only if default_route is false)
            // When default_route is true, all traffic goes through VPN anyway
            if !self.config.default_route {
                // Calculate network address from IP and netmask
                let ip_octets = dhcp_config.ip.octets();
                let mask_octets = dhcp_config.netmask.octets();

                // Calculate prefix length from netmask
                let prefix_len: u8 = mask_octets.iter().map(|b| b.count_ones() as u8).sum();

                // Calculate network address
                let network = Ipv4Addr::new(
                    ip_octets[0] & mask_octets[0],
                    ip_octets[1] & mask_octets[1],
                    ip_octets[2] & mask_octets[2],
                    ip_octets[3] & mask_octets[3],
                );

                // For typical VPN setups, we often want a broader route
                // If the netmask is /24 or smaller but IP looks like 10.x.x.x, use /16
                // This is a common pattern for SoftEther VPN
                let (route_network, route_prefix) = if ip_octets[0] == 10 && prefix_len >= 16 {
                    // Use /16 for 10.x.x.x networks
                    let net = Ipv4Addr::new(ip_octets[0], ip_octets[1], 0, 0);
                    (net, 16u8)
                } else if ip_octets[0] == 172
                    && (ip_octets[1] >= 16 && ip_octets[1] <= 31)
                    && prefix_len >= 12
                {
                    // Use /12 for 172.16-31.x.x networks
                    let net = Ipv4Addr::new(172, 16, 0, 0);
                    (net, 12u8)
                } else if ip_octets[0] == 192 && ip_octets[1] == 168 && prefix_len >= 16 {
                    // Use /16 for 192.168.x.x networks
                    let net = Ipv4Addr::new(192, 168, 0, 0);
                    (net, 16u8)
                } else {
                    // Use the exact network from DHCP
                    (network, prefix_len)
                };

                debug!(network = %route_network, prefix = route_prefix, "Adding VPN subnet route");
                tun.add_route_via_interface(route_network, route_prefix)
                    .map_err(|e| {
                        Error::TunDevice(format!("Failed to add VPN subnet route: {e}"))
                    })?;
            }
        }

        // Configure DNS servers from DHCP
        tun.configure_dns(dhcp_config.dns1, dhcp_config.dns2)
            .map_err(|e| Error::TunDevice(format!("Failed to configure DNS: {e}")))?;

        Ok(())
    }
}
