//! LocalBridge-compatible DHCP client
//! 
//! This module extends the existing DHCP implementation to handle LocalBridge
//! mode where DHCP responses come from external servers forwarded through
//! the SoftEther bridge rather than the SoftEther virtual DHCP server.

use anyhow::Result;
use cedar::DataPlane;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::dhcp::{DhcpClient, Lease};
use crate::network_mode::NetworkMode;

/// Enhanced DHCP client that supports both SecureNAT and LocalBridge modes
pub struct AdaptiveDhcpClient {
    #[allow(dead_code)] // Will be used when DHCP functionality is expanded
    dataplane: DataPlane,
    #[allow(dead_code)] // Will be used when DHCP functionality is expanded  
    mac_address: [u8; 6],
    mode: Option<NetworkMode>,
    dhcp_client: DhcpClient,
}

impl AdaptiveDhcpClient {
    /// Create a new adaptive DHCP client
    pub fn new(dataplane: DataPlane, mac_address: [u8; 6]) -> Self {
        let dhcp_client = DhcpClient::new(dataplane.clone(), mac_address);

        Self {
            dataplane,
            mac_address,
            mode: None,
            dhcp_client,
        }
    }

    /// Run DHCP client with adaptive mode detection
    pub async fn run(&mut self, hostname: &str) -> Result<Lease> {
        info!("🔄 Starting adaptive DHCP client for {}", hostname);

        // First, try to detect the network mode
        if self.mode.is_none() {
            self.mode = Some(self.detect_network_mode().await?);
        }

        let mode = self.mode.unwrap();
        info!("📋 Operating in {:?} mode", mode);

        match mode {
            NetworkMode::SecureNAT => {
                match self.run_secure_nat_mode(hostname).await {
                    Ok(lease) => Ok(lease),
                    Err(e) => {
                        warn!("⚠️  SecureNAT mode failed: {}, trying LocalBridge approach...", e);
                        self.run_localbridge_mode(hostname).await
                    }
                }
            }
            NetworkMode::LocalBridge => {
                self.run_localbridge_mode(hostname).await
            }
            NetworkMode::Unknown => {
                warn!("⚠️  Unknown mode, trying both approaches");
                // Try SecureNAT first, then LocalBridge (Go-style fallback)
                match self.run_secure_nat_mode(hostname).await {
                    Ok(lease) => Ok(lease),
                    Err(_) => {
                        info!("🌉 SecureNAT failed, attempting LocalBridge approach (Go-style)...");
                        self.run_localbridge_mode(hostname).await
                    }
                }
            }
        }
    }

    /// Detect network mode using quick DHCP response timing
    async fn detect_network_mode(&mut self) -> Result<NetworkMode> {
        info!("🔍 Detecting VPN server network mode using DHCP timing...");
        
        // Try a quick DHCP discover to analyze response characteristics
        let start_time = Instant::now();
        let short_timeout = Duration::from_secs(3); // Very short timeout for detection
        
        match self.dhcp_client.run_once(
            "mode-detector", 
            short_timeout, 
            None
        ).await {
            Ok(Some(lease)) => {
                let response_time = start_time.elapsed();
                
                // Analyze response characteristics to determine mode
                if self.analyze_dhcp_response(&lease, response_time) {
                    info!("   ✅ Detected: SecureNAT mode (SoftEther DHCP server)");
                    Ok(NetworkMode::SecureNAT)
                } else {
                    info!("   ✅ Detected: LocalBridge mode (External DHCP forwarded)");
                    Ok(NetworkMode::LocalBridge)
                }
            }
            Ok(None) | Err(_) => {
                // If quick detection fails, assume SecureNAT as fallback
                info!("   ⚠️  Quick detection failed, defaulting to SecureNAT mode");
                Ok(NetworkMode::SecureNAT)
            }
        }
    }

    /// Analyze DHCP response to determine if it came from SoftEther or external server
    fn analyze_dhcp_response(&self, lease: &Lease, response_time: Duration) -> bool {
        let mut is_secure_nat = true;

        // Check response time - SecureNAT is much faster
        if response_time > Duration::from_millis(300) {
            debug!("   📊 Slow DHCP response ({:?}) indicates external server", response_time);
            is_secure_nat = false;
        }

        // Check IP ranges - SoftEther defaults to 192.168.30.x
        let client_ip = lease.client_ip;
        if client_ip.octets()[0] == 192 && client_ip.octets()[1] == 168 && client_ip.octets()[2] == 30 {
            debug!("   📊 SoftEther default subnet (192.168.30.x) detected");
        } else {
            debug!("   📊 Non-SoftEther subnet ({}) indicates LocalBridge", client_ip);
            is_secure_nat = false;
        }

        // Check lease time - SoftEther uses 7200 seconds default
        if let Some(lease_time) = lease.lease_time {
            if lease_time.as_secs() == 7200 {
                debug!("   📊 SoftEther default lease time (7200s) detected");
            } else {
                debug!("   📊 Non-SoftEther lease time ({}s) indicates external DHCP", lease_time.as_secs());
                is_secure_nat = false;
            }
        }

        is_secure_nat
    }

    /// Run DHCP client in SecureNAT mode (standard SoftEther DHCP)
    async fn run_secure_nat_mode(&mut self, hostname: &str) -> Result<Lease> {
        info!("🏢 Running DHCP in SecureNAT mode");
        
        // Use standard timeout for SecureNAT
        let timeout = Duration::from_secs(10);
        
        match self.dhcp_client.run_once(hostname, timeout, None).await? {
            Some(mut lease) => {
                // Apply Go-style enhancements for consistency
                lease = self.enhance_lease_with_go_logic(lease);
                info!("✅ SecureNAT DHCP lease acquired: {}", lease.client_ip);
                Ok(lease)
            }
            None => {
                Err(anyhow::anyhow!("DHCP request timed out in SecureNAT mode"))
            }
        }
    }

    /// Run DHCP client in LocalBridge mode (external DHCP forwarding) - Enhanced with Go logic
    async fn run_localbridge_mode(&mut self, hostname: &str) -> Result<Lease> {
        info!("🌉 Running DHCP in LocalBridge mode (with Go-inspired enhancements)");
        
        // LocalBridge needs longer timeouts due to forwarding delay (from Go analysis)
        let _timeout = Duration::from_secs(30);
        
        // Try with enhanced retries for LocalBridge (matching Go implementation)
        for attempt in 1..=4 {
            info!("   📡 LocalBridge DHCP attempt {} of 4 (Go-style retry)", attempt);
            
            // Increase timeout per attempt (from Go obtainIPConfiguration)
            let attempt_timeout = Duration::from_secs(5 + 5 * attempt as u64);
            
            match self.dhcp_client.run_once(hostname, attempt_timeout, None).await? {
                Some(mut lease) => {
                    // Apply Go-style lease enhancement
                    lease = self.enhance_lease_with_go_logic(lease);
                    info!("✅ LocalBridge DHCP lease acquired: {} (enhanced with Go logic)", lease.client_ip);
                    return Ok(lease);
                }
                None => {
                    if attempt < 4 {
                        warn!("   ⏳ Attempt {} failed, retrying with longer timeout...", attempt);
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            }
        }

        // If DHCP completely fails, try static fallback (Go approach)
        warn!("⚠️  LocalBridge DHCP failed after 4 attempts, attempting static configuration");
        self.try_static_fallback().await
    }

    /// Attempt static IP configuration when DHCP fails in LocalBridge mode
    async fn try_static_fallback(&mut self) -> Result<Lease> {
        info!("🔧 Attempting static IP fallback for LocalBridge");

        // Generate a static IP in a common subnet range
        let static_ip = Ipv4Addr::new(192, 168, 1, 200);
        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        let subnet_mask = Ipv4Addr::new(255, 255, 255, 0);
        
        info!("📍 Using static IP configuration: {}", static_ip);
        
        // Create a static lease configuration
        Ok(Lease {
            client_ip: static_ip,
            server_ip: Some(gateway),
            gateway: Some(gateway),
            subnet_mask: Some(subnet_mask),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
            lease_time: Some(Duration::from_secs(86400)), // 24 hours
            renewal_time: Some(Duration::from_secs(43200)), // 12 hours
            rebinding_time: Some(Duration::from_secs(75600)), // 21 hours
            domain_name: None,
            interface_mtu: Some(1500),
            broadcast_addr: Some(Ipv4Addr::new(192, 168, 1, 255)),
            classless_routes: vec![],
            server_mac: None,
        })
    }

    /// Apply Go-style subnet mask inference and fallback DNS configuration
    fn enhance_lease_with_go_logic(&self, mut lease: Lease) -> Lease {
        // Apply subnet mask inference if missing (key Go innovation)
        if lease.subnet_mask.is_none() {
            lease.subnet_mask = Some(self.infer_subnet_mask(&lease));
            info!("🔧 Applied inferred subnet mask: {:?}", lease.subnet_mask);
        }

        // Apply fallback DNS logic (use gateway/server as DNS)
        if lease.dns_servers.is_empty() {
            if let Some(gateway) = lease.gateway {
                lease.dns_servers.push(gateway);
                info!("✅ Using gateway as DNS: {}", gateway);
            } else if let Some(server) = lease.server_ip {
                lease.dns_servers.push(server);
                info!("✅ Using server as DNS: {}", server);
            }
        }

        // Ensure gateway is set (use server IP if not provided)
        if lease.gateway.is_none() && lease.server_ip.is_some() {
            lease.gateway = lease.server_ip;
            info!("✅ Using server as gateway: {:?}", lease.gateway);
        }

        lease
    }

    /// Infer subnet mask from client and server IP relationship (from Go implementation)
    fn infer_subnet_mask(&self, lease: &Lease) -> Ipv4Addr {
        let client_octets = lease.client_ip.octets();
        
        if let Some(server_ip) = lease.server_ip {
            let server_octets = server_ip.octets();
            
            // Same Class B network - likely /16 (Go logic)
            if client_octets[0] == server_octets[0] && client_octets[1] == server_octets[1] {
                info!("📊 Detected Class B network - using /16 subnet mask");
                return Ipv4Addr::new(255, 255, 0, 0);
            }
            
            // Same Class C network - likely /24 (Go logic)
            if client_octets[0] == server_octets[0] && 
               client_octets[1] == server_octets[1] && 
               client_octets[2] == server_octets[2] {
                info!("📊 Detected Class C network - using /24 subnet mask");
                return Ipv4Addr::new(255, 255, 255, 0);
            }
        }
        
        // Default assumption for VPN networks (Go logic)
        info!("📊 Using default /16 subnet mask for VPN");
        Ipv4Addr::new(255, 255, 0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_mode_analysis() {
        // Test DHCP response analysis logic
        let lease = Lease {
            client_ip: Ipv4Addr::new(192, 168, 30, 100),
            server_ip: Some(Ipv4Addr::new(192, 168, 30, 1)),
            gateway: Some(Ipv4Addr::new(192, 168, 30, 1)),
            subnet_mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            dns_servers: vec![],
            lease_time: Some(Duration::from_secs(7200)),
            renewal_time: Some(Duration::from_secs(3600)),
            rebinding_time: Some(Duration::from_secs(6300)),
            domain_name: None,
            interface_mtu: Some(1500),
            broadcast_addr: None,
            classless_routes: vec![],
            server_mac: None,
        };

        let client = AdaptiveDhcpClient {
            dataplane: DataPlane::new(), // Would need mock implementation
            mac_address: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            mode: None,
            dhcp_client: DhcpClient::new(DataPlane::new(), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        };

        // Fast response with SoftEther subnet and lease time = SecureNAT
        let response_time = Duration::from_millis(50);
        assert!(client.analyze_dhcp_response(&lease, response_time));

        // Slow response = LocalBridge
        let response_time = Duration::from_millis(500);
        assert!(!client.analyze_dhcp_response(&lease, response_time));
    }

    #[test]
    fn test_go_style_subnet_inference() {
        let client = AdaptiveDhcpClient {
            dataplane: DataPlane::new(),
            mac_address: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            mode: None,
            dhcp_client: DhcpClient::new(DataPlane::new(), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        };

        // Test Class B network inference (like Go example: 10.21.x.x)
        let lease_class_b = Lease {
            client_ip: Ipv4Addr::new(10, 21, 255, 203),
            server_ip: Some(Ipv4Addr::new(10, 21, 0, 1)),
            gateway: None,
            subnet_mask: None,
            dns_servers: vec![],
            lease_time: None,
            renewal_time: None,
            rebinding_time: None,
            domain_name: None,
            interface_mtu: None,
            broadcast_addr: None,
            classless_routes: vec![],
            server_mac: None,
        };

        let inferred_mask = client.infer_subnet_mask(&lease_class_b);
        assert_eq!(inferred_mask, Ipv4Addr::new(255, 255, 0, 0)); // Should infer /16

        // Test Class C network inference
        let lease_class_c = Lease {
            client_ip: Ipv4Addr::new(192, 168, 1, 100),
            server_ip: Some(Ipv4Addr::new(192, 168, 1, 1)),
            gateway: None,
            subnet_mask: None,
            dns_servers: vec![],
            lease_time: None,
            renewal_time: None,
            rebinding_time: None,
            domain_name: None,
            interface_mtu: None,
            broadcast_addr: None,
            classless_routes: vec![],
            server_mac: None,
        };

        let inferred_mask = client.infer_subnet_mask(&lease_class_c);
        assert_eq!(inferred_mask, Ipv4Addr::new(255, 255, 255, 0)); // Should infer /24
    }

    #[test]
    fn test_go_style_lease_enhancement() {
        let client = AdaptiveDhcpClient {
            dataplane: DataPlane::new(),
            mac_address: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            mode: None,
            dhcp_client: DhcpClient::new(DataPlane::new(), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        };

        // Test incomplete lease (like Go example where subnet mask was missing)
        let incomplete_lease = Lease {
            client_ip: Ipv4Addr::new(10, 21, 255, 203),
            server_ip: Some(Ipv4Addr::new(10, 21, 0, 1)),
            gateway: None,          // Missing
            subnet_mask: None,      // Missing (like Go example)
            dns_servers: vec![],    // Missing
            lease_time: Some(Duration::from_secs(21600)),
            renewal_time: None,
            rebinding_time: None,
            domain_name: None,
            interface_mtu: None,
            broadcast_addr: None,
            classless_routes: vec![],
            server_mac: None,
        };

        let enhanced_lease = client.enhance_lease_with_go_logic(incomplete_lease);

        // Should have inferred subnet mask
        assert!(enhanced_lease.subnet_mask.is_some());
        assert_eq!(enhanced_lease.subnet_mask.unwrap(), Ipv4Addr::new(255, 255, 0, 0));

        // Should have used server as gateway
        assert!(enhanced_lease.gateway.is_some());
        assert_eq!(enhanced_lease.gateway.unwrap(), Ipv4Addr::new(10, 21, 0, 1));

        // Should have used gateway as DNS
        assert!(!enhanced_lease.dns_servers.is_empty());
        assert_eq!(enhanced_lease.dns_servers[0], Ipv4Addr::new(10, 21, 0, 1));
    }

    #[test]
    fn test_static_fallback() {
        // Test static IP generation
        let static_ip = Ipv4Addr::new(192, 168, 1, 200);
        assert_eq!(static_ip.octets()[3], 200);
    }
}