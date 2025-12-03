use std::process::Command;

/// Platform-specific route management for VPN tunnel configuration
/// 
/// Handles:
/// - Saving original default gateway
/// - Adding host routes for VPN server through original gateway
/// - Replacing default gateway with VPN gateway
/// - Configuring TUN interface with IP/netmask
/// - Restoring original routes on disconnect
#[derive(Debug)]
pub struct RouteManager {
    local_gateway: Option<[u8; 4]>,
    vpn_gateway: Option<[u8; 4]>,
    vpn_server: Option<[u8; 4]>,
    routes_configured: bool,
}

impl RouteManager {
    pub fn new() -> Self {
        Self {
            local_gateway: None,
            vpn_gateway: None,
            vpn_server: None,
            routes_configured: false,
        }
    }
    
    /// Get current default gateway by parsing netstat output
    /// Excludes utun interfaces to avoid detecting VPN gateways
    pub fn get_default_gateway(&mut self) -> Result<[u8; 4], String> {
        #[cfg(target_os = "macos")]
        {
            let output = Command::new("/bin/sh")
                .arg("-c")
                .arg("netstat -rn | grep '^default' | grep -v utun | awk '{print $2}' | head -1")
                .output()
                .map_err(|e| format!("Failed to run netstat: {}", e))?;
            
            if !output.status.success() {
                return Err("netstat command failed".into());
            }
            
            let ip_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if ip_str.is_empty() {
                return Err("No default gateway found".into());
            }
            
            let octets: Vec<u8> = ip_str.split('.')
                .filter_map(|s| s.parse().ok())
                .collect();
            
            if octets.len() != 4 {
                return Err(format!("Invalid gateway IP: {}", ip_str));
            }
            
            let gateway = [octets[0], octets[1], octets[2], octets[3]];
            self.local_gateway = Some(gateway);
            
            log::info!("[●] ROUTE: Saved original gateway: {}.{}.{}.{}", 
                       gateway[0], gateway[1], gateway[2], gateway[3]);
            
            Ok(gateway)
        }
        
        #[cfg(not(target_os = "macos"))]
        {
            Err("Route management not implemented for this platform".into())
        }
    }
    
    /// Add host route for VPN server through original gateway
    /// This ensures the VPN connection itself doesn't get routed through the VPN
    pub fn add_host_route(&mut self, server: [u8; 4]) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            let gateway = self.local_gateway
                .ok_or("No local gateway saved. Call get_default_gateway() first")?;
            
            let server_str = format!("{}.{}.{}.{}", server[0], server[1], server[2], server[3]);
            let gateway_str = format!("{}.{}.{}.{}", gateway[0], gateway[1], gateway[2], gateway[3]);
            
            log::info!("[●] ROUTE: add host {} gateway {}", server_str, gateway_str);
            
            let output = Command::new("route")
                .args(&["-n", "add", "-host", &server_str, &gateway_str])
                .output()
                .map_err(|e| format!("Failed to add host route: {}", e))?;
            
            if !output.status.success() {
                // Try without -n flag as fallback
                let fallback = Command::new("route")
                    .args(&["add", "-host", &server_str, &gateway_str])
                    .output()
                    .map_err(|e| format!("Failed to add host route (fallback): {}", e))?;
                
                if !fallback.status.success() {
                    let stderr = String::from_utf8_lossy(&fallback.stderr);
                    return Err(format!("Failed to add host route: {}", stderr));
                }
            }
            
            self.vpn_server = Some(server);
            Ok(())
        }
        
        #[cfg(not(target_os = "macos"))]
        {
            let _ = server;
            Err("Route management not implemented for this platform".into())
        }
    }
    
    /// Replace default gateway with VPN gateway (full tunnel mode)
    /// Deletes all existing default routes and adds VPN as default
    pub fn replace_default_gateway(&mut self, vpn_gw: [u8; 4]) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            self.vpn_gateway = Some(vpn_gw);
            
            // Delete existing default routes (macOS may have multiple)
            log::info!("[●] ROUTE: delete net default");
            for _ in 0..3 {
                let _ = Command::new("route")
                    .args(&["-n", "delete", "default"])
                    .output();
            }
            
            // Add VPN default route
            let vpn_str = format!("{}.{}.{}.{}", vpn_gw[0], vpn_gw[1], vpn_gw[2], vpn_gw[3]);
            log::info!("[●] ROUTE: add net default: gateway {}", vpn_str);
            
            let output = Command::new("route")
                .args(&["-n", "add", "-inet", "default", &vpn_str])
                .output()
                .map_err(|e| format!("Failed to add default route: {}", e))?;
            
            if !output.status.success() {
                // Fallback without -n flag
                let fallback = Command::new("route")
                    .args(&["add", "-inet", "default", &vpn_str])
                    .output()
                    .map_err(|e| format!("Failed to add default route (fallback): {}", e))?;
                
                if !fallback.status.success() {
                    let stderr = String::from_utf8_lossy(&fallback.stderr);
                    return Err(format!("Failed to add default route: {}", stderr));
                }
            }
            
            self.routes_configured = true;
            log::info!("[●] VPN: Configuring full tunnel mode (routing all traffic through VPN)");
            
            Ok(())
        }
        
        #[cfg(not(target_os = "macos"))]
        {
            let _ = vpn_gw;
            Err("Route management not implemented for this platform".into())
        }
    }
    
    /// Configure TUN interface with IP address and netmask
    /// For macOS utun devices (point-to-point), uses destination address syntax
    pub fn configure_interface(&self, device: &str, ip: [u8; 4], netmask: [u8; 4]) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            let ip_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
            
            // macOS utun devices are point-to-point and require destination address
            // Use the gateway IP as destination (peer address)
            // Syntax: ifconfig utun0 <local_ip> <peer_ip> netmask <mask> up
            // For VPN, we use: ifconfig utun0 10.21.248.153 10.21.0.1 netmask 255.255.0.0 up
            
            // Calculate destination IP: use first IP in subnet (typically gateway)
            // For /16 network (255.255.0.0), use x.x.0.1 as destination
            let dest_ip = if netmask == [255, 255, 0, 0] {
                format!("{}.{}.0.1", ip[0], ip[1])
            } else if netmask == [255, 255, 255, 0] {
                format!("{}.{}.{}.1", ip[0], ip[1], ip[2])
            } else {
                // Default: use .0.1 in the same network
                format!("{}.{}.0.1", ip[0], ip[1])
            };
            
            let mask_str = format!("{}.{}.{}.{}", netmask[0], netmask[1], netmask[2], netmask[3]);
            
            log::info!("[●] INTERFACE: {} {} {} netmask {}", device, ip_str, dest_ip, mask_str);
            
            let output = Command::new("ifconfig")
                .args(&[device, &ip_str, &dest_ip, "netmask", &mask_str, "up"])
                .output()
                .map_err(|e| format!("Failed to configure interface: {}", e))?;
            
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("Failed to configure interface: {}", stderr));
            }
            
            // ✅ CRITICAL FIX: Delete auto-generated host route for gateway
            // macOS creates: "10.21.0.1 → 10.21.248.148" which causes routing loop
            // We need gateway to be directly reachable on the p2p link, not via local IP
            log::info!("[●] ROUTE: Removing auto-generated host route for gateway {}", dest_ip);
            let _ = Command::new("route")
                .args(&["-n", "delete", "-host", &dest_ip])
                .output();
            
            // Add correct host route: gateway is on the interface itself
            log::info!("[●] ROUTE: Adding correct host route for gateway {} on {}", dest_ip, device);
            let output = Command::new("route")
                .args(&["-n", "add", "-host", &dest_ip, "-interface", device])
                .output()
                .map_err(|e| format!("Failed to add gateway host route: {}", e))?;
            
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!("Failed to add gateway host route: {}", stderr);
            }
            
            Ok(())
        }
        
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (device, ip, netmask);
            Err("Route management not implemented for this platform".into())
        }
    }
    
    /// Restore original routes on disconnect
    /// Deletes VPN routes and restores original default gateway
    pub fn restore_routes(&mut self) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            if !self.routes_configured {
                return Ok(());
            }
            
            log::info!("[●] ROUTE: Restoring original network configuration...");
            
            // Delete VPN default route
            let _ = Command::new("route")
                .args(&["-n", "delete", "default"])
                .output();
            
            // Delete host route for VPN server
            if let Some(server) = self.vpn_server {
                let server_str = format!("{}.{}.{}.{}", server[0], server[1], server[2], server[3]);
                let _ = Command::new("route")
                    .args(&["-n", "delete", "-host", &server_str])
                    .output();
            }
            
            // Restore original gateway
            if let Some(orig_gw) = self.local_gateway {
                let gw_str = format!("{}.{}.{}.{}", orig_gw[0], orig_gw[1], orig_gw[2], orig_gw[3]);
                
                let output = Command::new("route")
                    .args(&["-n", "add", "-inet", "default", &gw_str])
                    .output()
                    .map_err(|e| format!("Failed to restore default route: {}", e))?;
                
                if !output.status.success() {
                    // Fallback without -n flag
                    let _ = Command::new("route")
                        .args(&["add", "-inet", "default", &gw_str])
                        .output();
                }
                
                log::info!("[●] ROUTE: Restored original gateway: {}", gw_str);
            }
            
            self.routes_configured = false;
            Ok(())
        }
        
        #[cfg(not(target_os = "macos"))]
        {
            Err("Route management not implemented for this platform".into())
        }
    }
    
    /// Check if routes are currently configured
    pub fn is_configured(&self) -> bool {
        self.routes_configured
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        // Best effort cleanup on drop
        let _ = self.restore_routes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[ignore] // Requires root privileges
    fn test_get_default_gateway() {
        let mut rm = RouteManager::new();
        match rm.get_default_gateway() {
            Ok(gw) => {
                println!("Default gateway: {}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]);
                assert!(gw[0] > 0); // Basic sanity check
            }
            Err(e) => {
                println!("Failed to get gateway (may need root): {}", e);
            }
        }
    }
}
