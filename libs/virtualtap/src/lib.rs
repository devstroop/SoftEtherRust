//! Rust FFI bindings for VirtualTap L2↔L3 translator
//!
//! This crate provides safe Rust bindings to the VirtualTap C library,
//! which handles Layer 2 (Ethernet) to Layer 3 (IP) packet translation.
//!
//! Key features:
//! - Converts IP packets to Ethernet frames (for sending to SoftEther server)
//! - Converts Ethernet frames to IP packets (for sending to TUN device)
//! - Handles ARP requests/replies internally
//! - Learns client IP from DHCP packets
//! - Builds DHCP DISCOVER/REQUEST packets

use std::ptr;

/// VirtualTap error codes
pub const VTAP_ERROR_INVALID_PARAMS: i32 = -1;
pub const VTAP_ERROR_PARSE_FAILED: i32 = -2;
pub const VTAP_ERROR_BUFFER_TOO_SMALL: i32 = -3;
pub const VTAP_ERROR_ALLOC_FAILED: i32 = -4;

/// Opaque handle to VirtualTap instance
#[repr(C)]
pub struct VirtualTap {
    _private: [u8; 0],
}

/// VirtualTap configuration
#[repr(C)]
pub struct VirtualTapConfig {
    pub our_mac: [u8; 6],
    pub our_ip: u32,           // Network byte order, 0 if unknown
    pub gateway_ip: u32,       // Network byte order, 0 if unknown
    pub gateway_mac: [u8; 6],  // All zeros if unknown
    pub handle_arp: bool,
    pub learn_ip: bool,
    pub learn_gateway_mac: bool,
    pub enable_dns_cache: bool,
    pub verbose: bool,
}

/// VirtualTap statistics
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtualTapStats {
    pub ip_to_eth_packets: u64,
    pub eth_to_ip_packets: u64,
    pub arp_requests_handled: u64,
    pub arp_replies_sent: u64,
    pub arp_requests_sent: u64,
    pub ipv4_packets: u64,
    pub ipv6_packets: u64,
    pub arp_packets: u64,
    pub icmpv6_packets: u64,
    pub dhcp_packets: u64,
    pub dns_queries: u64,
    pub dns_cache_hits: u64,
    pub dns_cache_misses: u64,
    pub ipv4_fragments: u64,
    pub ipv6_fragments: u64,
    pub fragments_reassembled: u64,
    pub icmp_errors_received: u64,
    pub icmpv6_errors_received: u64,
    pub arp_table_entries: u64,
    pub other_packets: u64,
}

extern "C" {
    fn virtual_tap_create(config: *const VirtualTapConfig) -> *mut VirtualTap;
    fn virtual_tap_destroy(tap: *mut VirtualTap);
    
    fn virtual_tap_ip_to_ethernet(
        tap: *mut VirtualTap,
        ip_packet: *const u8,
        ip_len: u32,
        eth_frame_out: *mut u8,
        out_capacity: u32,
    ) -> i32;
    
    fn virtual_tap_ethernet_to_ip(
        tap: *mut VirtualTap,
        eth_frame: *const u8,
        eth_len: u32,
        ip_packet_out: *mut u8,
        out_capacity: u32,
    ) -> i32;
    
    fn virtual_tap_get_learned_ip(tap: *mut VirtualTap) -> u32;
    fn virtual_tap_get_gateway_mac(tap: *mut VirtualTap, mac_out: *mut u8) -> bool;
    fn virtual_tap_get_stats(tap: *mut VirtualTap, stats: *mut VirtualTapStats);
    fn virtual_tap_has_pending_arp_reply(tap: *mut VirtualTap) -> bool;
    fn virtual_tap_pop_arp_reply(tap: *mut VirtualTap, arp_reply_out: *mut u8, out_capacity: u32) -> i32;
    fn virtual_tap_send_arp_request(tap: *mut VirtualTap, target_ip: u32) -> i32;
    
    fn dhcp_build_discover(
        client_mac: *const u8,
        transaction_id: u32,
        eth_frame_out: *mut u8,
        out_capacity: u32,
    ) -> i32;
    
    fn dhcp_build_request(
        client_mac: *const u8,
        transaction_id: u32,
        requested_ip: u32,
        server_ip: u32,
        eth_frame_out: *mut u8,
        out_capacity: u32,
    ) -> i32;
    
    // TUN device functions
    fn tun_device_create(device_name: *mut u8, device_name_size: usize) -> i32;
    fn tun_device_close(fd: i32);
    fn tun_device_read(fd: i32, buffer: *mut u8, buffer_size: u32) -> i32;
    fn tun_device_write(fd: i32, packet: *const u8, packet_size: u32) -> i32;
}

/// Safe Rust wrapper for VirtualTap
pub struct VirtualTapTranslator {
    handle: *mut VirtualTap,
}

impl VirtualTapTranslator {
    /// Create a new VirtualTap translator with the given configuration
    pub fn new(config: VirtualTapConfig) -> Option<Self> {
        let handle = unsafe { virtual_tap_create(&config) };
        if handle.is_null() {
            None
        } else {
            Some(Self { handle })
        }
    }
    
    /// Convert IP packet (L3) to Ethernet frame (L2)
    /// Returns the Ethernet frame on success
    pub fn ip_to_ethernet(&mut self, ip_packet: &[u8]) -> Result<Vec<u8>, i32> {
        let mut eth_frame = vec![0u8; ip_packet.len() + 14]; // IP + Ethernet header
        
        let result = unsafe {
            virtual_tap_ip_to_ethernet(
                self.handle,
                ip_packet.as_ptr(),
                ip_packet.len() as u32,
                eth_frame.as_mut_ptr(),
                eth_frame.len() as u32,
            )
        };
        
        if result > 0 {
            eth_frame.truncate(result as usize);
            Ok(eth_frame)
        } else {
            Err(result)
        }
    }
    
    /// Convert Ethernet frame (L2) to IP packet (L3)
    /// Returns:
    /// - Ok(Some(ip_packet)) if frame contained IP packet
    /// - Ok(None) if frame was ARP (handled internally)
    /// - Err(code) on error
    pub fn ethernet_to_ip(&mut self, eth_frame: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        let mut ip_packet = vec![0u8; eth_frame.len()]; // IP packet will be smaller than frame
        
        let result = unsafe {
            virtual_tap_ethernet_to_ip(
                self.handle,
                eth_frame.as_ptr(),
                eth_frame.len() as u32,
                ip_packet.as_mut_ptr(),
                ip_packet.len() as u32,
            )
        };
        
        if result > 0 {
            // IP packet extracted
            ip_packet.truncate(result as usize);
            Ok(Some(ip_packet))
        } else if result == 0 {
            // ARP handled internally
            Ok(None)
        } else {
            // Error
            Err(result)
        }
    }
    
    /// Get the learned IP address (from DHCP)
    /// Returns IP in network byte order, or 0 if not learned yet
    pub fn get_learned_ip(&self) -> u32 {
        unsafe { virtual_tap_get_learned_ip(self.handle) }
    }
    
    /// Get the learned gateway MAC address
    pub fn get_gateway_mac(&self) -> Option<[u8; 6]> {
        let mut mac = [0u8; 6];
        let success = unsafe { virtual_tap_get_gateway_mac(self.handle, mac.as_mut_ptr()) };
        if success {
            Some(mac)
        } else {
            None
        }
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> VirtualTapStats {
        let mut stats = VirtualTapStats {
            ip_to_eth_packets: 0,
            eth_to_ip_packets: 0,
            arp_requests_handled: 0,
            arp_replies_sent: 0,
            arp_requests_sent: 0,
            ipv4_packets: 0,
            ipv6_packets: 0,
            arp_packets: 0,
            icmpv6_packets: 0,
            dhcp_packets: 0,
            dns_queries: 0,
            dns_cache_hits: 0,
            dns_cache_misses: 0,
            ipv4_fragments: 0,
            ipv6_fragments: 0,
            fragments_reassembled: 0,
            icmp_errors_received: 0,
            icmpv6_errors_received: 0,
            arp_table_entries: 0,
            other_packets: 0,
        };
        unsafe { virtual_tap_get_stats(self.handle, &mut stats) };
        stats
    }
    
    /// Check if there are pending ARP replies
    pub fn has_pending_arp_reply(&self) -> bool {
        unsafe { virtual_tap_has_pending_arp_reply(self.handle) }
    }
    
    /// Pop a pending ARP reply
    /// Returns the ARP reply frame on success
    pub fn pop_arp_reply(&mut self) -> Result<Option<Vec<u8>>, i32> {
        let mut arp_reply = vec![0u8; 64]; // ARP replies are small (42 bytes minimum)
        
        let result = unsafe {
            virtual_tap_pop_arp_reply(
                self.handle,
                arp_reply.as_mut_ptr(),
                arp_reply.len() as u32,
            )
        };
        
        if result > 0 {
            arp_reply.truncate(result as usize);
            Ok(Some(arp_reply))
        } else if result == 0 {
            Ok(None) // No pending replies
        } else {
            Err(result)
        }
    }
    
    /// Send an ARP request for a specific IP address
    pub fn send_arp_request(&mut self, target_ip: u32) -> Result<(), i32> {
        let result = unsafe { virtual_tap_send_arp_request(self.handle, target_ip) };
        if result == 0 {
            Ok(())
        } else {
            Err(result)
        }
    }
}

impl Drop for VirtualTapTranslator {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { virtual_tap_destroy(self.handle) };
        }
    }
}

unsafe impl Send for VirtualTapTranslator {}
unsafe impl Sync for VirtualTapTranslator {}

/// Build a DHCP DISCOVER packet
pub fn build_dhcp_discover(client_mac: [u8; 6], transaction_id: u32) -> Result<Vec<u8>, i32> {
    let mut eth_frame = vec![0u8; 342]; // Standard DHCP DISCOVER size
    
    let result = unsafe {
        dhcp_build_discover(
            client_mac.as_ptr(),
            transaction_id,
            eth_frame.as_mut_ptr(),
            eth_frame.len() as u32,
        )
    };
    
    if result > 0 {
        eth_frame.truncate(result as usize);
        Ok(eth_frame)
    } else {
        Err(result)
    }
}

/// Build a DHCP REQUEST packet
pub fn build_dhcp_request(
    client_mac: [u8; 6],
    transaction_id: u32,
    requested_ip: u32,
    server_ip: u32,
) -> Result<Vec<u8>, i32> {
    let mut eth_frame = vec![0u8; 362]; // Standard DHCP REQUEST size
    
    let result = unsafe {
        dhcp_build_request(
            client_mac.as_ptr(),
            transaction_id,
            requested_ip,
            server_ip,
            eth_frame.as_mut_ptr(),
            eth_frame.len() as u32,
        )
    };
    
    if result > 0 {
        eth_frame.truncate(result as usize);
        Ok(eth_frame)
    } else {
        Err(result)
    }
}

// ============================================================================
// TUN Device API
// ============================================================================

/// TUN device handle (file descriptor)
pub struct TunDevice {
    fd: i32,
    name: String,
}

impl TunDevice {
    /// Create a new TUN device
    /// Returns the device with its auto-assigned name (e.g., "utun7")
    pub fn create() -> Result<Self, String> {
        let mut name_buf = vec![0u8; 64];
        
        let fd = unsafe {
            tun_device_create(name_buf.as_mut_ptr(), name_buf.len())
        };
        
        if fd < 0 {
            return Err(format!("Failed to create TUN device (error code: {})", fd));
        }
        
        // Extract device name from C string
        let name = unsafe {
            let len = name_buf.iter().position(|&c| c == 0).unwrap_or(name_buf.len());
            String::from_utf8_lossy(&name_buf[..len]).into_owned()
        };
        
        Ok(Self { fd, name })
    }
    
    /// Get the device name (e.g., "utun7")
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Get the file descriptor
    pub fn fd(&self) -> i32 {
        self.fd
    }
    
    /// Read an IP packet from the TUN device
    /// Returns Ok(Some(packet)) if data available, Ok(None) if would block, Err on error
    pub fn read(&self) -> Result<Option<Vec<u8>>, String> {
        let mut buffer = vec![0u8; 2048];
        
        let result = unsafe {
            tun_device_read(self.fd, buffer.as_mut_ptr(), buffer.len() as u32)
        };
        
        if result > 0 {
            buffer.truncate(result as usize);
            Ok(Some(buffer))
        } else if result == 0 {
            Ok(None) // Would block (non-blocking mode)
        } else {
            Err(format!("TUN read error (code: {})", result))
        }
    }
    
    /// Write an IP packet to the TUN device
    /// Returns Ok(bytes_written) on success, Err on error
    pub fn write(&self, packet: &[u8]) -> Result<usize, String> {
        let result = unsafe {
            tun_device_write(self.fd, packet.as_ptr(), packet.len() as u32)
        };
        
        if result > 0 {
            Ok(result as usize)
        } else if result == 0 {
            Ok(0) // Would block
        } else {
            Err(format!("TUN write error (code: {})", result))
        }
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { tun_device_close(self.fd) };
        }
    }
}

unsafe impl Send for TunDevice {}
unsafe impl Sync for TunDevice {}
