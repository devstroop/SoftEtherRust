//! VirtualTapRust - Pure Rust iOS Virtual Network Adapter
//!
//! This module provides a safe, high-performance virtual network interface
//! for iOS using the native `utun` device. It replaces the C-based VirtualTap
//! implementation with pure Rust for:
//!
//! - Memory safety (no unsafe C FFI boundary in data path)
//! - Zero-copy packet handling with Rust ownership
//! - Better async integration with Tokio
//! - Cross-platform support (iOS/macOS)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐
//! │  PacketTunnel   │ (Swift/iOS)
//! │    Provider     │
//! └────────┬────────┘
//!          │ NEPacketTunnelFlow
//!          ↓
//! ┌─────────────────┐
//! │ VirtualTapRust  │ (Pure Rust)
//! │   - utun FD     │
//! │   - RingBuffer  │
//! │   - AsyncIO     │
//! └────────┬────────┘
//!          │ Crossbeam Channels
//!          ↓
//! ┌─────────────────┐
//! │   DataPlane     │ (SoftEther VPN)
//! │  SessionManager │
//! └─────────────────┘
//! ```

pub mod error;
pub mod ffi;
pub mod ios_utun;
pub mod packet;
pub mod ring_buffer;

use anyhow::Result;
use std::os::fd::RawFd;
use tracing::{debug, info};

pub use error::{VTapError, VTapResult};
pub use ios_utun::IosUtunDevice;
pub use packet::EthernetFrame;
pub use ring_buffer::RingBuffer;

/// Virtual network adapter for iOS
///
/// Provides a safe interface to the iOS `utun` device with:
/// - Async packet I/O
/// - Zero-copy buffer management
/// - Automatic MTU handling
/// - MAC address management
pub struct VirtualTapAdapter {
    /// The underlying utun device
    device: IosUtunDevice,
    
    /// Ring buffer for zero-copy packet exchange
    ring_buffer: RingBuffer,
    
    /// MAC address for this adapter
    mac_address: [u8; 6],
    
    /// Interface name (e.g., "utun3")
    interface_name: String,
    
    /// Maximum transmission unit
    mtu: usize,
}

impl VirtualTapAdapter {
    /// Create a new virtual network adapter
    ///
    /// # Arguments
    ///
    /// * `mac` - MAC address for the adapter
    /// * `mtu` - Maximum transmission unit (default: 1280 for IPv6)
    ///
    /// # Returns
    ///
    /// A new adapter instance ready for packet I/O
    pub fn new(mac: [u8; 6], mtu: usize) -> Result<Self> {
        info!("Creating VirtualTapRust adapter with MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        
        // Create utun device
        let device = IosUtunDevice::create()?;
        let interface_name = device.name().to_string();
        
        info!("Created utun device: {}", interface_name);
        
        // Create ring buffer for packet exchange
        let ring_buffer = RingBuffer::new(8192)?; // 8MB buffer
        
        Ok(Self {
            device,
            ring_buffer,
            mac_address: mac,
            interface_name,
            mtu,
        })
    }
    
    /// Get the interface name
    pub fn name(&self) -> &str {
        &self.interface_name
    }
    
    /// Get the interface name (alias for name)
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }
    
    /// Get the MAC address
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }
    
    /// Get the MTU
    pub fn mtu(&self) -> usize {
        self.mtu
    }
    
    /// Get the raw file descriptor for the utun device
    ///
    /// This allows integration with external I/O frameworks
    pub fn raw_fd(&self) -> RawFd {
        self.device.raw_fd()
    }
    
    /// Get the file descriptor (alias for raw_fd)
    pub fn file_descriptor(&self) -> i32 {
        self.device.raw_fd()
    }
    
    /// Get reference to the ring buffer
    pub fn ring_buffer(&self) -> &RingBuffer {
        &self.ring_buffer
    }
    
    /// Read a packet from the virtual interface
    ///
    /// Returns an Ethernet frame or None if no packet available
    pub async fn read_packet(&mut self) -> Result<Option<EthernetFrame>> {
        self.device.read_packet().await
    }
    
    /// Write a packet to the virtual interface
    ///
    /// # Arguments
    ///
    /// * `frame` - Ethernet frame to write
    pub async fn write_packet(&mut self, frame: &EthernetFrame) -> Result<()> {
        self.device.write_packet(frame).await
    }
    
    /// Start the adapter packet processing loop
    ///
    /// This runs continuously, forwarding packets between the utun device
    /// and the ring buffer for the VPN engine
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting VirtualTapRust packet processing loop");
        
        loop {
            // Try to read from utun (non-blocking)
            if let Some(frame) = self.read_packet().await? {
                debug!("Read {} bytes from utun", frame.len());
                self.ring_buffer.write(&frame.data())?;
            }
            
            // Try to read from ring buffer (non-blocking)
            if let Some(data) = self.ring_buffer.read()? {
                let frame = EthernetFrame::from_bytes(&data)?;
                debug!("Writing {} bytes to utun", frame.len());
                self.write_packet(&frame).await?;
            }
            
            // Small yield to prevent busy loop
            tokio::task::yield_now().await;
        }
    }
}

impl Drop for VirtualTapAdapter {
    fn drop(&mut self) {
        info!("Dropping VirtualTapRust adapter: {}", self.interface_name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires root privileges to create utun device
    fn test_mac_address() {
        let mac = [0x02, 0x00, 0x00, 0x11, 0x22, 0x33];
        let adapter = VirtualTapAdapter::new(mac, 1500).unwrap();
        assert_eq!(adapter.mac_address(), mac);
    }
}
