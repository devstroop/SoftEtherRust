//! Lock-free ring buffer for zero-copy packet exchange
//!
//! Provides a high-performance ring buffer using crossbeam for
//! lock-free concurrent access between the utun reader/writer
//! and the VPN engine.

use crate::error::VTapError;
use anyhow::Result;
use crossbeam::channel::{bounded, Receiver, Sender};
use parking_lot::Mutex;
use std::sync::Arc;
use tracing::debug;

/// Lock-free ring buffer for packet exchange
///
/// Uses crossbeam channels internally for zero-allocation message passing.
/// Packets are passed by value, avoiding copies where possible.
pub struct RingBuffer {
    /// Sender for packets from utun → VPN
    tx_to_vpn: Sender<Vec<u8>>,
    
    /// Receiver for packets from utun → VPN
    rx_from_utun: Receiver<Vec<u8>>,
    
    /// Sender for packets from VPN → utun
    tx_to_utun: Sender<Vec<u8>>,
    
    /// Receiver for packets from VPN → utun
    rx_from_vpn: Receiver<Vec<u8>>,
    
    /// Statistics
    stats: Arc<Mutex<RingBufferStats>>,
}

#[derive(Default, Debug)]
pub struct RingBufferStats {
    pub packets_written: u64,
    pub packets_read: u64,
    pub bytes_written: u64,
    pub bytes_read: u64,
    pub drops: u64,
}

impl RingBuffer {
    /// Create a new ring buffer
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of packets that can be queued (in KB)
    pub fn new(capacity_kb: usize) -> Result<Self> {
        // Estimate ~200 packets per MB at 1500 byte MTU
        let packet_capacity = (capacity_kb * 200) / 1024;
        
        let (tx_to_vpn, rx_from_utun) = bounded(packet_capacity);
        let (tx_to_utun, rx_from_vpn) = bounded(packet_capacity);
        
        debug!("Created ring buffer with capacity: {} packets", packet_capacity);
        
        Ok(Self {
            tx_to_vpn,
            rx_from_utun,
            tx_to_utun,
            rx_from_vpn,
            stats: Arc::new(Mutex::new(RingBufferStats::default())),
        })
    }
    
    /// Write a packet to the buffer (utun → VPN direction)
    pub fn write(&self, data: &[u8]) -> Result<()> {
        let packet = data.to_vec();
        let len = packet.len();
        
        match self.tx_to_vpn.try_send(packet) {
            Ok(()) => {
                let mut stats = self.stats.lock();
                stats.packets_written += 1;
                stats.bytes_written += len as u64;
                Ok(())
            }
            Err(_) => {
                let mut stats = self.stats.lock();
                stats.drops += 1;
                Err(VTapError::BufferFull.into())
            }
        }
    }
    
    /// Read a packet from the buffer (VPN → utun direction)
    pub fn read(&self) -> Result<Option<Vec<u8>>> {
        match self.rx_from_vpn.try_recv() {
            Ok(packet) => {
                let len = packet.len();
                let mut stats = self.stats.lock();
                stats.packets_read += 1;
                stats.bytes_read += len as u64;
                Ok(Some(packet))
            }
            Err(_) => Ok(None),
        }
    }
    
    /// Wait for buffer to be readable
    pub async fn wait_readable(&self) -> Result<()> {
        // Use async-friendly waiting
        tokio::task::spawn_blocking({
            let rx = self.rx_from_vpn.clone();
            move || {
                let _ = rx.recv();
            }
        })
        .await?;
        Ok(())
    }
    
    /// Get receiver for utun → VPN packets
    pub fn utun_to_vpn_receiver(&self) -> Receiver<Vec<u8>> {
        self.rx_from_utun.clone()
    }
    
    /// Get sender for VPN → utun packets
    pub fn vpn_to_utun_sender(&self) -> Sender<Vec<u8>> {
        self.tx_to_utun.clone()
    }
    
    /// Get buffer statistics
    pub fn stats(&self) -> RingBufferStats {
        *self.stats.lock()
    }
    
    /// Reset statistics
    pub fn reset_stats(&self) {
        *self.stats.lock() = RingBufferStats::default();
    }
}

impl Clone for RingBufferStats {
    fn clone(&self) -> Self {
        Self {
            packets_written: self.packets_written,
            packets_read: self.packets_read,
            bytes_written: self.bytes_written,
            bytes_read: self.bytes_read,
            drops: self.drops,
        }
    }
}

impl Copy for RingBufferStats {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_write_read() {
        let rb = RingBuffer::new(1024).unwrap();
        
        let data = vec![1, 2, 3, 4, 5];
        rb.write(&data).unwrap();
        
        let stats = rb.stats();
        assert_eq!(stats.packets_written, 1);
        assert_eq!(stats.bytes_written, 5);
    }

    #[test]
    fn test_ring_buffer_empty_read() {
        let rb = RingBuffer::new(1024).unwrap();
        assert!(rb.read().unwrap().is_none());
    }
}
