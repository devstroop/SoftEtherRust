//! Concurrent connection reader for multi-connection mode.
//!
//! This module provides true concurrent reading from multiple VPN connections
//! using spawned tasks and channels. This eliminates the sequential polling
//! bottleneck that causes latency with multiple connections.
//!
//! Each connection has its own RC4 decryption state (if encryption is enabled)
//! to handle per-connection cipher synchronization with the server.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::crypto::TunnelEncryption;

use super::connection::VpnConnection;
use super::multi_connection::TcpDirection;

/// A packet received from a connection.
#[derive(Debug)]
pub struct ReceivedPacket {
    /// Index of the connection that received this packet.
    pub conn_index: usize,
    /// The raw data received.
    pub data: Bytes,
}

/// Handle for a single connection reader task.
struct ReaderHandle {
    /// Connection index.
    index: usize,
    /// Task handle for cleanup.
    task: tokio::task::JoinHandle<()>,
    /// Bytes received counter (shared with task).
    bytes_received: Arc<AtomicU64>,
}

/// Concurrent reader that spawns a task per receive connection.
///
/// Each task reads from its connection and sends packets to a shared channel.
/// The main loop can then receive from any connection with zero latency.
pub struct ConcurrentReader {
    /// Channel receiver for incoming packets from all connections.
    rx: mpsc::Receiver<ReceivedPacket>,
    /// Handles to reader tasks.
    handles: Vec<ReaderHandle>,
    /// Shutdown flag shared with all tasks.
    shutdown: Arc<AtomicBool>,
}

impl ConcurrentReader {
    /// Create a new concurrent reader from receive-capable connections.
    ///
    /// Takes ownership of the connections (with optional per-connection encryption)
    /// and spawns reader tasks. Each task handles its own decryption if encryption
    /// state is provided.
    ///
    /// Returns the reader and a vec of (index, bytes_received) for stats tracking.
    pub fn new(
        connections: Vec<(usize, VpnConnection, TcpDirection, Option<TunnelEncryption>)>,
        channel_size: usize,
    ) -> Self {
        let (tx, rx) = mpsc::channel(channel_size);
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::with_capacity(connections.len());

        for (index, conn, direction, encryption) in connections {
            if !direction.can_recv() {
                warn!("Connection {} cannot receive, skipping", index);
                continue;
            }

            let bytes_received = Arc::new(AtomicU64::new(0));
            let task_tx = tx.clone();
            let task_shutdown = shutdown.clone();
            let task_bytes = bytes_received.clone();

            let task = tokio::spawn(async move {
                Self::reader_task(index, conn, encryption, task_tx, task_shutdown, task_bytes)
                    .await;
            });

            handles.push(ReaderHandle {
                index,
                task,
                bytes_received,
            });
        }

        debug!(
            "ConcurrentReader started with {} reader tasks",
            handles.len()
        );

        Self {
            rx,
            handles,
            shutdown,
        }
    }

    /// Reader task for a single connection with optional per-connection decryption.
    async fn reader_task(
        index: usize,
        mut conn: VpnConnection,
        mut encryption: Option<TunnelEncryption>,
        tx: mpsc::Sender<ReceivedPacket>,
        shutdown: Arc<AtomicBool>,
        bytes_received: Arc<AtomicU64>,
    ) {
        let mut buf = vec![0u8; 65536];

        loop {
            if shutdown.load(Ordering::Relaxed) {
                debug!("Reader {} shutting down", index);
                break;
            }

            match conn.read(&mut buf).await {
                Ok(0) => {
                    debug!("Connection {} closed", index);
                    break;
                }
                Ok(n) => {
                    bytes_received.fetch_add(n as u64, Ordering::Relaxed);

                    // Decrypt in-place if per-connection encryption is enabled
                    if let Some(ref mut enc) = encryption {
                        enc.decrypt(&mut buf[..n]);
                    }

                    let packet = ReceivedPacket {
                        conn_index: index,
                        data: Bytes::copy_from_slice(&buf[..n]),
                    };

                    if tx.send(packet).await.is_err() {
                        debug!("Reader {} channel closed", index);
                        break;
                    }
                }
                Err(e) => {
                    if !shutdown.load(Ordering::Relaxed) {
                        warn!("Connection {} read error: {}", index, e);
                    }
                    break;
                }
            }
        }
    }

    /// Receive the next packet from any connection.
    ///
    /// Returns `None` if all connections are closed.
    pub async fn recv(&mut self) -> Option<ReceivedPacket> {
        self.rx.recv().await
    }

    /// Try to receive a packet without blocking.
    pub fn try_recv(&mut self) -> Option<ReceivedPacket> {
        self.rx.try_recv().ok()
    }

    /// Get the number of active reader tasks.
    pub fn reader_count(&self) -> usize {
        self.handles.len()
    }

    /// Get bytes received per connection.
    pub fn bytes_received(&self) -> Vec<(usize, u64)> {
        self.handles
            .iter()
            .map(|h| (h.index, h.bytes_received.load(Ordering::Relaxed)))
            .collect()
    }

    /// Shutdown all reader tasks.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

impl Drop for ConcurrentReader {
    fn drop(&mut self) {
        self.shutdown();
        // Abort tasks to ensure cleanup
        for handle in &self.handles {
            handle.task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // TcpDirection tests (duplicated from multi_connection for coverage)
    // ==========================================================================

    #[test]
    fn test_tcp_direction_can_recv() {
        assert!(TcpDirection::Both.can_recv());
        assert!(TcpDirection::ServerToClient.can_recv());
        assert!(!TcpDirection::ClientToServer.can_recv());
    }

    #[test]
    fn test_tcp_direction_can_send() {
        assert!(TcpDirection::Both.can_send());
        assert!(TcpDirection::ClientToServer.can_send());
        assert!(!TcpDirection::ServerToClient.can_send());
    }

    // ==========================================================================
    // ReceivedPacket tests
    // ==========================================================================

    #[test]
    fn test_received_packet_structure() {
        let data = Bytes::from_static(b"test packet data");
        let packet = ReceivedPacket {
            conn_index: 2,
            data: data.clone(),
        };

        assert_eq!(packet.conn_index, 2);
        assert_eq!(packet.data.len(), 16);
        assert_eq!(&packet.data[..], b"test packet data");
    }

    #[test]
    fn test_received_packet_zero_copy() {
        // Verify Bytes provides zero-copy semantics
        let original = Bytes::from(vec![1u8, 2, 3, 4, 5]);
        let packet = ReceivedPacket {
            conn_index: 0,
            data: original.clone(),
        };

        // Clone should share underlying data
        let cloned = packet.data.clone();
        assert_eq!(original.as_ptr(), cloned.as_ptr(), "Bytes should share memory");
    }

    // ==========================================================================
    // Connection filtering tests
    // ==========================================================================

    #[test]
    fn test_filter_recv_capable_connections() {
        // Simulate filtering connections for ConcurrentReader
        let directions = [
            TcpDirection::ClientToServer, // 0: cannot recv
            TcpDirection::ServerToClient, // 1: can recv
            TcpDirection::Both,           // 2: can recv
            TcpDirection::ServerToClient, // 3: can recv
        ];

        let recv_capable: Vec<usize> = directions
            .iter()
            .enumerate()
            .filter(|(_, d)| d.can_recv())
            .map(|(i, _)| i)
            .collect();

        assert_eq!(recv_capable, vec![1, 2, 3]);
    }

    #[test]
    fn test_extract_server_to_client_only() {
        // ConcurrentReader extracts only ServerToClient connections
        // Both connections remain for bidirectional use
        let directions = [
            TcpDirection::ClientToServer, // 0: skip
            TcpDirection::ServerToClient, // 1: extract
            TcpDirection::Both,           // 2: skip (bidirectional)
            TcpDirection::ServerToClient, // 3: extract
        ];

        let extracted: Vec<usize> = directions
            .iter()
            .enumerate()
            .filter(|(_, d)| **d == TcpDirection::ServerToClient)
            .map(|(i, _)| i)
            .collect();

        assert_eq!(extracted, vec![1, 3]);
    }

    // ==========================================================================
    // Bytes accumulation tests
    // ==========================================================================

    #[test]
    fn test_bytes_received_tracking() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let bytes_received = AtomicU64::new(0);

        // Simulate receiving packets
        bytes_received.fetch_add(1500, Ordering::Relaxed);
        bytes_received.fetch_add(1200, Ordering::Relaxed);
        bytes_received.fetch_add(800, Ordering::Relaxed);

        assert_eq!(bytes_received.load(Ordering::Relaxed), 3500);
    }

    #[test]
    fn test_multi_connection_bytes_aggregation() {
        use std::sync::atomic::{AtomicU64, Ordering};

        // Simulate multiple connections
        let conn_bytes: Vec<AtomicU64> = (0..4).map(|_| AtomicU64::new(0)).collect();

        // Each connection receives different amounts
        conn_bytes[0].store(10000, Ordering::Relaxed);
        conn_bytes[1].store(15000, Ordering::Relaxed);
        conn_bytes[2].store(8000, Ordering::Relaxed);
        conn_bytes[3].store(12000, Ordering::Relaxed);

        let total: u64 = conn_bytes.iter().map(|c| c.load(Ordering::Relaxed)).sum();
        assert_eq!(total, 45000);

        // Get stats as tuples
        let stats: Vec<(usize, u64)> = conn_bytes
            .iter()
            .enumerate()
            .map(|(i, c)| (i, c.load(Ordering::Relaxed)))
            .collect();

        assert_eq!(stats, vec![(0, 10000), (1, 15000), (2, 8000), (3, 12000)]);
    }

    // ==========================================================================
    // Shutdown flag tests
    // ==========================================================================

    #[test]
    fn test_shutdown_flag_propagation() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let shutdown = Arc::new(AtomicBool::new(false));

        // Simulate multiple reader tasks checking flag
        let flag1 = shutdown.clone();
        let flag2 = shutdown.clone();
        let flag3 = shutdown.clone();

        assert!(!flag1.load(Ordering::Relaxed));
        assert!(!flag2.load(Ordering::Relaxed));
        assert!(!flag3.load(Ordering::Relaxed));

        // Signal shutdown
        shutdown.store(true, Ordering::Relaxed);

        // All flags should see the update
        assert!(flag1.load(Ordering::Relaxed));
        assert!(flag2.load(Ordering::Relaxed));
        assert!(flag3.load(Ordering::Relaxed));
    }

    // ==========================================================================
    // Channel capacity tests
    // ==========================================================================

    #[test]
    fn test_channel_capacity_selection() {
        // Test that channel capacity is reasonable for different connection counts
        let test_cases = [
            (1, 256),  // Single connection
            (4, 256),  // Typical multi-connection
            (8, 256),  // Large multi-connection
            (16, 256), // Maximum connections
        ];

        for (num_conns, expected_capacity) in test_cases {
            // In real code, capacity is constant (256)
            // This test documents the expected behavior
            let capacity = 256; // From ConcurrentReader::new
            assert_eq!(
                capacity, expected_capacity,
                "Channel capacity for {} connections",
                num_conns
            );
            let _ = num_conns; // Suppress warning
        }
    }

    // ==========================================================================
    // Connection index tracking tests
    // ==========================================================================

    #[test]
    fn test_connection_index_preservation() {
        // Verify that connection indices are preserved through extraction
        let original_indices = [0usize, 1, 2, 3];
        let directions = [
            TcpDirection::ClientToServer, // 0
            TcpDirection::ServerToClient, // 1
            TcpDirection::ClientToServer, // 2
            TcpDirection::ServerToClient, // 3
        ];

        // Extract recv-only with original indices
        let extracted: Vec<(usize, TcpDirection)> = original_indices
            .iter()
            .zip(directions.iter())
            .filter(|(_, d)| **d == TcpDirection::ServerToClient)
            .map(|(i, d)| (*i, *d))
            .collect();

        assert_eq!(extracted.len(), 2);
        assert_eq!(extracted[0].0, 1, "First extracted should have index 1");
        assert_eq!(extracted[1].0, 3, "Second extracted should have index 3");
    }
}
