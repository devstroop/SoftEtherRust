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

    #[test]
    fn test_tcp_direction_can_recv() {
        assert!(TcpDirection::Both.can_recv());
        assert!(TcpDirection::ServerToClient.can_recv());
        assert!(!TcpDirection::ClientToServer.can_recv());
    }
}
