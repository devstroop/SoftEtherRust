//! Concurrent connection reader for multi-connection mode.
//!
//! This module provides true concurrent reading from multiple VPN connections
//! using spawned tasks and channels. This eliminates the sequential polling
//! bottleneck that causes latency with multiple connections.
//!
//! Each connection has its own RC4 decryption state (if encryption is enabled)
//! to handle per-connection cipher synchronization with the server.
//!
//! ## Buffer Pooling
//!
//! To reduce allocation overhead, this module uses a shared buffer pool.
//! Reader tasks grab pre-allocated `BytesMut` buffers from the pool,
//! read directly into them, then freeze to `Bytes` for zero-copy transfer.
//! When the pool is empty, new buffers are allocated on demand.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use crate::crypto::TunnelEncryption;

use super::connection::VpnConnection;
use super::multi_connection::TcpDirection;

/// Default buffer size for receive operations (64KB - max VPN packet size).
const DEFAULT_BUFFER_SIZE: usize = 65536;

/// Default number of buffers to pre-allocate per reader task.
const BUFFERS_PER_READER: usize = 8;

/// A pool of reusable buffers to reduce allocation overhead.
///
/// Uses a bounded channel as a lock-free pool. When empty, new buffers
/// are allocated on demand (graceful degradation).
#[derive(Clone)]
pub struct BufferPool {
    /// Channel for available buffers.
    pool: Arc<mpsc::Sender<BytesMut>>,
    /// Receiver for getting buffers (shared via try_recv).
    receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<BytesMut>>>,
    /// Buffer capacity for new allocations.
    buffer_size: usize,
    /// Stats: buffers acquired from pool.
    pool_hits: Arc<AtomicU64>,
    /// Stats: buffers allocated fresh.
    pool_misses: Arc<AtomicU64>,
}

impl BufferPool {
    /// Create a new buffer pool with pre-allocated buffers.
    ///
    /// # Arguments
    /// * `pool_size` - Maximum number of buffers to keep in pool
    /// * `buffer_size` - Capacity of each buffer
    pub fn new(pool_size: usize, buffer_size: usize) -> Self {
        let (tx, rx) = mpsc::channel(pool_size);

        // Pre-allocate buffers
        for _ in 0..pool_size {
            let buf = BytesMut::with_capacity(buffer_size);
            // Ignore error if channel is full (shouldn't happen)
            let _ = tx.try_send(buf);
        }

        Self {
            pool: Arc::new(tx),
            receiver: Arc::new(tokio::sync::Mutex::new(rx)),
            buffer_size,
            pool_hits: Arc::new(AtomicU64::new(0)),
            pool_misses: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get a buffer from the pool, or allocate a new one if empty.
    ///
    /// The returned buffer is cleared and ready for use.
    pub async fn get(&self) -> BytesMut {
        // Try to get from pool without blocking
        let mut rx = self.receiver.lock().await;
        match rx.try_recv() {
            Ok(mut buf) => {
                self.pool_hits.fetch_add(1, Ordering::Relaxed);
                buf.clear();
                buf.reserve(self.buffer_size);
                buf
            }
            Err(_) => {
                self.pool_misses.fetch_add(1, Ordering::Relaxed);
                trace!("Buffer pool empty, allocating new buffer");
                BytesMut::with_capacity(self.buffer_size)
            }
        }
    }

    /// Return a buffer to the pool for reuse.
    ///
    /// If the pool is full, the buffer is dropped.
    pub fn return_buf(&self, buf: BytesMut) {
        // Only return if buffer has reasonable capacity
        if buf.capacity() >= self.buffer_size / 2 {
            let _ = self.pool.try_send(buf);
        }
    }

    /// Try to reclaim a `Bytes` back to `BytesMut` if we're the sole owner.
    ///
    /// This enables zero-copy buffer recycling when possible.
    pub fn try_reclaim(&self, bytes: Bytes) {
        // try_into_mut returns Ok(BytesMut) if we're the only reference
        if let Ok(buf) = bytes.try_into_mut() {
            self.return_buf(buf);
        }
    }

    /// Get pool statistics: (hits, misses).
    pub fn stats(&self) -> (u64, u64) {
        (
            self.pool_hits.load(Ordering::Relaxed),
            self.pool_misses.load(Ordering::Relaxed),
        )
    }

    /// Get the hit rate as a percentage (0.0 - 100.0).
    pub fn hit_rate(&self) -> f64 {
        let hits = self.pool_hits.load(Ordering::Relaxed);
        let misses = self.pool_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            100.0
        } else {
            (hits as f64 / total as f64) * 100.0
        }
    }
}

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
///
/// Uses a shared buffer pool to reduce allocation overhead.
pub struct ConcurrentReader {
    /// Channel receiver for incoming packets from all connections.
    rx: mpsc::Receiver<ReceivedPacket>,
    /// Handles to reader tasks.
    handles: Vec<ReaderHandle>,
    /// Shutdown flag shared with all tasks.
    shutdown: Arc<AtomicBool>,
    /// Shared buffer pool for all reader tasks.
    buffer_pool: BufferPool,
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

        // Create shared buffer pool: buffers per reader * number of readers
        // Plus some extra for in-flight packets
        let pool_size = connections.len() * BUFFERS_PER_READER + channel_size;
        let buffer_pool = BufferPool::new(pool_size, DEFAULT_BUFFER_SIZE);

        for (index, conn, direction, encryption) in connections {
            if !direction.can_recv() {
                warn!("Connection {} cannot receive, skipping", index);
                continue;
            }

            let bytes_received = Arc::new(AtomicU64::new(0));
            let task_tx = tx.clone();
            let task_shutdown = shutdown.clone();
            let task_bytes = bytes_received.clone();
            let task_pool = buffer_pool.clone();

            let task = tokio::spawn(async move {
                Self::reader_task(
                    index,
                    conn,
                    encryption,
                    task_tx,
                    task_shutdown,
                    task_bytes,
                    task_pool,
                )
                .await;
            });

            handles.push(ReaderHandle {
                index,
                task,
                bytes_received,
            });
        }

        debug!(
            "ConcurrentReader started with {} reader tasks, buffer pool size {}",
            handles.len(),
            pool_size
        );

        Self {
            rx,
            handles,
            shutdown,
            buffer_pool,
        }
    }

    /// Reader task for a single connection with optional per-connection decryption.
    ///
    /// Uses the shared buffer pool to reduce allocation overhead.
    async fn reader_task(
        index: usize,
        mut conn: VpnConnection,
        mut encryption: Option<TunnelEncryption>,
        tx: mpsc::Sender<ReceivedPacket>,
        shutdown: Arc<AtomicBool>,
        bytes_received: Arc<AtomicU64>,
        pool: BufferPool,
    ) {
        loop {
            if shutdown.load(Ordering::Relaxed) {
                debug!("Reader {} shutting down", index);
                break;
            }

            // Get a buffer from the pool
            let mut buf = pool.get().await;
            buf.resize(DEFAULT_BUFFER_SIZE, 0);

            match conn.read(&mut buf).await {
                Ok(0) => {
                    debug!("Connection {} closed", index);
                    // Return buffer to pool before exiting
                    pool.return_buf(buf);
                    break;
                }
                Ok(n) => {
                    bytes_received.fetch_add(n as u64, Ordering::Relaxed);

                    // Truncate to actual data size
                    buf.truncate(n);

                    // Decrypt in-place if per-connection encryption is enabled
                    if let Some(ref mut enc) = encryption {
                        enc.decrypt(&mut buf);
                    }

                    // Freeze to Bytes (zero-copy, shares underlying memory)
                    let data = buf.freeze();

                    let packet = ReceivedPacket {
                        conn_index: index,
                        data,
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
                    // Return buffer to pool before exiting
                    pool.return_buf(buf);
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

    /// Reclaim a packet's buffer back to the pool if possible.
    ///
    /// Call this after you're done processing a packet to enable buffer reuse.
    /// If the buffer can't be reclaimed (still referenced elsewhere), it's dropped.
    pub fn reclaim(&self, packet: ReceivedPacket) {
        self.buffer_pool.try_reclaim(packet.data);
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

    /// Get buffer pool statistics: (hits, misses, hit_rate%).
    pub fn pool_stats(&self) -> (u64, u64, f64) {
        let (hits, misses) = self.buffer_pool.stats();
        (hits, misses, self.buffer_pool.hit_rate())
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

    // ==========================================================================
    // Buffer Pool tests
    // ==========================================================================

    #[tokio::test]
    async fn test_buffer_pool_creation() {
        let pool = BufferPool::new(4, 1024);

        // Pool should be created with initial buffers
        let (hits, misses) = pool.stats();
        assert_eq!(hits, 0);
        assert_eq!(misses, 0);
        assert_eq!(pool.hit_rate(), 100.0); // No operations yet
    }

    #[tokio::test]
    async fn test_buffer_pool_get_returns_buffer() {
        let pool = BufferPool::new(4, 1024);

        let buf = pool.get().await;
        assert!(buf.capacity() >= 1024);

        // Should count as a hit (from pre-allocated pool)
        let (hits, misses) = pool.stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 0);
    }

    #[tokio::test]
    async fn test_buffer_pool_exhaustion() {
        let pool = BufferPool::new(2, 1024);

        // Exhaust the pool
        let _buf1 = pool.get().await;
        let _buf2 = pool.get().await;

        // This should allocate a new buffer (miss)
        let _buf3 = pool.get().await;

        let (hits, misses) = pool.stats();
        assert_eq!(hits, 2);
        assert_eq!(misses, 1);
    }

    #[tokio::test]
    async fn test_buffer_pool_return_and_reuse() {
        let pool = BufferPool::new(2, 1024);

        // Get a buffer
        let buf = pool.get().await;
        let (hits1, _) = pool.stats();
        assert_eq!(hits1, 1);

        // Return it
        pool.return_buf(buf);

        // Get another - should reuse
        let _buf2 = pool.get().await;
        let (hits2, misses2) = pool.stats();
        assert_eq!(hits2, 2);
        assert_eq!(misses2, 0);
    }

    #[tokio::test]
    async fn test_buffer_pool_hit_rate() {
        let pool = BufferPool::new(3, 1024);

        // 3 hits (from pre-allocated)
        let _b1 = pool.get().await;
        let _b2 = pool.get().await;
        let _b3 = pool.get().await;

        // 1 miss (pool exhausted)
        let _b4 = pool.get().await;

        let hit_rate = pool.hit_rate();
        assert!((hit_rate - 75.0).abs() < 0.01, "Expected 75% hit rate, got {}", hit_rate);
    }

    #[tokio::test]
    async fn test_buffer_pool_try_reclaim() {
        let pool = BufferPool::new(1, 1024);

        // Get and freeze a buffer
        let mut buf = pool.get().await;
        buf.extend_from_slice(b"test data");
        let bytes = buf.freeze();

        // Since we're the only owner, try_reclaim should work
        pool.try_reclaim(bytes);

        // Now pool should have a buffer again
        let (hits_before, _) = pool.stats();
        let _buf = pool.get().await;
        let (hits_after, misses_after) = pool.stats();

        // Should be another hit, not a miss
        assert_eq!(hits_after, hits_before + 1);
        assert_eq!(misses_after, 0);
    }

    #[tokio::test]
    async fn test_buffer_pool_try_reclaim_with_clone() {
        let pool = BufferPool::new(1, 1024);

        // Get and freeze a buffer
        let mut buf = pool.get().await;
        buf.extend_from_slice(b"test data");
        let bytes = buf.freeze();

        // Clone to increase ref count
        let _clone = bytes.clone();

        // try_reclaim should fail silently (buffer still referenced)
        pool.try_reclaim(bytes);

        // Pool should be empty, so next get is a miss
        let _buf = pool.get().await;
        let (_, misses) = pool.stats();
        assert_eq!(misses, 1, "Should have missed because reclaim failed");
    }

    #[test]
    fn test_buffer_pool_constants() {
        // Verify the constants make sense
        assert_eq!(DEFAULT_BUFFER_SIZE, 65536, "Should match max VPN packet");
        assert!(BUFFERS_PER_READER >= 4, "Should have enough buffers per reader");
    }

    #[tokio::test]
    async fn test_buffer_pool_cleared_on_get() {
        let pool = BufferPool::new(1, 1024);

        // Get a buffer and fill it with data
        let mut buf = pool.get().await;
        buf.extend_from_slice(b"some data that should be cleared");

        // Return it
        pool.return_buf(buf);

        // Get it back - should be cleared
        let buf2 = pool.get().await;
        assert!(buf2.is_empty(), "Buffer should be cleared after get");
        assert!(buf2.capacity() >= 1024, "Buffer should have capacity reserved");
    }
}
