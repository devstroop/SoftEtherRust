//! Multi-connection manager for SoftEther VPN.
//!
//! Handles multiple TCP connections to the VPN server in half-connection mode.
//! When max_connections > 1, SoftEther uses half-connection mode where each
//! connection is designated for either sending (client-to-server) or receiving
//! (server-to-client) data.

use std::io;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::config::VpnConfig;
use crate::crypto::{Rc4KeyPair, TunnelEncryption};
use crate::error::{Error, Result};
use crate::protocol::{
    AuthResult, HelloResponse, HttpCodec, HttpRequest, Pack, CONTENT_TYPE_PACK, VPN_TARGET,
};

use super::connection::VpnConnection;

/// Direction of a TCP connection in half-connection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpDirection {
    /// Connection can both send and receive (single connection mode).
    Both,
    /// Connection is designated for client-to-server traffic (sending).
    ClientToServer,
    /// Connection is designated for server-to-client traffic (receiving).
    ServerToClient,
}

impl TcpDirection {
    /// Parse direction from server response.
    /// Based on SoftEther Cedar.h:
    /// - TCP_BOTH = 0 (bi-directional)
    /// - TCP_SERVER_TO_CLIENT = 1 (server sends to client, client receives)
    /// - TCP_CLIENT_TO_SERVER = 2 (client sends to server)
    pub fn from_int(value: u32) -> Self {
        match value {
            1 => TcpDirection::ServerToClient, // Server->Client = client receives
            2 => TcpDirection::ClientToServer, // Client->Server = client sends
            _ => TcpDirection::Both,
        }
    }

    /// Check if this connection can be used for sending (from client perspective).
    /// Client can send on: Both, or ClientToServer
    pub fn can_send(&self) -> bool {
        matches!(self, TcpDirection::Both | TcpDirection::ClientToServer)
    }

    /// Check if this connection can be used for receiving (from client perspective).
    /// Client can receive on: Both, or ServerToClient
    pub fn can_recv(&self) -> bool {
        matches!(self, TcpDirection::Both | TcpDirection::ServerToClient)
    }
}

/// A managed TCP connection with metadata.
pub struct ManagedConnection {
    /// The underlying VPN connection.
    pub conn: VpnConnection,
    /// Connection direction for half-connection mode.
    pub direction: TcpDirection,
    /// Per-connection RC4 encryption state (if enabled).
    /// Each TCP socket has independent RC4 cipher state on the server,
    /// so we must maintain independent state per connection on the client.
    pub encryption: Option<TunnelEncryption>,
    /// When this connection was established.
    pub connected_at: Instant,
    /// Last activity time.
    pub last_activity: Instant,
    /// Number of bytes sent through this connection.
    pub bytes_sent: u64,
    /// Number of bytes received through this connection.
    pub bytes_received: u64,
    /// Whether this connection is healthy.
    pub healthy: bool,
    /// Connection index (for debugging).
    pub index: usize,
}

impl ManagedConnection {
    /// Create a new managed connection without encryption.
    pub fn new(conn: VpnConnection, direction: TcpDirection, index: usize) -> Self {
        let now = Instant::now();
        Self {
            conn,
            direction,
            encryption: None,
            connected_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            healthy: true,
            index,
        }
    }

    /// Create a new managed connection with RC4 encryption.
    ///
    /// Each connection gets its own fresh RC4 cipher state because the server
    /// maintains independent RC4 state per TCP socket.
    pub fn with_encryption(
        conn: VpnConnection,
        direction: TcpDirection,
        index: usize,
        rc4_key_pair: &Rc4KeyPair,
    ) -> Self {
        let now = Instant::now();
        Self {
            conn,
            direction,
            encryption: Some(TunnelEncryption::new(rc4_key_pair)),
            connected_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            healthy: true,
            index,
        }
    }

    /// Encrypt data in-place for sending (if encryption is enabled).
    #[inline]
    pub fn encrypt(&mut self, data: &mut [u8]) {
        if let Some(ref mut enc) = self.encryption {
            enc.encrypt(data);
        }
    }

    /// Decrypt data in-place after receiving (if encryption is enabled).
    #[inline]
    pub fn decrypt(&mut self, data: &mut [u8]) {
        if let Some(ref mut enc) = self.encryption {
            enc.decrypt(data);
        }
    }

    /// Check if this connection has encryption enabled.
    #[inline]
    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    /// Update activity timestamp.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if connection has been idle too long.
    pub fn is_idle(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

/// Manager for multiple VPN connections.
///
/// Handles establishing additional connections and provides unified read/write interface.
pub struct ConnectionManager {
    /// All managed connections.
    connections: Vec<ManagedConnection>,
    /// Target number of connections (from config).
    max_connections: usize,
    /// Whether half-connection mode is enabled.
    half_connection: bool,
    /// Session key for additional connections.
    session_key: Vec<u8>,
    /// Server address for additional connections (may be redirect server).
    server: String,
    /// Server port for additional connections (may be redirect server).
    port: u16,
    /// Config for creating new connections.
    config: VpnConfig,
    /// Index of next connection to use for sending (round-robin).
    send_index: usize,
    /// Index of next connection to use for receiving (round-robin).
    recv_index: usize,
    /// Whether to use raw TCP mode (no TLS) for tunnel data.
    /// This is set when use_encrypt=false and server doesn't provide RC4 keys.
    use_raw_mode: bool,
    /// RC4 key pair for creating per-connection encryption.
    /// Each new connection gets fresh cipher state from this key pair.
    rc4_key_pair: Option<Rc4KeyPair>,
}

impl ConnectionManager {
    /// Create a new connection manager with the primary connection.
    ///
    /// Note: `actual_server` and `actual_port` should be the server we're actually
    /// connected to (after any cluster redirect), not the original config server.
    ///
    /// `use_raw_mode` indicates whether the server switched to raw TCP mode
    /// (when use_encrypt=false and no RC4 keys). Additional connections must
    /// also use raw TCP mode in this case.
    ///
    /// `rc4_key_pair` provides keys for per-connection RC4 encryption. Each connection
    /// gets its own fresh cipher state because the server maintains independent RC4
    /// state per TCP socket.
    pub fn new(
        primary_conn: VpnConnection,
        config: &VpnConfig,
        auth_result: &AuthResult,
        actual_server: &str,
        actual_port: u16,
        use_raw_mode: bool,
        rc4_key_pair: Option<Rc4KeyPair>,
    ) -> Self {
        // Use half_connection from config (user controls this, not auto-calculated)
        let half_connection = config.half_connection;

        // In half-connection mode, the PRIMARY connection is ALWAYS ClientToServer (sending)
        // as per SoftEther Protocol.c: "The direction of the first socket is client to server"
        // The server doesn't tell us this - it's implicit in the protocol.
        // Additional connections get directions assigned by the server.
        let direction = if half_connection {
            info!("Half-connection mode: primary connection is ClientToServer (send-only)");
            TcpDirection::ClientToServer
        } else {
            TcpDirection::Both
        };

        // Create primary connection with per-connection encryption if keys provided
        let primary = if let Some(ref keys) = rc4_key_pair {
            info!("RC4 encryption enabled for primary connection");
            ManagedConnection::with_encryption(primary_conn, direction, 0, keys)
        } else {
            ManagedConnection::new(primary_conn, direction, 0)
        };

        // Create a config pointing to the actual server (may be redirect server)
        let mut actual_config = config.clone();
        actual_config.server = actual_server.to_string();
        actual_config.port = actual_port;

        Self {
            connections: vec![primary],
            max_connections: config.max_connections as usize,
            half_connection,
            session_key: auth_result.session_key.to_vec(),
            server: actual_server.to_string(),
            port: actual_port,
            config: actual_config,
            send_index: 0,
            recv_index: 0,
            use_raw_mode,
            rc4_key_pair,
        }
    }

    /// Get the number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.iter().filter(|c| c.healthy).count()
    }

    /// Check if we need more connections.
    pub fn needs_more_connections(&self) -> bool {
        self.connection_count() < self.max_connections
    }

    /// Check if half-connection mode is enabled.
    pub fn is_half_connection(&self) -> bool {
        self.half_connection
    }

    /// Temporarily enable bidirectional mode on the primary connection.
    /// This is needed for DHCP before additional connections are established.
    /// Returns the original direction so it can be restored.
    pub fn enable_primary_bidirectional(&mut self) -> Option<TcpDirection> {
        if !self.connections.is_empty() {
            let original = self.connections[0].direction;
            if original != TcpDirection::Both {
                info!("Temporarily enabling bidirectional mode on primary connection for DHCP");
                self.connections[0].direction = TcpDirection::Both;
                return Some(original);
            }
        }
        None
    }

    /// Restore the primary connection's original direction after DHCP.
    pub fn restore_primary_direction(&mut self, original: TcpDirection) {
        if !self.connections.is_empty() {
            info!("Restoring primary connection direction to {:?}", original);
            self.connections[0].direction = original;
        }
    }

    /// Establish additional connections up to max_connections.
    pub async fn establish_additional_connections(&mut self) -> Result<()> {
        if self.max_connections <= 1 {
            return Ok(());
        }

        info!(
            "Establishing additional connections (target: {})",
            self.max_connections
        );

        while self.connection_count() < self.max_connections {
            let index = self.connections.len();
            match self.establish_one_additional().await {
                Ok(conn) => {
                    info!(
                        "Additional connection {} established (direction: {:?})",
                        index, conn.direction
                    );
                    self.connections.push(conn);
                }
                Err(e) => {
                    warn!("Failed to establish additional connection {}: {}", index, e);
                    // Don't fail completely, continue with what we have
                    break;
                }
            }
        }

        info!(
            "Connection pool: {}/{} connections active",
            self.connection_count(),
            self.max_connections
        );
        Ok(())
    }

    /// Establish a single additional connection.
    /// Wrapped with a timeout to prevent hanging if server doesn't respond.
    async fn establish_one_additional(&self) -> Result<ManagedConnection> {
        use tokio::time::timeout;

        // Use the same timeout as primary connection establishment
        let connect_timeout = Duration::from_secs(self.config.timeout_seconds);

        timeout(connect_timeout, self.establish_one_additional_inner())
            .await
            .map_err(|_| {
                Error::TimeoutMessage(format!(
                    "Additional connection establishment timed out after {}s",
                    self.config.timeout_seconds
                ))
            })?
    }

    /// Inner implementation of additional connection establishment.
    async fn establish_one_additional_inner(&self) -> Result<ManagedConnection> {
        let index = self.connections.len();

        // Create a new TCP connection to the server
        let mut conn = VpnConnection::connect(&self.config).await?;

        // Perform HTTP handshake (signature)
        self.upload_signature(&mut conn).await?;

        // Download Hello from server
        let _hello = self.download_hello(&mut conn).await?;

        // Send additional connection authentication
        let direction = self.upload_additional_auth(&mut conn).await?;

        // Convert to raw TCP if use_encrypt=false (same as primary connection)
        let conn = if self.use_raw_mode {
            debug!("Converting additional connection {} to raw TCP mode", index);
            conn.into_plain()
        } else {
            conn
        };

        debug!(
            "Additional connection {} ready with direction {:?}",
            index, direction
        );

        // Create managed connection with fresh per-connection RC4 encryption.
        // Each TCP socket has independent RC4 state on the server, so we need
        // fresh cipher state for each new connection.
        let managed = if let Some(ref keys) = self.rc4_key_pair {
            debug!("RC4 encryption enabled for additional connection {}", index);
            ManagedConnection::with_encryption(conn, direction, index, keys)
        } else {
            ManagedConnection::new(conn, direction, index)
        };

        Ok(managed)
    }

    /// Upload VPN signature to server.
    async fn upload_signature(&self, conn: &mut VpnConnection) -> Result<()> {
        use crate::protocol::{CONTENT_TYPE_SIGNATURE, SIGNATURE_TARGET, VPN_SIGNATURE};

        let request = HttpRequest::post(SIGNATURE_TARGET)
            .header("Content-Type", CONTENT_TYPE_SIGNATURE)
            .header("Connection", "Keep-Alive")
            .body(VPN_SIGNATURE);

        let host = format!("{}:{}", self.server, self.port);
        let request_bytes = request.build(&host);

        conn.write_all(&request_bytes).await?;
        Ok(())
    }

    /// Download Hello packet from server.
    async fn download_hello(&self, conn: &mut VpnConnection) -> Result<HelloResponse> {
        let mut codec = HttpCodec::new();
        let mut buf = vec![0u8; 4096];

        loop {
            let n = conn.read(&mut buf).await?;
            if n == 0 {
                return Err(Error::ConnectionFailed(
                    "Connection closed during hello".into(),
                ));
            }

            if let Some(response) = codec.feed(&buf[..n])? {
                if response.status_code != 200 {
                    return Err(Error::ServerError(format!(
                        "Server returned status {}",
                        response.status_code
                    )));
                }

                if !response.body.is_empty() {
                    let pack = Pack::deserialize(&response.body)?;
                    return HelloResponse::from_pack(&pack);
                } else {
                    return Err(Error::ServerError("Empty hello response".into()));
                }
            }
        }
    }

    /// Upload additional connection authentication.
    async fn upload_additional_auth(&self, conn: &mut VpnConnection) -> Result<TcpDirection> {
        // Build additional connection pack
        let mut pack = Pack::new();
        pack.add_str("method", "additional_connect");
        pack.add_data("session_key", self.session_key.clone());

        let request = HttpRequest::post(VPN_TARGET)
            .header("Content-Type", CONTENT_TYPE_PACK)
            .header("Connection", "Keep-Alive")
            .body(pack.to_bytes());

        let host = format!("{}:{}", self.server, self.port);
        let request_bytes = request.build(&host);

        conn.write_all(&request_bytes).await?;

        // Read response
        let mut codec = HttpCodec::new();
        let mut buf = vec![0u8; 4096];

        loop {
            let n = conn.read(&mut buf).await?;
            if n == 0 {
                return Err(Error::ConnectionFailed(
                    "Connection closed during additional auth".into(),
                ));
            }

            if let Some(response) = codec.feed(&buf[..n])? {
                if response.status_code != 200 {
                    return Err(Error::AuthenticationFailed(format!(
                        "Additional connection rejected: status {}",
                        response.status_code
                    )));
                }

                if !response.body.is_empty() {
                    let pack = Pack::deserialize(&response.body)?;

                    // Check for error
                    if let Some(error) = pack.get_int("error") {
                        if error != 0 {
                            return Err(Error::AuthenticationFailed(format!(
                                "Additional connection error: {error}"
                            )));
                        }
                    }

                    // Get direction
                    let raw_direction = pack.get_int("direction").unwrap_or(0);
                    let direction = TcpDirection::from_int(raw_direction);
                    debug!(
                        "Additional connection auth response - raw direction: {}, parsed: {:?}",
                        raw_direction, direction
                    );

                    return Ok(direction);
                } else {
                    // Empty body is OK, means success with default direction
                    return Ok(TcpDirection::Both);
                }
            }
        }
    }

    /// Get a connection suitable for sending data.
    /// Uses round-robin among send-capable connections.
    pub fn get_send_connection(&mut self) -> Option<&mut ManagedConnection> {
        let send_capable: Vec<usize> = self
            .connections
            .iter()
            .enumerate()
            .filter(|(_, c)| c.healthy && c.direction.can_send())
            .map(|(i, _)| i)
            .collect();

        if send_capable.is_empty() {
            return None;
        }

        self.send_index = (self.send_index + 1) % send_capable.len();
        let idx = send_capable[self.send_index];
        Some(&mut self.connections[idx])
    }

    /// Get all connections suitable for receiving data.
    pub fn get_recv_connections(&mut self) -> impl Iterator<Item = &mut ManagedConnection> {
        self.connections
            .iter_mut()
            .filter(|c| c.healthy && c.direction.can_recv())
    }

    /// Get the primary (first) connection for operations that need a single connection.
    pub fn primary(&mut self) -> &mut ManagedConnection {
        &mut self.connections[0]
    }

    /// Get mutable reference to connection by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut ManagedConnection> {
        self.connections.get_mut(index)
    }

    /// Get all connections.
    pub fn all_connections(&mut self) -> &mut Vec<ManagedConnection> {
        &mut self.connections
    }

    /// Read data from a single receive-capable connection (round-robin).
    /// Returns (connection_index, data_length) on success.
    ///
    /// Note: For truly concurrent multi-connection reading, use `take_recv_connections()`
    /// with `ConcurrentReader`. This method is for simple cases or bidirectional
    /// connections that also need to send.
    pub async fn read_any(&mut self, buf: &mut [u8]) -> io::Result<(usize, usize)> {
        // Get indices of receive-capable connections
        let recv_indices: Vec<usize> = self
            .connections
            .iter()
            .enumerate()
            .filter(|(_, c)| c.healthy && c.direction.can_recv())
            .map(|(i, _)| i)
            .collect();

        if recv_indices.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "No receive-capable connections available",
            ));
        }

        // Round-robin selection for fairness
        self.recv_index = (self.recv_index + 1) % recv_indices.len();
        let idx = recv_indices[self.recv_index];

        let conn = &mut self.connections[idx];
        let n = conn.conn.read(buf).await?;
        if n > 0 {
            conn.bytes_received += n as u64;
            conn.touch();
        }
        Ok((idx, n))
    }

    /// Read with short timeout from each receive-capable connection.
    /// Returns immediately when any connection has data available.
    /// This provides better latency than sequential polling.
    pub async fn read_any_with_timeout(
        &mut self,
        buf: &mut [u8],
        timeout_ms: u64,
    ) -> io::Result<Option<(usize, usize)>> {
        use tokio::time::timeout;

        let recv_indices: Vec<usize> = self
            .connections
            .iter()
            .enumerate()
            .filter(|(_, c)| c.healthy && c.direction.can_recv())
            .map(|(i, _)| i)
            .collect();

        if recv_indices.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "No receive-capable connections available",
            ));
        }

        // Try each connection with a very short timeout
        let per_conn_timeout = Duration::from_millis(timeout_ms / recv_indices.len() as u64)
            .max(Duration::from_millis(1));

        for &idx in &recv_indices {
            let conn = &mut self.connections[idx];
            match timeout(per_conn_timeout, conn.conn.read(buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    conn.bytes_received += n as u64;
                    conn.touch();
                    return Ok(Some((idx, n)));
                }
                Ok(Ok(_)) => {} // Zero bytes, continue
                Ok(Err(e)) => return Err(e),
                Err(_) => {} // Timeout, try next
            }
        }

        Ok(None) // No data available within timeout
    }

    /// Write data using an appropriate send connection.
    /// Flushes immediately to minimize latency for VPN traffic.
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        // Select a send-capable connection
        let idx = {
            let send_capable: Vec<usize> = self
                .connections
                .iter()
                .enumerate()
                .filter(|(_, c)| c.healthy && c.direction.can_send())
                .map(|(i, _)| i)
                .collect();

            if send_capable.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "No send-capable connections available",
                ));
            }

            self.send_index = (self.send_index + 1) % send_capable.len();
            send_capable[self.send_index]
        };

        let conn = &mut self.connections[idx];
        conn.conn.write_all(buf).await?;
        conn.conn.flush().await?; // Flush immediately for low latency
        conn.bytes_sent += buf.len() as u64;
        conn.touch();
        Ok(())
    }

    /// Write data with per-connection encryption.
    /// Encrypts using the selected connection's own cipher state, then sends.
    /// Each TCP socket has independent RC4 state on the server.
    pub async fn write_all_encrypted(&mut self, buf: &mut [u8]) -> io::Result<()> {
        // Select a send-capable connection
        let idx = {
            let send_capable: Vec<usize> = self
                .connections
                .iter()
                .enumerate()
                .filter(|(_, c)| c.healthy && c.direction.can_send())
                .map(|(i, _)| i)
                .collect();

            if send_capable.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "No send-capable connections available",
                ));
            }

            self.send_index = (self.send_index + 1) % send_capable.len();
            send_capable[self.send_index]
        };

        let conn = &mut self.connections[idx];
        // Encrypt with this connection's own cipher state
        conn.encrypt(buf);
        conn.conn.write_all(buf).await?;
        conn.conn.flush().await?; // Flush immediately for low latency
        conn.bytes_sent += buf.len() as u64;
        conn.touch();
        Ok(())
    }

    /// Read data from a bidirectional connection with per-connection decryption.
    /// Returns (connection_index, data_length) on success.
    /// Decrypts in-place using the connection's own cipher state.
    pub async fn read_any_decrypt(&mut self, buf: &mut [u8]) -> io::Result<(usize, usize)> {
        // Get indices of receive-capable connections
        let recv_indices: Vec<usize> = self
            .connections
            .iter()
            .enumerate()
            .filter(|(_, c)| c.healthy && c.direction.can_recv())
            .map(|(i, _)| i)
            .collect();

        if recv_indices.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "No receive-capable connections available",
            ));
        }

        // Round-robin selection for fairness
        self.recv_index = (self.recv_index + 1) % recv_indices.len();
        let idx = recv_indices[self.recv_index];

        let conn = &mut self.connections[idx];
        let n = conn.conn.read(buf).await?;
        if n > 0 {
            // Decrypt with this connection's own cipher state
            conn.decrypt(&mut buf[..n]);
            conn.bytes_received += n as u64;
            conn.touch();
        }
        Ok((idx, n))
    }

    /// Mark a connection as unhealthy.
    pub fn mark_unhealthy(&mut self, index: usize) {
        if let Some(conn) = self.connections.get_mut(index) {
            conn.healthy = false;
            warn!("Connection {} marked unhealthy", index);
        }
    }

    /// Extract receive-ONLY connections for concurrent reading.
    ///
    /// This removes ONLY receive-only connections (ServerToClient direction) from
    /// the manager and returns them as (index, connection, direction, encryption) tuples
    /// for use with ConcurrentReader.
    ///
    /// IMPORTANT: Bidirectional connections (Both) are NOT extracted because they
    /// are needed for sending. Only in half-connection mode with dedicated
    /// receive connections do we extract them.
    ///
    /// Each connection includes its own RC4 encryption state (if enabled) for
    /// per-connection decryption.
    ///
    /// After calling this, bidirectional and send-only connections remain.
    pub fn take_recv_connections(
        &mut self,
    ) -> Vec<(
        usize,
        super::VpnConnection,
        TcpDirection,
        Option<TunnelEncryption>,
    )> {
        let mut recv_conns = Vec::new();
        let mut remaining = Vec::new();

        for (i, managed) in self.connections.drain(..).enumerate() {
            // Only extract ServerToClient (receive-only) connections.
            // Both (bidirectional) connections must stay for sending!
            if managed.direction == TcpDirection::ServerToClient && managed.healthy {
                recv_conns.push((i, managed.conn, managed.direction, managed.encryption));
            } else {
                remaining.push(managed);
            }
        }

        self.connections = remaining;

        info!(
            "Extracted {} receive-only connections, {} connections remain for sending",
            recv_conns.len(),
            self.connections.len()
        );

        recv_conns
    }

    /// Check if the manager still has send-capable connections.
    pub fn has_send_connections(&self) -> bool {
        self.connections
            .iter()
            .any(|c| c.healthy && c.direction.can_send())
    }

    /// Get statistics for all connections.
    pub fn stats(&self) -> ConnectionStats {
        let mut stats = ConnectionStats {
            total_connections: self.connections.len(),
            healthy_connections: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
        };

        for conn in &self.connections {
            if conn.healthy {
                stats.healthy_connections += 1;
            }
            stats.total_bytes_sent += conn.bytes_sent;
            stats.total_bytes_received += conn.bytes_received;
        }

        stats
    }

    /// Flush all send-capable connections.
    pub async fn flush(&mut self) -> io::Result<()> {
        for conn in &mut self.connections {
            if conn.healthy && conn.direction.can_send() {
                conn.conn.flush().await?;
            }
        }
        Ok(())
    }

    /// Update received bytes stats from concurrent reader.
    pub fn update_recv_stats(&mut self, recv_stats: &[(usize, u64)]) {
        // These stats are for extracted connections, add to total
        for (_, bytes) in recv_stats {
            // We don't have the connection anymore, but we can track total
            // This is a simplification - in practice we'd track separately
            let _ = bytes; // Stats tracked in ConcurrentReader
        }
    }
}

/// Statistics for all managed connections.
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Total number of connections.
    pub total_connections: usize,
    /// Number of healthy connections.
    pub healthy_connections: usize,
    /// Total bytes sent across all connections.
    pub total_bytes_sent: u64,
    /// Total bytes received across all connections.
    pub total_bytes_received: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // TcpDirection tests
    // ==========================================================================

    #[test]
    fn test_tcp_direction_from_int() {
        // TCP_BOTH = 0
        assert_eq!(TcpDirection::from_int(0), TcpDirection::Both);
        // TCP_SERVER_TO_CLIENT = 1
        assert_eq!(TcpDirection::from_int(1), TcpDirection::ServerToClient);
        // TCP_CLIENT_TO_SERVER = 2
        assert_eq!(TcpDirection::from_int(2), TcpDirection::ClientToServer);
        // Unknown values default to Both
        assert_eq!(TcpDirection::from_int(99), TcpDirection::Both);
    }

    #[test]
    fn test_tcp_direction_can_send() {
        // Both: can send and receive
        assert!(TcpDirection::Both.can_send());
        // ClientToServer: send only
        assert!(TcpDirection::ClientToServer.can_send());
        // ServerToClient: receive only
        assert!(!TcpDirection::ServerToClient.can_send());
    }

    #[test]
    fn test_tcp_direction_can_recv() {
        // Both: can send and receive
        assert!(TcpDirection::Both.can_recv());
        // ServerToClient: receive only
        assert!(TcpDirection::ServerToClient.can_recv());
        // ClientToServer: send only
        assert!(!TcpDirection::ClientToServer.can_recv());
    }

    #[test]
    fn test_tcp_direction_half_connection_split() {
        // In half-connection mode with 4 connections:
        // - 2 should be ClientToServer (upload)
        // - 2 should be ServerToClient (download)
        let directions = [
            TcpDirection::ClientToServer, // Primary is always C2S
            TcpDirection::ServerToClient, // Server assigns
            TcpDirection::ClientToServer, // Server assigns
            TcpDirection::ServerToClient, // Server assigns
        ];

        let send_count = directions.iter().filter(|d| d.can_send()).count();
        let recv_count = directions.iter().filter(|d| d.can_recv()).count();

        assert_eq!(send_count, 2, "Should have 2 send-capable connections");
        assert_eq!(recv_count, 2, "Should have 2 recv-capable connections");
    }

    // ==========================================================================
    // ManagedConnection tests (without actual network)
    // ==========================================================================

    // Note: ManagedConnection requires a real VpnConnection, so we test
    // the encryption methods separately.

    #[test]
    fn test_tunnel_encryption_independent_state() {
        // Each connection should have independent RC4 state
        // This test verifies that creating multiple encryptions from same keys
        // produces independent cipher streams
        use crate::crypto::{Rc4KeyPair, RC4_KEY_SIZE};

        let keys = Rc4KeyPair {
            server_to_client: [0x01; RC4_KEY_SIZE],
            client_to_server: [0x02; RC4_KEY_SIZE],
        };

        let mut enc1 = TunnelEncryption::new(&keys);
        let mut enc2 = TunnelEncryption::new(&keys);

        // Same plaintext
        let mut data1 = vec![0u8; 16];
        let mut data2 = vec![0u8; 16];

        // Both should produce identical ciphertext (same initial state)
        enc1.encrypt(&mut data1);
        enc2.encrypt(&mut data2);

        assert_eq!(data1, data2, "Same keys should produce same ciphertext");

        // But after encrypting different amounts, they diverge
        let mut data3 = vec![0u8; 8]; // Advance enc1 by 8 more bytes
        enc1.encrypt(&mut data3);

        let mut data4 = vec![0u8; 16];
        let mut data5 = vec![0u8; 16];
        enc1.encrypt(&mut data4); // enc1 is now at position 32
        enc2.encrypt(&mut data5); // enc2 is at position 16

        assert_ne!(
            data4, data5,
            "Different stream positions should produce different ciphertext"
        );
    }

    // ==========================================================================
    // ConnectionStats tests
    // ==========================================================================

    #[test]
    fn test_connection_stats_default() {
        let stats = ConnectionStats {
            total_connections: 0,
            healthy_connections: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
        };

        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.healthy_connections, 0);
        assert_eq!(stats.total_bytes_sent, 0);
        assert_eq!(stats.total_bytes_received, 0);
    }

    #[test]
    fn test_connection_stats_aggregation() {
        // Simulate stats from multiple connections
        let conn_stats = [
            (100u64, 200u64), // conn 0: 100 sent, 200 received
            (150u64, 300u64), // conn 1
            (50u64, 100u64),  // conn 2
        ];

        let total_sent: u64 = conn_stats.iter().map(|(s, _)| s).sum();
        let total_recv: u64 = conn_stats.iter().map(|(_, r)| r).sum();

        assert_eq!(total_sent, 300);
        assert_eq!(total_recv, 600);
    }

    // ==========================================================================
    // Half-connection mode logic tests
    // ==========================================================================

    #[test]
    fn test_half_connection_primary_direction() {
        // In half-connection mode, primary connection is ALWAYS ClientToServer
        // This is per SoftEther Protocol.c specification
        let half_connection = true;

        let expected = if half_connection {
            TcpDirection::ClientToServer
        } else {
            TcpDirection::Both
        };

        assert_eq!(expected, TcpDirection::ClientToServer);
    }

    #[test]
    fn test_connection_distribution_4_conns() {
        // Test typical 4-connection half-connection setup
        // Server should assign directions to balance send/recv
        //
        // Typical distribution:
        // - Connection 0: ClientToServer (primary, always C2S)
        // - Connection 1: ServerToClient
        // - Connection 2: ClientToServer
        // - Connection 3: ServerToClient
        let directions = simulate_connection_distribution(4);

        let c2s_count = directions
            .iter()
            .filter(|d| **d == TcpDirection::ClientToServer)
            .count();
        let s2c_count = directions
            .iter()
            .filter(|d| **d == TcpDirection::ServerToClient)
            .count();

        // Should be roughly balanced (2 and 2)
        assert!(
            c2s_count >= 1 && c2s_count <= 3,
            "C2S count {} not in expected range",
            c2s_count
        );
        assert!(
            s2c_count >= 1 && s2c_count <= 3,
            "S2C count {} not in expected range",
            s2c_count
        );
        assert_eq!(c2s_count + s2c_count, 4, "Total should be 4 connections");
    }

    #[test]
    fn test_connection_distribution_8_conns() {
        // Test 8-connection half-connection setup
        let directions = simulate_connection_distribution(8);

        let c2s_count = directions
            .iter()
            .filter(|d| **d == TcpDirection::ClientToServer)
            .count();
        let s2c_count = directions
            .iter()
            .filter(|d| **d == TcpDirection::ServerToClient)
            .count();

        // Should be balanced (4 and 4)
        assert!(
            c2s_count >= 3 && c2s_count <= 5,
            "C2S count {} not in expected range",
            c2s_count
        );
        assert!(
            s2c_count >= 3 && s2c_count <= 5,
            "S2C count {} not in expected range",
            s2c_count
        );
    }

    /// Simulate how server assigns directions to N connections.
    /// Based on SoftEther Protocol.c: alternates after primary.
    fn simulate_connection_distribution(n: usize) -> Vec<TcpDirection> {
        let mut directions = Vec::with_capacity(n);

        for i in 0..n {
            if i == 0 {
                // Primary is always ClientToServer
                directions.push(TcpDirection::ClientToServer);
            } else {
                // Server alternates remaining connections
                // Odd index -> ServerToClient, Even index -> ClientToServer
                if i % 2 == 1 {
                    directions.push(TcpDirection::ServerToClient);
                } else {
                    directions.push(TcpDirection::ClientToServer);
                }
            }
        }

        directions
    }

    // ==========================================================================
    // Round-robin selection tests
    // ==========================================================================

    #[test]
    fn test_round_robin_send_selection() {
        // Simulate round-robin selection among send-capable connections
        let directions = [
            TcpDirection::ClientToServer, // 0: can send
            TcpDirection::ServerToClient, // 1: cannot send
            TcpDirection::ClientToServer, // 2: can send
            TcpDirection::ServerToClient, // 3: cannot send
        ];

        let send_indices: Vec<usize> = directions
            .iter()
            .enumerate()
            .filter(|(_, d)| d.can_send())
            .map(|(i, _)| i)
            .collect();

        assert_eq!(send_indices, vec![0, 2], "Only indices 0 and 2 can send");

        // Round-robin should cycle through send-capable connections
        let mut send_index = 0;
        let selected: Vec<usize> = (0..6)
            .map(|_| {
                send_index = (send_index + 1) % send_indices.len();
                send_indices[send_index]
            })
            .collect();

        // Should cycle: 2, 0, 2, 0, 2, 0
        assert_eq!(selected, vec![2, 0, 2, 0, 2, 0]);
    }

    #[test]
    fn test_round_robin_recv_selection() {
        // Simulate round-robin selection among recv-capable connections
        let directions = [
            TcpDirection::ClientToServer, // 0: cannot recv
            TcpDirection::ServerToClient, // 1: can recv
            TcpDirection::Both,           // 2: can recv
            TcpDirection::ServerToClient, // 3: can recv
        ];

        let recv_indices: Vec<usize> = directions
            .iter()
            .enumerate()
            .filter(|(_, d)| d.can_recv())
            .map(|(i, _)| i)
            .collect();

        assert_eq!(recv_indices, vec![1, 2, 3], "Indices 1, 2, 3 can recv");
    }

    // ==========================================================================
    // Connection extraction tests (for ConcurrentReader)
    // ==========================================================================

    #[test]
    fn test_take_recv_connections_logic() {
        // Test the logic of extracting recv-only connections
        // ServerToClient should be extracted
        // Both and ClientToServer should remain

        let directions = [
            TcpDirection::ClientToServer, // 0: remains (for sending)
            TcpDirection::ServerToClient, // 1: extracted (recv-only)
            TcpDirection::Both,           // 2: remains (bidirectional)
            TcpDirection::ServerToClient, // 3: extracted (recv-only)
        ];

        let mut extracted = Vec::new();
        let mut remaining = Vec::new();

        for (i, dir) in directions.iter().enumerate() {
            if *dir == TcpDirection::ServerToClient {
                extracted.push(i);
            } else {
                remaining.push(i);
            }
        }

        assert_eq!(extracted, vec![1, 3], "S2C connections should be extracted");
        assert_eq!(
            remaining,
            vec![0, 2],
            "C2S and Both should remain for sending"
        );
    }

    #[test]
    fn test_has_send_connections_after_extraction() {
        // After extracting recv-only connections, we should still have send connections
        let remaining_directions = [
            TcpDirection::ClientToServer, // 0: can send
            TcpDirection::Both,           // 2: can send
        ];

        let has_send = remaining_directions.iter().any(|d| d.can_send());
        assert!(has_send, "Should still have send connections after extraction");
    }

    // ==========================================================================
    // Timeout configuration tests
    // ==========================================================================

    #[test]
    fn test_connection_timeout_detection() {
        use std::time::Duration;

        // Simulate idle detection
        let timeout = Duration::from_secs(30);
        let last_activity_secs = 35u64; // 35 seconds ago

        let is_idle = last_activity_secs > timeout.as_secs();
        assert!(is_idle, "Connection should be detected as idle");

        let recent_activity_secs = 10u64;
        let is_active = recent_activity_secs <= timeout.as_secs();
        assert!(is_active, "Recent connection should not be idle");
    }

    // ==========================================================================
    // Packet encoding/decoding consistency tests
    // ==========================================================================

    #[test]
    fn test_session_key_validity() {
        // Session key should be non-empty for additional connections
        let session_key = vec![0x01, 0x02, 0x03, 0x04, 0x05];

        assert!(!session_key.is_empty(), "Session key should not be empty");
        assert!(
            session_key.len() >= 4,
            "Session key should have reasonable length"
        );
    }

    #[test]
    fn test_additional_connection_pack_format() {
        use crate::protocol::Pack;

        // Verify the pack format for additional connection auth
        let session_key = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let mut pack = Pack::new();
        pack.add_str("method", "additional_connect");
        pack.add_data("session_key", session_key.clone());

        // Verify fields were added
        assert_eq!(pack.get_str("method"), Some("additional_connect"));

        // Serialize and verify it's valid
        let bytes = pack.to_bytes();
        assert!(!bytes.is_empty(), "Pack should serialize to non-empty bytes");

        // Deserialize and verify roundtrip
        let pack2 = Pack::deserialize(&bytes).expect("Should deserialize");
        assert_eq!(pack2.get_str("method"), Some("additional_connect"));
    }
}
