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
use crate::error::{Error, Result};
use crate::protocol::{
    AuthResult, HelloResponse, HttpCodec, HttpRequest, Pack,
    CONTENT_TYPE_PACK, VPN_TARGET,
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
            1 => TcpDirection::ServerToClient,  // Server->Client = client receives
            2 => TcpDirection::ClientToServer,  // Client->Server = client sends
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
    /// Create a new managed connection.
    pub fn new(conn: VpnConnection, direction: TcpDirection, index: usize) -> Self {
        let now = Instant::now();
        Self {
            conn,
            direction,
            connected_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            healthy: true,
            index,
        }
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
}

impl ConnectionManager {
    /// Create a new connection manager with the primary connection.
    /// 
    /// Note: `actual_server` and `actual_port` should be the server we're actually
    /// connected to (after any cluster redirect), not the original config server.
    pub fn new(
        primary_conn: VpnConnection,
        config: &VpnConfig,
        auth_result: &AuthResult,
        actual_server: &str,
        actual_port: u16,
    ) -> Self {
        let half_connection = config.max_connections > 1;
        
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
        
        let primary = ManagedConnection::new(primary_conn, direction, 0);
        
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
    
    /// Establish additional connections up to max_connections.
    pub async fn establish_additional_connections(&mut self) -> Result<()> {
        if self.max_connections <= 1 {
            return Ok(());
        }
        
        info!("Establishing additional connections (target: {})", self.max_connections);
        
        while self.connection_count() < self.max_connections {
            let index = self.connections.len();
            match self.establish_one_additional().await {
                Ok(conn) => {
                    info!("Additional connection {} established (direction: {:?})", 
                          index, conn.direction);
                    self.connections.push(conn);
                }
                Err(e) => {
                    warn!("Failed to establish additional connection {}: {}", index, e);
                    // Don't fail completely, continue with what we have
                    break;
                }
            }
        }
        
        info!("Connection pool: {}/{} connections active", 
              self.connection_count(), self.max_connections);
        Ok(())
    }
    
    /// Establish a single additional connection.
    async fn establish_one_additional(&self) -> Result<ManagedConnection> {
        let index = self.connections.len();
        
        // Create a new TCP connection to the server
        let mut conn = VpnConnection::connect(&self.config).await?;
        
        // Perform HTTP handshake (signature)
        self.upload_signature(&mut conn).await?;
        
        // Download Hello from server
        let _hello = self.download_hello(&mut conn).await?;
        
        // Send additional connection authentication
        let direction = self.upload_additional_auth(&mut conn).await?;
        
        debug!("Additional connection {} ready with direction {:?}", index, direction);
        
        Ok(ManagedConnection::new(conn, direction, index))
    }
    
    /// Upload VPN signature to server.
    async fn upload_signature(&self, conn: &mut VpnConnection) -> Result<()> {
        use crate::protocol::{SIGNATURE_TARGET, CONTENT_TYPE_SIGNATURE, VPN_SIGNATURE};
        
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
                return Err(Error::ConnectionFailed("Connection closed during hello".into()));
            }
            
            if let Some(response) = codec.feed(&buf[..n])? {
                if response.status_code != 200 {
                    return Err(Error::ServerError(format!(
                        "Server returned status {}", response.status_code
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
                return Err(Error::ConnectionFailed("Connection closed during additional auth".into()));
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
                                "Additional connection error: {}",
                                error
                            )));
                        }
                    }
                    
                    // Get direction
                    let raw_direction = pack.get_int("direction").unwrap_or(0);
                    let direction = TcpDirection::from_int(raw_direction);
                    debug!("Additional connection auth response - raw direction: {}, parsed: {:?}", raw_direction, direction);
                    
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
        let send_capable: Vec<usize> = self.connections.iter()
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
        self.connections.iter_mut()
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
        let recv_indices: Vec<usize> = self.connections.iter()
            .enumerate()
            .filter(|(_, c)| c.healthy && c.direction.can_recv())
            .map(|(i, _)| i)
            .collect();
        
        if recv_indices.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "No receive-capable connections available"
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
    pub async fn read_any_with_timeout(&mut self, buf: &mut [u8], timeout_ms: u64) -> io::Result<Option<(usize, usize)>> {
        use tokio::time::timeout;
        
        let recv_indices: Vec<usize> = self.connections.iter()
            .enumerate()
            .filter(|(_, c)| c.healthy && c.direction.can_recv())
            .map(|(i, _)| i)
            .collect();
        
        if recv_indices.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "No receive-capable connections available"
            ));
        }
        
        // Try each connection with a very short timeout
        let per_conn_timeout = Duration::from_millis(timeout_ms / recv_indices.len() as u64).max(Duration::from_millis(1));
        
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
            let send_capable: Vec<usize> = self.connections.iter()
                .enumerate()
                .filter(|(_, c)| c.healthy && c.direction.can_send())
                .map(|(i, _)| i)
                .collect();
            
            if send_capable.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "No send-capable connections available"
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
    /// the manager and returns them as (index, connection, direction) tuples for
    /// use with ConcurrentReader.
    ///
    /// IMPORTANT: Bidirectional connections (Both) are NOT extracted because they
    /// are needed for sending. Only in half-connection mode with dedicated
    /// receive connections do we extract them.
    ///
    /// After calling this, bidirectional and send-only connections remain.
    pub fn take_recv_connections(&mut self) -> Vec<(usize, super::VpnConnection, TcpDirection)> {
        let mut recv_conns = Vec::new();
        let mut remaining = Vec::new();
        
        for (i, managed) in self.connections.drain(..).enumerate() {
            // Only extract ServerToClient (receive-only) connections.
            // Both (bidirectional) connections must stay for sending!
            if managed.direction == TcpDirection::ServerToClient && managed.healthy {
                recv_conns.push((i, managed.conn, managed.direction));
            } else {
                remaining.push(managed);
            }
        }
        
        self.connections = remaining;
        
        info!("Extracted {} receive-only connections, {} connections remain for sending",
              recv_conns.len(), self.connections.len());
        
        recv_conns
    }
    
    /// Check if the manager still has send-capable connections.
    pub fn has_send_connections(&self) -> bool {
        self.connections.iter().any(|c| c.healthy && c.direction.can_send())
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
