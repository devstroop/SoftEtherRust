//! Connection management for SoftEther VPN protocol
//!
//! Implementation of CONNECTION structure and connection lifecycle management.

use crate::constants::ConnectionStatus;
use crate::{
    MAX_CLIENT_STR_LEN, MAX_HOST_NAME_LEN, MAX_SERVER_STR_LEN, SHA1_SIZE, SOFTETHER_BUILD,
    SOFTETHER_VER,
};
use mayaqua::{get_tick64, Error, Pack, Result, Tick64};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::{sleep, Duration};

/// Connection configuration
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    pub server_mode: bool,
    pub use_ssl: bool,
    pub timeout: u32,
    pub keep_alive_interval: u32,
    pub max_recv_block_size: usize,
    pub max_send_block_size: usize,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            server_mode: false,
            use_ssl: true,
            timeout: 15,
            keep_alive_interval: 50,
            max_recv_block_size: 32768,
            max_send_block_size: 32768,
        }
    }
}

/// Network block for data transmission
#[derive(Debug, Clone)]
pub struct Block {
    pub data: Vec<u8>,
    pub size: usize,
    pub compressed: bool,
    pub priority: bool,
}

impl Block {
    pub fn new(data: Vec<u8>) -> Self {
        let size = data.len();
        Self {
            data,
            size,
            compressed: false,
            priority: false,
        }
    }

    pub fn new_compressed(data: Vec<u8>) -> Self {
        let size = data.len();
        Self {
            data,
            size,
            compressed: true,
            priority: false,
        }
    }

    pub fn new_priority(data: Vec<u8>) -> Self {
        let size = data.len();
        Self {
            data,
            size,
            compressed: false,
            priority: true,
        }
    }
}

/// Connection state information
#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub status: ConnectionStatus,
    pub connected_tick: Tick64,
    pub last_comm_tick: Tick64,
    pub error_code: u32,
    pub current_send_queue_size: usize,
    pub last_tcp_queue_size: usize,
    pub last_packet_queue_size: usize,
    pub total_sent: u64,
    pub total_received: u64,
    pub rtt_millis: u32,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            status: ConnectionStatus::Negotiation,
            connected_tick: get_tick64(),
            last_comm_tick: get_tick64(),
            error_code: 0,
            current_send_queue_size: 0,
            last_tcp_queue_size: 0,
            last_packet_queue_size: 0,
            total_sent: 0,
            total_received: 0,
            rtt_millis: 0,
        }
    }
}

/// Connection management structure (matches C CONNECTION structure)
#[derive(Debug)]
pub struct Connection {
    // Core connection data
    pub name: String, // Connection name
    pub config: ConnectionConfig,

    // Version negotiation
    pub server_ver: u32,    // Server version
    pub server_build: u32,  // Server build number
    pub client_ver: u32,    // Client version
    pub client_build: u32,  // Client build number
    pub server_str: String, // Server string
    pub client_str: String, // Client string

    // Random values and tickets
    pub random: [u8; SHA1_SIZE], // Authentication random (20 bytes)
    pub use_ticket: bool,        // Ticket authentication flag
    pub ticket: [u8; SHA1_SIZE], // Authentication ticket

    // Network information
    pub server_name: String,     // Server hostname
    pub server_port: u16,        // Server port
    pub client_ip: String,       // Client IP address
    pub client_port: u16,        // Client port number
    pub client_hostname: String, // Client hostname

    // Certificates and encryption
    pub server_cert: Option<Vec<u8>>, // Server certificate (X.509 DER)
    pub client_cert: Option<Vec<u8>>, // Client certificate (X.509 DER)
    pub cipher_name: String,          // Cipher algorithm name
    pub dont_use_tls1: bool,          // Disable TLS 1.0

    // Connection state
    pub state: Arc<Mutex<ConnectionState>>,

    // Control channels
    pub halt: bool,
    pub halt_tx: Option<oneshot::Sender<()>>,
    pub halt_rx: Option<oneshot::Receiver<()>>,

    // Data queues
    pub received_blocks: Arc<Mutex<VecDeque<Block>>>,
    pub send_blocks: Arc<Mutex<VecDeque<Block>>>,
    pub send_blocks_priority: Arc<Mutex<VecDeque<Block>>>,

    // Network connection
    pub tcp_stream: Option<TcpStream>,

    // Protocol flags
    pub was_sstp: bool,        // SSTP processed
    pub was_dat_proxy: bool,   // DAT proxy processed
    pub is_json_rpc: bool,     // JSON-RPC connection
    pub json_rpc_authed: bool, // JSON-RPC authenticated

    // Hash values
    pub ctoken_hash: [u8; SHA1_SIZE], // CTOKEN hash

    // Connection counters
    pub additional_connection_failed_counter: u32,
    pub last_counter_reset_tick: Tick64,
}

impl Connection {
    /// Create a new connection
    pub fn new(name: String, config: ConnectionConfig) -> Self {
        let (halt_tx, halt_rx) = oneshot::channel();

        Self {
            name,
            config,

            server_ver: 0,
            server_build: 0,
            client_ver: SOFTETHER_VER,
            client_build: SOFTETHER_BUILD,
            server_str: String::new(),
            client_str: format!("SoftEtherVPN_Rust/{}.{}", SOFTETHER_VER, SOFTETHER_BUILD),

            random: [0u8; SHA1_SIZE],
            use_ticket: false,
            ticket: [0u8; SHA1_SIZE],

            server_name: String::new(),
            server_port: 0,
            client_ip: String::new(),
            client_port: 0,
            client_hostname: String::new(),

            server_cert: None,
            client_cert: None,
            cipher_name: String::new(),
            dont_use_tls1: false,

            state: Arc::new(Mutex::new(ConnectionState::default())),

            halt: false,
            halt_tx: Some(halt_tx),
            halt_rx: Some(halt_rx),

            received_blocks: Arc::new(Mutex::new(VecDeque::new())),
            send_blocks: Arc::new(Mutex::new(VecDeque::new())),
            send_blocks_priority: Arc::new(Mutex::new(VecDeque::new())),

            tcp_stream: None,

            was_sstp: false,
            was_dat_proxy: false,
            is_json_rpc: false,
            json_rpc_authed: false,

            ctoken_hash: [0u8; SHA1_SIZE],

            additional_connection_failed_counter: 0,
            last_counter_reset_tick: get_tick64(),
        }
    }

    /// Connect to server
    pub async fn connect(&mut self, hostname: &str, port: u16) -> Result<()> {
        if hostname.len() > MAX_HOST_NAME_LEN {
            return Err(Error::InvalidParameter);
        }

        self.server_name = hostname.to_string();
        self.server_port = port;

        // Attempt TCP connection
        let addr = format!("{}:{}", hostname, port);
        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                self.tcp_stream = Some(stream);

                // Update connection state
                {
                    let mut state = self.state.lock().unwrap();
                    state.status = ConnectionStatus::Negotiation;
                    state.connected_tick = get_tick64();
                    state.last_comm_tick = state.connected_tick;
                }

                log::info!("Connected to {}:{}", hostname, port);
                Ok(())
            }
            Err(e) => {
                log::error!("Failed to connect to {}:{}: {}", hostname, port, e);
                Err(Error::ConnectFailed)
            }
        }
    }

    /// Disconnect from server
    pub async fn disconnect(&mut self) -> Result<()> {
        if !self.halt {
            self.halt = true;

            // Send halt signal
            if let Some(halt_tx) = self.halt_tx.take() {
                let _ = halt_tx.send(());
            }

            // Close TCP stream
            if let Some(_stream) = self.tcp_stream.take() {
                // TcpStream will be dropped and closed
            }

            log::info!("Connection '{}' disconnected", self.name);
        }
        Ok(())
    }

    /// Attempt to recover from a transient error with exponential backoff.
    pub async fn recover_from_error(&mut self, hostname: &str, port: u16) -> Result<()> {
        let mut delay_ms = 250u64;
        for attempt in 0..5 {
            match self.connect(hostname, port).await {
                Ok(()) => {
                    log::info!("Recovered connection after {} attempts", attempt + 1);
                    return Ok(());
                }
                Err(_) => {
                    sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms = (delay_ms * 2).min(8_000);
                }
            }
        }
        Err(Error::ConnectFailed)
    }

    /// Update basic quality metrics (RTT) using a timestamp echo mechanism.
    /// Placeholder: in absence of protocol echo, we update last_comm_tick.
    pub fn update_quality_metrics(&self) {
        let mut state = self.state.lock().unwrap();
        // In real impl, compute RTT from ping/echo. Keep 0 when unknown.
        state.last_comm_tick = get_tick64();
    }

    /// Adjust buffer sizes based on current queues (placeholder logic)
    pub fn adjust_buffer_sizes(&mut self) {
        let queue = self.get_send_queue_size();
        if queue > 1024 {
            self.config.max_send_block_size = (self.config.max_send_block_size * 2).min(256 * 1024);
        } else if queue == 0 {
            self.config.max_send_block_size = self
                .config
                .max_send_block_size
                .saturating_sub(4096)
                .max(16 * 1024);
        }
    }

    /// Generate authentication random
    pub fn generate_auth_random(&mut self) -> Result<()> {
        use rand::RngCore;
        let mut rng = rand::rng();
        rng.fill_bytes(&mut self.random);
        Ok(())
    }

    /// Set server information from negotiation
    pub fn set_server_info(&mut self, ver: u32, build: u32, server_str: &str) -> Result<()> {
        if server_str.len() > MAX_SERVER_STR_LEN {
            return Err(Error::InvalidParameter);
        }

        self.server_ver = ver;
        self.server_build = build;
        self.server_str = server_str.to_string();
        Ok(())
    }

    /// Set client string
    pub fn set_client_string(&mut self, client_str: &str) -> Result<()> {
        if client_str.len() > MAX_CLIENT_STR_LEN {
            return Err(Error::InvalidParameter);
        }

        self.client_str = client_str.to_string();
        Ok(())
    }

    /// Add block to send queue
    pub fn send_block(&self, block: Block) -> Result<()> {
        if self.halt {
            return Err(Error::DisconnectedError);
        }

        if block.priority {
            self.send_blocks_priority.lock().unwrap().push_back(block);
        } else {
            self.send_blocks.lock().unwrap().push_back(block);
        }

        // Update queue size
        let queue_size = self.send_blocks.lock().unwrap().len()
            + self.send_blocks_priority.lock().unwrap().len();
        self.state.lock().unwrap().current_send_queue_size = queue_size;

        Ok(())
    }

    /// Get next received block
    pub fn receive_block(&self) -> Option<Block> {
        self.received_blocks.lock().unwrap().pop_front()
    }

    /// Add received block to queue
    pub fn add_received_block(&self, block: Block) -> Result<()> {
        if self.halt {
            return Err(Error::DisconnectedError);
        }

        self.received_blocks.lock().unwrap().push_back(block);

        // Update last communication time
        self.state.lock().unwrap().last_comm_tick = get_tick64();

        Ok(())
    }

    /// Send a pack over the connection
    pub fn send_pack(&self, pack: &Pack) -> Result<()> {
        let data = pack.to_buffer()?;
        let block = Block::new(data);
        self.send_block(block)
    }

    /// Send a priority pack over the connection
    pub fn send_pack_priority(&self, pack: &Pack) -> Result<()> {
        let data = pack.to_buffer()?;
        let block = Block::new_priority(data);
        self.send_block(block)
    }

    /// Get connection status
    pub fn get_status(&self) -> ConnectionStatus {
        self.state.lock().unwrap().status
    }

    /// Set connection status
    pub fn set_status(&self, status: ConnectionStatus) {
        self.state.lock().unwrap().status = status;
    }

    /// Check if connection is established
    pub fn is_established(&self) -> bool {
        !self.halt && self.get_status() == ConnectionStatus::Established
    }

    /// Check if connection is connected
    pub fn is_connected(&self) -> bool {
        !self.halt && self.tcp_stream.is_some()
    }

    /// Update traffic statistics
    pub fn update_traffic(&self, sent: u64, received: u64) {
        let mut state = self.state.lock().unwrap();
        state.total_sent += sent;
        state.total_received += received;
        state.last_comm_tick = get_tick64();
    }

    /// Get send queue size
    pub fn get_send_queue_size(&self) -> usize {
        self.state.lock().unwrap().current_send_queue_size
    }

    /// Clear send queues
    pub fn clear_send_queues(&self) {
        self.send_blocks.lock().unwrap().clear();
        self.send_blocks_priority.lock().unwrap().clear();
        self.state.lock().unwrap().current_send_queue_size = 0;
    }

    /// Get connection statistics
    pub fn get_stats(&self) -> ConnectionStats {
        let state = self.state.lock().unwrap();
        ConnectionStats {
            connection_name: self.name.clone(),
            status: state.status,
            server_name: self.server_name.clone(),
            server_port: self.server_port,
            client_ip: self.client_ip.clone(),
            client_port: self.client_port,
            connected_time: state.connected_tick,
            last_comm_time: state.last_comm_tick,
            total_sent: state.total_sent,
            total_received: state.total_received,
            send_queue_size: state.current_send_queue_size,
            server_version: self.server_ver,
            server_build: self.server_build,
            cipher_name: self.cipher_name.clone(),
        }
    }
}

/// Connection statistics for monitoring
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub connection_name: String,
    pub status: ConnectionStatus,
    pub server_name: String,
    pub server_port: u16,
    pub client_ip: String,
    pub client_port: u16,
    pub connected_time: Tick64,
    pub last_comm_time: Tick64,
    pub total_sent: u64,
    pub total_received: u64,
    pub send_queue_size: usize,
    pub server_version: u32,
    pub server_build: u32,
    pub cipher_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_creation() {
        let config = ConnectionConfig::default();
        let connection = Connection::new("TestConnection".to_string(), config);

        assert_eq!(connection.name, "TestConnection");
        assert!(!connection.halt);
        assert_eq!(connection.get_status(), ConnectionStatus::Negotiation);
        assert!(!connection.is_established());
        assert!(!connection.is_connected());
    }

    #[test]
    fn test_server_info() {
        let config = ConnectionConfig::default();
        let mut connection = Connection::new("TestConnection".to_string(), config);

        connection
            .set_server_info(4, 9672, "SoftEther VPN Server")
            .unwrap();

        assert_eq!(connection.server_ver, 4);
        assert_eq!(connection.server_build, 9672);
        assert_eq!(connection.server_str, "SoftEther VPN Server");
    }

    #[test]
    fn test_block_queuing() {
        let config = ConnectionConfig::default();
        let connection = Connection::new("TestConnection".to_string(), config);

        let block = Block::new(vec![1, 2, 3, 4]);
        connection.send_block(block).unwrap();

        assert_eq!(connection.get_send_queue_size(), 1);

        // Test priority block
        let priority_block = Block::new_priority(vec![5, 6, 7, 8]);
        connection.send_block(priority_block).unwrap();

        assert_eq!(connection.get_send_queue_size(), 2);
    }

    #[test]
    fn test_auth_random_generation() {
        let config = ConnectionConfig::default();
        let mut connection = Connection::new("TestConnection".to_string(), config);

        connection.generate_auth_random().unwrap();

        // Random should be non-zero
        assert_ne!(connection.random, [0u8; SHA1_SIZE]);
    }

    #[test]
    fn test_connection_stats() {
        let config = ConnectionConfig::default();
        let connection = Connection::new("TestConnection".to_string(), config);

        connection.update_traffic(1024, 2048);
        let stats = connection.get_stats();

        assert_eq!(stats.connection_name, "TestConnection");
        assert_eq!(stats.status, ConnectionStatus::Negotiation);
        assert_eq!(stats.total_sent, 1024);
        assert_eq!(stats.total_received, 2048);
    }
}
