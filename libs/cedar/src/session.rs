//! Session management for SoftEther VPN protocol
//!
//! Implementation of SESSION structure and session lifecycle management.

use crate::constants::{ProtocolOptions, RudpSettings, SessionFlags, UdpAccelSettings};
use crate::{ClientAuth, ClientOption, SHA1_SIZE};
use mayaqua::Pack;
use mayaqua::{get_tick64, Error, Result, Tick64};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub timeout: u32,                        // Session timeout in seconds
    pub max_connection: u32,                 // Maximum concurrent connections
    pub keep_alive_interval: u32,            // Keep-alive interval
    pub additional_connection_interval: u32, // Additional connection interval
    pub connection_disconnect_span: u32,     // Connection disconnect span
    pub retry_interval: u32,                 // Retry interval
    pub qos: bool,                           // VoIP/QoS support
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout: 20,
            max_connection: 1,
            keep_alive_interval: 50,
            additional_connection_interval: 1000,
            connection_disconnect_span: 12000,
            retry_interval: 15,
            qos: false,
        }
    }
}

/// Session state information
#[derive(Debug, Clone)]
pub struct SessionState {
    pub session_key: [u8; SHA1_SIZE],       // Session key (20 bytes)
    pub session_key32: u32,                 // 32-bit session key
    pub session_key_str: String,            // Session key as string
    pub created_time: Tick64,               // Creation timestamp
    pub last_comm_time: Tick64,             // Last communication time
    pub last_comm_time_for_dormant: Tick64, // Last comm time (dormant)
    pub total_send_size: u64,               // Total bytes sent
    pub total_recv_size: u64,               // Total bytes received
    pub total_send_size_real: u64,          // Total sent (uncompressed)
    pub total_recv_size_real: u64,          // Total received (uncompressed)
    pub num_disconnected: u32,              // Number of disconnections
    pub unique_id: u32,                     // Unique session ID
}

impl Default for SessionState {
    fn default() -> Self {
        let now = get_tick64();
        Self {
            session_key: [0u8; SHA1_SIZE],
            session_key32: 0,
            session_key_str: String::new(),
            created_time: now,
            last_comm_time: now,
            last_comm_time_for_dormant: now,
            total_send_size: 0,
            total_recv_size: 0,
            total_send_size_real: 0,
            total_recv_size_real: 0,
            num_disconnected: 0,
            unique_id: 0,
        }
    }
}

/// Session management structure (matches C SESSION structure)
#[derive(Debug)]
pub struct Session {
    // Core session data
    pub name: String,              // Session name
    pub username: String,          // Username
    pub username_real: String,     // Real username
    pub group_name: String,        // Group name
    pub client_ip: String,         // Client IP address
    pub client_port: u16,          // Client port
    pub server_ip: String,         // Server IP address
    pub server_port: u16,          // Server port
    pub client_hostname: String,   // Client hostname
    pub underlay_protocol: String, // Physical protocol
    pub protocol_details: String,  // Protocol details

    // Session configuration
    pub config: SessionConfig,
    pub client_option: ClientOption,
    pub client_auth: ClientAuth,

    // Session flags and settings
    pub flags: SessionFlags,
    pub protocol_options: ProtocolOptions,
    pub udp_accel_settings: UdpAccelSettings,
    pub rudp_settings: RudpSettings,

    // Session state
    pub state: Arc<Mutex<SessionState>>,

    // Control channels
    pub halt_tx: Option<oneshot::Sender<()>>,
    pub halt_rx: Option<oneshot::Receiver<()>>,

    // Communication channels
    pub packet_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    pub packet_rx: Option<mpsc::UnboundedReceiver<Vec<u8>>>,

    // Session status
    pub halt: bool,
    pub cancel_connect: bool,
    pub error_code: u32,
    pub client_status: u32,
    pub retry_flag: bool,
    pub force_stop_flag: bool,
    pub current_retry_count: u32,
    pub connect_succeed: bool,
    pub session_timed_out: bool,
    pub administrator_mode: bool,
    pub user_canceled: bool,

    // OpenVPN compatibility
    pub is_openvpn_l3_session: bool,
    pub is_openvpn_l2_session: bool,

    // Azure VPN support
    pub is_azure_session: bool,
    pub azure_real_server_global_ip: String,

    // VLAN settings
    pub vlan_id: u32,
    pub ipc_mac_address: [u8; 6],

    // NAT traversal mode
    pub force_nat_traversal: bool,

    // Encryption keys
    pub udp_send_key: [u8; 16],
    pub udp_recv_key: [u8; 16],
}

impl Session {
    /// Create a new session
    pub fn new(
        name: String,
        client_option: ClientOption,
        client_auth: ClientAuth,
        config: SessionConfig,
    ) -> Result<Self> {
        // Validate inputs
        client_option.validate()?;
        client_auth.validate()?;

        let (halt_tx, halt_rx) = oneshot::channel();
        let (packet_tx, packet_rx) = mpsc::unbounded_channel();

        let mut session = Self {
            name,
            username: client_auth.username.clone(),
            username_real: client_auth.username.clone(),
            group_name: String::new(),
            client_ip: String::new(),
            client_port: 0,
            server_ip: client_option.hostname.clone(),
            server_port: client_option.port,
            client_hostname: String::new(),
            underlay_protocol: String::from("TCP"),
            protocol_details: String::new(),

            config,
            client_option,
            client_auth,

            flags: SessionFlags::default(),
            protocol_options: ProtocolOptions::default(),
            udp_accel_settings: UdpAccelSettings::default(),
            rudp_settings: RudpSettings::default(),

            state: Arc::new(Mutex::new(SessionState::default())),

            halt_tx: Some(halt_tx),
            halt_rx: Some(halt_rx),
            packet_tx: Some(packet_tx),
            packet_rx: Some(packet_rx),

            halt: false,
            cancel_connect: false,
            error_code: 0,
            client_status: 0,
            retry_flag: false,
            force_stop_flag: false,
            current_retry_count: 0,
            connect_succeed: false,
            session_timed_out: false,
            administrator_mode: false,
            user_canceled: false,

            is_openvpn_l3_session: false,
            is_openvpn_l2_session: false,

            is_azure_session: false,
            azure_real_server_global_ip: String::new(),

            vlan_id: 0,
            ipc_mac_address: [0u8; 6],

            force_nat_traversal: false,

            udp_send_key: [0u8; 16],
            udp_recv_key: [0u8; 16],
        };

        // Generate unique session ID
        session.generate_unique_id()?;

        // Generate session keys
        session.generate_session_keys()?;

        Ok(session)
    }

    /// Generate unique session ID
    fn generate_unique_id(&mut self) -> Result<()> {
        let uuid = Uuid::new_v4();
        let bytes = uuid.as_bytes();
        self.state.lock().unwrap().unique_id =
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Ok(())
    }

    /// Generate session keys
    fn generate_session_keys(&mut self) -> Result<()> {
        use rand::RngCore;
        use sha1::{Digest, Sha1};

        let mut rng = rand::rng();
        let mut state = self.state.lock().unwrap();

        // Generate random session key
        rng.fill_bytes(&mut state.session_key);

        // Generate 32-bit key from session key
        state.session_key32 = u32::from_le_bytes([
            state.session_key[0],
            state.session_key[1],
            state.session_key[2],
            state.session_key[3],
        ]);

        // Generate string representation
        state.session_key_str = hex::encode(&state.session_key);

        // Generate UDP keys from session key
        let mut hasher = Sha1::new();
        hasher.update(&state.session_key);
        hasher.update(b"UDP_SEND");
        let send_hash = hasher.finalize();
        self.udp_send_key.copy_from_slice(&send_hash[..16]);

        let mut hasher = Sha1::new();
        hasher.update(&state.session_key);
        hasher.update(b"UDP_RECV");
        let recv_hash = hasher.finalize();
        self.udp_recv_key.copy_from_slice(&recv_hash[..16]);

        Ok(())
    }

    /// Start the session
    pub async fn start(&mut self) -> Result<()> {
        if self.halt {
            return Err(Error::InvalidParameter);
        }

        // Mark session as started
        self.state.lock().unwrap().created_time = get_tick64();

        log::info!(
            "Session '{}' started for user '{}'",
            self.name,
            self.username
        );
        Ok(())
    }

    /// Keep-alive timing (match C defaults): 50s interval, 60s timeout
    pub const KEEP_ALIVE_INTERVAL: u64 = 50_000; // 50 seconds
    pub const KEEP_ALIVE_TIMEOUT: u64 = 60_000; // 60 seconds

    /// Build a minimal keep-alive Pack compatible with server expectations
    pub fn create_keep_alive_pack(&self) -> Pack {
        let mut pack = Pack::new();
        // Many implementations use either 'noop' or 'keep_alive' as an int flag.
        // Include both for compatibility; server ignores unknown fields gracefully.
        let _ = pack.add_int("keep_alive", 1);
        let _ = pack.add_int("noop", 1);
        let _ = pack.add_int64("tick64", get_tick64());
        pack
    }

    /// Stop the session
    pub async fn stop(&mut self) -> Result<()> {
        if !self.halt {
            self.halt = true;

            // Send halt signal
            if let Some(halt_tx) = self.halt_tx.take() {
                let _ = halt_tx.send(());
            }

            log::info!("Session '{}' stopped", self.name);
        }
        Ok(())
    }

    /// Update last communication time
    pub fn update_last_comm_time(&self) {
        let mut state = self.state.lock().unwrap();
        state.last_comm_time = get_tick64();
        state.last_comm_time_for_dormant = state.last_comm_time;
    }

    /// Add to traffic counters
    pub fn add_traffic(&self, send_bytes: u64, recv_bytes: u64) {
        let mut state = self.state.lock().unwrap();
        state.total_send_size += send_bytes;
        state.total_recv_size += recv_bytes;
        state.total_send_size_real += send_bytes; // TODO: Account for compression
        state.total_recv_size_real += recv_bytes;
    }

    /// Get session statistics
    pub fn get_stats(&self) -> SessionStats {
        let state = self.state.lock().unwrap();
        SessionStats {
            session_name: self.name.clone(),
            username: self.username.clone(),
            created_time: state.created_time,
            last_comm_time: state.last_comm_time,
            total_send_size: state.total_send_size,
            total_recv_size: state.total_recv_size,
            server_name: self.server_ip.clone(),
            server_port: self.server_port,
            client_ip: self.client_ip.clone(),
            client_port: self.client_port,
            protocol: self.underlay_protocol.clone(),
            is_connected: self.connect_succeed && !self.halt,
        }
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        !self.halt && !self.session_timed_out && !self.user_canceled
    }

    /// Check if session supports UDP acceleration
    pub fn supports_udp_acceleration(&self) -> bool {
        !self.client_option.no_udp_acceleration
            && self.client_option.is_udp_enabled()
            && self.udp_accel_settings.use_udp_acceleration
    }

    /// Get session ID
    pub fn get_session_id(&self) -> u32 {
        self.state.lock().unwrap().unique_id
    }

    /// Get session key string
    pub fn get_session_key_string(&self) -> String {
        self.state.lock().unwrap().session_key_str.clone()
    }
}

/// Session statistics for monitoring
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub session_name: String,
    pub username: String,
    pub created_time: Tick64,
    pub last_comm_time: Tick64,
    pub total_send_size: u64,
    pub total_recv_size: u64,
    pub server_name: String,
    pub server_port: u16,
    pub client_ip: String,
    pub client_port: u16,
    pub protocol: String,
    pub is_connected: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let client_option = ClientOption::new("vpn.example.com", 443, "DEFAULT").unwrap();
        let client_auth = ClientAuth::new_password("user1", "password123").unwrap();
        let config = SessionConfig::default();

        let session = Session::new(
            "TestSession".to_string(),
            client_option,
            client_auth,
            config,
        )
        .unwrap();

        assert_eq!(session.name, "TestSession");
        assert_eq!(session.username, "user1");
        assert_eq!(session.server_ip, "vpn.example.com");
        assert_eq!(session.server_port, 443);
        assert!(!session.halt);
        assert!(session.is_active());
    }

    #[test]
    fn test_session_keys_generation() {
        let client_option = ClientOption::new("vpn.example.com", 443, "DEFAULT").unwrap();
        let client_auth = ClientAuth::new_anonymous();
        let config = SessionConfig::default();

        let session = Session::new(
            "TestSession".to_string(),
            client_option,
            client_auth,
            config,
        )
        .unwrap();

        let state = session.state.lock().unwrap();
        // Session key should be non-zero
        assert_ne!(state.session_key, [0u8; SHA1_SIZE]);
        assert_ne!(state.session_key32, 0);
        assert!(!state.session_key_str.is_empty());

        // UDP keys should be non-zero
        assert_ne!(session.udp_send_key, [0u8; 16]);
        assert_ne!(session.udp_recv_key, [0u8; 16]);
    }

    #[test]
    fn test_session_stats() {
        let client_option = ClientOption::new("vpn.example.com", 443, "DEFAULT").unwrap();
        let client_auth = ClientAuth::new_password("user1", "password123").unwrap();
        let config = SessionConfig::default();

        let session = Session::new(
            "TestSession".to_string(),
            client_option,
            client_auth,
            config,
        )
        .unwrap();

        session.add_traffic(1024, 2048);
        let stats = session.get_stats();

        assert_eq!(stats.session_name, "TestSession");
        assert_eq!(stats.username, "user1");
        assert_eq!(stats.total_send_size, 1024);
        assert_eq!(stats.total_recv_size, 2048);
        assert_eq!(stats.server_name, "vpn.example.com");
        assert_eq!(stats.server_port, 443);
    }
}
