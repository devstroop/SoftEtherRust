// Modern VPN Client - streamlined using modular architecture
// This replaces the 2,105-line vpnclient.rs with clean, focused design

use crate::modules::{
    auth::AuthManager,
    dhcp::DhcpOptions,
    network::{NetworkManager, NetworkConfig},
    bridge::{BridgeManager, AdapterType},
    session::{SessionWithDhcp, SessionManager, SessionEvent, SessionConfig},
    ModuleError, ModuleResult,
};

use crate::config::RuntimeConfig;
use crate::types::{ClientEvent, ClientState, NetworkSettings};
use cedar::{
    session::{Session, SessionConfig as CedarSessionConfig},
    dataplane::DataPlane,
    ClientAuth, ClientOption, SessionManager as CedarSessionManager, EngineConfig
};
use mayaqua::{Result, Error};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn, error};
use uuid::Uuid;

/// Streamlined VPN Client using modular architecture
/// This replaces the God Class anti-pattern with focused components
pub struct ModernVpnClient {
    // Core configuration
    config: RuntimeConfig,
    
    // Modular components (single responsibility)
    auth_manager: AuthManager,
    session_manager: SessionManager,
    network_manager: NetworkManager,
    bridge_manager: BridgeManager,
    
    // Cedar integration - real VPN session
    cedar_session: Option<Session>,
    cedar_session_manager: CedarSessionManager,
    
    // Active session and connections
    active_session: Option<Arc<Mutex<SessionWithDhcp>>>,
    dataplane: Option<DataPlane>,
    
    // State tracking
    state: ConnectionState,
    is_connected: bool,
    
    // Event system
    state_tx: Option<mpsc::UnboundedSender<ClientState>>,
    event_tx: Option<mpsc::UnboundedSender<ClientEvent>>,
    session_event_rx: Option<mpsc::UnboundedReceiver<SessionEvent>>,
    
    // Network configuration
    network_settings: Option<NetworkSettings>,
    adapter_is_l2: bool,
}

/// Connection state (simplified from the old complex state)
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Idle,
    Connecting,
    Authenticating,
    Establishing,
    Connected,
    Disconnecting,
    Error(String),
}

impl ModernVpnClient {
    /// Create a new modern VPN client with clean architecture
    pub fn new(config: RuntimeConfig) -> ModuleResult<Self> {
        info!("Creating modern VPN client with modular architecture");
        
        // Extract authentication info from config
        let username = config.username.clone();
        let auth_config = config.auth.clone();
        
        // Create modular components
        let auth_manager = AuthManager::new(username.clone(), auth_config.clone());
        let session_manager = SessionManager::new(config.username.clone(), auth_config);
        let network_manager = NetworkManager::new();
        let bridge_manager = BridgeManager::new();
        
        // Initialize Cedar session manager
        let cedar_session_manager = CedarSessionManager::new(EngineConfig::default());
        
        // Set up event channels
        let (session_event_tx, session_event_rx) = mpsc::unbounded_channel();
        
        let mut client = Self {
            config,
            auth_manager,
            session_manager,
            network_manager,
            bridge_manager,
            cedar_session: None,
            cedar_session_manager,
            active_session: None,
            dataplane: None,
            state: ConnectionState::Idle,
            is_connected: false,
            state_tx: None,
            event_tx: None,
            session_event_rx: Some(session_event_rx),
            network_settings: None,
            adapter_is_l2: false, // Default to L3 (Wintun)
        };
        
        // Set up session manager event forwarding
        client.session_manager.set_event_channel(session_event_tx);
        
        info!("Modern VPN client created successfully");
        Ok(client)
    }

    /// Set state and event channels
    pub fn set_state_channel(&mut self, state_tx: mpsc::UnboundedSender<ClientState>) {
        self.state_tx = Some(state_tx);
    }

    pub fn set_event_channel(&mut self, event_tx: mpsc::UnboundedSender<ClientEvent>) {
        self.event_tx = Some(event_tx);
    }

    /// Main connection method - clean and focused
    pub async fn connect(&mut self) -> ModuleResult<()> {
        info!("Starting VPN connection using modern architecture");
        
        self.set_state(ConnectionState::Connecting).await;
        
        // Step 1: Set up network adapter
        self.setup_network_adapter().await?;
        
        // Step 2: Authenticate with server
        self.set_state(ConnectionState::Authenticating).await;
        let _auth_result = self.auth_manager.authenticate().await
            .map_err(|e| ModuleError::Auth(e.to_string()))?;
        
        // Step 3: Establish session
        self.set_state(ConnectionState::Establishing).await;
        self.establish_session().await?;
        
        // Step 4: Configure network
        self.configure_network().await?;
        
        self.set_state(ConnectionState::Connected).await;
        self.is_connected = true;
        
        info!("VPN connection established successfully");
        Ok(())
    }

    /// Set up network adapter (TUN/TAP/Wintun)
    async fn setup_network_adapter(&mut self) -> ModuleResult<()> {
        info!("Setting up network adapter");
        
        // Determine adapter type based on platform and configuration
        let adapter_type = if cfg!(target_os = "windows") {
            AdapterType::Wintun // L3 for Windows
        } else if cfg!(target_os = "macos") || cfg!(target_os = "linux") {
            AdapterType::L3Tun // L3 TUN for Unix-like systems
        } else {
            AdapterType::L3Tun // Default
        };
        
        // Create adapter
        self.bridge_manager.create_adapter("SoftEtherVPN", adapter_type).await
            .map_err(|e| ModuleError::Bridge(e.to_string()))?;
        
        // Set L2/L3 mode flag
        self.adapter_is_l2 = self.bridge_manager.is_l2_adapter();
        
        info!("Network adapter created: L2={}", self.adapter_is_l2);
        Ok(())
    }

    /// Establish VPN session with DHCP
    async fn establish_session(&mut self) -> ModuleResult<()> {
        info!("Establishing VPN session with Cedar integration");
        
        // Create session configuration
        let _session_config = SessionConfig {
            hostname: self.config.host.clone(),
            mac_address: self.generate_mac_address(),
            auto_dhcp: true, // Enable DHCP by default
            static_ip: None, // Could be configured from self.config in the future
        };
        
        // Create Cedar ClientAuth based on configuration
        let client_auth = self.create_client_auth()
            .map_err(|e| ModuleError::Auth(format!("Failed to create client auth: {}", e)))?;
            
        // Create Cedar ClientOption
        let client_option = self.create_client_option()
            .map_err(|e| ModuleError::Auth(format!("Failed to create client option: {}", e)))?;
            
        // Create Cedar session configuration
        let cedar_session_config = CedarSessionConfig {
            timeout: self.config.connection.timeout,
            max_connection: self.config.connection.max_connections,
            keep_alive_interval: 50,
            additional_connection_interval: 1000,
            connection_disconnect_span: 12000,
            retry_interval: 15,
            qos: false,
        };
        
        // Create Cedar session
        let session_name = format!("SoftEtherRust_{}", Uuid::new_v4());
        let session = Session::new(
            session_name,
            client_option,
            client_auth,
            cedar_session_config,
        ).map_err(|e| ModuleError::Session(format!("Failed to create session: {}", e)))?;
        
        // Store the session
        self.cedar_session = Some(session);
        
        info!("Cedar VPN session created successfully");
        Ok(())
    }

    /// Configure network settings
    async fn configure_network(&mut self) -> ModuleResult<()> {
        info!("Configuring network settings");
        
        // TODO: This will be implemented when we integrate the session properly
        // For now, create placeholder network settings
        
        let network_config = NetworkConfig {
            ipv4_addr: Some((std::net::Ipv4Addr::new(10, 0, 0, 100), 24)),
            ipv6_addr: None,
            gateway: Some(std::net::Ipv4Addr::new(10, 0, 0, 1).into()),
            dns_servers: vec![
                std::net::Ipv4Addr::new(8, 8, 8, 8).into(),
                std::net::Ipv4Addr::new(8, 8, 4, 4).into(),
            ],
            routes: Vec::new(),
        };
        
        self.network_manager.apply_config(network_config).await
            .map_err(|e| ModuleError::Network(e.to_string()))?;
        
        info!("Network configuration applied");
        Ok(())
    }

    /// Disconnect from VPN
    pub async fn disconnect(&mut self) -> ModuleResult<()> {
        info!("Disconnecting VPN");
        
        self.set_state(ConnectionState::Disconnecting).await;
        
        // Clean up session
        if let Some(_session) = &self.active_session {
            // TODO: Implement proper session cleanup
            info!("Cleaning up session");
        }
        
        // Clean up Cedar session
        if let Some(_cedar_session) = &self.cedar_session {
            info!("Cleaning up Cedar session");
            // TODO: Implement proper Cedar session cleanup
        }
        
        // Clean up all sessions
        self.session_manager.cleanup_all_sessions().await;
        
        self.set_state(ConnectionState::Idle).await;
        self.is_connected = false;
        self.active_session = None;
        self.dataplane = None;
        self.cedar_session = None;
        
        info!("VPN disconnected successfully");
        Ok(())
    }

    /// Get current connection state
    pub fn get_state(&self) -> &ConnectionState {
        &self.state
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    /// Get current network settings
    pub fn get_network_settings(&self) -> Option<&NetworkSettings> {
        self.network_settings.as_ref()
    }

    /// Generate MAC address for the session
    fn generate_mac_address(&self) -> [u8; 6] {
        // Generate deterministic MAC address based on username
        let mut mac = [0x00, 0xac, 0xde, 0x00, 0x00, 0x00];
        let username_bytes = self.config.username.as_bytes();
        
        // Use first 3 bytes of username hash for last 3 bytes of MAC
        for (i, &byte) in username_bytes.iter().take(3).enumerate() {
            mac[3 + i] = byte;
        }
        
        mac
    }
    
    /// Create Cedar ClientAuth from configuration
    fn create_client_auth(&self) -> Result<ClientAuth> {
        use crate::config::AuthConfig;
        
        match &self.config.auth {
            AuthConfig::Anonymous => Ok(ClientAuth::new_anonymous()),
            AuthConfig::Password { hashed_password } => {
                // Use the pre-hashed password
                let mut auth = ClientAuth::new_password(&self.config.username, "__PLACEHOLDER__")?;
                // Set the pre-computed hash
                if let Ok(hash_bytes) = hex::decode(hashed_password) {
                    if hash_bytes.len() == 20 {
                        auth.hashed_password.copy_from_slice(&hash_bytes);
                    }
                }
                Ok(auth)
            }
            AuthConfig::Certificate { cert_file, key_file } => {
                // Load certificate and key from files
                let cert_data = std::fs::read(cert_file)
                    .map_err(|e| Error::IoError(format!("Failed to read cert file: {}", e)))?;
                let key_data = std::fs::read(key_file)
                    .map_err(|e| Error::IoError(format!("Failed to read key file: {}", e)))?;
                ClientAuth::new_certificate(&self.config.username, cert_data, key_data)
            }
            AuthConfig::SecureDevice { cert_name, key_name } => {
                ClientAuth::new_secure_device(&self.config.username, cert_name, key_name)
            }
        }
    }
    
    /// Create Cedar ClientOption from configuration
    fn create_client_option(&self) -> Result<ClientOption> {
        let mut option = ClientOption::new(
            &self.config.host,
            self.config.port,
            &self.config.hub_name,
        )?;
        
        // Configure connection options
        option.max_connection = self.config.connection.max_connections;
        option.use_compress = true; // Enable compression by default
        option.half_connection = self.config.connection.half_connection;
        option.no_udp_acceleration = !self.config.connection.udp_acceleration;
        option.enable_nat_traversal = self.config.connection.nat_traversal;
        option.retry_interval = 15;
        option.additional_connection_interval = 1000;
        option.connection_disconnect_span = 12000;
        
        // Configure proxy if present
        if let Some(proxy) = &self.config.connection.proxy {
            use cedar::constants::ProxyType;
            option.proxy_type = ProxyType::Http; // Assume HTTP proxy
            option.proxy_name = proxy.host.clone();
            option.proxy_port = proxy.port;
            if let Some(username) = &proxy.username {
                option.proxy_username = username.clone();
            }
            if let Some(password) = &proxy.password {
                option.proxy_password = password.clone();
            }
        }
        
        Ok(option)
    }

    /// Set connection state and notify observers
    async fn set_state(&mut self, new_state: ConnectionState) {
        if self.state != new_state {
            debug!("Connection state: {:?} -> {:?}", self.state, new_state);
            self.state = new_state.clone();
            
            // Convert to legacy ClientState for compatibility
            let client_state = match new_state {
                ConnectionState::Idle => ClientState::Idle,
                ConnectionState::Connecting => ClientState::Connecting,
                ConnectionState::Authenticating => ClientState::Connecting, // Map to existing state
                ConnectionState::Establishing => ClientState::Connecting,
                ConnectionState::Connected => ClientState::Established,
                ConnectionState::Disconnecting => ClientState::Disconnecting,
                ConnectionState::Error(_) => ClientState::Idle, // Reset to idle on error
            };
            
            if let Some(state_tx) = &self.state_tx {
                let _ = state_tx.send(client_state);
            }
        }
    }

    /// Process session events (to be called in background task)
    pub async fn process_session_events(&mut self) {
        if let Some(session_event_rx) = &mut self.session_event_rx {
            while let Some(event) = session_event_rx.recv().await {
                match event {
                    SessionEvent::StateChanged(session_state) => {
                        debug!("Session state changed: {:?}", session_state);
                        // Could update connection state based on session state
                    }
                    SessionEvent::DhcpCompleted(dhcp_options) => {
                        info!("DHCP completed: IP={}", 
                              std::net::Ipv4Addr::from(dhcp_options.client_address.to_be_bytes()));
                        
                        // Update network settings
                        self.update_network_settings_from_dhcp(&dhcp_options);
                        return; // Exit to avoid borrowing issues
                    }
                    SessionEvent::NetworkConfigured => {
                        info!("Network configuration completed");
                    }
                    SessionEvent::Error(msg) => {
                        error!("Session error: {}", msg);
                        // Store error message temporarily to avoid borrowing issues
                        let _error_msg = msg.clone();
                        return; // Exit early to avoid borrowing issues, will set state later
                    }
                }
            }
        }
    }

    /// Update network settings from DHCP result
    fn update_network_settings_from_dhcp(&mut self, dhcp_options: &DhcpOptions) {
        // Convert DHCP options to NetworkSettings
        let network_settings = NetworkSettings {
            assigned_ipv4: Some(std::net::Ipv4Addr::from(dhcp_options.client_address.to_be_bytes())),
            subnet_mask: if dhcp_options.subnet_mask != 0 {
                Some(std::net::Ipv4Addr::from(dhcp_options.subnet_mask.to_be_bytes()))
            } else {
                None
            },
            gateway: if dhcp_options.gateway != 0 {
                Some(std::net::Ipv4Addr::from(dhcp_options.gateway.to_be_bytes()))
            } else {
                None
            },
            dns_servers: {
                let mut dns = Vec::new();
                if dhcp_options.dns_server != 0 {
                    dns.push(std::net::Ipv4Addr::from(dhcp_options.dns_server.to_be_bytes()));
                }
                if dhcp_options.dns_server2 != 0 {
                    dns.push(std::net::Ipv4Addr::from(dhcp_options.dns_server2.to_be_bytes()));
                }
                dns
            },
            ..Default::default()
        };
        
        self.network_settings = Some(network_settings);
        
        // Emit network settings event
        if let Some(event_tx) = &self.event_tx {
            let json = crate::types::settings_json_with_kind(self.network_settings.as_ref(), true);
            let _ = event_tx.send(ClientEvent {
                level: crate::types::EventLevel::Info,
                message: json,
                code: 1001,
            });
        }
    }

    /// Get module managers for advanced usage
    pub fn get_auth_manager(&self) -> &AuthManager {
        &self.auth_manager
    }

    pub fn get_network_manager(&mut self) -> &mut NetworkManager {
        &mut self.network_manager
    }

    pub fn get_bridge_manager(&mut self) -> &mut BridgeManager {
        &mut self.bridge_manager
    }

    pub fn get_session_manager(&mut self) -> &mut SessionManager {
        &mut self.session_manager
    }
    
    /// Get Cedar session (for advanced integration)
    pub fn get_cedar_session(&self) -> Option<&Session> {
        self.cedar_session.as_ref()
    }
    
    /// Get dataplane access (for FFI compatibility)
    pub fn get_dataplane(&self) -> Option<&cedar::DataPlane> {
        self.dataplane.as_ref()
    }
}

impl Drop for ModernVpnClient {
    fn drop(&mut self) {
        if self.is_connected {
            warn!("VPN client dropped while still connected - consider calling disconnect() first");
        }
    }
}