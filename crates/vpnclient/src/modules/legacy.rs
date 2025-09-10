// Legacy VPN Client Wrapper
// Provides backward compatibility during the migration from monster file to modular architecture
// This allows existing code to work while we migrate to the new ModernVpnClient

use crate::modules::{client::ModernVpnClient, ModuleResult};
use crate::config::RuntimeConfig;
use crate::types::{ClientEvent, ClientState, NetworkSettings};
use crate::shared_config;
use tokio::sync::mpsc;
use tracing::{info, warn};
use std::convert::TryFrom;

/// Legacy VPN Client wrapper for backward compatibility
/// This maintains the same interface as the old 2,105-line vpnclient.rs
/// while using the new modular architecture underneath
pub struct VpnClient {
    modern_client: ModernVpnClient,
    
    // Legacy compatibility fields
    state_tx: Option<mpsc::UnboundedSender<ClientState>>,
    event_tx: Option<mpsc::UnboundedSender<ClientEvent>>,
    
    // Event processing task handle
    event_task_handle: Option<tokio::task::JoinHandle<()>>,
}

impl VpnClient {
    /// Create a new VPN client (legacy interface)
    pub fn new(config: RuntimeConfig) -> ModuleResult<Self> {
        info!("Creating VPN client with legacy compatibility wrapper");
        
        let modern_client = ModernVpnClient::new(config)?;
        
        Ok(Self {
            modern_client,
            state_tx: None,
            event_tx: None,
            event_task_handle: None,
        })
    }

    /// Create VPN client from shared config (legacy compatibility)
    pub fn from_shared_config(shared_config: shared_config::ClientConfig) -> ModuleResult<Self> {
        info!("Creating VPN client from shared config (legacy compatibility)");
        
        // Convert shared config to runtime config
        let runtime_config = RuntimeConfig::try_from(shared_config)
            .map_err(|e| crate::modules::ModuleError::Config(format!("Config conversion failed: {}", e)))?;
        
        // Create using runtime config
        Self::new(runtime_config)
    }

    /// Set state channel (legacy interface)
    pub fn set_state_channel(&mut self, state_tx: mpsc::UnboundedSender<ClientState>) {
        self.modern_client.set_state_channel(state_tx.clone());
        self.state_tx = Some(state_tx);
    }

    /// Set event channel (legacy interface)
    pub fn set_event_channel(&mut self, event_tx: mpsc::UnboundedSender<ClientEvent>) {
        self.modern_client.set_event_channel(event_tx.clone());
        self.event_tx = Some(event_tx);
    }

    /// Connect to VPN (legacy interface)
    pub async fn connect(&mut self) -> ModuleResult<()> {
        info!("Connecting VPN using legacy interface");
        
        // Start event processing task
        self.start_event_processing().await;
        
        // Use modern client's connect method
        self.modern_client.connect().await
    }

    /// Disconnect from VPN (legacy interface)
    pub async fn disconnect(&mut self) -> ModuleResult<()> {
        info!("Disconnecting VPN using legacy interface");
        
        // Stop event processing task
        if let Some(handle) = self.event_task_handle.take() {
            handle.abort();
        }
        
        // Use modern client's disconnect method
        self.modern_client.disconnect().await
    }

    /// Check if connected (legacy interface)
    pub fn is_connected(&self) -> bool {
        self.modern_client.is_connected()
    }

    /// Get current network settings (legacy interface)
    pub fn get_network_settings(&self) -> Option<&NetworkSettings> {
        self.modern_client.get_network_settings()
    }

    /// Get dataplane access (legacy interface for FFI compatibility)
    pub fn dataplane(&self) -> Option<&cedar::DataPlane> {
        self.modern_client.get_dataplane()
    }

    /// Run VPN client until interrupted (legacy interface)
    pub async fn run_until_interrupted(&mut self) -> ModuleResult<()> {
        info!("Starting VPN client with interrupt handling");
        
        // Connect first
        self.connect().await?;
        
        // Set up interrupt handler (Windows compatible)
        #[cfg(unix)]
        {
            let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|e| crate::modules::ModuleError::Io(e))?;
            let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|e| crate::modules::ModuleError::Io(e))?;
            
            tokio::select! {
                _ = sigint.recv() => {
                    info!("Received SIGINT, disconnecting...");
                    self.disconnect().await?;
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, disconnecting...");  
                    self.disconnect().await?;
                }
            }
        }
        
        #[cfg(windows)]
        {
            let ctrl_c = tokio::signal::ctrl_c();
            tokio::select! {
                _ = ctrl_c => {
                    info!("Received Ctrl+C, disconnecting...");
                    self.disconnect().await?;
                }
                // Keep connection alive until interrupted
                _ = tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)) => {
                    // This will never complete
                }
            }
        }
        
        Ok(())
    }

    /// Start background event processing
    async fn start_event_processing(&mut self) {
        if self.event_task_handle.is_some() {
            return; // Already started
        }

        // Move the modern client into an Arc<Mutex<>> for task sharing
        // For now, we'll skip this complex pattern and keep it simple
        info!("Event processing setup (simplified during migration)");
    }

    /// Legacy method: Get VPN session info
    pub fn get_session_info(&self) -> Option<String> {
        if self.modern_client.is_connected() {
            Some("Connected to SoftEther VPN using modular architecture".to_string())
        } else {
            None
        }
    }

    /// Legacy method: Get adapter type info
    pub fn get_adapter_info(&self) -> String {
        "Modern modular adapter".to_string()
    }

    /// Legacy method: Force reconnect
    pub async fn reconnect(&mut self) -> ModuleResult<()> {
        info!("Reconnecting VPN");
        
        // Disconnect first
        if self.is_connected() {
            self.disconnect().await?;
        }
        
        // Short delay
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        // Reconnect
        self.connect().await
    }

    /// Legacy method: Get detailed connection status
    pub fn get_connection_status(&self) -> ConnectionStatus {
        match self.modern_client.get_state() {
            crate::modules::client::ConnectionState::Idle => ConnectionStatus::Idle,
            crate::modules::client::ConnectionState::Connecting => ConnectionStatus::Connecting,
            crate::modules::client::ConnectionState::Authenticating => ConnectionStatus::Authenticating,
            crate::modules::client::ConnectionState::Establishing => ConnectionStatus::Establishing,
            crate::modules::client::ConnectionState::Connected => ConnectionStatus::Connected,
            crate::modules::client::ConnectionState::Disconnecting => ConnectionStatus::Disconnecting,
            crate::modules::client::ConnectionState::Error(msg) => ConnectionStatus::Error(msg.clone()),
        }
    }

    /// Access to modular components (for migration period)
    pub fn get_modern_client(&self) -> &ModernVpnClient {
        &self.modern_client
    }

    pub fn get_modern_client_mut(&mut self) -> &mut ModernVpnClient {
        &mut self.modern_client
    }
}

/// Legacy connection status enum (maintained for compatibility)
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionStatus {
    Idle,
    Connecting,
    Authenticating,
    Establishing,
    Connected,
    Disconnecting,
    Error(String),
}

impl Drop for VpnClient {
    fn drop(&mut self) {
        if let Some(handle) = self.event_task_handle.take() {
            handle.abort();
        }
        
        if self.is_connected() {
            warn!("Legacy VPN client dropped while still connected");
        }
    }
}

/// Helper functions for migration
impl VpnClient {
    /// Migrate to modern client (for gradual transition)
    pub fn into_modern(self) -> ModernVpnClient {
        warn!("Migrating from legacy wrapper to modern client");
        // Use ManuallyDrop to avoid running Drop on self
        let me = std::mem::ManuallyDrop::new(self);
        // Use ptr::read to move the value out without running drop
        unsafe { std::ptr::read(&me.modern_client) }
    }

    /// Create from modern client (for testing)
    pub fn from_modern(modern_client: ModernVpnClient) -> Self {
        Self {
            modern_client,
            state_tx: None,
            event_tx: None,
            event_task_handle: None,
        }
    }
}