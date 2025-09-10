// Session manager - central session coordination
// Inspired by Go's session management patterns

use super::{SessionWithDhcp, SessionEvent, SessionConfig};
use crate::modules::{auth::AuthManager, network::NetworkManager, bridge::BridgeManager};
use crate::config::AuthConfig;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::info;

/// Central session manager - coordinates all session operations
pub struct SessionManager {
    auth_manager: AuthManager,
    network_manager: NetworkManager,
    bridge_manager: BridgeManager,
    active_sessions: Vec<Arc<Mutex<SessionWithDhcp>>>,
    event_tx: Option<mpsc::UnboundedSender<SessionEvent>>,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(username: String, auth_config: AuthConfig) -> Self {
        Self {
            auth_manager: AuthManager::new(username, auth_config),
            network_manager: NetworkManager::new(),
            bridge_manager: BridgeManager::new(),
            active_sessions: Vec::new(),
            event_tx: None,
        }
    }

    /// Set event channel for monitoring
    pub fn set_event_channel(&mut self, event_tx: mpsc::UnboundedSender<SessionEvent>) {
        self.event_tx = Some(event_tx);
    }

    /// Create a new session with DHCP support
    pub async fn create_session(&mut self, _config: SessionConfig) -> Result<(), Box<dyn std::error::Error>> {
        info!("Session creation temporarily disabled during refactoring");
        
        // TODO: Implement proper session creation after refactoring is complete
        // This would integrate with cedar::session::Session properly
        
        Ok(())
    }

    /// Get authentication manager
    pub fn get_auth_manager(&self) -> &AuthManager {
        &self.auth_manager
    }

    /// Get network manager
    pub fn get_network_manager(&mut self) -> &mut NetworkManager {
        &mut self.network_manager
    }

    /// Get bridge manager
    pub fn get_bridge_manager(&mut self) -> &mut BridgeManager {
        &mut self.bridge_manager
    }

    /// Get number of active sessions
    pub fn get_active_session_count(&self) -> usize {
        self.active_sessions.len()
    }

    /// Cleanup all sessions
    pub async fn cleanup_all_sessions(&mut self) {
        info!("Cleaning up {} active sessions", self.active_sessions.len());
        
        for session_arc in &self.active_sessions {
            let mut session = session_arc.lock().await;
            session.cleanup().await;
        }
        
        self.active_sessions.clear();
        info!("All sessions cleaned up");
    }
}