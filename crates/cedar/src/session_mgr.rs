use crate::{ClusterRedirectInfo, CredentialSet, EngineConfig, EngineState, TrafficStats};
use async_trait::async_trait;
use log::debug;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct SessionManager {
    inner: Arc<Mutex<SessionManagerInner>>,
}

struct SessionManagerInner {
    state: EngineState,
    #[allow(dead_code)]
    config: EngineConfig,
    creds: Option<CredentialSet>,
    #[allow(dead_code)]
    traffic: TrafficStats,
}

impl SessionManager {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionManagerInner {
                state: EngineState::Idle,
                config,
                creds: None,
                traffic: TrafficStats::new(),
            })),
        }
    }

    pub fn set_credentials(&self, creds: CredentialSet) {
        self.inner.lock().unwrap().creds = Some(creds);
    }

    pub fn state(&self) -> EngineState {
        self.inner.lock().unwrap().state.clone()
    }

    pub fn begin_redirect(&self, info: ClusterRedirectInfo) {
        let mut g = self.inner.lock().unwrap();
        g.state = EngineState::RedirectPending(info);
    }

    pub fn mark_established(&self) {
        self.inner.lock().unwrap().state = EngineState::Established;
    }
}

#[async_trait]
pub trait SessionManagerAsync {
    async fn reconnect_with_ticket(&self, ticket: Vec<u8>) -> Result<(), String>;
}

#[async_trait]
impl SessionManagerAsync for SessionManager {
    async fn reconnect_with_ticket(&self, ticket: Vec<u8>) -> Result<(), String> {
        let mut g = self.inner.lock().unwrap();

        // Simulate reconnection logic
        debug!("Attempting to reconnect with ticket: {ticket:?}");

        // Example: Validate the ticket and update state
        if ticket.is_empty() {
            return Err("Invalid ticket: empty".to_string());
        }

        // Update state to reflect reconnection attempt
        g.state = EngineState::Reconnecting;

        // Simulate successful reconnection
        g.state = EngineState::Established;
        debug!("Reconnection successful");

        Ok(())
    }
}
