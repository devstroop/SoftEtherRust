// Removed unused protocol imports to silence warnings
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub max_sessions: u32,
    pub keep_alive_interval: Duration,
    pub reconnect_interval: Duration,
    pub enable_multi_connection: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_sessions: 4096,
            keep_alive_interval: Duration::from_secs(30),
            reconnect_interval: Duration::from_secs(5),
            enable_multi_connection: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrafficStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub last_updated: Instant,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self {
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            last_updated: Instant::now(),
        }
    }
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct ClusterRedirectInfo {
    pub host: String,
    pub port: u16,
    pub ticket: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum EngineState {
    Idle,
    Connecting,
    RedirectPending(ClusterRedirectInfo),
    Authenticating,
    Established,
    Reconnecting,
    Stopped,
}

#[derive(Debug, Clone)]
pub struct SessionHandle(pub u64);
