use crate::TrafficStats;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Clone, Debug)]
pub struct ConnectionHandle(pub u64);

#[derive(Clone)]
pub struct ConnectionManager {
    inner: Arc<Mutex<ConnectionManagerInner>>,
}

struct ConnectionManagerInner {
    next_id: u64,
    #[allow(dead_code)]
    stats: TrafficStats,
    bonds: Vec<ConnectionInfo>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ConnectionManagerInner {
                next_id: 1,
                stats: TrafficStats::new(),
                bonds: Vec::new(),
            })),
        }
    }

    pub fn open(&self) -> ConnectionHandle {
        let mut g = self.inner.lock().unwrap();
        let id = g.next_id;
        g.next_id += 1;
        ConnectionHandle(id)
    }

    /// Register a bonded TCP link with its direction (1=c2s, 2=s2c, 0=both/unspecified)
    pub fn register_bond(&self, direction: i32) -> ConnectionHandle {
        let mut g = self.inner.lock().unwrap();
        let id = g.next_id;
        g.next_id += 1;
        g.bonds.push(ConnectionInfo {
            id,
            direction,
            created_at: SystemTime::now(),
            is_active: true,
        });
        ConnectionHandle(id)
    }

    /// Mark a bond as inactive (best-effort; ignored if not found)
    pub fn unregister_bond(&self, handle: ConnectionHandle) {
        let mut g = self.inner.lock().unwrap();
        if let Some(b) = g.bonds.iter_mut().find(|b| b.id == handle.0) {
            b.is_active = false;
        }
    }

    /// Get a simple summary of current bonds
    pub fn summary(&self) -> ConnectionSummary {
        let g = self.inner.lock().unwrap();
        let mut c2s = 0usize;
        let mut s2c = 0usize;
        let mut both = 0usize;
        let mut active = 0usize;
        for b in &g.bonds {
            if b.is_active {
                active += 1;
            }
            match b.direction {
                1 => c2s += 1,
                2 => s2c += 1,
                _ => both += 1,
            }
        }
        ConnectionSummary {
            total: active,
            c2s,
            s2c,
            both,
        }
    }
}

#[derive(Clone, Debug)]
struct ConnectionInfo {
    id: u64,
    direction: i32,
    created_at: SystemTime,
    is_active: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectionSummary {
    pub total: usize,
    pub c2s: usize,
    pub s2c: usize,
    pub both: usize,
}
