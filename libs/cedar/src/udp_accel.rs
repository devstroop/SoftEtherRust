//! UDP Acceleration (NAT-T / R-UDP) scaffolding for client
//!
//! This provides a minimal, non-functional skeleton matching the C Cedar UdpAccel.c concepts
//! so higher layers can be wired while we incrementally implement real NAT traversal.

use crate::constants::{
    UDP_ACCELERATION_COMMON_KEY_SIZE_V1, UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX,
    UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN, UDP_ACCELERATION_MAX_PAYLOAD_SIZE,
};
use mayaqua::Result;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpAccelState {
    Disabled,
    Probing,
    Established,
    Failed,
}

#[derive(Clone)]
pub struct UdpAccelerator {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    state: UdpAccelState,
    local_addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
    socket: Option<UdpSocket>,
    #[allow(dead_code)]
    last_activity: Instant,
    keepalive_task: Option<JoinHandle<()>>,
    #[allow(dead_code)]
    common_key_v1: [u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V1],
    max_payload: usize,
}

impl Default for UdpAccelerator {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpAccelerator {
    pub fn new() -> Self {
        let inner = Inner {
            state: UdpAccelState::Disabled,
            local_addr: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            peer_addr: None,
            socket: None,
            last_activity: Instant::now(),
            keepalive_task: None,
            common_key_v1: [0u8; UDP_ACCELERATION_COMMON_KEY_SIZE_V1],
            max_payload: UDP_ACCELERATION_MAX_PAYLOAD_SIZE,
        };
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Configure and bind a local UDP socket (no NAT traversal yet).
    pub fn bind_local(&self, port: u16) -> Result<()> {
        let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        let local = socket.local_addr()?;
        let mut g = self.inner.lock().unwrap();
        g.socket = Some(socket);
        g.local_addr = local;
        g.state = UdpAccelState::Probing;
        Ok(())
    }

    /// Set the peer address; real implementations would be discovered via control channel.
    pub fn set_peer(&self, addr: SocketAddr) {
        let mut g = self.inner.lock().unwrap();
        g.peer_addr = Some(addr);
    }

    /// Start simple keepalive loop to maintain NAT bindings (no real encryption/HMAC yet).
    pub fn start_keepalive(&self) {
        let inner = self.inner.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (should_break, socket_opt, peer_opt) = {
                    let g = inner.lock().unwrap();
                    (
                        g.state == UdpAccelState::Failed,
                        g.socket.as_ref().and_then(|s| s.try_clone().ok()),
                        g.peer_addr,
                    )
                };
                if should_break {
                    break;
                }
                if let (Some(socket), Some(peer)) = (socket_opt, peer_opt) {
                    let payload = b"KEEPALIVE";
                    let _ = socket.send_to(payload, peer);
                }
                tokio::time::sleep(Duration::from_millis(
                    ((UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN
                        + UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX)
                        / 2) as u64,
                ))
                .await;
            }
        });
        self.inner.lock().unwrap().keepalive_task = Some(handle);
    }

    /// Very small helper for sending a frame (no fragmentation, no crypto yet).
    pub fn send(&self, data: &[u8]) -> Result<usize> {
        let g = self.inner.lock().unwrap();
        if g.state == UdpAccelState::Disabled || g.socket.is_none() || g.peer_addr.is_none() {
            return Ok(0);
        }
        if data.len() > g.max_payload {
            // Upper layers should fragment; we drop for now
            return Ok(0);
        }
        let n = g
            .socket
            .as_ref()
            .unwrap()
            .send_to(data, g.peer_addr.unwrap())?;
        Ok(n)
    }

    pub fn state(&self) -> UdpAccelState {
        self.inner.lock().unwrap().state
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.inner.lock().unwrap().local_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_accel_default() {
        let ua = UdpAccelerator::new();
        assert_eq!(ua.state(), UdpAccelState::Disabled);
        assert_eq!(ua.local_addr().port(), 0);
    }
}
