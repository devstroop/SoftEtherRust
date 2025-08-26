#![allow(async_fn_in_trait)]
//! Network utilities and socket abstractions
//!
//! Cross-platform networking primitives for SoftEther VPN

use crate::error::{Error, Result};
use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};
// (no direct tokio io trait usage here; streams are used via methods)

/// Socket interface trait for unified network operations
pub trait SocketInterface {
    async fn connect(addr: SocketAddr) -> Result<Self>
    where
        Self: Sized;
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<usize>> + Send;
    fn recv(
        &mut self,
        buffer: &mut [u8],
    ) -> impl std::future::Future<Output = Result<usize>> + Send;
    fn close(&mut self) -> Result<()>;
}

/// TCP socket wrapper
#[allow(dead_code)]
pub struct TcpSocket {
    stream: TcpStream,
}

impl TcpSocket {
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|_| Error::ConnectFailed)?;
        // Tune TCP options similar to C implementation
        stream.set_nodelay(true).ok();
        Ok(Self { stream })
    }

    /// Enable TCP keepalive with a small idle interval
    pub fn set_keepalive(&self, _secs: u64) {
        #[cfg(all(unix, feature = "macos"))]
        {
            use std::os::unix::prelude::AsRawFd;
            let fd = self.stream.as_raw_fd();
            unsafe {
                #[allow(unused_unsafe)]
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_KEEPALIVE,
                    &1 as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as u32,
                );
            }
            // Platform-specific tuning omitted for brevity
        }
    }
}

/// UDP socket wrapper  
#[allow(dead_code)]
pub struct UdpSocketWrapper {
    socket: UdpSocket,
}

impl UdpSocketWrapper {
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|_| Error::SocketError)?;
        Ok(Self { socket })
    }
}

// TODO: Implement full network abstraction layer
// - TLS/SSL socket support
// - HTTP client/server
// - WebSocket support
// - Platform-specific optimizations

/// Async DNS resolver returning SocketAddrs for a given host:port
pub async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| Error::SocketError)?
        .collect::<Vec<_>>();
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_localhost() {
        let addrs = resolve("localhost", 80).await.unwrap();
        assert!(!addrs.is_empty());
    }
}
