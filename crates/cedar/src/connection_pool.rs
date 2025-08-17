use log::{debug, info, warn};
use native_tls::TlsStream;
use std::io::Read;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct ConnectionPool {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    next_id: u64,
    links: Vec<Link>,
}

struct Link {
    id: u64,
    direction: i32,
    #[allow(dead_code)]
    handle: JoinHandle<()>,
    bytes_read: u64,
}

#[derive(Default, Clone, Copy)]
pub struct PoolStats {
    pub total_links: usize,
    pub bytes_read: u64,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                next_id: 1,
                links: Vec::new(),
            })),
        }
    }

    /// Register a bonded TLS stream with the given direction.
    /// Spawns a blocking read loop that counts bytes as a placeholder for data-plane wiring.
    pub fn register_link(&self, mut stream: TlsStream<TcpStream>, direction: i32) -> u64 {
        let mut g = self.inner.lock().unwrap();
        let id = g.next_id;
        g.next_id += 1;

        let handle = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => {
                        info!("connection_pool link id={} closed by peer", id);
                        break;
                    }
                    Ok(n) => {
                        debug!("connection_pool link id={} read {} bytes", id, n);
                        // NOTE: We do not yet parse packets; this is placeholder accounting.
                    }
                    Err(e) => {
                        warn!("connection_pool link id={} read error: {}", id, e);
                        break;
                    }
                }
            }
        });

        g.links.push(Link {
            id,
            direction,
            handle,
            bytes_read: 0,
        });
        id
    }

    pub fn stats(&self) -> PoolStats {
        let g = self.inner.lock().unwrap();
        PoolStats {
            total_links: g.links.len(),
            bytes_read: g.links.iter().map(|l| l.bytes_read).sum(),
        }
    }
}
