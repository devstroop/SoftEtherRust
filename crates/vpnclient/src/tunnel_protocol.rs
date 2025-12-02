//! SoftEther tunnel protocol handler
//! Bridges TLS connections with Session packet channels

use anyhow::Result;
use cedar::{Session, TlsStream};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn, error};
use std::sync::Mutex;
use std::io::{Read, Write};

/// SoftEther tunnel protocol handler
/// Bridges TLS stream with Session packet channels
pub struct TunnelProtocolHandler {
    session: Arc<Session>,
    tasks: Vec<JoinHandle<()>>,
}

impl TunnelProtocolHandler {
    /// Create new tunnel protocol handler for a session
    pub fn new(session: Arc<Session>) -> Self {
        Self {
            session,
            tasks: Vec::new(),
        }
    }

    /// Register a TLS stream and start bidirectional pumping
    pub fn register_tls_stream(&mut self, tls: TlsStream) -> Result<()> {
        let tls_shared = Arc::new(Mutex::new(tls));
        
        // Start RX pump: TLS → Session (Server to Local)
        if let Some(session_tx) = &self.session.packet_tx {
            let session_tx = session_tx.clone();
            let tls_rx = tls_shared.clone();
            
            let rx_task = tokio::task::spawn_blocking(move || {
                debug!("TunnelProtocol RX pump started (TLS → Session)");
                
                loop {
                    // Read SoftEther frame from TLS
                    let frame = match read_softether_frame(&tls_rx) {
                        Ok(Some(f)) => f,
                        Ok(None) => continue, // keepalive or empty
                        Err(e) => {
                            debug!("TunnelProtocol RX pump exit: {}", e);
                            break;
                        }
                    };
                    
                    debug!("TunnelProtocol: received {} bytes from TLS → Session", frame.len());
                    
                    // Forward to session (will reach DataPlane)
                    if let Err(_) = session_tx.send(frame) {
                        warn!("TunnelProtocol: session channel closed");
                        break;
                    }
                }
                debug!("TunnelProtocol RX pump ended");
            });
            
            self.tasks.push(rx_task);
        }

        // Start TX pump: Session → TLS (Local to Server)  
        // Note: This requires session.packet_rx but that's taken by DataPlane
        // We need to hook into DataPlane's TX path instead
        debug!("TunnelProtocol: TLS stream registered");
        Ok(())
    }
}

/// Read a SoftEther frame from TLS stream
fn read_softether_frame(tls: &Arc<Mutex<TlsStream>>) -> std::io::Result<Option<Vec<u8>>> {
    let mut guard = tls.lock().unwrap();
    
    // Read frame header: [count:4][len:4] or [0xffffffff][len:4] for keepalive
    let mut header = [0u8; 8];
    guard.read_exact(&mut header)?;
    
    let first = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let second = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    
    if first == 0xffffffff {
        // Keepalive frame - read and discard payload
        if second > 0 {
            let mut buf = vec![0u8; second as usize];
            guard.read_exact(&mut buf)?;
            debug!("TunnelProtocol: keepalive frame ({} bytes)", second);
        }
        return Ok(None);
    }
    
    // Data frame: first=count, second=length of first frame
    if first == 0 {
        return Ok(None); // empty batch
    }
    
    // For now, handle single frame (count should be 1)
    if first != 1 {
        warn!("TunnelProtocol: multi-frame batch not implemented (count={})", first);
        return Ok(None);
    }
    
    let frame_len = second;
    if frame_len == 0 || frame_len > (1 << 20) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid frame length: {}", frame_len)
        ));
    }
    
    // Read frame payload
    let mut frame = vec![0u8; frame_len as usize];
    guard.read_exact(&mut frame)?;
    
    Ok(Some(frame))
}
