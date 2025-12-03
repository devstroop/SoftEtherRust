use log::{debug, warn};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};

use crate::session::Session;

// Crypto and compression support
use mayaqua::crypto::rc4_apply_inplace;
#[cfg(feature = "compress")]
use mayaqua::compress::{compress_deflate, decompress_deflate};

/// Direction per SoftEther semantics
/// 0 = both, 1 = client->server (TX), 2 = server->client (RX)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkDirection {
    Both,
    ClientToServer,
    ServerToClient,
}

impl From<i32> for LinkDirection {
    fn from(v: i32) -> Self {
        match v {
            1 => LinkDirection::ClientToServer,
            2 => LinkDirection::ServerToClient,
            _ => LinkDirection::Both,
        }
    }
}

#[derive(Clone)]
pub struct DataPlane {
    inner: Arc<Mutex<Inner>>,
    event_cb: Option<Arc<dyn Fn(u32, String) + Send + Sync>>,
}

struct Inner {
    half_connection: bool,
    // Session-facing channels
    #[allow(dead_code)]
    session_tx: mpsc::UnboundedSender<Vec<u8>>, // RX into session (currently unused)
    // Optional external RX sink (e.g., OS adapter) to receive frames coming from links
    adapter_rx_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    // Optional RX tap (sniffer) to observe frames (e.g., DHCP client)
    tap_rx_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    adapter_tx_task: Option<JoinHandle<()>>,
    
    // Crypto/compression configuration
    use_encrypt: bool,
    use_compress: bool,
    rc4_key: Vec<u8>,

    // Links and scheduling
    next_id: u64,
    links: HashMap<u64, Link>,
    rr_queue: VecDeque<u64>,
    rr_index: usize,

    // Counters
    total_rx: u64,
    total_tx: u64,

    // Background scheduler task handle
    tx_task: Option<JoinHandle<()>>,
}

struct Link {
    #[allow(dead_code)]
    id: u64,
    direction: LinkDirection,
    writer_tx: mpsc::UnboundedSender<Vec<u8>>,
    // Single TCP handle with timeout to prevent deadlock
    tcp: Arc<Mutex<TcpStream>>,
    #[allow(dead_code)]
    rx_handle: JoinHandle<()>,
    #[allow(dead_code)]
    tx_handle: JoinHandle<()>,
    #[allow(dead_code)]
    ka_handle: JoinHandle<()>,
    #[allow(dead_code)]
    rx_bytes: u64,
    #[allow(dead_code)]
    tx_bytes: u64,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct DataPlaneSummary {
    pub total_links: usize,
    pub total_rx: u64,
    pub total_tx: u64,
    pub c2s_links: usize,
    pub s2c_links: usize,
    pub both_links: usize,
}

impl DataPlane {
    /// Create a dataplane bound to the session's packet channels.
    /// Takes ownership of session.packet_rx (TX out of session) and clones session.packet_tx (RX into session).
    pub fn new(session: &mut Session, half_connection: bool) -> Option<Self> {
        let session_tx = session.packet_tx.as_ref()?.clone();
        let mut session_rx = session.packet_rx.take()?; // take ownership

        let inner = Arc::new(Mutex::new(Inner {
            half_connection,
            session_tx: session_tx.clone(), // Store for feeding from links
            use_encrypt: session.server_use_encrypt,
            use_compress: session.server_use_compress,
            rc4_key: {
                let state = session.state.lock().unwrap();
                state.session_key.to_vec()
            },
            adapter_rx_tx: None,
            tap_rx_tx: None,
            adapter_tx_task: None,
            next_id: 1,
            links: HashMap::new(),
            rr_queue: VecDeque::new(),
            rr_index: 0,
            total_rx: 0,
            total_tx: 0,
            tx_task: None,
        }));

        // Spawn the scheduler that forwards frames from session_rx to link writers
        let inner_for_task = inner.clone();
        let tx_task = tokio::spawn(async move {
            debug!("DataPlane scheduler started - will forward session frames to links");
            while let Some(frame) = session_rx.recv().await {
                debug!("DataPlane scheduler: received {} bytes from session", frame.len());
                
                // Log frame type for debugging
                if frame.len() >= 14 {
                    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
                    debug!("DataPlane scheduler: EtherType=0x{:04x} len={}", ethertype, frame.len());
                }
                
                // Choose a TX-capable link under lock, but don't hold across await
                let target_id = {
                    let mut g = inner_for_task.lock().unwrap();
                    // Eligible links for TX are those not marked ServerToClient
                    let elig: Vec<u64> = g
                        .links
                        .iter()
                        .filter_map(|(id, l)| {
                            if l.direction != LinkDirection::ServerToClient {
                                Some(*id)
                            } else {
                                None
                            }
                        })
                        .collect();
                    if elig.is_empty() {
                        None
                    } else if g.half_connection {
                        if let Some(id) = g.links.iter().find_map(|(id, l)| {
                            if l.direction == LinkDirection::ClientToServer {
                                Some(*id)
                            } else {
                                None
                            }
                        }) {
                            Some(id)
                        } else {
                            let idx = g.rr_index % elig.len();
                            g.rr_index = g.rr_index.wrapping_add(1);
                            Some(elig[idx])
                        }
                    } else {
                        let idx = g.rr_index % elig.len();
                        g.rr_index = g.rr_index.wrapping_add(1);
                        Some(elig[idx])
                    }
                };

                if let Some(id) = target_id {
                    let writer = {
                        let g = inner_for_task.lock().unwrap();
                        g.links.get(&id).map(|l| l.writer_tx.clone())
                    };
                    if let Some(w) = writer {
                        debug!("DataPlane scheduler: forwarding {} bytes to link id={}", frame.len(), id);
                        let _ = w.send(frame);
                    } else {
                        warn!("DataPlane scheduler: no writer found for link id={}", id);
                    }
                } else {
                    warn!("DataPlane scheduler: no active links for frame (len={}) - dropping", frame.len());
                }
            }
        });
        // store handle
        {
            let mut g = inner.lock().unwrap();
            g.tx_task = Some(tx_task);
        }

        Some(Self { inner, event_cb: None })
    }

    pub fn set_event_callback(&mut self, cb: Arc<dyn Fn(u32, String) + Send + Sync>) { self.event_cb=Some(cb); }

    /// Set an optional external RX sink (e.g., virtual adapter) to receive frames coming from links.
    /// The provided sender will be cloned internally and used by all link RX workers.
    pub fn set_adapter_rx(&self, tx: mpsc::UnboundedSender<Vec<u8>>) {
        let mut g = self.inner.lock().unwrap();
        g.adapter_rx_tx = Some(tx);
    }

    /// Provide a channel receiver for frames coming from a virtual adapter (adapter->session).
    /// Spawns a task to forward those frames into the dataplane's scheduling path (session_tx).
    pub fn set_adapter_tx(&self, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
        let inner = self.inner.clone();
        let _task = tokio::spawn(async move {
            debug!("DataPlane adapter TX task started (TAP → Links)");
            while let Some(frame) = rx.recv().await {
                debug!("DataPlane adapter TX: received {} bytes from TAP", frame.len());
                
                // ✅ FIX: Send directly to session_tx to feed the scheduler
                let session_tx = {
                    let g = inner.lock().unwrap();
                    g.session_tx.clone()
                };
                
                if let Err(_) = session_tx.send(frame) {
                    warn!("DataPlane adapter TX: session channel closed");
                    break;
                }
            }
            debug!("DataPlane adapter TX task ended");
        });
        let mut g = self.inner.lock().unwrap();
        g.adapter_tx_task = Some(_task);
    }

    /// Set an optional RX tap to observe frames delivered from links (used by protocol helpers like DHCP).
    pub fn set_rx_tap(&self, tx: mpsc::UnboundedSender<Vec<u8>>) {
        let mut g = self.inner.lock().unwrap();
        g.tap_rx_tx = Some(tx);
    }
    
    /// Update crypto/compression settings based on server negotiation.
    /// CRITICAL: Must be called after receiving server's welcome pack to match server's expectations!
    pub fn update_crypto_settings(&self, use_encrypt: bool, use_compress: bool) {
        let mut g = self.inner.lock().unwrap();
        g.use_encrypt = use_encrypt;
        g.use_compress = use_compress;
        debug!("DataPlane crypto settings updated: encrypt={} compress={}", use_encrypt, use_compress);
    }

    /// Send a raw L2 frame into the dataplane via any TX-capable link; returns true if queued.
    pub fn send_frame(&self, frame: Vec<u8>) -> bool {
        // Choose a TX-capable link
        let (id, writer) = {
            let mut g = self.inner.lock().unwrap();
            let mut elig: Vec<(u64, mpsc::UnboundedSender<Vec<u8>>)> = g
                .links
                .iter()
                .filter_map(|(id, l)| {
                    if l.direction != LinkDirection::ServerToClient {
                        Some((*id, l.writer_tx.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            if elig.is_empty() {
                if let Some(cb)=&self.event_cb { cb(293, "dataplane tx failure: no eligible links".into()); }
                return false;
            }
            if g.half_connection {
                if let Some((id, tx)) = g.links.iter().find_map(|(id, l)| {
                    if l.direction == LinkDirection::ClientToServer {
                        Some((*id, l.writer_tx.clone()))
                    } else {
                        None
                    }
                }) {
                    (id, tx)
                } else {
                    let idx = g.rr_index % elig.len();
                    g.rr_index = g.rr_index.wrapping_add(1);
                    elig.remove(idx)
                }
            } else {
                let idx = g.rr_index % elig.len();
                g.rr_index = g.rr_index.wrapping_add(1);
                elig.remove(idx)
            }
        };
        debug!(
            "dataplane: inject TX frame len={} via link id={}",
            frame.len(),
            id
        );
        
        // Debug: Check if this is a DHCP packet
        if frame.len() > 42 {
            let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            if ethertype == 0x0800 && frame.len() > 34 {
                let ip_proto = frame[23];
                if ip_proto == 17 { // UDP
                    let udp_start = 34;
                    if frame.len() > udp_start + 4 {
                        let src_port = u16::from_be_bytes([frame[udp_start], frame[udp_start + 1]]);
                        let dst_port = u16::from_be_bytes([frame[udp_start + 2], frame[udp_start + 3]]);
                        // DHCP packet (client -> server)
                    }
                }
            }
        }
        
        let ok = writer.send(frame).is_ok();
        if !ok {
            if let Some(cb)=&self.event_cb { cb(293, format!("dataplane tx failure: enqueue error link_id={}", id)); }
            // Remove defunct link (Option A minimal recovery)
            let removed = {
                let mut g = self.inner.lock().unwrap();
                g.links.remove(&id).is_some()
            };
            if removed { if let Some(cb)=&self.event_cb { cb(291, format!("dataplane link removed id={} reason=enqueue_error", id)); } }
        }
        ok
    }

    /// Register a bonded TCP stream with direction and spawn RX/TX workers.
    /// NOTE: After SoftEther additional_connect handshake, data links use RAW TCP with
    /// SoftEther framing, NOT TLS! The TLS layer is only for the initial HTTP handshake.
    pub fn register_link(&self, mut tcp: TcpStream, direction: i32) -> u64 {
        let direction = LinkDirection::from(direction);
        debug!("dataplane: registering link with direction={:?}", direction);
        
        // Set TCP socket options for optimal performance
        let _ = tcp.set_write_timeout(Some(Duration::from_secs(30)));
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = tcp.set_nodelay(true); // Disable Nagle for low latency
        
        // CRITICAL FIX: Clone the TcpStream for TX and RX to avoid lock contention
        // TCP streams are full-duplex and can read/write simultaneously with separate handles
        let tcp_rx = tcp.try_clone().expect("Failed to clone TCP stream for RX");
        let tcp_tx = tcp; // Original stream for TX
        
        // Separate mutexes for RX and TX (no contention)
        let tcp_rx_shared = Arc::new(Mutex::new(tcp_rx));
        let tcp_tx_shared = Arc::new(Mutex::new(tcp_tx));
        
        // Writer channel toward this link
        let (writer_tx, mut writer_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // RX task: parse frames from link RX and forward to adapter sink
        let inner_for_rx = self.inner.clone();
        let tcp_for_rx = tcp_rx_shared.clone();
        let link_id_for_debug = {
            let g = self.inner.lock().unwrap();
            g.next_id
        };
        let rx_handle = tokio::task::spawn_blocking(move || {
            debug!("dataplane: Starting RX loop for link_id={}", link_id_for_debug);
            // limit hexdump logs to avoid noise
            let mut debug_hexdump_budget: usize = 8;
            loop {
                // Helper: read big-endian u32
                let read_u32_be = |guard: &mut TcpStream| -> std::io::Result<u32> {
                    let mut b = [0u8; 4];
                    if let Err(e) = guard.read_exact(&mut b) {
                        // Treat timeout / wouldblock as transient; sleep briefly and continue
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut
                        {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                            return Err(e);
                        } else {
                            return Err(e);
                        }
                    }
                    Ok(u32::from_be_bytes(b))
                };
                // Parse message: either KEEP_ALIVE ([0xffffffff][len][bytes]) or data batch ([count][len][frame] * count)
                let mut frames: Vec<Vec<u8>> = Vec::new();
                {
                    let mut guard = tcp_for_rx.lock().unwrap();
                    let first = match read_u32_be(&mut guard) {
                        Ok(v) => v,
                        Err(e) => {
                            // For transient errors, continue; for others, exit quietly (link closed)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut
                            {
                                continue;
                            } else {
                                debug!("dataplane: RX exit: {e}");
                                return;
                            }
                        }
                    };
                    if first == u32::MAX {
                        // KEEP_ALIVE: read size and discard payload
                        let sz = match read_u32_be(&mut guard) {
                            Ok(v) => v,
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut
                                {
                                    continue;
                                }
                                debug!("dataplane: RX keepalive exit: {e}");
                                return;
                            }
                        };
                        debug!("dataplane: RX keepalive sz={sz}");
                        if sz > 0 {
                            let mut tmp = vec![0u8; sz as usize];
                            if let Err(e) = guard.read_exact(&mut tmp) {
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut
                                {
                                    continue;
                                }
                                debug!("dataplane: RX keepalive read exit: {e}");
                                return;
                            }
                            if debug_hexdump_budget > 0 {
                                let dump_len = tmp.len().min(64);
                                debug!(
                                    "dataplane: KEEPALIVE dump ({} bytes): {}",
                                    dump_len,
                                    hex::encode(&tmp[..dump_len])
                                );
                                debug_hexdump_budget -= 1;
                            }
                        }
                        // No frames in this iteration; continue
                        continue;
                    } else {
                        let count = first;
                        debug!("dataplane: RX batch count={count} (link dir={direction:?})");
                        if count == 0 {
                            continue;
                        }
                        for _ in 0..count {
                            let len = match read_u32_be(&mut guard) {
                                Ok(v) => v,
                                Err(e) => {
                                    if e.kind() == std::io::ErrorKind::WouldBlock
                                        || e.kind() == std::io::ErrorKind::TimedOut
                                    {
                                        continue;
                                    }
                                    debug!("dataplane: RX frame len exit: {e}");
                                    return;
                                }
                            };
                            if len == 0 || len > (1 << 20) {
                                // 1 MiB guard
                                warn!("dataplane: RX invalid frame length: {len}");
                                return;
                            }
                            let mut buf = vec![0u8; len as usize];
                            if let Err(e) = guard.read_exact(&mut buf) {
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut
                                {
                                    continue;
                                }
                                debug!("dataplane: RX read exit: {e}");
                                return;
                            }
                            
                            // ✅ DECRYPT immediately after reading (before any processing)
                            let (use_encrypt, use_compress, rc4_key) = {
                                let g = inner_for_rx.lock().unwrap();
                                (g.use_encrypt, g.use_compress, g.rc4_key.clone())
                            };
                            
                            if use_encrypt && !rc4_key.is_empty() {
                                rc4_apply_inplace(&rc4_key, &mut buf);
                                debug!("DataPlane RX: decrypted {} bytes", buf.len());
                            }
                            
                            // ✅ DECOMPRESS after decryption
                            #[cfg(feature = "compress")]
                            if use_compress {
                                match decompress_deflate(&buf) {
                                    Ok(decompressed) => {
                                        debug!("DataPlane RX: decompressed {} -> {} bytes", buf.len(), decompressed.len());
                                        buf = decompressed;
                                    }
                                    Err(e) => {
                                        warn!("DataPlane RX: decompression failed: {}, dropping frame", e);
                                        continue;
                                    }
                                }
                            }
                            
                            if debug_hexdump_budget > 0 {
                                let dump_len = buf.len().min(96);
                                let hex = hex::encode(&buf[..dump_len]);
                                debug!("dataplane: RX frame[0..{dump_len}]={hex}");
                            }
                            frames.push(buf);
                        }
                    }
                }
                
                // Frames received from server
                
                // Optional: log DHCP for diagnostics (silent in production)
                for f in &frames {
                    if f.len() >= 42 {
                        let ethertype = u16::from_be_bytes([f[12], f[13]]);
                        if ethertype == 0x0800 {
                            let ip_proto = f[23];
                            if ip_proto == 17 {
                                let src_port = u16::from_be_bytes([f[34], f[35]]);
                                let dst_port = u16::from_be_bytes([f[36], f[37]]);
                                if (src_port == 67 || src_port == 68)
                                    || (dst_port == 67 || dst_port == 68)
                                {
                                    debug!("dataplane: DHCP packet observed ({src_port} -> {dst_port})");
                                }
                            }
                        }
                    }
                }
                // Forward to adapter sink and tap (if any)
                let adapter_tx_opt = { inner_for_rx.lock().unwrap().adapter_rx_tx.clone() };
                if let Some(ext) = adapter_tx_opt {
                    debug!("DataPlane link RX: forwarding {} frames to adapter sink", frames.len());
                    for f in &frames {
                        let _ = ext.send(f.clone());
                    }
                } else {
                    if !frames.is_empty() {
                        debug!("DataPlane link RX: no adapter sink configured - {} frames dropped", frames.len());
                    }
                }
                let tap_tx_opt = { inner_for_rx.lock().unwrap().tap_rx_tx.clone() };
                if let Some(ext) = tap_tx_opt {
                    debug!("DataPlane link RX: forwarding {} frames to tap", frames.len());
                    for f in &frames {
                        let _ = ext.send(f.clone());
                    }
                }
                let mut g = inner_for_rx.lock().unwrap();
                let bytes: u64 = frames.iter().map(|f| f.len() as u64).sum();
                g.total_rx += bytes;
            }
        });

        // TX task: write frames to the link as they come (SoftEther framing: [count][len][frame])
        let inner_for_tx = self.inner.clone();
        let tcp_for_tx = tcp_tx_shared.clone();
        let tx_handle = tokio::spawn(async move {
            debug!("DataPlane TX task started for link");
            while let Some(mut frame) = writer_rx.recv().await {
                debug!("DataPlane TX: received {} bytes from writer_rx", frame.len());
                // Get crypto/compress config
                let (use_encrypt, use_compress, rc4_key) = {
                    let g = inner_for_tx.lock().unwrap();
                    (g.use_encrypt, g.use_compress, g.rc4_key.clone())
                };
                
                // Apply compression FIRST (before encryption)
                #[cfg(feature = "compress")]
                if use_compress {
                    match compress_deflate(&frame) {
                        Ok(compressed) => {
                            debug!("DataPlane TX: compressed {} -> {} bytes", frame.len(), compressed.len());
                            frame = compressed;
                        }
                        Err(e) => {
                            warn!("DataPlane TX: compression failed: {}, sending uncompressed", e);
                        }
                    }
                }
                
                // Apply encryption (in-place for efficiency)
                if use_encrypt && !rc4_key.is_empty() {
                    rc4_apply_inplace(&rc4_key, &mut frame);
                    debug!("DataPlane TX: encrypted {} bytes", frame.len());
                }
                
                let len = frame.len();
                debug!("DataPlane TX: about to write {} bytes to TCP", len);
                
                // Prepare the full message buffer to minimize lock time
                let mut msg_buf = Vec::with_capacity(8 + len);
                msg_buf.extend_from_slice(&1u32.to_be_bytes()); // count=1
                msg_buf.extend_from_slice(&(len as u32).to_be_bytes()); // frame length
                msg_buf.extend_from_slice(&frame); // frame payload
                
                debug!("DataPlane TX: prepared msg_buf of {} bytes (8 header + {} payload)", msg_buf.len(), len);
                
                let tcp_for_tx2 = tcp_for_tx.clone();
                let res = tokio::task::spawn_blocking(move || {
                    debug!("DataPlane TX: inside spawn_blocking, attempting write");
                    let mut guard = tcp_for_tx2.lock().unwrap();
                    debug!("DataPlane TX: acquired tcp lock");
                    // Write the entire message in one call to minimize lock time
                    guard.write_all(&msg_buf)?;
                    debug!("DataPlane TX: write_all completed");
                    guard.flush()?;
                    debug!("DataPlane TX: flush completed");
                    Ok::<(), std::io::Error>(())
                })
                .await;
                debug!("DataPlane TX: write completed, result: {:?}", res.as_ref().map(|_| "ok").map_err(|e| e.to_string()));
                match res {
                    Ok(Ok(())) => {
                        let mut g = inner_for_tx.lock().unwrap();
                        g.total_tx += len as u64;
                        debug!("DataPlane TX: updated total_tx");
                    }
                    Ok(Err(e)) => {
                        debug!("dataplane: TX exit: {e}");
                        break;
                    }
                    Err(e) => {
                        warn!("dataplane: TX join error: {e}");
                        break;
                    }
                }
            }
            debug!("DataPlane TX task ended");
        });

        // Keepalive task: periodically send a neutral keepalive on this link
        let tcp_for_ka = tcp_tx_shared.clone();
        let ka_handle = tokio::spawn(async move {
            // Many implementations use a ~20s heartbeat when idle
            let mut ticker = interval(Duration::from_secs(20));
            loop {
                ticker.tick().await;
                let tcp_for_ka2 = tcp_for_ka.clone();
                let res = tokio::task::spawn_blocking(move || {
                    let mut guard = tcp_for_ka2.lock().unwrap();
                    // Write a SoftEther keepalive frame: magic 0xffffffff, then BE length, then payload.
                    // Use a small textual payload as seen in other implementations for compatibility.
                    const MAGIC: u32 = 0xffff_ffff;
                    let payload = crate::KEEP_ALIVE_STRING.as_bytes();
                    let mut buf = Vec::with_capacity(4 + 4 + payload.len());
                    buf.extend_from_slice(&MAGIC.to_be_bytes());
                    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                    buf.extend_from_slice(payload);
                    guard.write_all(&buf)
                })
                .await;
                match res {
                    Ok(Ok(())) => { /* ok */ }
                    Ok(Err(e)) => {
                        debug!("dataplane: keepalive TX exit: {e}");
                        break;
                    }
                    Err(e) => {
                        debug!("dataplane: keepalive join exit: {e}");
                        break;
                    }
                }
            }
        });

        // Register
        let mut g = self.inner.lock().unwrap();
        let id = g.next_id;
        g.next_id += 1;
    g.links.insert(
            id,
            Link {
                id,
                direction,
                writer_tx,
                tcp: tcp_tx_shared, // Store TX stream handle for reference
                rx_handle,
                tx_handle,
                ka_handle,
                rx_bytes: 0,
                tx_bytes: 0,
            },
        );
    if let Some(cb)=&self.event_cb { cb(292, format!("dataplane link registered id={id} direction={direction:?}")); }
        debug!("dataplane: link_id={} fully registered and RX/TX tasks started", id);
        id
    }

    pub fn summary(&self) -> DataPlaneSummary {
        let g = self.inner.lock().unwrap();
        let mut c2s = 0usize;
        let mut s2c = 0usize;
        let mut both = 0usize;
        for l in g.links.values() {
            match l.direction {
                LinkDirection::ClientToServer => c2s += 1,
                LinkDirection::ServerToClient => s2c += 1,
                LinkDirection::Both => both += 1,
            }
        }
        DataPlaneSummary {
            total_links: g.links.len(),
            total_rx: g.total_rx,
            total_tx: g.total_tx,
            c2s_links: c2s,
            s2c_links: s2c,
            both_links: both,
        }
    }

    /// Gracefully shut down all dataplane activities and close underlying sockets.
    pub fn shutdown(&self) {
        let mut g = self.inner.lock().unwrap();
        // Close sockets to make blocking RX/TX exit
        for (_id, link) in g.links.iter() {
            // Attempt to shut down the underlying TCP socket; ignore errors
            if let Ok(tcp) = link.tcp.lock() {
                let _ = tcp.shutdown(Shutdown::Both);
            }
        }
        // Abort async tasks (scheduler and adapter forwarder)
        if let Some(h) = g.tx_task.take() {
            h.abort();
        }
        if let Some(h) = g.adapter_tx_task.take() {
            h.abort();
        }
        // Best-effort: abort per-link async tasks (spawn_blocking tasks will unwind after socket shutdown)
        for (_id, link) in g.links.iter() {
            link.rx_handle.abort();
            link.tx_handle.abort();
            link.ka_handle.abort();
        }
        g.links.clear();
        g.rr_queue.clear();
        g.adapter_rx_tx = None;
        g.tap_rx_tx = None;
    }
}
