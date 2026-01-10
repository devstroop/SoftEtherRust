//! Multi-connection data loop for tunnel runner.
//!
//! This module contains the packet forwarding loop for half-connection mode
//! with multiple TCP connections (receive-only + bidirectional).

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::adapter::TunAdapter;
#[cfg(target_os = "windows")]
use crate::adapter::WintunDevice;
use crate::client::{ConcurrentReader, ConnectionManager};
use crate::error::Result;
use crate::packet::{ArpHandler, DhcpConfig};
use crate::protocol::{compress_into, decompress_into, is_compressed, TunnelCodec};

use super::DataLoopState;
use super::TunnelRunner;

impl TunnelRunner {
    /// Run the multi-connection data loop (half-connection mode).
    ///
    /// This mode uses multiple TCP connections:
    /// - Receive-only connections: handled by ConcurrentReader
    /// - Bidirectional connections: used for both send and receive
    ///
    /// Each connection has its own encryption state for per-connection RC4.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) async fn run_data_loop_multi(
        &self,
        conn_mgr: &mut ConnectionManager,
        tun: &mut impl TunAdapter,
        dhcp_config: &DhcpConfig,
    ) -> Result<()> {
        let mut state = DataLoopState::new(self.mac);
        let gateway = dhcp_config.gateway.unwrap_or(dhcp_config.ip);
        state.configure(dhcp_config.ip, gateway);

        // Get the total number of connections before extraction
        let total_conns = conn_mgr.connection_count();

        // Extract receive-only connections for concurrent reading.
        // Bidirectional connections stay in conn_mgr for both send AND receive.
        // Each connection carries its own encryption state for per-connection RC4.
        let recv_conns = conn_mgr.take_recv_connections();
        let num_recv = recv_conns.len();
        let num_bidir = conn_mgr.connection_count(); // Bidirectional connections remaining

        // Create concurrent reader for receive-only connections (may be empty!)
        // The concurrent reader handles per-connection decryption internally.
        let mut concurrent_reader = if !recv_conns.is_empty() {
            Some(ConcurrentReader::new(recv_conns, 256))
        } else {
            None
        };

        // One codec per original connection index for stateful frame parsing
        let mut codecs: Vec<TunnelCodec> = (0..total_conns).map(|_| TunnelCodec::new()).collect();

        // Per-connection encryption is now handled by ManagedConnection.
        // No shared encryption variable - each connection has its own cipher state.
        let has_encryption = self.config.rc4_key_pair.is_some();
        if has_encryption {
            info!("RC4 defense-in-depth encryption active (per-connection cipher state)");
        } else {
            debug!("No RC4 encryption (TLS-only mode for multi-connection tunnel)");
        }

        // Buffer for reading from bidirectional connections
        let mut bidir_read_buf = vec![0u8; 8192];

        let mut send_buf = vec![0u8; 4096];
        let mut comp_buf = vec![0u8; 4096]; // Pre-allocated buffer for compression
        let mut decomp_buf = vec![0u8; 4096];
        let mut tun_write_buf = vec![0u8; 2048];

        // Set up ARP handler
        let mut arp = ArpHandler::new(self.mac);
        arp.configure(dhcp_config.ip, gateway);

        // Send gratuitous ARP to announce our presence
        let garp = arp.build_gratuitous_arp();
        self.send_frame_multi(conn_mgr, &garp, &mut send_buf)
            .await?;
        debug!("Sent gratuitous ARP");

        // Send ARP request for gateway
        let gateway_arp = arp.build_gateway_request();
        self.send_frame_multi(conn_mgr, &gateway_arp, &mut send_buf)
            .await?;
        debug!("Sent gateway ARP request");

        let mut keepalive_interval = interval(Duration::from_secs(self.config.keepalive_interval));
        let mut last_activity = Instant::now();

        // Zero-copy TUN reader using fixed buffer
        let (tun_tx, mut tun_rx) = mpsc::channel::<(usize, [u8; 2048])>(256);
        let tun_fd = tun.raw_fd();
        let running = self.running.clone();

        // Spawn blocking TUN reader task
        let tun_reader = tokio::task::spawn_blocking(move || {
            let mut read_buf = [0u8; 2048];

            while running.load(Ordering::SeqCst) {
                let mut poll_fds = [libc::pollfd {
                    fd: tun_fd,
                    events: libc::POLLIN,
                    revents: 0,
                }];

                let poll_result = unsafe {
                    libc::poll(poll_fds.as_mut_ptr(), 1, 1) // 1ms timeout for low latency
                };

                if poll_result > 0 && (poll_fds[0].revents & libc::POLLIN) != 0 {
                    let n = unsafe {
                        libc::read(
                            tun_fd,
                            read_buf.as_mut_ptr() as *mut libc::c_void,
                            read_buf.len(),
                        )
                    };

                    #[cfg(target_os = "macos")]
                    let min_len = 4;
                    #[cfg(target_os = "linux")]
                    let min_len = 1;

                    if n > min_len as isize && tun_tx.blocking_send((n as usize, read_buf)).is_err()
                    {
                        break;
                    }
                }
            }
        });

        info!(
            connections = total_conns,
            recv_only = num_recv,
            bidirectional = num_bidir,
            "VPN tunnel active"
        );

        let our_ip = dhcp_config.ip;
        let use_compress = self.config.use_compress;
        let my_mac = self.mac;

        while self.running.load(Ordering::SeqCst) {
            // Helper macro to process received VPN data
            macro_rules! process_vpn_data {
                ($conn_idx:expr, $data:expr) => {{
                    match codecs.get_mut($conn_idx).map(|c| c.feed($data)) {
                        Some(Ok(frames)) => {
                            for frame in frames {
                                if frame.is_keepalive() {
                                    debug!("Received keepalive on conn {}", $conn_idx);
                                    continue;
                                }

                                if let Some(packets) = frame.packets() {
                                    for packet in packets {
                                        let frame_data: &[u8] = if is_compressed(packet) {
                                            match decompress_into(packet, &mut decomp_buf) {
                                                Ok(len) => &decomp_buf[..len],
                                                Err(_) => continue,
                                            }
                                        } else {
                                            packet
                                        };

                                        if let Err(e) = self.process_frame_zerocopy(
                                            tun_fd,
                                            &mut tun_write_buf,
                                            &mut arp,
                                            frame_data,
                                            our_ip,
                                        ) {
                                            error!("Process error: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                        Some(Err(e)) => {
                            error!("Decode error on conn {}: {}", $conn_idx, e);
                        }
                        None => {}
                    }

                    // Send any pending ARP replies
                    if let Some(reply) = arp.build_pending_reply() {
                        if let Err(e) = self.send_frame_multi(conn_mgr, &reply, &mut send_buf).await
                        {
                            error!("Failed to send ARP reply: {}", e);
                        } else {
                            debug!("Sent ARP reply");
                        }
                        arp.take_pending_reply();
                    }

                    last_activity = Instant::now();
                }};
            }

            // Create futures for reading
            // 1. Concurrent reader for receive-only connections (half-connection mode)
            let concurrent_recv = async {
                if let Some(ref mut reader) = concurrent_reader {
                    reader.recv().await
                } else {
                    // No concurrent reader - pend forever
                    std::future::pending::<Option<crate::client::ReceivedPacket>>().await
                }
            };

            // 2. Direct read from bidirectional connections in conn_mgr (with per-conn decryption)
            let bidir_recv = async {
                if num_bidir > 0 {
                    conn_mgr.read_any_decrypt(&mut bidir_read_buf).await
                } else {
                    // No bidirectional connections - pend forever
                    std::future::pending::<std::io::Result<(usize, usize)>>().await
                }
            };

            tokio::select! {
                // Biased: prioritize data paths over timers to minimize latency
                biased;

                // Packet from TUN device (from local applications)
                Some((len, tun_buf)) = tun_rx.recv() => {
                    #[cfg(target_os = "macos")]
                    let ip_packet = &tun_buf[4..len];
                    #[cfg(target_os = "linux")]
                    let ip_packet = &tun_buf[..len];

                    if ip_packet.is_empty() {
                        continue;
                    }

                    let gateway_mac = arp.gateway_mac_or_broadcast();

                    // Build tunnel frame
                    let eth_len = 14 + ip_packet.len();
                    let total_len = 8 + eth_len;

                    if total_len > send_buf.len() {
                        warn!("Packet too large: {}", ip_packet.len());
                        continue;
                    }

                    let ip_version = (ip_packet[0] >> 4) & 0x0F;
                    if ip_version != 4 && ip_version != 6 {
                        continue;
                    }

                    if use_compress {
                        // Compression path
                        let eth_start = 8;
                        send_buf[eth_start..eth_start + 6].copy_from_slice(&gateway_mac);
                        send_buf[eth_start + 6..eth_start + 12].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[eth_start + 12] = 0x08;
                            send_buf[eth_start + 13] = 0x00;
                        } else {
                            send_buf[eth_start + 12] = 0x86;
                            send_buf[eth_start + 13] = 0xDD;
                        }
                        send_buf[eth_start + 14..eth_start + 14 + ip_packet.len()]
                            .copy_from_slice(ip_packet);

                        let eth_frame = &send_buf[eth_start..eth_start + eth_len];

                        match compress_into(eth_frame, &mut comp_buf) {
                            Ok(comp_len) => {
                                let comp_total = 8 + comp_len;
                                if comp_total <= send_buf.len() {
                                    send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                    send_buf[4..8].copy_from_slice(&(comp_len as u32).to_be_bytes());
                                    send_buf[8..8 + comp_len].copy_from_slice(&comp_buf[..comp_len]);
                                    // Use per-connection encryption via ConnectionManager
                                    conn_mgr.write_all_encrypted(&mut send_buf[..comp_total]).await?;
                                }
                            }
                            Err(e) => {
                                warn!("Compression failed: {}", e);
                                send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                                // Use per-connection encryption via ConnectionManager
                                conn_mgr.write_all_encrypted(&mut send_buf[..total_len]).await?;
                            }
                        }
                    } else {
                        // Uncompressed path
                        send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                        send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                        send_buf[8..14].copy_from_slice(&gateway_mac);
                        send_buf[14..20].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[20] = 0x08;
                            send_buf[21] = 0x00;
                        } else {
                            send_buf[20] = 0x86;
                            send_buf[21] = 0xDD;
                        }
                        send_buf[22..22 + ip_packet.len()].copy_from_slice(ip_packet);

                        // Use per-connection encryption via ConnectionManager
                        conn_mgr.write_all_encrypted(&mut send_buf[..total_len]).await?;
                    }

                    last_activity = Instant::now();
                }

                // Data from receive-only connections via ConcurrentReader
                // ConcurrentReader handles per-connection decryption internally
                Some(packet) = concurrent_recv => {
                    let conn_idx = packet.conn_index;
                    // Data is already decrypted by ConcurrentReader's per-connection cipher
                    // Use &[u8] deref directly - Bytes implements Deref<Target=[u8]>
                    process_vpn_data!(conn_idx, &packet.data[..]);
                }

                // Data from bidirectional connections (direct read with per-conn decryption)
                result = bidir_recv => {
                    if let Ok((conn_idx, n)) = result {
                        if n > 0 {
                            // Data is already decrypted by read_any_decrypt
                            let data = &bidir_read_buf[..n];
                            process_vpn_data!(conn_idx, data);
                        }
                    }
                }

                // Keepalive timer
                _ = keepalive_interval.tick() => {
                    if last_activity.elapsed() > Duration::from_secs(3) {
                        let keepalive = TunnelCodec::encode_keepalive_direct(
                            32,
                            &mut send_buf,
                        );
                        if let Some(ka) = keepalive {
                            // Use per-connection encryption via ConnectionManager
                            let ka_len = ka.len();
                            conn_mgr.write_all_encrypted(&mut send_buf[..ka_len]).await?;
                            debug!("Sent keepalive");
                        }
                    }

                    if arp.should_send_periodic_garp() {
                        let garp = arp.build_gratuitous_arp();
                        self.send_frame_multi(conn_mgr, &garp, &mut send_buf).await?;
                        arp.mark_garp_sent();
                        debug!("Sent periodic GARP");
                    }
                }
            }
        }

        info!("VPN tunnel stopped");

        // Cleanup
        if let Some(ref mut reader) = concurrent_reader {
            reader.shutdown();
            let recv_stats = reader.bytes_received();
            let total_recv: u64 = recv_stats.iter().map(|(_, b)| b).sum();
            debug!(
                bytes = total_recv,
                connections = recv_stats.len(),
                "Concurrent reader shutdown"
            );
        }
        tun_reader.abort();

        Ok(())
    }

    /// Windows-specific multi-connection data loop.
    /// Note: On Windows, this falls back to single-connection behavior since
    /// the Wintun API doesn't support the same zero-copy optimizations.
    #[cfg(target_os = "windows")]
    pub(super) async fn run_data_loop_multi(
        &self,
        conn_mgr: &mut ConnectionManager,
        tun: &mut WintunDevice,
        dhcp_config: &DhcpConfig,
    ) -> Result<()> {
        let mut state = DataLoopState::new(self.mac);
        let gateway = dhcp_config.gateway.unwrap_or(dhcp_config.ip);
        state.configure(dhcp_config.ip, gateway);

        // Get the total number of connections
        let total_conns = conn_mgr.connection_count();
        let recv_conns = conn_mgr.take_recv_connections();
        let num_recv = recv_conns.len();
        let num_bidir = conn_mgr.connection_count();

        let mut concurrent_reader = if !recv_conns.is_empty() {
            Some(ConcurrentReader::new(recv_conns, 256))
        } else {
            None
        };

        let mut codecs: Vec<TunnelCodec> = (0..total_conns).map(|_| TunnelCodec::new()).collect();
        let mut bidir_read_buf = vec![0u8; 8192];
        let mut send_buf = vec![0u8; 4096];
        let mut comp_buf = vec![0u8; 4096]; // Pre-allocated buffer for compression
        let mut decomp_buf = vec![0u8; 4096];

        // Per-connection encryption is now managed by ConnectionManager

        let mut arp = ArpHandler::new(self.mac);
        arp.configure(dhcp_config.ip, gateway);

        let garp = arp.build_gratuitous_arp();
        self.send_frame_multi(conn_mgr, &garp, &mut send_buf)
            .await?;
        debug!("Sent gratuitous ARP");

        let gateway_arp = arp.build_gateway_request();
        self.send_frame_multi(conn_mgr, &gateway_arp, &mut send_buf)
            .await?;
        debug!("Sent gateway ARP request");

        let mut keepalive_interval = interval(Duration::from_secs(self.config.keepalive_interval));
        let mut last_activity = Instant::now();

        let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(256);
        let session = tun.session();
        let running = self.running.clone();

        let tun_reader = tokio::task::spawn_blocking(move || {
            while running.load(Ordering::SeqCst) {
                match session.receive_blocking() {
                    Ok(packet) => {
                        let bytes = packet.bytes().to_vec();
                        if tun_tx.blocking_send(bytes).is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        });

        info!(
            connections = total_conns,
            recv_only = num_recv,
            bidirectional = num_bidir,
            "VPN tunnel active (Windows)"
        );

        let our_ip = dhcp_config.ip;
        let use_compress = self.config.use_compress;
        let my_mac = self.mac;

        while self.running.load(Ordering::SeqCst) {
            // Helper macro to process received VPN data
            macro_rules! process_vpn_data {
                ($conn_idx:expr, $data:expr) => {{
                    match codecs.get_mut($conn_idx).map(|c| c.feed($data)) {
                        Some(Ok(frames)) => {
                            for frame in frames {
                                if frame.is_keepalive() {
                                    debug!("Received keepalive on conn {}", $conn_idx);
                                    continue;
                                }

                                if let Some(packets) = frame.packets() {
                                    for packet in packets {
                                        let frame_data: &[u8] = if is_compressed(packet) {
                                            match decompress_into(packet, &mut decomp_buf) {
                                                Ok(len) => &decomp_buf[..len],
                                                Err(_) => continue,
                                            }
                                        } else {
                                            packet
                                        };

                                        if let Err(e) = self.process_frame_windows(
                                            tun, &mut arp, frame_data, our_ip,
                                        ) {
                                            error!("Process error: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                        Some(Err(e)) => {
                            error!("Decode error on conn {}: {}", $conn_idx, e);
                        }
                        None => {}
                    }

                    if let Some(reply) = arp.build_pending_reply() {
                        if let Err(e) = self.send_frame_multi(conn_mgr, &reply, &mut send_buf).await
                        {
                            error!("Failed to send ARP reply: {}", e);
                        } else {
                            debug!("Sent ARP reply");
                        }
                        arp.take_pending_reply();
                    }

                    last_activity = Instant::now();
                }};
            }

            let concurrent_recv = async {
                if let Some(ref mut reader) = concurrent_reader {
                    reader.recv().await
                } else {
                    std::future::pending::<Option<crate::client::ReceivedPacket>>().await
                }
            };

            let bidir_recv = async {
                if num_bidir > 0 {
                    conn_mgr.read_any_decrypt(&mut bidir_read_buf).await
                } else {
                    std::future::pending::<std::io::Result<(usize, usize)>>().await
                }
            };

            tokio::select! {
                biased;

                Some(ip_packet) = tun_rx.recv() => {
                    if ip_packet.is_empty() {
                        continue;
                    }

                    let gateway_mac = arp.gateway_mac_or_broadcast();
                    let eth_len = 14 + ip_packet.len();
                    let total_len = 8 + eth_len;

                    if total_len > send_buf.len() {
                        warn!("Packet too large: {}", ip_packet.len());
                        continue;
                    }

                    let ip_version = (ip_packet[0] >> 4) & 0x0F;
                    if ip_version != 4 && ip_version != 6 {
                        continue;
                    }

                    if use_compress {
                        let eth_start = 8;
                        send_buf[eth_start..eth_start + 6].copy_from_slice(&gateway_mac);
                        send_buf[eth_start + 6..eth_start + 12].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[eth_start + 12] = 0x08;
                            send_buf[eth_start + 13] = 0x00;
                        } else {
                            send_buf[eth_start + 12] = 0x86;
                            send_buf[eth_start + 13] = 0xDD;
                        }
                        send_buf[eth_start + 14..eth_start + 14 + ip_packet.len()]
                            .copy_from_slice(&ip_packet);

                        let eth_frame = &send_buf[eth_start..eth_start + eth_len];

                        match compress_into(eth_frame, &mut comp_buf) {
                            Ok(comp_len) => {
                                let comp_total = 8 + comp_len;
                                if comp_total <= send_buf.len() {
                                    send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                    send_buf[4..8].copy_from_slice(&(comp_len as u32).to_be_bytes());
                                    send_buf[8..8 + comp_len].copy_from_slice(&comp_buf[..comp_len]);
                                    conn_mgr.write_all_encrypted(&mut send_buf[..comp_total]).await?;
                                }
                            }
                            Err(e) => {
                                warn!("Compression failed: {}", e);
                                send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                                conn_mgr.write_all_encrypted(&mut send_buf[..total_len]).await?;
                            }
                        }
                    } else {
                        send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                        send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                        send_buf[8..14].copy_from_slice(&gateway_mac);
                        send_buf[14..20].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[20] = 0x08;
                            send_buf[21] = 0x00;
                        } else {
                            send_buf[20] = 0x86;
                            send_buf[21] = 0xDD;
                        }
                        send_buf[22..22 + ip_packet.len()].copy_from_slice(&ip_packet);

                        conn_mgr.write_all_encrypted(&mut send_buf[..total_len]).await?;
                    }

                    last_activity = Instant::now();
                }

                // ConcurrentReader handles per-connection decryption internally
                Some(packet) = concurrent_recv => {
                    let conn_idx = packet.conn_index;
                    // Data is already decrypted by ConcurrentReader's per-connection cipher
                    let data: Vec<u8> = packet.data.to_vec();
                    process_vpn_data!(conn_idx, &data[..]);
                }

                result = bidir_recv => {
                    if let Ok((conn_idx, n)) = result {
                        if n > 0 {
                            // Data is already decrypted by read_any_decrypt
                            let data = &bidir_read_buf[..n];
                            process_vpn_data!(conn_idx, data);
                        }
                    }
                }

                _ = keepalive_interval.tick() => {
                    if last_activity.elapsed() > Duration::from_secs(3) {
                        let keepalive = TunnelCodec::encode_keepalive_direct(32, &mut send_buf);
                        if let Some(ka) = keepalive {
                            let ka_len = ka.len();
                            conn_mgr.write_all_encrypted(&mut send_buf[..ka_len]).await?;
                            debug!("Sent keepalive");
                        }
                    }

                    if arp.should_send_periodic_garp() {
                        let garp = arp.build_gratuitous_arp();
                        self.send_frame_multi(conn_mgr, &garp, &mut send_buf).await?;
                        arp.mark_garp_sent();
                        debug!("Sent periodic GARP");
                    }
                }
            }
        }

        info!("VPN tunnel stopped");

        if let Some(ref mut reader) = concurrent_reader {
            reader.shutdown();
            let recv_stats = reader.bytes_received();
            let total_recv: u64 = recv_stats.iter().map(|(_, b)| b).sum();
            debug!(
                bytes = total_recv,
                connections = recv_stats.len(),
                "Concurrent reader shutdown"
            );
        }
        tun_reader.abort();

        Ok(())
    }
}
