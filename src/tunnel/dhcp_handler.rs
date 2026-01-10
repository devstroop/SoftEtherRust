//! DHCP handling for tunnel runner.
//!
//! This module contains DHCP discovery logic for both single-connection
//! and multi-connection modes.

use std::time::{Duration, Instant};

use tokio::time::timeout;
use tracing::{debug, warn};

use crate::client::{ConnectionManager, VpnConnection};
use crate::error::{Error, Result};
use crate::packet::{DhcpClient, DhcpConfig, DhcpState};
use crate::protocol::{compress, decompress, is_compressed, TunnelCodec};

use super::TunnelRunner;

impl TunnelRunner {
    /// Perform DHCP through the tunnel (single connection).
    pub(super) async fn perform_dhcp(&self, conn: &mut VpnConnection) -> Result<DhcpConfig> {
        let mut dhcp = DhcpClient::new(self.mac);
        let mut codec = TunnelCodec::new();
        let mut buf = vec![0u8; 65536];
        let mut send_buf = vec![0u8; 2048];

        let deadline = Instant::now() + Duration::from_secs(self.config.dhcp_timeout);

        // Send DHCP DISCOVER
        let discover = dhcp.build_discover();
        debug!(bytes = discover.len(), "Sending DHCP DISCOVER");
        self.send_frame(conn, &discover, &mut send_buf).await?;

        // Wait for OFFER
        loop {
            if Instant::now() > deadline {
                return Err(Error::TimeoutMessage(
                    "DHCP timeout - no OFFER received".into(),
                ));
            }

            match timeout(Duration::from_secs(3), conn.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    debug!("Received {} bytes from tunnel", n);
                    // Decode tunnel frames
                    let frames = codec.feed(&buf[..n])?;
                    for frame in frames {
                        if frame.is_keepalive() {
                            debug!("Received keepalive frame");
                            continue;
                        }
                        if let Some(packets) = frame.packets() {
                            for packet in packets {
                                // Check if packet is compressed and decompress if needed
                                let packet_data: Vec<u8> = if is_compressed(packet) {
                                    match decompress(packet) {
                                        Ok(decompressed) => {
                                            debug!(
                                                "Decompressed {} -> {} bytes",
                                                packet.len(),
                                                decompressed.len()
                                            );
                                            decompressed
                                        }
                                        Err(e) => {
                                            warn!("Decompression failed: {}", e);
                                            continue;
                                        }
                                    }
                                } else {
                                    packet.to_vec()
                                };

                                // Log packet details
                                if packet_data.len() >= 14 {
                                    let ethertype =
                                        format!("0x{:02X}{:02X}", packet_data[12], packet_data[13]);
                                    debug!(
                                        "Packet: {} bytes, ethertype={}",
                                        packet_data.len(),
                                        ethertype
                                    );
                                }

                                // Check if this is a DHCP response (UDP port 68)
                                if self.is_dhcp_response(&packet_data) {
                                    debug!("DHCP response received");
                                    if dhcp.process_response(&packet_data) {
                                        // Got ACK
                                        return Ok(dhcp.config().clone());
                                    } else if dhcp.state() == DhcpState::DiscoverSent {
                                        // Got OFFER, send REQUEST
                                        if let Some(request) = dhcp.build_request() {
                                            debug!("Sending DHCP REQUEST");
                                            self.send_frame(conn, &request, &mut send_buf).await?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(Ok(_)) => {
                    return Err(Error::ConnectionFailed(
                        "Connection closed during DHCP".into(),
                    ));
                }
                Ok(Err(e)) => {
                    return Err(Error::Io(e));
                }
                Err(_) => {
                    // Timeout, retry DISCOVER if still in initial state
                    if dhcp.state() == DhcpState::DiscoverSent {
                        warn!("DHCP timeout, retrying DISCOVER");
                        let discover = dhcp.build_discover();
                        self.send_frame(conn, &discover, &mut send_buf).await?;
                    } else if dhcp.state() == DhcpState::RequestSent {
                        warn!("DHCP timeout, retrying REQUEST");
                        if let Some(request) = dhcp.build_request() {
                            self.send_frame(conn, &request, &mut send_buf).await?;
                        }
                    }
                }
            }
        }
    }

    /// Check if an Ethernet frame is a DHCP response (UDP dst port 68).
    pub(super) fn is_dhcp_response(&self, frame: &[u8]) -> bool {
        // Ethernet(14) + IP header(20 min) + UDP header(8)
        if frame.len() < 42 {
            return false;
        }

        // Check EtherType is IPv4
        if frame[12] != 0x08 || frame[13] != 0x00 {
            return false;
        }

        // Check IP protocol is UDP (17)
        if frame[23] != 17 {
            return false;
        }

        // Check UDP destination port is 68 (DHCP client)
        let dst_port = u16::from_be_bytes([frame[36], frame[37]]);
        dst_port == 68
    }

    /// Send an Ethernet frame through the tunnel.
    pub(super) async fn send_frame(
        &self,
        conn: &mut VpnConnection,
        frame: &[u8],
        buf: &mut [u8],
    ) -> Result<()> {
        // Compress if enabled
        let data_to_send: std::borrow::Cow<[u8]> = if self.config.use_compress {
            match compress(frame) {
                Ok(compressed) => {
                    debug!("Compressed {} -> {} bytes", frame.len(), compressed.len());
                    std::borrow::Cow::Owned(compressed)
                }
                Err(e) => {
                    warn!("Compression failed, sending uncompressed: {}", e);
                    std::borrow::Cow::Borrowed(frame)
                }
            }
        } else {
            std::borrow::Cow::Borrowed(frame)
        };

        // Encode as tunnel packet: [num_blocks=1][size][data]
        let total_len = 4 + 4 + data_to_send.len();
        if buf.len() < total_len {
            return Err(Error::Protocol("Send buffer too small".into()));
        }

        buf[0..4].copy_from_slice(&1u32.to_be_bytes());
        buf[4..8].copy_from_slice(&(data_to_send.len() as u32).to_be_bytes());
        buf[8..8 + data_to_send.len()].copy_from_slice(&data_to_send);

        conn.write_all(&buf[..total_len]).await?;
        Ok(())
    }

    /// Perform DHCP through the tunnel using ConnectionManager (multi-connection).
    pub(super) async fn perform_dhcp_multi(
        &self,
        conn_mgr: &mut ConnectionManager,
    ) -> Result<DhcpConfig> {
        let mut dhcp = DhcpClient::new(self.mac);
        // One codec per receive connection for stateful parsing
        let num_conns = conn_mgr.connection_count();
        let mut codecs: Vec<TunnelCodec> = (0..num_conns).map(|_| TunnelCodec::new()).collect();
        let mut buf = vec![0u8; 65536];
        let mut send_buf = vec![0u8; 2048];

        let deadline = Instant::now() + Duration::from_secs(self.config.dhcp_timeout);

        // Get all receive-capable connection indices
        let recv_conn_indices: Vec<usize> = conn_mgr
            .all_connections()
            .iter()
            .enumerate()
            .filter(|(_, c)| c.direction.can_recv())
            .map(|(i, _)| i)
            .collect();

        debug!(
            connections = recv_conn_indices.len(),
            "DHCP using receive connections"
        );

        // Note: DHCP happens before authentication and RC4 key exchange,
        // so no encryption is used for DHCP packets. The ConnectionManager
        // will have None for rc4_key_pair at this point.

        // Send DHCP DISCOVER
        let discover = dhcp.build_discover();
        debug!(bytes = discover.len(), "Sending DHCP DISCOVER");
        self.send_frame_multi(conn_mgr, &discover, &mut send_buf)
            .await?;

        let mut last_send = Instant::now();
        let mut poll_idx = 0;

        // Use longer timeout per read - we want to actually wait for data
        // With 1 connection, we can afford to wait longer
        let per_conn_timeout_ms = if recv_conn_indices.len() <= 1 {
            100
        } else {
            std::cmp::max(10, 100 / recv_conn_indices.len() as u64)
        };

        // Wait for OFFER/ACK
        loop {
            if Instant::now() > deadline {
                return Err(Error::TimeoutMessage(
                    "DHCP timeout - no response received".into(),
                ));
            }

            // Retry DHCP if no response for 1 second (server may be slow)
            if last_send.elapsed() > Duration::from_millis(1000) {
                if dhcp.state() == DhcpState::DiscoverSent {
                    warn!("DHCP timeout, retrying DISCOVER");
                    let discover = dhcp.build_discover();
                    self.send_frame_multi(conn_mgr, &discover, &mut send_buf)
                        .await?;
                } else if dhcp.state() == DhcpState::RequestSent {
                    warn!("DHCP timeout, retrying REQUEST");
                    if let Some(request) = dhcp.build_request() {
                        self.send_frame_multi(conn_mgr, &request, &mut send_buf)
                            .await?;
                    }
                }
                last_send = Instant::now();
            }

            if recv_conn_indices.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }

            // Poll each connection with very short timeout
            for _ in 0..recv_conn_indices.len() {
                let conn_idx = recv_conn_indices[poll_idx % recv_conn_indices.len()];
                poll_idx += 1;

                let recv_conn = match conn_mgr.get_mut(conn_idx) {
                    Some(c) => c,
                    None => continue,
                };

                match timeout(
                    Duration::from_millis(per_conn_timeout_ms),
                    recv_conn.conn.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(n)) if n > 0 => {
                        recv_conn.touch();
                        debug!(conn = conn_idx, bytes = n, "Received data on connection");

                        // Use per-connection codec for proper frame parsing
                        let codec = &mut codecs[conn_idx];
                        let frames = match codec.feed(&buf[..n]) {
                            Ok(f) => f,
                            Err(e) => {
                                warn!("Codec error on conn {}: {}", conn_idx, e);
                                continue;
                            }
                        };

                        for frame in frames {
                            if frame.is_keepalive() {
                                debug!("Received keepalive frame");
                                continue;
                            }
                            if let Some(packets) = frame.packets() {
                                for packet in packets {
                                    let packet_data: Vec<u8> = if is_compressed(packet) {
                                        match decompress(packet) {
                                            Ok(d) => d,
                                            Err(_) => continue,
                                        }
                                    } else {
                                        packet.to_vec()
                                    };

                                    if self.is_dhcp_response(&packet_data) {
                                        debug!("DHCP response received on conn {}", conn_idx);
                                        if dhcp.process_response(&packet_data) {
                                            return Ok(dhcp.config().clone());
                                        } else if dhcp.state() == DhcpState::DiscoverSent {
                                            if let Some(request) = dhcp.build_request() {
                                                debug!("Sending DHCP REQUEST");
                                                self.send_frame_multi(
                                                    conn_mgr,
                                                    &request,
                                                    &mut send_buf,
                                                )
                                                .await?;
                                                last_send = Instant::now();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(Ok(_)) => {
                        // Zero bytes = connection closed
                        warn!(conn = conn_idx, "Connection closed during DHCP");
                    }
                    Ok(Err(e)) => {
                        warn!(conn = conn_idx, error = %e, "Read error during DHCP");
                    }
                    Err(_) => {
                        // Timeout - normal, continue to next connection
                    }
                }
            }
        }
    }

    /// Send an Ethernet frame using ConnectionManager (multi-connection).
    pub(super) async fn send_frame_multi(
        &self,
        conn_mgr: &mut ConnectionManager,
        frame: &[u8],
        buf: &mut [u8],
    ) -> Result<()> {
        // Compress if enabled
        let data_to_send: std::borrow::Cow<[u8]> = if self.config.use_compress {
            match compress(frame) {
                Ok(compressed) => {
                    debug!("Compressed {} -> {} bytes", frame.len(), compressed.len());
                    std::borrow::Cow::Owned(compressed)
                }
                Err(e) => {
                    warn!("Compression failed, sending uncompressed: {}", e);
                    std::borrow::Cow::Borrowed(frame)
                }
            }
        } else {
            std::borrow::Cow::Borrowed(frame)
        };

        // Encode as tunnel packet
        let total_len = 4 + 4 + data_to_send.len();
        if buf.len() < total_len {
            return Err(Error::Protocol("Send buffer too small".into()));
        }

        buf[0..4].copy_from_slice(&1u32.to_be_bytes());
        buf[4..8].copy_from_slice(&(data_to_send.len() as u32).to_be_bytes());
        buf[8..8 + data_to_send.len()].copy_from_slice(&data_to_send);

        // Write through connection manager (handles send connection selection)
        conn_mgr.write_all(&buf[..total_len]).await?;
        Ok(())
    }
}
