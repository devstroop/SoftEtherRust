//! Shared packet processing logic for data loop.
//!
//! This module extracts the common packet processing code that is shared between
//! Unix (macOS/Linux) and Windows data loops, eliminating ~200 lines of duplication.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use tracing::{debug, error, warn};

use crate::client::VpnConnection;
use crate::crypto::TunnelEncryption;
use crate::error::Result;
use crate::packet::ArpHandler;
use crate::protocol::TunnelCodec;

/// Build an ethernet frame header in the send buffer (uncompressed path).
///
/// Layout: [4: num_blocks=1][4: block_size][6: dst_mac][6: src_mac][2: ethertype][IP packet]
///
/// Returns the total frame length (8-byte tunnel header + 14-byte eth header + IP packet),
/// or None if packet is too large or invalid IP version.
#[inline]
pub fn build_ethernet_frame(
    send_buf: &mut [u8],
    ip_packet: &[u8],
    gateway_mac: &[u8; 6],
    my_mac: &[u8; 6],
) -> Option<usize> {
    let eth_len = 14 + ip_packet.len();
    let total_len = 8 + eth_len;

    if total_len > send_buf.len() {
        warn!("Packet too large: {}", ip_packet.len());
        return None;
    }

    if ip_packet.is_empty() {
        return None;
    }

    let ip_version = (ip_packet[0] >> 4) & 0x0F;
    if ip_version != 4 && ip_version != 6 {
        return None;
    }

    // Tunnel header: num_blocks = 1, block_size = eth_len
    send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
    send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());

    // Ethernet header
    send_buf[8..14].copy_from_slice(gateway_mac);
    send_buf[14..20].copy_from_slice(my_mac);

    // EtherType
    if ip_version == 4 {
        send_buf[20] = 0x08;
        send_buf[21] = 0x00;
    } else {
        send_buf[20] = 0x86;
        send_buf[21] = 0xDD;
    }

    // IP packet
    send_buf[22..22 + ip_packet.len()].copy_from_slice(ip_packet);

    Some(total_len)
}

/// Build ethernet frame for compression path (frame at offset 8).
///
/// Returns (eth_len, ip_version) or None if invalid.
#[inline]
pub fn build_ethernet_frame_for_compress(
    send_buf: &mut [u8],
    ip_packet: &[u8],
    gateway_mac: &[u8; 6],
    my_mac: &[u8; 6],
) -> Option<(usize, u8)> {
    let eth_len = 14 + ip_packet.len();
    let total_len = 8 + eth_len;

    if total_len > send_buf.len() || ip_packet.is_empty() {
        return None;
    }

    let ip_version = (ip_packet[0] >> 4) & 0x0F;
    if ip_version != 4 && ip_version != 6 {
        return None;
    }

    let eth_start = 8;
    send_buf[eth_start..eth_start + 6].copy_from_slice(gateway_mac);
    send_buf[eth_start + 6..eth_start + 12].copy_from_slice(my_mac);
    if ip_version == 4 {
        send_buf[eth_start + 12] = 0x08;
        send_buf[eth_start + 13] = 0x00;
    } else {
        send_buf[eth_start + 12] = 0x86;
        send_buf[eth_start + 13] = 0xDD;
    }
    send_buf[eth_start + 14..eth_start + 14 + ip_packet.len()].copy_from_slice(ip_packet);

    Some((eth_len, ip_version))
}

/// Send keepalive packet if no recent activity.
pub async fn send_keepalive_if_needed(
    conn: &mut VpnConnection,
    last_activity: Instant,
    send_buf: &mut [u8],
    encryption: &mut Option<TunnelEncryption>,
) -> Result<()> {
    if last_activity.elapsed() > Duration::from_secs(3) {
        let keepalive = TunnelCodec::encode_keepalive_direct(32, send_buf);
        if let Some(ka) = keepalive {
            let ka_len = ka.len();
            if let Some(ref mut enc) = encryption {
                enc.encrypt(&mut send_buf[..ka_len]);
            }
            conn.write_all(&send_buf[..ka_len]).await?;
            debug!("Sent keepalive");
        }
    }
    Ok(())
}

/// Send periodic gratuitous ARP if needed.
pub async fn send_periodic_garp_if_needed(
    conn: &mut VpnConnection,
    arp: &mut ArpHandler,
    send_buf: &mut [u8],
    encryption: &mut Option<TunnelEncryption>,
) -> Result<()> {
    if arp.should_send_periodic_garp() {
        let garp = arp.build_gratuitous_arp();
        send_frame_encrypted(conn, &garp, send_buf, encryption).await?;
        arp.mark_garp_sent();
        debug!("Sent periodic GARP");
    }
    Ok(())
}

/// Send any pending ARP replies.
pub async fn send_pending_arp_reply(
    conn: &mut VpnConnection,
    arp: &mut ArpHandler,
    send_buf: &mut [u8],
    encryption: &mut Option<TunnelEncryption>,
) -> Result<()> {
    if let Some(reply) = arp.build_pending_reply() {
        if let Err(e) = send_frame_encrypted(conn, &reply, send_buf, encryption).await {
            error!("Failed to send ARP reply: {}", e);
        } else {
            debug!("Sent ARP reply");
        }
        arp.take_pending_reply();
    }
    Ok(())
}

/// Send an ethernet frame with optional encryption.
pub async fn send_frame_encrypted(
    conn: &mut VpnConnection,
    frame: &[u8],
    send_buf: &mut [u8],
    encryption: &mut Option<TunnelEncryption>,
) -> Result<()> {
    let total_len = 8 + frame.len();
    if total_len > send_buf.len() {
        return Ok(());
    }

    // Tunnel header
    send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
    send_buf[4..8].copy_from_slice(&(frame.len() as u32).to_be_bytes());
    send_buf[8..8 + frame.len()].copy_from_slice(frame);

    if let Some(ref mut enc) = encryption {
        enc.encrypt(&mut send_buf[..total_len]);
    }

    conn.write_all(&send_buf[..total_len]).await?;
    Ok(())
}

/// Initialize ARP and send initial ARP packets.
pub async fn init_arp(
    conn: &mut VpnConnection,
    arp: &mut ArpHandler,
    our_ip: Ipv4Addr,
    gateway: Ipv4Addr,
    send_buf: &mut [u8],
    encryption: &mut Option<TunnelEncryption>,
) -> Result<()> {
    arp.configure(our_ip, gateway);

    // Send gratuitous ARP to announce our presence
    let garp = arp.build_gratuitous_arp();
    send_frame_encrypted(conn, &garp, send_buf, encryption).await?;
    debug!("Sent gratuitous ARP");

    // Send ARP request for gateway
    let gateway_arp = arp.build_gateway_request();
    send_frame_encrypted(conn, &gateway_arp, send_buf, encryption).await?;
    debug!("Sent gateway ARP request");

    Ok(())
}
