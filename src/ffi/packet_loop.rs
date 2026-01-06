//! Packet processing helpers for FFI client.
//!
//! This module extracts packet handling logic from the main client to reduce
//! function complexity and improve code organization.
//!
//! These helpers are prepared for future refactoring when the main client
//! run_packet_loop function is further modularized.

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use super::callbacks::SoftEtherCallbacks;
use crate::packet::ArpHandler;
use crate::protocol::{decompress, is_compressed};

/// Process an ARP packet and learn gateway MAC if applicable.
/// Returns true if gateway MAC was just learned.
pub fn process_arp_for_learning(
    frame: &[u8],
    arp: &mut ArpHandler,
    callbacks: &SoftEtherCallbacks,
    source: &str,
) -> bool {
    if frame.len() < 14 {
        return false;
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0806 {
        return false;
    }

    let had_mac = arp.has_gateway_mac();
    arp.process_arp(frame);

    if !had_mac {
        if let Some(gw_mac) = arp.gateway_mac() {
            callbacks.log_info(&format!(
                "[RUST] Learned gateway MAC ({}): {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                source, gw_mac[0], gw_mac[1], gw_mac[2], gw_mac[3], gw_mac[4], gw_mac[5]
            ));
            return true;
        }
    }
    false
}

/// Modify outbound frames: set destination MAC to gateway and optionally apply QoS sorting.
pub fn prepare_outbound_frames(
    frames: Vec<Vec<u8>>,
    gateway_mac: &[u8; 6],
    qos_enabled: bool,
) -> Vec<Vec<u8>> {
    use crate::packet::is_priority_packet;

    // Rewrite destination MAC to gateway
    let mut modified: Vec<Vec<u8>> = frames
        .into_iter()
        .map(|mut frame| {
            if frame.len() >= 14 {
                frame[0..6].copy_from_slice(gateway_mac);
            }
            frame
        })
        .collect();

    // QoS: Sort priority packets to front if enabled
    if qos_enabled && modified.len() > 1 {
        modified.sort_by(|a, b| {
            let a_prio = is_priority_packet(a);
            let b_prio = is_priority_packet(b);
            b_prio.cmp(&a_prio)
        });
    }

    modified
}

/// Process a received frame: decompress if needed and check for ARP.
/// Returns the decompressed frame data.
pub fn process_received_frame(
    frame: &[u8],
    arp: &mut ArpHandler,
    callbacks: &SoftEtherCallbacks,
) -> Vec<u8> {
    // Decompress if needed
    let frame_data: Vec<u8> = if is_compressed(frame) {
        decompress(frame).unwrap_or_else(|_| frame.to_vec())
    } else {
        frame.to_vec()
    };

    // Process ARP for gateway MAC learning
    process_arp_for_learning(&frame_data, arp, callbacks, "TCP");

    frame_data
}

/// Build a length-prefixed buffer for delivering packets to mobile app.
pub fn build_callback_buffer(frames: &[Vec<u8>]) -> Vec<u8> {
    let total_size: usize = frames.iter().map(|f| 2 + f.len()).sum();
    let mut buffer = Vec::with_capacity(total_size);

    for frame in frames {
        let len = frame.len() as u16;
        buffer.extend_from_slice(&len.to_be_bytes());
        buffer.extend_from_slice(frame);
    }

    buffer
}

/// Update packet statistics atomically.
pub fn update_stats(
    packets_counter: &AtomicU64,
    bytes_counter: &AtomicU64,
    packet_count: u64,
    byte_count: u64,
) {
    packets_counter.fetch_add(packet_count, Ordering::Relaxed);
    bytes_counter.fetch_add(byte_count, Ordering::Relaxed);
}

/// Parse length-prefixed packets from a buffer.
pub fn parse_length_prefixed_packets(data: &[u8]) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    let mut offset = 0;

    while offset + 2 <= data.len() {
        let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + len <= data.len() {
            result.push(data[offset..offset + len].to_vec());
            offset += len;
        } else {
            break;
        }
    }

    result
}
