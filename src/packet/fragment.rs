//! IPv4 packet fragmentation and reassembly.
//!
//! This module handles IP packet fragmentation when packets exceed the MTU.
//! Fragmentation is required when:
//! - An IP packet from the TUN device is larger than the tunnel MTU
//! - The Don't Fragment (DF) flag is NOT set
//!
//! ## IPv4 Header Layout (relevant fields for fragmentation)
//! ```text
//! Offset  Field
//! 0       Version (4 bits) + IHL (4 bits)
//! 2-3     Total Length (16 bits)
//! 4-5     Identification (16 bits)
//! 6-7     Flags (3 bits) + Fragment Offset (13 bits)
//! 8       TTL
//! 9       Protocol
//! 10-11   Header Checksum
//! 12-15   Source Address
//! 16-19   Destination Address
//! 20+     Options (if IHL > 5)
//! ```
//!
//! Fragment Offset field:
//! - Bits 0-2: Flags
//!   - Bit 0: Reserved (must be 0)
//!   - Bit 1: Don't Fragment (DF)
//!   - Bit 2: More Fragments (MF)
//! - Bits 3-15: Fragment Offset (in 8-byte units)

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

/// Default MTU for IP fragmentation (typical tunnel MTU minus overhead)
pub const DEFAULT_FRAGMENT_MTU: usize = 1400;

/// Minimum MTU per RFC 791
pub const MIN_MTU: usize = 576;

/// Maximum fragment offset value (13 bits = 8191, in 8-byte units = 65528)
pub const MAX_FRAGMENT_OFFSET: usize = 8191 * 8;

/// IPv4 header Don't Fragment flag
const IP_FLAG_DF: u16 = 0x4000;

/// IPv4 header More Fragments flag  
const IP_FLAG_MF: u16 = 0x2000;

/// Fragment offset mask (13 bits)
const FRAGMENT_OFFSET_MASK: u16 = 0x1FFF;

/// Global identification counter for fragmented packets
static FRAGMENT_ID: AtomicU16 = AtomicU16::new(0);

/// Get next fragment identification number
fn next_fragment_id() -> u16 {
    FRAGMENT_ID.fetch_add(1, Ordering::SeqCst)
}

/// Calculate IPv4 header checksum
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum all 16-bit words (skip checksum field at offset 10-11)
    for i in (0..header.len()).step_by(2) {
        if i == 10 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum += word as u32;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return one's complement
    !(sum as u16)
}

/// Result of attempting to fragment a packet
#[derive(Debug)]
pub enum FragmentResult {
    /// Packet fits within MTU, no fragmentation needed
    NoFragmentationNeeded,
    /// Packet was fragmented into multiple parts
    Fragmented(Vec<Vec<u8>>),
    /// Packet cannot be fragmented (DF flag set) and exceeds MTU
    DontFragment,
    /// Invalid packet (too small, bad header, etc.)
    InvalidPacket,
}

/// Fragment an IPv4 packet if it exceeds the given MTU.
///
/// # Arguments
/// * `ip_packet` - The complete IPv4 packet (header + payload)
/// * `mtu` - Maximum transmission unit (must be at least MIN_MTU)
///
/// # Returns
/// * `FragmentResult` indicating the outcome
pub fn fragment_ipv4_packet(ip_packet: &[u8], mtu: usize) -> FragmentResult {
    // Validate MTU
    let mtu = mtu.max(MIN_MTU);

    // Need at least 20 bytes for minimal IPv4 header
    if ip_packet.len() < 20 {
        return FragmentResult::InvalidPacket;
    }

    // Check IP version
    let version = (ip_packet[0] >> 4) & 0x0F;
    if version != 4 {
        return FragmentResult::InvalidPacket;
    }

    // Get header length (IHL field * 4)
    let ihl = (ip_packet[0] & 0x0F) as usize;
    let header_len = ihl * 4;

    if header_len < 20 || header_len > ip_packet.len() {
        return FragmentResult::InvalidPacket;
    }

    // Get total length from header
    let total_len = u16::from_be_bytes([ip_packet[2], ip_packet[3]]) as usize;

    // Validate total length
    if total_len < header_len || total_len > ip_packet.len() {
        return FragmentResult::InvalidPacket;
    }

    // No fragmentation needed if packet fits
    if total_len <= mtu {
        return FragmentResult::NoFragmentationNeeded;
    }

    // Check Don't Fragment flag
    let flags_and_offset = u16::from_be_bytes([ip_packet[6], ip_packet[7]]);
    if flags_and_offset & IP_FLAG_DF != 0 {
        return FragmentResult::DontFragment;
    }

    // Check if already a fragment (MF set or offset > 0)
    let original_offset = (flags_and_offset & FRAGMENT_OFFSET_MASK) as usize * 8;
    let original_mf = flags_and_offset & IP_FLAG_MF != 0;

    // Calculate payload info
    let payload = &ip_packet[header_len..total_len];
    let payload_len = payload.len();

    // Maximum payload per fragment (must be multiple of 8 bytes)
    let max_payload = ((mtu - header_len) / 8) * 8;

    if max_payload == 0 {
        return FragmentResult::InvalidPacket;
    }

    // Generate or use existing identification
    let identification = if ip_packet[4] == 0 && ip_packet[5] == 0 {
        next_fragment_id()
    } else {
        u16::from_be_bytes([ip_packet[4], ip_packet[5]])
    };

    let mut fragments = Vec::new();
    let mut offset = 0;

    while offset < payload_len {
        let fragment_payload_len = if offset + max_payload < payload_len {
            max_payload
        } else {
            payload_len - offset
        };

        let is_last_fragment = offset + fragment_payload_len >= payload_len;

        // Create fragment
        let fragment_total_len = header_len + fragment_payload_len;
        let mut fragment = Vec::with_capacity(fragment_total_len);

        // Copy header
        fragment.extend_from_slice(&ip_packet[..header_len]);

        // Update total length
        fragment[2] = (fragment_total_len >> 8) as u8;
        fragment[3] = fragment_total_len as u8;

        // Update identification
        fragment[4] = (identification >> 8) as u8;
        fragment[5] = identification as u8;

        // Calculate new fragment offset (in 8-byte units)
        let new_offset = original_offset + offset;
        let fragment_offset_units = (new_offset / 8) as u16;

        // Set flags and offset
        let mut new_flags_and_offset = fragment_offset_units;

        // Set MF flag if not last fragment OR if original had MF set and this is last
        if !is_last_fragment || (original_mf && offset > 0) {
            new_flags_and_offset |= IP_FLAG_MF;
        } else if original_mf && is_last_fragment && offset == 0 {
            // Original had more fragments, but we're the last of this fragmentation
            // Keep MF if there were more original fragments
            new_flags_and_offset |= IP_FLAG_MF;
        }
        // For the very last fragment of a complete packet, MF should be 0
        if is_last_fragment && !original_mf {
            new_flags_and_offset &= !IP_FLAG_MF;
        }

        fragment[6] = (new_flags_and_offset >> 8) as u8;
        fragment[7] = new_flags_and_offset as u8;

        // Clear checksum before recalculating
        fragment[10] = 0;
        fragment[11] = 0;

        // Calculate new checksum
        let checksum = ipv4_checksum(&fragment[..header_len]);
        fragment[10] = (checksum >> 8) as u8;
        fragment[11] = checksum as u8;

        // Append payload
        fragment.extend_from_slice(&payload[offset..offset + fragment_payload_len]);

        fragments.push(fragment);
        offset += fragment_payload_len;
    }

    FragmentResult::Fragmented(fragments)
}

/// Key for identifying fragmented packet streams
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FragmentKey {
    /// Source IP address
    pub src_ip: Ipv4Addr,
    /// Destination IP address  
    pub dst_ip: Ipv4Addr,
    /// Protocol
    pub protocol: u8,
    /// Identification
    pub identification: u16,
}

impl FragmentKey {
    /// Create a fragment key from an IPv4 packet
    pub fn from_packet(ip_packet: &[u8]) -> Option<Self> {
        if ip_packet.len() < 20 {
            return None;
        }

        let version = (ip_packet[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        Some(Self {
            src_ip: Ipv4Addr::new(ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]),
            dst_ip: Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]),
            protocol: ip_packet[9],
            identification: u16::from_be_bytes([ip_packet[4], ip_packet[5]]),
        })
    }
}

/// A single fragment entry
#[derive(Debug)]
struct FragmentEntry {
    /// The fragment data (payload only)
    data: Vec<u8>,
    /// Fragment offset in bytes
    offset: usize,
    /// Whether this is the last fragment
    #[allow(dead_code)]
    is_last: bool,
}

/// Fragment reassembly state
#[derive(Debug)]
struct ReassemblyState {
    /// Original IPv4 header (from first fragment, offset 0)
    header: Option<Vec<u8>>,
    /// Collected fragments
    fragments: Vec<FragmentEntry>,
    /// Total expected size (known when last fragment received)
    total_size: Option<usize>,
    /// Time when first fragment was received
    first_seen: Instant,
}

impl ReassemblyState {
    fn new() -> Self {
        Self {
            header: None,
            fragments: Vec::new(),
            total_size: None,
            first_seen: Instant::now(),
        }
    }

    /// Add a fragment to the reassembly state
    fn add_fragment(&mut self, ip_packet: &[u8]) -> bool {
        if ip_packet.len() < 20 {
            return false;
        }

        let ihl = (ip_packet[0] & 0x0F) as usize;
        let header_len = ihl * 4;

        if header_len < 20 || header_len > ip_packet.len() {
            return false;
        }

        let total_len = u16::from_be_bytes([ip_packet[2], ip_packet[3]]) as usize;
        if total_len > ip_packet.len() {
            return false;
        }

        let flags_and_offset = u16::from_be_bytes([ip_packet[6], ip_packet[7]]);
        let offset = (flags_and_offset & FRAGMENT_OFFSET_MASK) as usize * 8;
        let more_fragments = flags_and_offset & IP_FLAG_MF != 0;

        // Store header from first fragment
        if offset == 0 && self.header.is_none() {
            self.header = Some(ip_packet[..header_len].to_vec());
        }

        let payload = &ip_packet[header_len..total_len];

        // If this is the last fragment, we know the total size
        if !more_fragments {
            self.total_size = Some(offset + payload.len());
        }

        // Check for duplicate
        for existing in &self.fragments {
            if existing.offset == offset {
                return true; // Duplicate, already have it
            }
        }

        self.fragments.push(FragmentEntry {
            data: payload.to_vec(),
            offset,
            is_last: !more_fragments,
        });

        true
    }

    /// Check if reassembly is complete
    fn is_complete(&self) -> bool {
        let total_size = match self.total_size {
            Some(s) => s,
            None => return false, // Haven't received last fragment
        };

        if self.header.is_none() {
            return false; // Haven't received first fragment
        }

        // Check that we have all bytes covered
        let mut covered = vec![false; total_size];

        for fragment in &self.fragments {
            let end = fragment.offset + fragment.data.len();
            if end > total_size {
                return false; // Invalid fragment
            }
            for item in covered.iter_mut().take(end).skip(fragment.offset) {
                *item = true;
            }
        }

        covered.iter().all(|&b| b)
    }

    /// Reassemble the packet
    fn reassemble(&self) -> Option<Vec<u8>> {
        let header = self.header.as_ref()?;
        let total_size = self.total_size?;

        let mut payload = vec![0u8; total_size];

        for fragment in &self.fragments {
            let end = fragment.offset + fragment.data.len();
            if end > total_size {
                return None;
            }
            payload[fragment.offset..end].copy_from_slice(&fragment.data);
        }

        // Build complete packet
        let total_len = header.len() + total_size;
        let mut packet = Vec::with_capacity(total_len);
        packet.extend_from_slice(header);

        // Update total length in header
        packet[2] = (total_len >> 8) as u8;
        packet[3] = total_len as u8;

        // Clear fragmentation fields
        packet[6] = 0;
        packet[7] = 0;

        // Recalculate checksum
        packet[10] = 0;
        packet[11] = 0;
        let checksum = ipv4_checksum(&packet[..header.len()]);
        packet[10] = (checksum >> 8) as u8;
        packet[11] = checksum as u8;

        packet.extend_from_slice(&payload);

        Some(packet)
    }
}

/// Fragment reassembly handler
pub struct FragmentReassembler {
    /// Active reassembly states, keyed by fragment key
    states: HashMap<FragmentKey, ReassemblyState>,
    /// Timeout for incomplete reassembly (RFC 791 recommends 15 seconds minimum)
    timeout: Duration,
    /// Maximum number of active reassembly states
    max_states: usize,
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl FragmentReassembler {
    /// Create a new fragment reassembler
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            timeout: Duration::from_secs(30),
            max_states: 256,
        }
    }

    /// Create with custom settings
    pub fn with_settings(timeout_secs: u64, max_states: usize) -> Self {
        Self {
            states: HashMap::new(),
            timeout: Duration::from_secs(timeout_secs),
            max_states,
        }
    }

    /// Process an incoming IPv4 packet
    ///
    /// # Returns
    /// * `Some(packet)` - Complete reassembled packet
    /// * `None` - Fragment stored, waiting for more, or not a fragment
    pub fn process(&mut self, ip_packet: &[u8]) -> Option<Vec<u8>> {
        if ip_packet.len() < 20 {
            return None;
        }

        // Check if this is a fragment
        let flags_and_offset = u16::from_be_bytes([ip_packet[6], ip_packet[7]]);
        let offset = flags_and_offset & FRAGMENT_OFFSET_MASK;
        let more_fragments = flags_and_offset & IP_FLAG_MF != 0;

        // Not a fragment if offset is 0 and MF is not set
        if offset == 0 && !more_fragments {
            return None;
        }

        // Clean up expired states
        self.cleanup();

        let key = FragmentKey::from_packet(ip_packet)?;

        // Get or create reassembly state
        let state = self
            .states
            .entry(key.clone())
            .or_insert_with(ReassemblyState::new);

        // Add this fragment
        if !state.add_fragment(ip_packet) {
            return None;
        }

        // Check if complete
        if state.is_complete() {
            let reassembled = state.reassemble();
            self.states.remove(&key);
            return reassembled;
        }

        None
    }

    /// Clean up expired reassembly states
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.states
            .retain(|_, state| now.duration_since(state.first_seen) < self.timeout);

        // If still over limit, remove oldest
        while self.states.len() > self.max_states {
            if let Some(oldest_key) = self
                .states
                .iter()
                .min_by_key(|(_, s)| s.first_seen)
                .map(|(k, _)| k.clone())
            {
                self.states.remove(&oldest_key);
            } else {
                break;
            }
        }
    }

    /// Get number of active reassembly states
    pub fn active_count(&self) -> usize {
        self.states.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_ipv4_packet(payload_size: usize, df_flag: bool) -> Vec<u8> {
        let total_len = 20 + payload_size;
        let mut packet = vec![0u8; total_len];

        // Version (4) + IHL (5)
        packet[0] = 0x45;

        // Total length
        packet[2] = (total_len >> 8) as u8;
        packet[3] = total_len as u8;

        // ID
        packet[4] = 0x12;
        packet[5] = 0x34;

        // Flags and fragment offset
        if df_flag {
            packet[6] = 0x40; // DF flag set
        }

        // TTL
        packet[8] = 64;

        // Protocol (TCP)
        packet[9] = 6;

        // Source IP: 192.168.1.100
        packet[12] = 192;
        packet[13] = 168;
        packet[14] = 1;
        packet[15] = 100;

        // Dest IP: 192.168.1.1
        packet[16] = 192;
        packet[17] = 168;
        packet[18] = 1;
        packet[19] = 1;

        // Calculate checksum
        let checksum = ipv4_checksum(&packet[..20]);
        packet[10] = (checksum >> 8) as u8;
        packet[11] = checksum as u8;

        // Fill payload with pattern
        for i in 0..payload_size {
            packet[20 + i] = (i & 0xFF) as u8;
        }

        packet
    }

    #[test]
    fn test_no_fragmentation_needed() {
        let packet = create_ipv4_packet(100, false);

        match fragment_ipv4_packet(&packet, 1400) {
            FragmentResult::NoFragmentationNeeded => {}
            _ => panic!("Expected NoFragmentationNeeded"),
        }
    }

    #[test]
    fn test_dont_fragment() {
        let packet = create_ipv4_packet(2000, true);

        match fragment_ipv4_packet(&packet, 1400) {
            FragmentResult::DontFragment => {}
            _ => panic!("Expected DontFragment"),
        }
    }

    #[test]
    fn test_fragmentation() {
        // Create a 2000 byte payload packet
        let packet = create_ipv4_packet(2000, false);

        match fragment_ipv4_packet(&packet, 576) {
            FragmentResult::Fragmented(fragments) => {
                assert!(fragments.len() > 1, "Should have multiple fragments");

                // Verify all fragments have valid headers
                for (i, frag) in fragments.iter().enumerate() {
                    assert!(frag.len() >= 20, "Fragment {} too small", i);

                    // Check version
                    let version = (frag[0] >> 4) & 0x0F;
                    assert_eq!(version, 4, "Fragment {} has wrong IP version", i);

                    // Verify total length matches actual size
                    let total_len = u16::from_be_bytes([frag[2], frag[3]]) as usize;
                    assert_eq!(
                        total_len,
                        frag.len(),
                        "Fragment {} total length mismatch",
                        i
                    );

                    // Verify each fragment fits within MTU
                    assert!(frag.len() <= 576, "Fragment {} exceeds MTU", i);
                }

                // Last fragment should not have MF flag
                let last = fragments.last().unwrap();
                let flags = u16::from_be_bytes([last[6], last[7]]);
                assert_eq!(
                    flags & IP_FLAG_MF,
                    0,
                    "Last fragment should not have MF flag"
                );

                // Other fragments should have MF flag
                for frag in fragments.iter().take(fragments.len() - 1) {
                    let flags = u16::from_be_bytes([frag[6], frag[7]]);
                    assert_ne!(
                        flags & IP_FLAG_MF,
                        0,
                        "Non-last fragment should have MF flag"
                    );
                }
            }
            _ => panic!("Expected Fragmented"),
        }
    }

    #[test]
    fn test_reassembly() {
        // Create a large packet
        let original = create_ipv4_packet(2000, false);

        // Fragment it
        let fragments = match fragment_ipv4_packet(&original, 576) {
            FragmentResult::Fragmented(f) => f,
            _ => panic!("Expected Fragmented"),
        };

        // Reassemble
        let mut reassembler = FragmentReassembler::new();

        let mut result = None;
        for frag in fragments {
            if let Some(packet) = reassembler.process(&frag) {
                result = Some(packet);
                break;
            }
        }

        let reassembled = result.expect("Reassembly should complete");

        // Verify payload matches original
        assert_eq!(&reassembled[20..], &original[20..], "Payload should match");
    }

    #[test]
    fn test_checksum() {
        let packet = create_ipv4_packet(100, false);

        // Verify checksum
        let stored_checksum = u16::from_be_bytes([packet[10], packet[11]]);

        // Calculate checksum over header with checksum field set to stored value
        // This should give 0 if the checksum is correct
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            let word = u16::from_be_bytes([packet[i], packet[i + 1]]);
            sum += word as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        assert_eq!(sum as u16, 0xFFFF, "Checksum validation failed");
        assert_ne!(stored_checksum, 0, "Checksum should not be zero");
    }

    #[test]
    fn test_fragment_key() {
        let packet = create_ipv4_packet(100, false);

        let key = FragmentKey::from_packet(&packet).unwrap();

        assert_eq!(key.src_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(key.dst_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(key.protocol, 6); // TCP
        assert_eq!(key.identification, 0x1234);
    }
}
