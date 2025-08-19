// Utility helpers for FFI module

// no time-based RNG needed for fixed LAA MAC

pub(crate) fn fnv1a64(data: &[u8]) -> u64 {
    // Simple dependency-free 64-bit FNV-1a hash for deriving a MAC from a seed
    let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    for b in data {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x00000100000001B3);
    }
    hash
}

pub(crate) fn derive_laa_mac_from_seed(seed: &[u8]) -> [u8; 6] {
    let h = fnv1a64(seed);
    // Locally-administered, unicast: set bit1=1 (LAA), bit0=0 (unicast)
    let b0 = 0x02u8; // 0000_0010
    [
        b0,
        ((h >> 0) & 0xFF) as u8,
        ((h >> 8) & 0xFF) as u8,
        ((h >> 16) & 0xFF) as u8,
        ((h >> 24) & 0xFF) as u8,
        ((h >> 32) & 0xFF) as u8,
    ]
}

#[allow(dead_code)]
pub(crate) fn gen_laa_mac_default() -> [u8; 6] {
    // Fallback deterministic LAA derived from a constant string
    derive_laa_mac_from_seed(b"softether_rust_default")
}

#[inline]
pub(crate) fn mac_to_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[inline]
pub(crate) fn pad_eth_min(mut frame: Vec<u8>) -> Vec<u8> {
    if frame.len() < 60 {
        frame.resize(60, 0);
    }
    frame
}

/// Extract IPv4 payload from an Ethernet frame (EtherType 0x0800)
pub(crate) fn eth_to_ipv4(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    if ether_type != 0x0800 {
        return None;
    }
    Some(&frame[14..])
}
