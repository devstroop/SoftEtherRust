use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::utils::pad_eth_min;

#[derive(Default)]
pub(crate) struct ArpManager {
    pub table: HashMap<Ipv4Addr, [u8; 6]>,
    pub pending: HashMap<Ipv4Addr, VecDeque<Vec<u8>>>,
}

impl ArpManager {
    pub fn learn(&mut self, ip: Ipv4Addr, mac: [u8; 6]) {
        self.table.insert(ip, mac);
    }
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<[u8; 6]> {
        self.table.get(&ip).cloned()
    }
    // Inspect frame, learn ARP replies; return flush batch if any
    pub fn on_frame(
        &mut self,
        frame: &[u8],
    ) -> (
        Option<Ipv4Addr>,
        Option<[u8; 6]>,
        Option<(Ipv4Addr, [u8; 6], Vec<Vec<u8>>)>,
    ) {
        if frame.len() >= 14 + 28 {
            let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            if ethertype == 0x0806 {
                // ARP
                let off = 14;
                if frame[off + 0] == 0x00
                    && frame[off + 1] == 0x01
                    && frame[off + 2] == 0x08
                    && frame[off + 3] == 0x00
                    && frame[off + 4] == 0x06
                    && frame[off + 5] == 0x04
                {
                    // op at off+6..off+8 (we don't check)
                    let sha = [
                        frame[off + 8],
                        frame[off + 9],
                        frame[off + 10],
                        frame[off + 11],
                        frame[off + 12],
                        frame[off + 13],
                    ];
                    let spa = Ipv4Addr::new(
                        frame[off + 14],
                        frame[off + 15],
                        frame[off + 16],
                        frame[off + 17],
                    );
                    self.learn(spa, sha);
                    if let Some(mut q) = self.pending.remove(&spa) {
                        let mac = sha;
                        let mut batch = Vec::with_capacity(q.len());
                        while let Some(pkt) = q.pop_front() {
                            batch.push(pkt);
                        }
                        return (Some(spa), Some(mac), Some((spa, mac, batch)));
                    }
                    return (Some(spa), Some(sha), None);
                }
            }
        }
        (None, None, None)
    }
    // Queue IP packet for next-hop; returns Some(new_len) if enqueued, or None if dropped
    // Caller can treat new_len == 1 as "pending started" for this next-hop.
    pub fn enqueue(&mut self, next_hop: Ipv4Addr, ip: Vec<u8>) -> Option<usize> {
        let q = self
            .pending
            .entry(next_hop)
            .or_insert_with(|| VecDeque::with_capacity(16));
        if q.len() >= 16 {
            // bounded
            return None;
        }
        q.push_back(ip);
        Some(q.len())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ProbeState {
    pub last: Instant,
    pub interval: Duration,
}

pub(crate) fn build_arp_request(src_mac: [u8; 6], src_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut arp = Vec::with_capacity(14 + 28);
    // Ethernet broadcast
    arp.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    arp.extend_from_slice(&src_mac);
    arp.extend_from_slice(&0x0806u16.to_be_bytes());
    // ARP header
    arp.extend_from_slice(&0x0001u16.to_be_bytes()); // htype Ethernet
    arp.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype IPv4
    arp.push(6); // hlen
    arp.push(4); // plen
    arp.extend_from_slice(&0x0001u16.to_be_bytes()); // oper request
                                                      // sha, spa, tha, tpa
    arp.extend_from_slice(&src_mac);
    arp.extend_from_slice(&src_ip.octets());
    arp.extend_from_slice(&[0u8; 6]);
    arp.extend_from_slice(&target_ip.octets());
    pad_eth_min(arp)
}
