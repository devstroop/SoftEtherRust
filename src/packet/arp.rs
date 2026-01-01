//! ARP handler for gateway MAC address discovery.
//!
//! ARP (Address Resolution Protocol) is used to discover the MAC address
//! of the gateway, which is needed for routing packets correctly.
//!
//! This implementation follows SoftEtherZig's pattern with:
//! - Pending reply queue for responding to ARP requests
//! - Need-based flags for gratuitous ARP and gateway requests  
//! - Timing state for periodic GARP

use bytes::{BufMut, Bytes, BytesMut};
use std::net::Ipv4Addr;
use std::time::Instant;
use tracing::{debug, info};

use super::ethernet::{BROADCAST_MAC, ZERO_MAC};

/// ARP operation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ArpOperation {
    Request = 1,
    Reply = 2,
}

impl TryFrom<u16> for ArpOperation {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Reply),
            _ => Err(()),
        }
    }
}

/// Pending ARP reply to send.
#[derive(Debug, Clone, Copy)]
pub struct PendingArpReply {
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

/// Gratuitous ARP interval (10 seconds).
const GARP_INTERVAL_MS: u64 = 10_000;

/// ARP handler for the virtual adapter.
#[derive(Debug)]
pub struct ArpHandler {
    /// Our MAC address.
    mac: [u8; 6],
    /// Our IP address (set after DHCP).
    my_ip: Ipv4Addr,
    /// Gateway IP address (set after DHCP).
    gateway_ip: Ipv4Addr,
    /// Discovered gateway MAC address.
    gateway_mac: Option<[u8; 6]>,

    // === State flags (like Zig) ===
    /// Pending ARP reply to send.
    pending_reply: Option<PendingArpReply>,
    /// Need to send gratuitous ARP.
    need_gratuitous_arp: bool,
    /// Need to send gateway ARP request.
    need_gateway_arp: bool,

    // === Timing ===
    /// Last gratuitous ARP send time.
    last_garp_time: Option<Instant>,
}

impl ArpHandler {
    /// Create a new ARP handler.
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            my_ip: Ipv4Addr::UNSPECIFIED,
            gateway_ip: Ipv4Addr::UNSPECIFIED,
            gateway_mac: None,
            pending_reply: None,
            need_gratuitous_arp: false,
            need_gateway_arp: false,
            last_garp_time: None,
        }
    }

    /// Configure with our IP and gateway IP (after DHCP).
    pub fn configure(&mut self, my_ip: Ipv4Addr, gateway_ip: Ipv4Addr) {
        self.my_ip = my_ip;
        self.gateway_ip = gateway_ip;
        self.gateway_mac = None; // Reset gateway MAC when reconfiguring

        // Queue required ARP operations (like Zig)
        self.need_gratuitous_arp = true;
        self.need_gateway_arp = true;

        debug!("ARP configured: my_ip={}, gateway_ip={}", my_ip, gateway_ip);
    }

    /// Get the discovered gateway MAC address.
    pub fn gateway_mac(&self) -> Option<&[u8; 6]> {
        self.gateway_mac.as_ref()
    }

    /// Check if gateway MAC has been discovered.
    pub fn has_gateway_mac(&self) -> bool {
        self.gateway_mac.is_some()
    }

    /// Get gateway MAC or return broadcast.
    pub fn gateway_mac_or_broadcast(&self) -> [u8; 6] {
        self.gateway_mac.unwrap_or(BROADCAST_MAC)
    }

    // === Need-based state (like Zig) ===

    /// Check if we need to send gratuitous ARP.
    pub fn needs_gratuitous_arp(&self) -> bool {
        self.need_gratuitous_arp
    }

    /// Check if we need to send gateway ARP request.
    pub fn needs_gateway_arp(&self) -> bool {
        self.need_gateway_arp
    }

    /// Check if we should send periodic gratuitous ARP.
    pub fn should_send_periodic_garp(&self) -> bool {
        if self.my_ip.is_unspecified() {
            return false;
        }
        match self.last_garp_time {
            Some(last) => last.elapsed().as_millis() as u64 >= GARP_INTERVAL_MS,
            None => true,
        }
    }

    /// Mark that gratuitous ARP was sent.
    pub fn mark_garp_sent(&mut self) {
        self.need_gratuitous_arp = false;
        self.last_garp_time = Some(Instant::now());
    }

    /// Mark that gateway ARP request was sent.
    pub fn mark_gateway_arp_sent(&mut self) {
        self.need_gateway_arp = false;
    }

    /// Get and clear pending ARP reply.
    pub fn take_pending_reply(&mut self) -> Option<PendingArpReply> {
        self.pending_reply.take()
    }

    /// Check if there's a pending ARP reply.
    pub fn has_pending_reply(&self) -> bool {
        self.pending_reply.is_some()
    }

    /// Build a gratuitous ARP packet (announces our presence).
    pub fn build_gratuitous_arp(&self) -> Bytes {
        self.build_arp(
            ArpOperation::Request,
            &self.mac,
            self.my_ip,
            &ZERO_MAC,
            self.my_ip, // Target = sender for gratuitous
        )
    }

    /// Build an ARP request for the gateway.
    pub fn build_gateway_request(&self) -> Bytes {
        self.build_arp(
            ArpOperation::Request,
            &self.mac,
            self.my_ip,
            &ZERO_MAC,
            self.gateway_ip,
        )
    }

    /// Build an ARP reply for a pending request.
    pub fn build_pending_reply(&self) -> Option<Bytes> {
        self.pending_reply.map(|reply| {
            self.build_arp(
                ArpOperation::Reply,
                &self.mac,
                self.my_ip,
                &reply.target_mac,
                reply.target_ip,
            )
        })
    }

    /// Process an incoming ARP packet.
    ///
    /// Returns an ARP reply if we need to respond to a request.
    /// Also queues pending reply for later retrieval.
    pub fn process_arp(&mut self, frame: &[u8]) -> Option<Bytes> {
        // Minimum ARP frame: Ethernet(14) + ARP(28)
        if frame.len() < 42 {
            return None;
        }

        // Check EtherType (ARP = 0x0806)
        if frame[12] != 0x08 || frame[13] != 0x06 {
            return None;
        }

        let arp_start = 14;

        // Hardware type (should be Ethernet = 1)
        let hw_type = u16::from_be_bytes([frame[arp_start], frame[arp_start + 1]]);
        if hw_type != 1 {
            return None;
        }

        // Protocol type (should be IPv4 = 0x0800)
        let proto_type = u16::from_be_bytes([frame[arp_start + 2], frame[arp_start + 3]]);
        if proto_type != 0x0800 {
            return None;
        }

        // Hardware/protocol address lengths
        if frame[arp_start + 4] != 6 || frame[arp_start + 5] != 4 {
            return None;
        }

        // Operation
        let operation = u16::from_be_bytes([frame[arp_start + 6], frame[arp_start + 7]]);

        // Sender MAC and IP
        let sender_mac: [u8; 6] = frame[arp_start + 8..arp_start + 14].try_into().unwrap();
        let sender_ip = Ipv4Addr::new(
            frame[arp_start + 14],
            frame[arp_start + 15],
            frame[arp_start + 16],
            frame[arp_start + 17],
        );

        // Target IP
        let target_ip = Ipv4Addr::new(
            frame[arp_start + 24],
            frame[arp_start + 25],
            frame[arp_start + 26],
            frame[arp_start + 27],
        );

        match ArpOperation::try_from(operation) {
            Ok(ArpOperation::Reply) => {
                // Learn gateway MAC from reply
                if sender_ip == self.gateway_ip {
                    self.gateway_mac = Some(sender_mac);
                    info!(
                        "Learned gateway MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        sender_mac[0],
                        sender_mac[1],
                        sender_mac[2],
                        sender_mac[3],
                        sender_mac[4],
                        sender_mac[5]
                    );
                }
                None
            }
            Ok(ArpOperation::Request) => {
                // Respond if it's asking for our IP
                if target_ip == self.my_ip && !self.my_ip.is_unspecified() {
                    debug!("Responding to ARP request from {}", sender_ip);

                    // Queue pending reply (like Zig)
                    self.pending_reply = Some(PendingArpReply {
                        target_mac: sender_mac,
                        target_ip: sender_ip,
                    });

                    // Also return immediate reply
                    Some(self.build_arp(
                        ArpOperation::Reply,
                        &self.mac,
                        self.my_ip,
                        &sender_mac,
                        sender_ip,
                    ))
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Process ARP reply - learn MAC if it's from gateway.
    /// Zero-copy version that doesn't build a reply.
    pub fn process_arp_reply(&mut self, eth_frame: &[u8]) {
        if eth_frame.len() < 42 {
            return;
        }

        // Check it's ARP
        if eth_frame[12] != 0x08 || eth_frame[13] != 0x06 {
            return;
        }

        // Check it's a reply (operation = 2)
        let operation = u16::from_be_bytes([eth_frame[20], eth_frame[21]]);
        if operation != 2 {
            return;
        }

        // Extract sender IP (bytes 28-31)
        let sender_ip = Ipv4Addr::new(eth_frame[28], eth_frame[29], eth_frame[30], eth_frame[31]);

        // If from gateway, learn its MAC
        if !self.gateway_ip.is_unspecified() && sender_ip == self.gateway_ip {
            let mut sender_mac = [0u8; 6];
            sender_mac.copy_from_slice(&eth_frame[22..28]);
            self.gateway_mac = Some(sender_mac);

            debug!(
                "Learned gateway MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                sender_mac[0],
                sender_mac[1],
                sender_mac[2],
                sender_mac[3],
                sender_mac[4],
                sender_mac[5]
            );
        }
    }

    /// Process ARP request - queue reply if asking for our IP.
    /// Zero-copy version.
    pub fn process_arp_request(&mut self, eth_frame: &[u8]) {
        if eth_frame.len() < 42 {
            return;
        }

        // Check it's ARP
        if eth_frame[12] != 0x08 || eth_frame[13] != 0x06 {
            return;
        }

        // Check it's a request (operation = 1)
        let operation = u16::from_be_bytes([eth_frame[20], eth_frame[21]]);
        if operation != 1 {
            return;
        }

        // Extract target IP (bytes 38-41)
        let target_ip = Ipv4Addr::new(eth_frame[38], eth_frame[39], eth_frame[40], eth_frame[41]);

        // If asking for our IP, queue reply
        if target_ip == self.my_ip && !self.my_ip.is_unspecified() {
            let mut sender_mac = [0u8; 6];
            sender_mac.copy_from_slice(&eth_frame[22..28]);

            let sender_ip =
                Ipv4Addr::new(eth_frame[28], eth_frame[29], eth_frame[30], eth_frame[31]);

            self.pending_reply = Some(PendingArpReply {
                target_mac: sender_mac,
                target_ip: sender_ip,
            });
        }
    }

    /// Build an ARP packet.
    fn build_arp(
        &self,
        operation: ArpOperation,
        sender_mac: &[u8; 6],
        sender_ip: Ipv4Addr,
        target_mac: &[u8; 6],
        target_ip: Ipv4Addr,
    ) -> Bytes {
        let mut packet = BytesMut::with_capacity(60);

        // Ethernet header
        if operation == ArpOperation::Request {
            packet.put_slice(&BROADCAST_MAC);
        } else {
            packet.put_slice(target_mac);
        }
        packet.put_slice(sender_mac);
        packet.put_u16(0x0806); // EtherType: ARP

        // ARP header
        packet.put_u16(0x0001); // Hardware type: Ethernet
        packet.put_u16(0x0800); // Protocol type: IPv4
        packet.put_u8(6); // Hardware address length
        packet.put_u8(4); // Protocol address length
        packet.put_u16(operation as u16);

        // Sender hardware address
        packet.put_slice(sender_mac);

        // Sender protocol address
        packet.put_slice(&sender_ip.octets());

        // Target hardware address
        packet.put_slice(target_mac);

        // Target protocol address
        packet.put_slice(&target_ip.octets());

        // Pad to minimum Ethernet frame size (60 bytes)
        while packet.len() < 60 {
            packet.put_u8(0x00);
        }

        packet.freeze()
    }

    /// Build an ARP packet into a pre-allocated buffer (zero-copy).
    ///
    /// Returns the slice of the buffer that was written.
    pub fn build_arp_into<'a>(
        &self,
        operation: ArpOperation,
        target_mac: &[u8; 6],
        target_ip: Ipv4Addr,
        buffer: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        if buffer.len() < 60 {
            return None;
        }

        // Ethernet header
        if operation == ArpOperation::Request {
            buffer[0..6].copy_from_slice(&BROADCAST_MAC);
        } else {
            buffer[0..6].copy_from_slice(target_mac);
        }
        buffer[6..12].copy_from_slice(&self.mac);
        buffer[12] = 0x08; // EtherType: ARP
        buffer[13] = 0x06;

        // ARP header
        buffer[14] = 0x00; // Hardware type: Ethernet
        buffer[15] = 0x01;
        buffer[16] = 0x08; // Protocol type: IPv4
        buffer[17] = 0x00;
        buffer[18] = 6; // Hardware address length
        buffer[19] = 4; // Protocol address length
        buffer[20] = (operation as u16 >> 8) as u8;
        buffer[21] = operation as u8;

        // Sender MAC + IP
        buffer[22..28].copy_from_slice(&self.mac);
        buffer[28..32].copy_from_slice(&self.my_ip.octets());

        // Target MAC + IP
        buffer[32..38].copy_from_slice(target_mac);
        buffer[38..42].copy_from_slice(&target_ip.octets());

        // Pad to 60 bytes
        buffer[42..60].fill(0);

        Some(&buffer[..60])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_handler_new() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let handler = ArpHandler::new(mac);
        assert!(!handler.has_gateway_mac());
        assert!(!handler.needs_gratuitous_arp());
        assert!(!handler.needs_gateway_arp());
    }

    #[test]
    fn test_configure() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let mut handler = ArpHandler::new(mac);
        handler.configure(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        assert_eq!(handler.my_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(handler.gateway_ip, Ipv4Addr::new(192, 168, 1, 1));

        // Should queue GARP and gateway ARP
        assert!(handler.needs_gratuitous_arp());
        assert!(handler.needs_gateway_arp());
    }

    #[test]
    fn test_build_gratuitous_arp() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let mut handler = ArpHandler::new(mac);
        handler.configure(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
        );

        let arp = handler.build_gratuitous_arp();
        assert!(arp.len() >= 42);

        // Should be broadcast
        assert_eq!(&arp[..6], &BROADCAST_MAC);
        // EtherType should be ARP
        assert_eq!(&arp[12..14], &[0x08, 0x06]);
    }

    #[test]
    fn test_build_gateway_request() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let mut handler = ArpHandler::new(mac);
        handler.configure(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
        );

        let arp = handler.build_gateway_request();
        assert!(arp.len() >= 42);
    }

    #[test]
    fn test_mark_sent() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let mut handler = ArpHandler::new(mac);
        handler.configure(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
        );

        assert!(handler.needs_gratuitous_arp());
        handler.mark_garp_sent();
        assert!(!handler.needs_gratuitous_arp());

        assert!(handler.needs_gateway_arp());
        handler.mark_gateway_arp_sent();
        assert!(!handler.needs_gateway_arp());
    }

    #[test]
    fn test_pending_reply() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let mut handler = ArpHandler::new(mac);

        assert!(!handler.has_pending_reply());
        assert!(handler.take_pending_reply().is_none());

        // Set pending reply manually
        handler.pending_reply = Some(PendingArpReply {
            target_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            target_ip: Ipv4Addr::new(192, 168, 1, 50),
        });

        assert!(handler.has_pending_reply());
        let reply = handler.take_pending_reply();
        assert!(reply.is_some());
        assert!(!handler.has_pending_reply());
    }

    #[test]
    fn test_gateway_mac_or_broadcast() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let mut handler = ArpHandler::new(mac);

        // Before learning gateway MAC, should return broadcast
        assert_eq!(handler.gateway_mac_or_broadcast(), BROADCAST_MAC);

        // After learning gateway MAC
        handler.gateway_mac = Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(
            handler.gateway_mac_or_broadcast(),
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        );
    }

    #[test]
    fn test_build_arp_into() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let mut handler = ArpHandler::new(mac);
        handler.configure(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
        );

        let mut buffer = [0u8; 100];
        let target_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);

        let result =
            handler.build_arp_into(ArpOperation::Reply, &target_mac, target_ip, &mut buffer);

        assert!(result.is_some());
        let frame = result.unwrap();
        assert_eq!(frame.len(), 60);

        // Check destination MAC (unicast for reply)
        assert_eq!(&frame[0..6], &target_mac);
        // Check source MAC
        assert_eq!(&frame[6..12], &mac);
        // Check EtherType is ARP
        assert_eq!(&frame[12..14], &[0x08, 0x06]);
    }

    #[test]
    fn test_build_arp_into_buffer_too_small() {
        let mac = [0x5E, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let mut handler = ArpHandler::new(mac);
        handler.configure(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
        );

        let mut buffer = [0u8; 30]; // Too small
        let target_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);

        let result =
            handler.build_arp_into(ArpOperation::Reply, &target_mac, target_ip, &mut buffer);

        assert!(result.is_none());
    }
}
