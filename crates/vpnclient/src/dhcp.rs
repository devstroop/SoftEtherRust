//! Minimal DHCPv4 client over the SoftEther L2 tunnel.
//!
//! Scope: craft DISCOVER/REQUEST frames, parse OFFER/ACK (very small subset),
//! and apply assigned IP/mask/router/DNS on macOS using existing helpers.

use anyhow::Result;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use cedar::DataPlane;

// DHCP constants
const ETHERTYPE_IPV4: u16 = 0x0800;
const UDP_PROTO: u8 = 17;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const HTYPE_ETHERNET: u8 = 1;
const HLEN_ETHERNET: u8 = 6;

const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPACK: u8 = 5;
const DHCPINFORM: u8 = 8;

const DHCP_OPTION_MSGTYPE: u8 = 53;
const DHCP_OPTION_REQIP: u8 = 50;
const DHCP_OPTION_SERVERID: u8 = 54;
const DHCP_OPTION_PARAMLIST: u8 = 55;
const DHCP_OPTION_SUBNET: u8 = 1;
const DHCP_OPTION_ROUTER: u8 = 3;
const DHCP_OPTION_DNS: u8 = 6;
const DHCP_OPTION_END: u8 = 255;

const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

#[derive(Clone, Debug, Default)]
pub struct Lease {
    pub yiaddr: [u8; 4],
    pub server_ip: Option<[u8; 4]>,
    pub subnet: Option<[u8; 4]>,
    pub router: Option<[u8; 4]>,
    pub dns: Vec<[u8; 4]>,
    pub lease_time: u32,
}

pub struct DhcpClient {
    dp: DataPlane,
    mac: [u8; 6],
}

impl DhcpClient {
    pub fn new(dp: DataPlane, mac: [u8; 6]) -> Self {
        Self { dp, mac }
    }

    pub async fn run_once(&self, ifname: &str, timeout: Duration) -> Result<Option<Lease>> {
        // Tap frames from dataplane
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        self.dp.set_rx_tap(tx);
        info!("DHCP: RX tap installed");

        // Transaction ID for this exchange
        let xid: u32 = rand::random();

        // Small settle delay to let bridge/RX tap propagate; prefer config knob via env override
        let settle_ms: u64 = std::env::var("RUST_DHCP_SETTLE_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| {
                // Try to read from process-wide config if available via static access
                // Fallback to 200ms when not available
                200
            });
        if settle_ms > 0 {
            tokio::time::sleep(Duration::from_millis(settle_ms)).await;
        }

        // Send DISCOVER (broadcast)
        let discover = build_dhcp_discover(self.mac, xid);
        if self.dp.send_frame(discover) {
            info!("DHCP: DISCOVER sent (xid={:#x})", xid);
        } else {
            warn!("DHCP: failed to queue DISCOVER (no TX-capable link)");
        }

        let deadline = tokio::time::Instant::now() + timeout;
        let mut offer: Option<(Lease, [u8; 4], [u8; 4])> = None; // (lease, server_id, yiaddr)
        let mut last_tx = tokio::time::Instant::now();
        // Faster initial retries with exponential backoff (+/- jitter)
        let initial_ms: u64 = std::env::var("RUST_DHCP_DISCOVER_INITIAL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(800);
        let max_ms: u64 = std::env::var("RUST_DHCP_DISCOVER_MAX_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8000);
        let mut retry_iv = std::time::Duration::from_millis(initial_ms);
        let jitter_pct: f64 = std::env::var("RUST_DHCP_JITTER_PCT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.15);
        // Wait for OFFER with periodic retransmit of DISCOVER
        while tokio::time::Instant::now() < deadline {
            let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
            let wait = remain.min(retry_iv);
            match tokio::time::timeout(wait, rx.recv()).await {
                Ok(Some(frame)) => {
                    if let Some((mt, lease, server_id, yiaddr, rx_xid)) = parse_dhcp(&frame) {
                        if rx_xid != xid {
                            continue;
                        }
                        if mt == DHCPOFFER {
                            info!(
                                "DHCP OFFER yiaddr={}.{}.{}.{}",
                                yiaddr[0], yiaddr[1], yiaddr[2], yiaddr[3]
                            );
                            offer = Some((lease, server_id, yiaddr));
                            break;
                        }
                    }
                }
                Ok(None) => {
                    break;
                }
                Err(_) => { /* timeout */ }
            }

            if tokio::time::Instant::now().saturating_duration_since(last_tx) >= retry_iv {
                let discover = build_dhcp_discover(self.mac, xid);
                if self.dp.send_frame(discover) {
                    debug!("DHCP: DISCOVER re-sent (xid={:#x})", xid);
                }
                last_tx = tokio::time::Instant::now();
                // Exponential backoff up to max
                let mut next = retry_iv.as_millis() as u64 * 2;
                next = next.min(max_ms).max(initial_ms);
                // Apply +/- jitter
                if jitter_pct > 0.0 {
                    let span = (next as f64 * jitter_pct) as i64;
                    let jitter = (rand::random::<f64>() * (span as f64) * 2.0 - span as f64) as i64;
                    let adj = (next as i64 + jitter).max(initial_ms as i64) as u64;
                    next = adj.min(max_ms);
                }
                retry_iv = std::time::Duration::from_millis(next);
            }
        }

        let Some((lease_offer, server_id, yiaddr)) = offer else {
            return Ok(None);
        };

        // Send REQUEST for offered address
        let request = build_dhcp_request(self.mac, xid, yiaddr, server_id);
        if self.dp.send_frame(request) {
            info!("DHCP: REQUEST sent (xid={:#x})", xid);
        } else {
            warn!("DHCP: failed to queue REQUEST (no TX-capable link)");
        }

        // Wait for ACK
        while tokio::time::Instant::now() < deadline {
            if let Some(frame) = rx.recv().await {
                if let Some((mt, mut lease, _server_id, _yiaddr, rx_xid)) = parse_dhcp(&frame) {
                    if rx_xid != xid {
                        continue;
                    }
                    if mt == DHCPACK {
                        // If options missing, try a DHCP INFORM to pick up mask/router/DNS
                        let missing_mask = lease.subnet.is_none();
                        let missing_router = lease.router.is_none();
                        let missing_dns = lease.dns.is_empty();
                        if missing_mask || missing_router || missing_dns {
                            if let Some(lease2) = self.try_inform(&lease, &mut rx, deadline).await {
                                if lease.subnet.is_none() {
                                    lease.subnet = lease2.subnet;
                                }
                                if lease.router.is_none() {
                                    lease.router = lease2.router;
                                }
                                if lease.dns.is_empty() && !lease2.dns.is_empty() {
                                    lease.dns = lease2.dns;
                                }
                            }
                        }
                        // Visibility: log presence of key options
                        if lease.subnet.is_some() {
                            info!("DHCP ACK includes subnet mask");
                        } else {
                            warn!("DHCP ACK has no subnet mask option");
                        }
                        if lease.router.is_some() {
                            info!("DHCP ACK includes router (default gateway)");
                        } else {
                            warn!("DHCP ACK has no router option");
                        }
                        if lease.dns.is_empty() {
                            warn!("DHCP ACK has no DNS servers");
                        } else {
                            info!("DHCP ACK includes {} DNS server(s)", lease.dns.len());
                        }
                        info!(
                            "DHCP ACK ip={}.{}.{}.{}",
                            lease.yiaddr[0], lease.yiaddr[1], lease.yiaddr[2], lease.yiaddr[3]
                        );
                        // Apply on macOS using existing helpers
                        #[cfg(target_os = "macos")]
                        {
                            use tokio::process::Command;
                            let ip = format!(
                                "{}.{}.{}.{}",
                                lease.yiaddr[0], lease.yiaddr[1], lease.yiaddr[2], lease.yiaddr[3]
                            );
                            let mask = lease
                                .subnet
                                .unwrap_or_else(|| classful_mask(lease.yiaddr[0]));
                            let mask_s = format!("{}.{}.{}.{}", mask[0], mask[1], mask[2], mask[3]);
                            let _ = Command::new("ifconfig")
                                .arg(ifname)
                                .arg("inet")
                                .arg(&ip)
                                .arg(&ip)
                                .arg("netmask")
                                .arg(&mask_s)
                                .output()
                                .await;
                            if let Some(router) = lease.router {
                                let gw = format!(
                                    "{}.{}.{}.{}",
                                    router[0], router[1], router[2], router[3]
                                );
                                let _ = Command::new("route")
                                    .arg("add")
                                    .arg("default")
                                    .arg(&gw)
                                    .output()
                                    .await;
                                info!("Router {}", gw);
                            }
                            let cidr = prefix_len(mask);
                            info!("Interface {}: {}/{}", ifname, ip, cidr);
                            if !lease.dns.is_empty() {
                                let dns_list: Vec<String> = lease
                                    .dns
                                    .iter()
                                    .map(|d| format!("{}.{}.{}.{}", d[0], d[1], d[2], d[3]))
                                    .collect();
                                info!("DNS {}", dns_list.join(", "));
                            }
                        }
                        return Ok(Some(lease));
                    }
                }
            } else {
                break;
            }
        }

        Ok(Some(lease_offer))
    }
}

fn build_dhcp_discover(src_mac: [u8; 6], xid: u32) -> Vec<u8> {
    let mut bootp = vec![0u8; 236];
    bootp[0] = BOOTREQUEST;
    bootp[1] = HTYPE_ETHERNET;
    bootp[2] = HLEN_ETHERNET;
    bootp[3] = 0; // hops
    bootp[4..8].copy_from_slice(&xid.to_be_bytes());
    // secs(8..10)=0; flags(10..12)=0x8000 (broadcast)
    bootp[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
    bootp[28..34].copy_from_slice(&src_mac);
    // options
    let mut opts = Vec::new();
    opts.extend_from_slice(&MAGIC_COOKIE);
    opts.extend_from_slice(&[DHCP_OPTION_MSGTYPE, 1, DHCPDISCOVER]);
    // Client identifier (type 1 = Ethernet, then MAC)
    opts.extend_from_slice(&[
        61, 7, 1, src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
    ]);
    // Parameter request list: subnet(1), router(3), dns(6)
    opts.extend_from_slice(&[
        DHCP_OPTION_PARAMLIST,
        3,
        DHCP_OPTION_SUBNET,
        DHCP_OPTION_ROUTER,
        DHCP_OPTION_DNS,
    ]);
    opts.push(DHCP_OPTION_END);

    build_eth_ipv4_udp_broadcast(src_mac, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, &bootp, &opts)
}

fn build_dhcp_request(src_mac: [u8; 6], xid: u32, req_ip: [u8; 4], server_id: [u8; 4]) -> Vec<u8> {
    let mut bootp = vec![0u8; 236];
    bootp[0] = BOOTREQUEST;
    bootp[1] = HTYPE_ETHERNET;
    bootp[2] = HLEN_ETHERNET;
    bootp[3] = 0;
    bootp[4..8].copy_from_slice(&xid.to_be_bytes());
    // Broadcast flag for safety
    bootp[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
    bootp[28..34].copy_from_slice(&src_mac);
    let mut opts = Vec::new();
    opts.extend_from_slice(&MAGIC_COOKIE);
    opts.extend_from_slice(&[DHCP_OPTION_MSGTYPE, 1, DHCPREQUEST]);
    // Client identifier
    opts.extend_from_slice(&[
        61, 7, 1, src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
    ]);
    opts.extend_from_slice(&[
        DHCP_OPTION_REQIP,
        4,
        req_ip[0],
        req_ip[1],
        req_ip[2],
        req_ip[3],
    ]);
    opts.extend_from_slice(&[
        DHCP_OPTION_SERVERID,
        4,
        server_id[0],
        server_id[1],
        server_id[2],
        server_id[3],
    ]);
    // Ask again for common config in ACK (some servers honor PRL only here)
    opts.extend_from_slice(&[
        DHCP_OPTION_PARAMLIST,
        3,
        DHCP_OPTION_SUBNET,
        DHCP_OPTION_ROUTER,
        DHCP_OPTION_DNS,
    ]);
    opts.push(DHCP_OPTION_END);
    build_eth_ipv4_udp_broadcast(src_mac, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, &bootp, &opts)
}

fn build_dhcp_inform(src_mac: [u8; 6], xid: u32, ciaddr: [u8; 4]) -> Vec<u8> {
    let mut bootp = vec![0u8; 236];
    bootp[0] = BOOTREQUEST;
    bootp[1] = HTYPE_ETHERNET;
    bootp[2] = HLEN_ETHERNET;
    bootp[3] = 0;
    bootp[4..8].copy_from_slice(&xid.to_be_bytes());
    bootp[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // broadcast
                                                             // ciaddr
    bootp[12..16].copy_from_slice(&ciaddr);
    bootp[28..34].copy_from_slice(&src_mac);
    let mut opts = Vec::new();
    opts.extend_from_slice(&MAGIC_COOKIE);
    opts.extend_from_slice(&[DHCP_OPTION_MSGTYPE, 1, DHCPINFORM]);
    // Client identifier (type 1 = Ethernet, then MAC)
    opts.extend_from_slice(&[
        61, 7, 1, src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
    ]);
    // Parameter request list: subnet(1), router(3), dns(6)
    opts.extend_from_slice(&[
        DHCP_OPTION_PARAMLIST,
        3,
        DHCP_OPTION_SUBNET,
        DHCP_OPTION_ROUTER,
        DHCP_OPTION_DNS,
    ]);
    opts.push(DHCP_OPTION_END);
    build_eth_ipv4_udp_broadcast(src_mac, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, &bootp, &opts)
}

fn build_eth_ipv4_udp_broadcast(
    src_mac: [u8; 6],
    src_port: u16,
    dst_port: u16,
    bootp: &[u8],
    opts: &[u8],
) -> Vec<u8> {
    let payload_len = bootp.len() + opts.len();
    let total_len = 14 + 20 + 8 + payload_len; // Eth + IPv4 + UDP + BOOTP+options
    let mut p = vec![0u8; total_len];
    // Ethernet
    p[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // broadcast
    p[6..12].copy_from_slice(&src_mac);
    p[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    // IPv4 header
    p[14] = (4 << 4) | 5; // v4, ihl=5
    p[15] = 0; // DSCP/ECN
    let ip_len = (20 + 8 + payload_len) as u16;
    p[16..18].copy_from_slice(&ip_len.to_be_bytes());
    p[18..20].copy_from_slice(&0u16.to_be_bytes()); // identification
    p[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // flags=DF
    p[22] = 64; // TTL
    p[23] = UDP_PROTO;
    // Header checksum lives at bytes 14+10..14+12; src/dst at 14+12..14+16 and 14+16..14+20
    p[26..30].copy_from_slice(&[0, 0, 0, 0]); // src IP 0.0.0.0
    p[30..34].copy_from_slice(&[255, 255, 255, 255]); // dst IP broadcast
    let ip_ck = ipv4_checksum(&p[14..34]);
    p[24..26].copy_from_slice(&ip_ck.to_be_bytes());
    // UDP header
    p[34..36].copy_from_slice(&src_port.to_be_bytes());
    p[36..38].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload_len) as u16;
    p[38..40].copy_from_slice(&udp_len.to_be_bytes());
    p[40..42].copy_from_slice(&0u16.to_be_bytes()); // temp 0 for checksum calc
                                                    // Payload
    p[42..42 + bootp.len()].copy_from_slice(bootp);
    p[42 + bootp.len()..42 + bootp.len() + opts.len()].copy_from_slice(opts);

    // Compute UDP checksum over pseudo-header + UDP header + payload
    let src_ip = [0u8, 0, 0, 0];
    let dst_ip = [255u8, 255, 255, 255];
    let csum = udp_checksum(&src_ip, &dst_ip, &p[34..(34 + 8 + payload_len)]);
    p[40..42].copy_from_slice(&csum.to_be_bytes());
    p
}

fn ipv4_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < hdr.len() {
        if i == 10 {
            i += 2;
            continue;
        } // skip checksum field
        sum += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], udp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // Pseudo header
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += u16::from_be_bytes([0, UDP_PROTO]) as u32;
    sum += u16::from_be_bytes([
        (udp.len() as u16 >> 8) as u8,
        (udp.len() as u16 & 0xff) as u8,
    ]) as u32;
    // UDP header + payload
    let mut i = 0;
    while i + 1 < udp.len() {
        // Skip checksum field itself (bytes 6..8 in UDP header)
        if i == 6 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
        i += 2;
    }
    if i < udp.len() {
        sum += (udp[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let res = !(sum as u16);
    if res == 0 {
        0xffff
    } else {
        res
    }
}

fn prefix_len(mask: [u8; 4]) -> u8 {
    (mask[0].count_ones() + mask[1].count_ones() + mask[2].count_ones() + mask[3].count_ones())
        as u8
}

fn classful_mask(first_octet: u8) -> [u8; 4] {
    if first_octet < 128 {
        [255, 0, 0, 0]
    } else if first_octet < 192 {
        [255, 255, 0, 0]
    } else {
        [255, 255, 255, 0]
    }
}

fn parse_dhcp(frame: &[u8]) -> Option<(u8, Lease, [u8; 4], [u8; 4], u32)> {
    if frame.len() < 42 {
        return None;
    }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    if ether_type != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = &frame[14..];
    if ip.len() < 20 {
        return None;
    }
    let ver_ihl = ip[0];
    if (ver_ihl >> 4) != 4 {
        return None;
    }
    let ihl = ((ver_ihl & 0x0f) as usize) * 4;
    if ip.len() < ihl + 8 {
        return None;
    }
    if ip[9] != UDP_PROTO {
        return None;
    }
    let src_port = u16::from_be_bytes([ip[ihl], ip[ihl + 1]]);
    let dst_port = u16::from_be_bytes([ip[ihl + 2], ip[ihl + 3]]);
    if !(src_port == DHCP_SERVER_PORT && dst_port == DHCP_CLIENT_PORT) {
        return None;
    }
    let udp_payload = &ip[ihl + 8..];
    if udp_payload.len() < 236 + 4 {
        return None;
    }
    let op = udp_payload[0];
    if op != BOOTREPLY {
        return None;
    }
    let mut yiaddr = [0u8; 4];
    yiaddr.copy_from_slice(&udp_payload[16..20]);
    let mut xid_b = [0u8; 4];
    xid_b.copy_from_slice(&udp_payload[4..8]);
    let xid = u32::from_be_bytes(xid_b);
    if udp_payload[236..240] != MAGIC_COOKIE {
        return None;
    }
    let mut lease = Lease::default();
    lease.yiaddr = yiaddr;
    let mut server_id = [0u8; 4];
    let mut msgtype = 0u8;
    // options
    let mut i = 240;
    while i < udp_payload.len() {
        let code = udp_payload[i];
        i += 1;
        if code == DHCP_OPTION_END {
            break;
        }
        if i >= udp_payload.len() {
            break;
        }
        let len = udp_payload[i] as usize;
        i += 1;
        if i + len > udp_payload.len() {
            break;
        }
        match code {
            DHCP_OPTION_MSGTYPE if len == 1 => {
                msgtype = udp_payload[i];
            }
            DHCP_OPTION_SUBNET if len == 4 => {
                let mut m = [0u8; 4];
                m.copy_from_slice(&udp_payload[i..i + 4]);
                lease.subnet = Some(m);
            }
            DHCP_OPTION_ROUTER if len >= 4 => {
                let mut r = [0u8; 4];
                r.copy_from_slice(&udp_payload[i..i + 4]);
                lease.router = Some(r);
            }
            DHCP_OPTION_DNS if len >= 4 => {
                let mut j = 0;
                while j + 3 < len {
                    let mut d = [0u8; 4];
                    d.copy_from_slice(&udp_payload[i + j..i + j + 4]);
                    lease.dns.push(d);
                    j += 4;
                }
            }
            DHCP_OPTION_SERVERID if len == 4 => {
                server_id.copy_from_slice(&udp_payload[i..i + 4]);
            }
            _ => {}
        }
        i += len;
    }
    if msgtype == 0 {
        return None;
    }
    Some((msgtype, lease, server_id, yiaddr, xid))
}

impl DhcpClient {
    async fn try_inform(
        &self,
        base_lease: &Lease,
        rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
        deadline: tokio::time::Instant,
    ) -> Option<Lease> {
        // Attempt a few INFORM retries until deadline
        let xid: u32 = rand::random();
        let inform = build_dhcp_inform(self.mac, xid, base_lease.yiaddr);
        let mut last_tx = tokio::time::Instant::now() - std::time::Duration::from_secs(10);
        let retry_iv = std::time::Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            if tokio::time::Instant::now().saturating_duration_since(last_tx) >= retry_iv {
                if self.dp.send_frame(inform.clone()) {
                    info!("DHCP: INFORM sent (xid={:#x})", xid);
                }
                last_tx = tokio::time::Instant::now();
            }
            let wait = std::time::Duration::from_millis(500);
            match tokio::time::timeout(wait, rx.recv()).await {
                Ok(Some(frame)) => {
                    if let Some((mt, lease, _server_id, _yiaddr, rx_xid)) = parse_dhcp(&frame) {
                        if rx_xid != xid {
                            continue;
                        }
                        if mt == DHCPACK {
                            return Some(lease);
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => {}
            }
        }
        None
    }
}
