//! Minimal DHCP client using `dhcproto` over the cedar `DataPlane`.
//! Crafts raw Ethernet/IPv4/UDP frames (broadcast) for DISCOVER/REQUEST and
//! listens on a dataplane RX tap for OFFER/ACK.

use anyhow::{Context, Result};
use dhcproto::v4::{self, Encodable, Decodable};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use cedar::DataPlane;

/// DHCP lease information
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Lease {
    pub client_ip: Ipv4Addr,
    pub server_ip: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_time: Option<Duration>,
    pub renewal_time: Option<Duration>,
    pub rebinding_time: Option<Duration>,
    pub domain_name: Option<String>,
    pub interface_mtu: Option<u16>,
    pub broadcast_addr: Option<Ipv4Addr>,
    pub classless_routes: Vec<(ipnet::Ipv4Net, Ipv4Addr)>,
    pub server_mac: Option<[u8; 6]>,
}

impl Default for Lease {
    fn default() -> Self { 
        Self { 
            client_ip: Ipv4Addr::UNSPECIFIED, 
            server_ip: None, 
            gateway: None,
            subnet_mask: None, 
            dns_servers: Vec::new(), 
            lease_time: None,
            renewal_time: None,
            rebinding_time: None,
            domain_name: None,
            interface_mtu: None,
            broadcast_addr: None,
            classless_routes: Vec::new(),
            server_mac: None,
        } 
    }
}

pub struct DhcpClient {
    dp: DataPlane,
    mac: [u8; 6],
    xid: u32,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    // Learned from OFFER/ACK frames when available (Ethernet mode)
    server_mac: Option<[u8; 6]>,
    server_ip_observed: Option<Ipv4Addr>,
}

impl DhcpClient {
    pub fn new(dp: DataPlane, mac: [u8; 6]) -> Self {
        use rand::RngCore;
        let mut xb = [0u8; 4];
        rand::rng().fill_bytes(&mut xb);
        let xid = u32::from_be_bytes(xb);
        let (tx, rx) = mpsc::unbounded_channel();
    dp.set_rx_tap(tx); // global tap (one-shot usage acceptable)
    Self { dp, mac, xid, rx, server_mac: None, server_ip_observed: None }
    }

    pub fn new_with_xid(dp: DataPlane, mac: [u8;6], xid: u32) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
    dp.set_rx_tap(tx);
    Self { dp, mac, xid, rx, server_mac: None, server_ip_observed: None }
    }

    pub fn xid(&self) -> u32 { self.xid }

    pub fn set_server_mac(&mut self, mac: Option<[u8;6]>) { self.server_mac = mac; }

    pub async fn run_once(&mut self, iface_name: &str, timeout: Duration, event_cb: Option<&(dyn Fn(u32, String) + Send + Sync)>) -> Result<Option<Lease>> {
        let deadline = Instant::now() + timeout;
        let mut attempt: u32 = 0;
        let mut next_send = Instant::now();
        let mut offer: Option<v4::Message> = None;
        // Adaptive backoff based on timeout - longer timeouts (LocalBridge) get slower backoff
        let mut backoff = if timeout > Duration::from_secs(15) {
            Duration::from_millis(1500) // LocalBridge mode: slower initial backoff
        } else {
            Duration::from_millis(800)  // SecureNAT mode: faster backoff
        };
        let max_backoff = if timeout > Duration::from_secs(15) {
            Duration::from_secs(8)      // LocalBridge mode: longer max backoff
        } else {
            Duration::from_secs(4)      // SecureNAT mode: shorter max backoff
        };
        // Track whether any DHCP traffic was observed during the discovery window (for diagnostics)
        let mut dhcp_frames_observed: u32 = 0;
    let mut decode_errs_emitted: u32 = 0; // throttle decode error events
    while Instant::now() < deadline {
            if Instant::now() >= next_send {
                let discover = self.build_discover()?;
                if attempt == 0 {
                    if let Some(cb)=event_cb { cb(298, format!("dhcp discover sent iface={iface_name} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} xid={:#x} attempt={} timeout={:?}", self.mac[0],self.mac[1],self.mac[2],self.mac[3],self.mac[4],self.mac[5], self.xid, attempt+1, timeout)); }
                    info!("DHCP DISCOVER sent iface={iface_name} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} xid={:#x} attempt={} timeout={:?}", self.mac[0],self.mac[1],self.mac[2],self.mac[3],self.mac[4],self.mac[5], self.xid, attempt+1, timeout);
                } else {
                    if let Some(cb)=event_cb { cb(295, format!("dhcp discover retransmit iface={iface_name} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} xid={:#x} attempt={} timeout={:?}", self.mac[0],self.mac[1],self.mac[2],self.mac[3],self.mac[4],self.mac[5], self.xid, attempt+1, timeout)); }
                    info!("DHCP DISCOVER retransmit iface={iface_name} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} xid={:#x} attempt={} timeout={:?}", self.mac[0],self.mac[1],self.mac[2],self.mac[3],self.mac[4],self.mac[5], self.xid, attempt+1, timeout);
                }
                if std::env::var("RUST_DHCP_DEBUG_FRAMES").ok().as_deref()==Some("1") {
                    let dump_len = discover.len().min(120);
                    info!("DHCP DISCOVER frame[0..{}]={}", dump_len, hex::encode(&discover[..dump_len]));
                }
                // Send full Ethernet frame over the SoftEther dataplane
                if !self.send_frame(discover) {
                    // If send fails, wait longer before retry and emit diagnostic event
                    let summary = self.dp.summary();
                    if let Some(cb) = event_cb { 
                        cb(2997, format!("dhcp discover send failed iface={iface_name} links={} attempt={}", summary.total_links, attempt)); 
                    }
                    warn!("DHCP DISCOVER send failed, extending backoff");
                    backoff = if timeout > Duration::from_secs(15) {
                        (backoff * 2).min(Duration::from_secs(10)) // LocalBridge mode: longer backoff
                    } else {
                        (backoff * 3).min(Duration::from_secs(8))  // SecureNAT mode: shorter backoff
                    };
                }
                attempt += 1;
                next_send = Instant::now() + backoff;
                backoff = (backoff * 2).min(max_backoff);
            }
            let slice_deadline = next_send.min(deadline);
            let mut remaining = slice_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() { continue; }
            if remaining > Duration::from_millis(300) { remaining = Duration::from_millis(300); }
            match tokio::time::timeout(remaining, self.rx.recv()).await {
                Ok(Some(frame)) => {
                    if let Some(view) = extract_dhcp(&frame) {
                        dhcp_frames_observed = dhcp_frames_observed.saturating_add(1);
                        use dhcproto::v4::Decoder;
                        match v4::Message::decode(&mut Decoder::new(view.dhcp)) {
                            Ok(msg) => {
                                let mt = msg.opts().msg_type();
                                if msg.xid() == self.xid && mt == Some(v4::MessageType::Offer) {
                                    // sanity: chaddr consistency
                                    let ch = msg.chaddr();
                                    if ch.len() >= 6 && &ch[0..6] != &self.mac {
                                        if let Some(cb)=event_cb { cb(294, format!("dhcp chaddr mismatch (offer) iface={iface_name} our_mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} frame_mac={}", self.mac[0],self.mac[1],self.mac[2],self.mac[3],self.mac[4],self.mac[5], hex::encode(&ch[0..6]))); }
                                    }
                                    // learn server identifiers
                                    if let Some(m) = view.l2_src { self.server_mac = Some(m); }
                                    if let Some(sip) = view.ip_src { self.server_ip_observed = Some(sip); }
                                    offer = Some(msg);
                                    break;
                                }
                                else if let Some(mt) = mt { if let Some(cb)=event_cb { cb(294, format!("dhcp frame observed mismatched iface={iface_name} our_xid={:#x} frame_xid={:#x} mt={:?}", self.xid, msg.xid(), mt)); } }
                            }
                            Err(e) => { 
                                debug!("DHCP decode error (discover): {e}"); 
                                if decode_errs_emitted < 3 { 
                                    if let Some(cb)=event_cb { 
                                        cb(2999, format!("dhcp decode error: {e} (frame_len={} dhcp_len={})", frame.len(), view.dhcp.len())); 
                                    } 
                                    decode_errs_emitted += 1; 
                                }
                                // Add hex dump for decode errors when debugging
                                if std::env::var("RUST_DHCP_DEBUG_FRAMES").ok().as_deref()==Some("1") && decode_errs_emitted <= 1 {
                                    let dump_len = view.dhcp.len().min(64);
                                    debug!("Failed DHCP decode frame[0..{}]={}", dump_len, hex::encode(&view.dhcp[..dump_len]));
                                }
                            }
                        }
                    } else if std::env::var("RUST_DHCP_DEBUG_FRAMES").ok().as_deref()==Some("1") {
                        let dump_len = frame.len().min(120);
                        debug!("Non-DHCP frame during discovery[0..{}]={}", dump_len, hex::encode(&frame[..dump_len]));
                    }
                }
                Ok(None) => break,
                Err(_) => { /* slice timeout */ }
            }
        }
    let offer = match offer { Some(m)=>m, None => {
        if dhcp_frames_observed == 0 { if let Some(cb)=event_cb { cb(2998, format!("dhcp no traffic observed iface={iface_name} xid={:#x} attempts={}", self.xid, attempt)); } }
        if let Some(cb)=event_cb { cb(297, format!("dhcp offer timeout iface={iface_name} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} xid={:#x} attempts={}", self.mac[0],self.mac[1],self.mac[2],self.mac[3],self.mac[4],self.mac[5], self.xid, attempt)); }
        info!("DHCP OFFER phase timeout iface={iface_name} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} xid={:#x} attempts={}", self.mac[0],self.mac[1],self.mac[2],self.mac[3],self.mac[4],self.mac[5], self.xid, attempt);
        return Ok(None);
    } };
    let request = self.build_request(&offer)?;
        if let Some(cb)=event_cb { cb(298, format!("dhcp request sent iface={iface_name} xid={:#x}", self.xid)); }
        info!("DHCP REQUEST sent iface={iface_name} xid={:#x}", self.xid);
        if std::env::var("RUST_DHCP_DEBUG_FRAMES").ok().as_deref()==Some("1") {
            let dump_len = request.len().min(120);
            info!("DHCP REQUEST frame[0..{}]={}", dump_len, hex::encode(&request[..dump_len]));
        }
    // Send full Ethernet frame over the SoftEther dataplane
    if !self.send_frame(request) {
        if let Some(cb) = event_cb { 
            cb(2997, format!("dhcp request send failed iface={iface_name} xid={:#x}", self.xid)); 
        }
        warn!("DHCP REQUEST send failed, may affect ACK reception");
    }
    if let Some(ack) = self.wait_for(v4::MessageType::Ack, deadline, event_cb, iface_name).await? {
            let lease = self.lease_from_ack(&ack)?;
            info!("DHCP lease iface={iface_name} ip={} gateway={:?} dns={:?}", lease.client_ip, lease.gateway, lease.dns_servers);
            return Ok(Some(lease));
        }
        if let Some(cb)=event_cb { cb(296, format!("dhcp ack timeout iface={iface_name} xid={:#x}", self.xid)); }
        info!("DHCP ACK wait timed out iface={iface_name} xid={:#x}", self.xid);
        Ok(None)
    }

    fn build_discover(&self) -> Result<Vec<u8>> {
        let mut msg = v4::Message::new_with_id(self.xid, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &self.mac);
        msg.set_opcode(v4::Opcode::BootRequest);
        msg.set_htype(v4::HType::Eth);
        msg.set_flags(v4::Flags::default().set_broadcast());
        msg.opts_mut().insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));
        // Add DHCP Client Identifier (htype=1 + MAC) for better interoperability with relays/bridges
        let mut cid = Vec::with_capacity(7); cid.push(1u8); cid.extend_from_slice(&self.mac);
        msg.opts_mut().insert(v4::DhcpOption::ClientIdentifier(cid));
        // Provide hostname if discoverable (mirrors Go impl behavior supplying a hostname)
        if let Ok(hn) = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")) { if !hn.is_empty() { msg.opts_mut().insert(v4::DhcpOption::Hostname(hn)); } }
        // Minimal initial parameter list; expanded during REQUEST to reduce initial packet size over slow LocalBridge paths
        msg.opts_mut().insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::AddressLeaseTime,
        ]));
        self.wrap_dhcp(&msg, Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(255,255,255,255), None, true)
    }

    fn build_request(&self, offer: &v4::Message) -> Result<Vec<u8>> {
        let mut msg = v4::Message::new_with_id(self.xid, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &self.mac);
        msg.set_opcode(v4::Opcode::BootRequest);
        msg.set_htype(v4::HType::Eth);
        msg.set_flags(v4::Flags::default().set_broadcast());
        msg.opts_mut().insert(v4::DhcpOption::MessageType(v4::MessageType::Request));
        if offer.yiaddr() != Ipv4Addr::UNSPECIFIED { msg.opts_mut().insert(v4::DhcpOption::RequestedIpAddress(offer.yiaddr())); }
        if let Some(v4::DhcpOption::ServerIdentifier(sid)) = offer.opts().get(v4::OptionCode::ServerIdentifier) { msg.opts_mut().insert(v4::DhcpOption::ServerIdentifier(*sid)); }
        // Include Client Identifier and Hostname again (some servers expect continuity)
        let mut cid = Vec::with_capacity(7); cid.push(1u8); cid.extend_from_slice(&self.mac); msg.opts_mut().insert(v4::DhcpOption::ClientIdentifier(cid));
        if let Ok(hn) = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")) { if !hn.is_empty() { msg.opts_mut().insert(v4::DhcpOption::Hostname(hn)); } }
        // Full parameter request list now that server selected an address
        msg.opts_mut().insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::AddressLeaseTime,
            v4::OptionCode::DomainName,
            v4::OptionCode::InterfaceMtu,
            v4::OptionCode::BroadcastAddr,
            v4::OptionCode::ClasslessStaticRoute,
        ]));
        self.wrap_dhcp(&msg, Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(255,255,255,255), None, true)
    }

    /// Build a broadcast RENEW/REBIND style REQUEST (broadcast IP/Ethernet)
    pub fn build_renew_broadcast(&self, lease: &Lease) -> Result<Vec<u8>> {
        let mut msg = v4::Message::new_with_id(self.xid, lease.client_ip, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &self.mac);
        msg.set_opcode(v4::Opcode::BootRequest);
        msg.set_htype(v4::HType::Eth);
        msg.set_flags(v4::Flags::default().set_broadcast());
        msg.opts_mut().insert(v4::DhcpOption::MessageType(v4::MessageType::Request));
        if let Some(sid) = lease.server_ip { msg.opts_mut().insert(v4::DhcpOption::ServerIdentifier(sid)); }
        msg.opts_mut().insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::AddressLeaseTime,
            v4::OptionCode::DomainName,
            v4::OptionCode::InterfaceMtu,
            v4::OptionCode::BroadcastAddr,
            v4::OptionCode::ClasslessStaticRoute,
        ]));
        self.wrap_dhcp(&msg, lease.client_ip, Ipv4Addr::new(255,255,255,255), None, true)
    }

    /// Build an attempted unicast RENEW to the original server (no broadcast flag, dst = server)
    pub fn build_renew_unicast(&self, lease: &Lease) -> Result<Option<Vec<u8>>> {
        let server = match lease.server_ip { Some(s) => s, None => return Ok(None) };
        let mut msg = v4::Message::new_with_id(self.xid, lease.client_ip, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &self.mac);
        msg.set_opcode(v4::Opcode::BootRequest);
        msg.set_htype(v4::HType::Eth);
        msg.set_flags(v4::Flags::default());
        msg.opts_mut().insert(v4::DhcpOption::MessageType(v4::MessageType::Request));
        msg.opts_mut().insert(v4::DhcpOption::ServerIdentifier(server));
        msg.opts_mut().insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::AddressLeaseTime,
            v4::OptionCode::DomainName,
            v4::OptionCode::InterfaceMtu,
            v4::OptionCode::BroadcastAddr,
            v4::OptionCode::ClasslessStaticRoute,
        ]));
        Ok(Some(self.wrap_dhcp(&msg, lease.client_ip, server, self.server_mac, false)?))
    }

    /// Build a REBIND (broadcast REQUEST without server identifier)
    pub fn build_rebind(&self, lease: &Lease) -> Result<Vec<u8>> {
        let mut msg = v4::Message::new_with_id(self.xid, lease.client_ip, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &self.mac);
        msg.set_opcode(v4::Opcode::BootRequest);
        msg.set_htype(v4::HType::Eth);
        msg.set_flags(v4::Flags::default().set_broadcast());
        msg.opts_mut().insert(v4::DhcpOption::MessageType(v4::MessageType::Request));
        msg.opts_mut().insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::AddressLeaseTime,
            v4::OptionCode::DomainName,
            v4::OptionCode::InterfaceMtu,
            v4::OptionCode::BroadcastAddr,
            v4::OptionCode::ClasslessStaticRoute,
        ]));
        self.wrap_dhcp(&msg, lease.client_ip, Ipv4Addr::new(255,255,255,255), None, true)
    }

    fn wrap_dhcp(&self, msg: &v4::Message, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, explicit_dst_mac: Option<[u8;6]>, broadcast_eth: bool) -> Result<Vec<u8>> {
        let mut dhcp_buf = Vec::new();
        let mut enc = v4::Encoder::new(&mut dhcp_buf);
        msg.encode(&mut enc).context("encode dhcp")?;
        // UDP header
        let udp_len = 8 + dhcp_buf.len();
        let mut udp = Vec::with_capacity(8 + dhcp_buf.len());
        udp.extend_from_slice(&68u16.to_be_bytes());
        udp.extend_from_slice(&67u16.to_be_bytes());
        udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes()); // checksum omitted
        udp.extend_from_slice(&dhcp_buf);
        // IPv4 header
        let total_len = 20 + udp.len();
        let mut ip = Vec::with_capacity(total_len);
        ip.push(0x45); ip.push(0); // ver/ihl, tos
        ip.extend_from_slice(&(total_len as u16).to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes()); // id
        ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
        ip.push(64); ip.push(17); // ttl, proto
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum (filled after header assembled)
        ip.extend_from_slice(&src_ip.octets());
        ip.extend_from_slice(&dst_ip.octets());
        let csum = ipv4_checksum(&ip);
        ip[10]=(csum>>8) as u8; ip[11]=(csum & 0xff) as u8;
        ip.extend_from_slice(&udp);
    // Ethernet
        let mut eth = Vec::with_capacity(14 + ip.len());
    if let Some(dst) = explicit_dst_mac { eth.extend_from_slice(&dst); }
    else if broadcast_eth { eth.extend_from_slice(&[0xff;6]); }
    else { eth.extend_from_slice(&[0u8;6]); }
        eth.extend_from_slice(&self.mac);
        eth.extend_from_slice(&0x0800u16.to_be_bytes());
        eth.extend_from_slice(&ip);
        Ok(eth)
    }

    pub fn send_frame(&self, frame: Vec<u8>) -> bool { 
        let success = self.dp.send_frame(frame.clone());
        if !success { 
            let summary = self.dp.summary();
            warn!("DHCP frame send failed: links={} tx_capable={} (total_tx={})", 
                  summary.total_links, 
                  summary.c2s_links + summary.both_links,
                  summary.total_tx); 
            // Add debug frame dump for troubleshooting
            if std::env::var("RUST_DHCP_DEBUG_FRAMES").ok().as_deref() == Some("1") {
                let dump_len = frame.len().min(120);
                warn!("Failed DHCP frame[0..{}]={}", dump_len, hex::encode(&frame[..dump_len]));
            }
        }
        success
    }

    // Removed raw IPv4 preference helper; SoftEther dataplane operates on L2 frames.

    pub async fn wait_for(&mut self, ty: v4::MessageType, deadline: Instant, event_cb: Option<&(dyn Fn(u32, String) + Send + Sync)>, iface_name: &str) -> Result<Option<v4::Message>> {
    use dhcproto::v4::Decoder;
        let mut decode_errs_emitted: u32 = 0;
        while Instant::now() < deadline {
            if let Some(frame) = self.rx.recv().await {
                if let Some(view) = extract_dhcp(&frame) {
                    let mut dec = Decoder::new(view.dhcp);
                    match v4::Message::decode(&mut dec) {
                        Ok(msg) => {
                            if msg.xid() != self.xid { if let Some(mt)=msg.opts().msg_type() { if let Some(cb)=event_cb { cb(294, format!("dhcp frame observed mismatched iface={iface_name} our_xid={:#x} frame_xid={:#x} mt={:?}", self.xid, msg.xid(), mt)); } } continue; }
                if msg.opts().msg_type() == Some(ty) {
                    // sanity: chaddr consistency
                    let ch = msg.chaddr();
                    if ch.len() >= 6 && &ch[0..6] != &self.mac {
                        if let Some(cb)=event_cb { cb(294, format!("dhcp chaddr mismatch ({:?}) iface={iface_name} our_mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} frame_mac={}", ty, self.mac[0],self.mac[1],self.mac[2],self.mac[3],self.mac[4],self.mac[5], hex::encode(&ch[0..6]))); }
                    }
                    // learn server identifiers
                    if let Some(m) = view.l2_src { self.server_mac = Some(m); }
                    if let Some(sip) = view.ip_src { self.server_ip_observed = Some(sip); }
                    return Ok(Some(msg));
                }
                        }
                        Err(e) => { 
                            debug!("DHCP decode error: {e}"); 
                            if decode_errs_emitted < 3 { 
                                if let Some(cb)=event_cb { 
                                    cb(2999, format!("dhcp decode error: {e} (frame_len={} dhcp_len={})", frame.len(), view.dhcp.len())); 
                                } 
                                decode_errs_emitted += 1; 
                            }
                            // Add hex dump for decode errors when debugging
                            if std::env::var("RUST_DHCP_DEBUG_FRAMES").ok().as_deref()==Some("1") && decode_errs_emitted <= 1 {
                                let dump_len = view.dhcp.len().min(64);
                                debug!("Failed DHCP decode frame[0..{}]={}", dump_len, hex::encode(&view.dhcp[..dump_len]));
                            }
                        },
                    }
                }
                if std::env::var("RUST_DHCP_DEBUG_FRAMES").ok().as_deref()==Some("1") {
                    let dump_len = frame.len().min(120);
                    debug!("DHCP RX frame[0..{}]={}", dump_len, hex::encode(&frame[..dump_len]));
                }
            } else { break; }
        }
        Ok(None)
    }

    pub fn lease_from_ack(&self, ack: &v4::Message) -> Result<Lease> {
    use dhcproto::v4::{DhcpOption, OptionCode as OC};
        let mut lease = Lease { client_ip: ack.yiaddr(), ..Default::default() };
    if let Some(DhcpOption::ServerIdentifier(ip)) = ack.opts().get(OC::ServerIdentifier) { lease.server_ip = Some(*ip); }
    lease.server_mac = self.server_mac;
    if let Some(DhcpOption::SubnetMask(mask)) = ack.opts().get(OC::SubnetMask) { lease.subnet_mask = Some(*mask); }
    if let Some(DhcpOption::Router(routers)) = ack.opts().get(OC::Router) { if let Some(r) = routers.first() { lease.gateway = Some(*r); } }
    if let Some(DhcpOption::DomainNameServer(servers)) = ack.opts().get(OC::DomainNameServer) { lease.dns_servers.extend(servers.iter().copied()); }
    if let Some(DhcpOption::AddressLeaseTime(secs)) = ack.opts().get(OC::AddressLeaseTime) { 
        lease.lease_time = Some(Duration::from_secs(*secs as u64)); 
        // Calculate renewal and rebinding times based on RFC 2131
        lease.renewal_time = Some(Duration::from_secs((*secs as u64) / 2));
        lease.rebinding_time = Some(Duration::from_secs((*secs as u64) * 7 / 8));
    }
    // Extract additional options
    if let Some(DhcpOption::DomainName(domain)) = ack.opts().get(OC::DomainName) { lease.domain_name = Some(domain.clone()); }
    if let Some(DhcpOption::InterfaceMtu(mtu)) = ack.opts().get(OC::InterfaceMtu) { lease.interface_mtu = Some(*mtu); }
    if let Some(DhcpOption::BroadcastAddr(addr)) = ack.opts().get(OC::BroadcastAddr) { lease.broadcast_addr = Some(*addr); }
    if let Some(DhcpOption::ClasslessStaticRoute(routes)) = ack.opts().get(OC::ClasslessStaticRoute) { lease.classless_routes.extend(routes.iter().copied()); }
    
    // Apply Go-style fallback logic for missing critical fields
    lease = self.apply_go_fallback_logic(lease);
    
    Ok(lease)
    }

    /// Apply Go implementation fallback logic for incomplete DHCP responses
    fn apply_go_fallback_logic(&self, mut lease: Lease) -> Lease {
        // Subnet mask inference (key Go innovation)
        if lease.subnet_mask.is_none() {
            lease.subnet_mask = Some(self.infer_subnet_mask_go_style(&lease));
        }

        // Gateway fallback (use server if no router provided)
        if lease.gateway.is_none() && lease.server_ip.is_some() {
            lease.gateway = lease.server_ip;
        }

        // DNS fallback (use gateway/server as DNS when not provided)
        if lease.dns_servers.is_empty() {
            if let Some(gateway) = lease.gateway {
                lease.dns_servers.push(gateway);
            } else if let Some(server) = lease.server_ip {
                lease.dns_servers.push(server);
            }
        }

        lease
    }

    /// Infer subnet mask using Go implementation logic
    fn infer_subnet_mask_go_style(&self, lease: &Lease) -> Ipv4Addr {
        let client_octets = lease.client_ip.octets();
        
        if let Some(server_ip) = lease.server_ip {
            let server_octets = server_ip.octets();
            
            // Same Class B network - likely /16 (Go logic)
            if client_octets[0] == server_octets[0] && client_octets[1] == server_octets[1] {
                return Ipv4Addr::new(255, 255, 0, 0);
            }
            
            // Same Class C network - likely /24 (Go logic)
            if client_octets[0] == server_octets[0] && 
               client_octets[1] == server_octets[1] && 
               client_octets[2] == server_octets[2] {
                return Ipv4Addr::new(255, 255, 255, 0);
            }
        }
        
        // Default assumption for VPN networks (Go logic)
        Ipv4Addr::new(255, 255, 0, 0)
    }
}

struct DhcpView<'a> {
    dhcp: &'a [u8],
    l2_src: Option<[u8;6]>,
    ip_src: Option<Ipv4Addr>,
}

fn extract_dhcp(frame: &[u8]) -> Option<DhcpView<'_>> {
    // Validate minimum frame size first
    if frame.len() < 42 { // Minimum Ethernet(14) + IPv4(20) + UDP(8)
        return None;
    }
    
    // Try Ethernet + IPv4 first
    if frame.len() >= 14 + 20 + 8 {
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if ethertype == 0x0800 {
            let ip = &frame[14..];
            if ip.len() >= 20 && ip[9] == 17 {
                let ihl = (ip[0] & 0x0f) as usize * 4;
                if ihl >= 20 && ip.len() >= ihl + 8 {
                    let udp = &ip[ihl..];
                    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
                    // Validate UDP length
                    if udp_len >= 8 && udp.len() >= udp_len && udp_len >= 8 + 240 { // Min DHCP size
                        let src = u16::from_be_bytes([udp[0], udp[1]]);
                        let dst = u16::from_be_bytes([udp[2], udp[3]]);
                        if (src == 67 || src == 68) || (dst == 67 || dst == 68) {
                            let mut mac = [0u8;6]; 
                            mac.copy_from_slice(&frame[6..12]);
                            let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
                            let dhcp_payload = &udp[8..udp_len];
                            // Basic DHCP validation: check magic cookie
                            if dhcp_payload.len() >= 240 && dhcp_payload.len() >= 236 + 4 {
                                let magic = u32::from_be_bytes([dhcp_payload[236], dhcp_payload[237], dhcp_payload[238], dhcp_payload[239]]);
                                if magic == 0x63825363 { // DHCP magic cookie
                                    return Some(DhcpView{ dhcp: dhcp_payload, l2_src: Some(mac), ip_src: Some(src_ip) });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Fallback: assume raw IPv4 without Ethernet header
    if frame.len() >= 20 + 8 {
        let v = frame[0] >> 4;
        if v == 4 {
            let ihl = (frame[0] & 0x0f) as usize * 4;
            if frame.len() >= ihl + 8 && frame[9] == 17 {
                let udp = &frame[ihl..];
                let src = u16::from_be_bytes([udp[0], udp[1]]);
                let dst = u16::from_be_bytes([udp[2], udp[3]]);
                if (src == 67 || src == 68) || (dst == 67 || dst == 68) {
                    let src_ip = Ipv4Addr::new(frame[12], frame[13], frame[14], frame[15]);
                    return Some(DhcpView{ dhcp: &udp[8..], l2_src: None, ip_src: Some(src_ip) });
                }
            }
        }
    }
    None
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0; let mut i = 0;
    while i+1 < header.len() { sum += u16::from_be_bytes([header[i],header[i+1]]) as u32; i+=2; }
    if i < header.len() { sum += (header[i] as u32) << 8; }
    while (sum >> 16) != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_dhcp_eth_ipv4() {
        // Build minimal Ethernet+IPv4+UDP header carrying BOOTP payload marker (just zeros)
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]); // dst
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype IPv4
        // IPv4 header 20 bytes
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; // v4, ihl=5
        ip[9] = 17; // UDP
        // fill src/dst later
        // UDP header 8 bytes + payload 4 bytes
        let mut udp = Vec::new();
        udp.extend_from_slice(&68u16.to_be_bytes());
        udp.extend_from_slice(&67u16.to_be_bytes());
        udp.extend_from_slice(&(8u16 + 4).to_be_bytes()); // length
        udp.extend_from_slice(&0u16.to_be_bytes()); // checksum
        udp.extend_from_slice(&[0u8; 4]);
        // finalize IP header
        let total_len = 20 + udp.len();
        ip[2] = ((total_len as u16) >> 8) as u8; ip[3] = (total_len as u16 & 0xff) as u8;
        let csum = super::ipv4_checksum(&ip);
        ip[10] = (csum >> 8) as u8; ip[11] = (csum & 0xff) as u8;
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&udp);
    assert!(extract_dhcp(&frame).map(|v| v.dhcp).is_some());
    }

    #[test]
    fn test_extract_dhcp_raw_ipv4() {
        // Build raw IPv4+UDP header
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; ip[9] = 17; // v4, UDP
        let mut udp = Vec::new();
        udp.extend_from_slice(&68u16.to_be_bytes());
        udp.extend_from_slice(&67u16.to_be_bytes());
        udp.extend_from_slice(&(8u16 + 4).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(&[0u8; 4]);
        let total_len = 20 + udp.len();
        ip[2] = ((total_len as u16) >> 8) as u8; ip[3] = (total_len as u16 & 0xff) as u8;
        let csum = super::ipv4_checksum(&ip);
        ip[10] = (csum >> 8) as u8; ip[11] = (csum & 0xff) as u8;
        let mut frame = Vec::new(); frame.extend_from_slice(&ip); frame.extend_from_slice(&udp);
    assert!(extract_dhcp(&frame).map(|v| v.dhcp).is_some());
    }

    #[test]
    fn test_extract_dhcp_short_frame() { assert!(extract_dhcp(&[0u8; 10]).is_none()); }
}