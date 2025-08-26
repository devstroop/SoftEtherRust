use anyhow::{Result, Context};
use dhcproto::v6::{Encodable, MessageType as MT, OptionCode, IANA};
use dhcproto::Decodable; // bring trait into scope for Message::decode
use tokio::sync::mpsc;
use std::time::{Duration, Instant};
use std::net::Ipv6Addr;
use cedar::DataPlane;
use tracing::{debug,info,warn};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct LeaseV6 {
    pub addr: Option<Ipv6Addr>,
    pub dns_servers: Vec<Ipv6Addr>,
    pub preferred_lifetime: Option<Duration>,
    pub valid_lifetime: Option<Duration>,
    pub t1: Option<Duration>,
    pub t2: Option<Duration>,
    pub server_id: Option<Vec<u8>>, // raw server DUID
    pub client_duid: Vec<u8>,
    pub iaid: u32,
    pub acquired_at: Option<u64>,
}

pub struct DhcpV6Client {
    dp: DataPlane,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pub duid: Vec<u8>,
    pub iaid: u32,
    pub xid: [u8;3],
}

impl DhcpV6Client {
    pub fn new(dp: DataPlane, mac: [u8;6]) -> Self {
        use rand::RngCore; // DUID-LLT simplified
        let mut rnd=[0u8;2]; rand::rng().fill_bytes(&mut rnd);
        let mut duid=Vec::with_capacity(2+2+mac.len());
        duid.extend_from_slice(&[0x00,0x01]);
        duid.extend_from_slice(&rnd);
        duid.extend_from_slice(&mac);
        let iaid = rand::random::<u32>();
        let xid: [u8;3] = rand::random();
        let (tx, rx) = mpsc::unbounded_channel();
        dp.set_rx_tap(tx);
        Self { dp, rx, duid, iaid, xid }
    }

    pub fn new_with_ids(dp: DataPlane, _mac: [u8;6], duid: Vec<u8>, iaid: u32) -> Self {
        let xid: [u8;3] = rand::random();
        let (tx, rx) = mpsc::unbounded_channel();
        dp.set_rx_tap(tx);
        Self { dp, rx, duid, iaid, xid }
    }

    pub fn dataplane(&self) -> DataPlane { self.dp.clone() }

    fn build_solicit(&self) -> Result<Vec<u8>> {
        use dhcproto::v6::{Message, DhcpOption, ORO};
        let mut msg = Message::new(MT::Solicit);
        msg.set_xid(self.xid);
        let mut oro = Vec::new();
        oro.push(OptionCode::DomainNameServers);
        msg.opts_mut().insert(DhcpOption::ClientId(self.duid.clone()));
        msg.opts_mut().insert(DhcpOption::ORO(ORO{opts:oro}));
        msg.opts_mut().insert(DhcpOption::IANA(IANA{ id:self.iaid, t1:0, t2:0, opts: Default::default()}));
        self.wrap_ipv6_udp(&msg)
    }

    fn build_request(&self, advertise: &dhcproto::v6::Message) -> Result<Vec<u8>> {
        use dhcproto::v6::{Message, DhcpOption};
        let mut msg = Message::new(MT::Request);
        msg.set_xid(self.xid);
        msg.opts_mut().insert(DhcpOption::ClientId(self.duid.clone()));
        if let Some(DhcpOption::ServerId(sid)) = advertise.opts().get(OptionCode::ServerId) {
            msg.opts_mut().insert(DhcpOption::ServerId(sid.clone()));
        }
        if let Some(DhcpOption::IANA(iana_adv)) = advertise.opts().get(OptionCode::IANA) {
            msg.opts_mut().insert(DhcpOption::IANA(iana_adv.clone()));
        }
        self.wrap_ipv6_udp(&msg)
    }

    pub fn build_renew(&self, lease: &LeaseV6) -> Result<Vec<u8>> {
        use dhcproto::v6::{Message, DhcpOption};
        let mut msg = Message::new(MT::Renew);
        msg.set_xid(rand::random());
        msg.opts_mut().insert(DhcpOption::ClientId(self.duid.clone()));
        if let Some(sid)=&lease.server_id { msg.opts_mut().insert(DhcpOption::ServerId(sid.clone())); }
        msg.opts_mut().insert(DhcpOption::IANA(IANA{ id: lease.iaid, t1:0, t2:0, opts: Default::default()}));
        self.wrap_ipv6_udp(&msg)
    }

    fn wrap_ipv6_udp(&self, msg: &dhcproto::v6::Message) -> Result<Vec<u8>> {
        use dhcproto::v6::Encoder;
        let mut dhcp_buf=Vec::new();
        let mut enc=Encoder::new(&mut dhcp_buf); msg.encode(&mut enc).context("encode dhcpv6")?;
        let src_port=546u16; let dst_port=547u16; let udp_len = 8 + dhcp_buf.len();
        let mut udp = Vec::with_capacity(8+dhcp_buf.len());
        udp.extend_from_slice(&src_port.to_be_bytes());
        udp.extend_from_slice(&dst_port.to_be_bytes());
        udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(&dhcp_buf);
        let mut ipv6 = Vec::with_capacity(40+udp.len());
    let ver_tc_fl: u32 = 6 << 28;
        ipv6.extend_from_slice(&ver_tc_fl.to_be_bytes());
        ipv6.extend_from_slice(&(udp_len as u16).to_be_bytes());
        ipv6.push(17); ipv6.push(1);
        let src = [0u8;16];
        let dst = multicast_addr().octets();
        ipv6.extend_from_slice(&src); ipv6.extend_from_slice(&dst);
        let csum = ipv6_udp_checksum(&src, &dst, &udp);
        udp[6]=(csum>>8) as u8; udp[7]=(csum & 0xff) as u8;
        ipv6.extend_from_slice(&udp);
        let mut eth = Vec::with_capacity(14+ipv6.len());
        eth.extend_from_slice(&[0x33,0x33,0x00,0x01,0x00,0x02]);
        eth.extend_from_slice(&[0u8;6]);
        eth.extend_from_slice(&0x86DDu16.to_be_bytes());
        eth.extend_from_slice(&ipv6);
        Ok(eth)
    }

    pub fn send_frame(&self, frame: Vec<u8>) { if !self.dp.send_frame(frame) { warn!("DHCPv6 frame send failed (no link)"); } }

    pub async fn wait_for(&mut self, ty: MT, deadline: Instant) -> Result<Option<dhcproto::v6::Message>> {
        use dhcproto::v6::Decoder;
        while Instant::now() < deadline {
            if let Some(frame)=self.rx.recv().await {
                if let Some(dhcp_bytes)=extract_dhcpv6(&frame) {
                    let mut dec=Decoder::new(dhcp_bytes);
                    if let Ok(msg)=dhcproto::v6::Message::decode(&mut dec) {
                        if msg.xid()!=self.xid { continue; }
                        if msg.msg_type()==ty { return Ok(Some(msg)); }
                    }
                }
            } else { break; }
        }
        Ok(None)
    }

    pub fn lease_from_reply(&self, reply: &dhcproto::v6::Message) -> LeaseV6 {
        use dhcproto::v6::{OptionCode as OC, DhcpOption};
        let mut lease=LeaseV6{ iaid:self.iaid, client_duid:self.duid.clone(), acquired_at: Some(current_unix_secs()), ..Default::default() };
        if let Some(DhcpOption::ServerId(sid)) = reply.opts().get(OC::ServerId) { lease.server_id=Some(sid.clone()); }
        if let Some(DhcpOption::IANA(iana)) = reply.opts().get(OC::IANA) {
            if iana.t1!=0 { lease.t1=Some(Duration::from_secs(iana.t1 as u64)); }
            if iana.t2!=0 { lease.t2=Some(Duration::from_secs(iana.t2 as u64)); }
            for opt in iana.opts.iter() {
                if let DhcpOption::IAAddr(addr_opt)=opt { lease.addr=Some(addr_opt.addr); lease.preferred_lifetime=Some(Duration::from_secs(addr_opt.preferred_life as u64)); lease.valid_lifetime=Some(Duration::from_secs(addr_opt.valid_life as u64)); }
            }
        }
        if let Some(DhcpOption::DomainNameServers(dns)) = reply.opts().get(OC::DomainNameServers) { lease.dns_servers = dns.clone(); }
        if lease.t1.is_none() || lease.t2.is_none() {
            if let Some(pref)=lease.preferred_lifetime { let t1d=pref/2; let t2d=pref*4/5; if lease.t1.is_none(){ lease.t1=Some(t1d);} if lease.t2.is_none(){ lease.t2=Some(t2d);} }
        }
        lease
    }

    pub async fn run_once(&mut self, timeout_total: Duration) -> Result<Option<LeaseV6>> {
        let solicit = self.build_solicit()?; self.send_frame(solicit); debug!("DHCPv6 SOLICIT sent");
        let deadline = Instant::now()+timeout_total;
        let adv = match self.wait_for(MT::Advertise, deadline).await? { Some(m)=>m, None=> return Ok(None)};
        let req = self.build_request(&adv)?; self.send_frame(req); debug!("DHCPv6 REQUEST sent");
        if let Some(rep)=self.wait_for(MT::Reply, deadline).await? { let lease=self.lease_from_reply(&rep); info!("DHCPv6 lease addr={:?} dns={:?}", lease.addr, lease.dns_servers); return Ok(Some(lease)); }
        Ok(None)
    }
}

fn multicast_addr() -> Ipv6Addr { Ipv6Addr::new(0xff02,0,0,0,0,0,0x1,0x0002) }

fn extract_dhcpv6(frame: &[u8]) -> Option<&[u8]> {
    if frame.len()<14+40+8 { return None; }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]); if ethertype!=0x86DD { return None; }
    let ipv6=&frame[14..]; if ipv6.len()<40 { return None; }
    let next = ipv6[6]; if next!=17 { return None; }
    let payload_len = u16::from_be_bytes([ipv6[4],ipv6[5]]) as usize; if ipv6.len()<40+payload_len { return None; }
    let udp=&ipv6[40..40+payload_len]; if udp.len()<8 { return None; }
    let src_port=u16::from_be_bytes([udp[0],udp[1]]); let dst_port=u16::from_be_bytes([udp[2],udp[3]]);
    if !((src_port==546||src_port==547)&&(dst_port==546||dst_port==547)) { return None; }
    Some(&udp[8..])
}

fn ipv6_udp_checksum(src:&[u8;16], dst:&[u8;16], udp:&[u8]) -> u16 {
    let mut sum:u32=0;
    for chunk in src.chunks_exact(2) { sum += u16::from_be_bytes([chunk[0],chunk[1]]) as u32; }
    for chunk in dst.chunks_exact(2) { sum += u16::from_be_bytes([chunk[0],chunk[1]]) as u32; }
    let len = udp.len() as u32; sum += ((len>>16) as u16) as u32; sum += (len as u16) as u32;
    sum += 17; 
    let mut chunks = udp.chunks_exact(2);
    for c in &mut chunks { sum += u16::from_be_bytes([c[0],c[1]]) as u32; }
    if let Some(rem)=chunks.remainder().first() { sum += ((*rem as u16) << 8) as u32; }
    while (sum>>16)!=0 { sum = (sum & 0xffff) + (sum>>16); }
    !(sum as u16)
}

fn current_unix_secs() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() }

impl DhcpV6Client {
    pub fn build_rebind(&self, lease: &LeaseV6) -> Result<Vec<u8>> {
        use dhcproto::v6::{Message, DhcpOption};
        let mut msg = Message::new(MT::Rebind);
        msg.set_xid(rand::random());
        msg.opts_mut().insert(DhcpOption::ClientId(self.duid.clone()));
        msg.opts_mut().insert(DhcpOption::IANA(IANA{ id: lease.iaid, t1:0, t2:0, opts: Default::default()}));
        self.wrap_ipv6_udp(&msg)
    }
}
