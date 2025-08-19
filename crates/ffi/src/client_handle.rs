use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::arp::{build_arp_request, ArpManager, ProbeState};
use crate::callbacks::{emit_event, EventCb, IpRxCb, RxCb, StateCb};
use crate::utils::{eth_to_ipv4, mac_to_string, pad_eth_min};
use vpnclient::VpnClient;

pub(crate) struct ClientHandle {
    pub rt: Runtime,
    pub client: Arc<Mutex<VpnClient>>, // guarded for FFI concurrency
    // Frame channels (optional wiring for future use)
    pub adapter_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    pub rx_cb: Arc<Mutex<Option<RxCb>>>,
    pub ip_rx_cb: Arc<Mutex<Option<IpRxCb>>>,
    pub state_cb: Arc<Mutex<Option<Arc<StateCb>>>>,
    pub event_cb: Arc<Mutex<Option<Arc<EventCb>>>>,
    // Track spawned tasks to allow explicit cleanup
    pub tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    // Guard to prevent duplicate demux tasks
    pub demux_running: Arc<Mutex<bool>>,
    // Last error message for diagnostics retrieval
    pub last_error: Arc<Mutex<Option<String>>>,
    // Session-scope L2/L3 parameters
    pub mac: [u8; 6],
    pub assigned_ip: Arc<Mutex<Option<Ipv4Addr>>>,
    pub netmask: Arc<Mutex<Option<Ipv4Addr>>>,
    pub gateway: Arc<Mutex<Option<Ipv4Addr>>>,
    // Simple ARP manager
    pub arp: Arc<Mutex<ArpManager>>,
    // ARP probe/backoff state for unresolved next-hops
    pub arp_probes: Arc<Mutex<std::collections::HashMap<Ipv4Addr, ProbeState>>>,
}

impl ClientHandle {
    /// Ensure a single adapter_rx channel is wired and a demux task is spawned
    /// that forwards L2 frames to rx_cb and IPv4 payloads to ip_rx_cb when set.
    pub fn ensure_adapter_rx(&mut self) {
        // prevent duplicates
        {
            let running = self.demux_running.lock().unwrap();
            if *running {
                return;
            }
        }
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        {
            let mut g = self.adapter_tx.lock().unwrap();
            if g.is_some() {
                return; // already initialized by a previous call
            }
            *g = Some(tx.clone());
        }
        // mark running
        {
            let mut running = self.demux_running.lock().unwrap();
            *running = true;
        }
        let rx_cb = self.rx_cb.clone();
        let ip_cb = self.ip_rx_cb.clone();
        let demux_flag = self.demux_running.clone();
        let arp_mgr = self.arp.clone();
        let client_arc2 = self.client.clone();
        let src_mac = self.mac; // stable LAA for this client handle
        let my_ip_arc = self.assigned_ip.clone();
        let probes = self.arp_probes.clone();
        let ev_cb = self.event_cb.clone();
        // Shared helper for demux
        let handle = self.rt.spawn(async move {
            while let Some(frame) = rx.recv().await {
                // Feed ARP manager for learning and flushing pending frames
                {
                    let mut mgr = arp_mgr.lock().unwrap();
                    let (resolved_ip, _mac, flush) = mgr.on_frame(&frame);
                    drop(mgr);
                    if let Some((nh, mac, batch)) = flush {
                        // Send pending frames now that we know MAC
                        let c = client_arc2.lock().unwrap();
                        let count = batch.len();
                        if let Some(dp) = c.dataplane() {
                            for ip in batch {
                                let mut eth = Vec::with_capacity(14 + ip.len());
                                eth.extend_from_slice(&mac);
                                eth.extend_from_slice(&src_mac);
                                eth.extend_from_slice(&0x0800u16.to_be_bytes());
                                eth.extend_from_slice(&ip);
                                let _ = dp.send_frame(pad_eth_min(eth));
                            }
                        }
                        // Emit light event so embedders can observe the flush
                        emit_event(
                            &ev_cb,
                            0,   // info
                            901, // ARP flush event code (custom)
                            &format!(
                                "flushed {} pending IPv4 packet(s) for next-hop {} via {}",
                                count,
                                nh,
                                mac_to_string(&mac)
                            ),
                        );
                    }
                    if let Some(ip) = resolved_ip {
                        // Stop probing once resolved
                        probes.lock().unwrap().remove(&ip);
                    }
                }
                // ARP responder: if it's an ARP request for our IP, reply so peers learn our MAC
                if frame.len() >= 14 + 28 {
                    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
                    if ethertype == 0x0806 {
                        let off = 14;
                        // Verify Ethernet ARP/IPv4 with hlen=6, plen=4
                        if frame[off + 0] == 0x00
                            && frame[off + 1] == 0x01
                            && frame[off + 2] == 0x08
                            && frame[off + 3] == 0x00
                            && frame[off + 4] == 0x06
                            && frame[off + 5] == 0x04
                        {
                            let oper = u16::from_be_bytes([frame[off + 6], frame[off + 7]]);
                            if oper == 1 {
                                // ARP request: who-has tpa? tell spa
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
                                let tpa = Ipv4Addr::new(
                                    frame[off + 24],
                                    frame[off + 25],
                                    frame[off + 26],
                                    frame[off + 27],
                                );
                                let my_ip_opt = my_ip_arc.lock().unwrap().clone();
                                if let Some(my_ip) = my_ip_opt {
                                    if tpa == my_ip {
                                        // Build ARP reply: SHA=our mac, SPA=our ip, THA=sender mac, TPA=sender ip
                                        let mut arp = Vec::with_capacity(14 + 28);
                                        // Ethernet: dst=sender MAC, src=our MAC, type=ARP
                                        arp.extend_from_slice(&sha);
                                        arp.extend_from_slice(&src_mac);
                                        arp.extend_from_slice(&0x0806u16.to_be_bytes());
                                        // ARP payload: htype=1, ptype=0x0800, hlen=6, plen=4, oper=2 (reply)
                                        arp.extend_from_slice(&0x0001u16.to_be_bytes());
                                        arp.extend_from_slice(&0x0800u16.to_be_bytes());
                                        arp.push(6);
                                        arp.push(4);
                                        arp.extend_from_slice(&0x0002u16.to_be_bytes());
                                        // sha, spa, tha, tpa
                                        arp.extend_from_slice(&src_mac);
                                        arp.extend_from_slice(&my_ip.octets());
                                        arp.extend_from_slice(&sha);
                                        arp.extend_from_slice(&spa.octets());
                                        let c = client_arc2.lock().unwrap();
                                        if let Some(dp) = c.dataplane() {
                                            let _ = dp.send_frame(pad_eth_min(arp));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // L2 callback if present
                if let Some(cb) = *rx_cb.lock().unwrap() {
                    (cb.func)(frame.as_ptr(), frame.len() as u32, cb.user);
                }
                // IPv4 demux
                if let Some(ip) = eth_to_ipv4(&frame) {
                    if let Some(cb) = *ip_cb.lock().unwrap() {
                        (cb.func)(ip.as_ptr(), ip.len() as u32, cb.user);
                    }
                }
            }
            // mark not running when channel closes
            *demux_flag.lock().unwrap() = false;
        });
        // track task
        self.tasks.lock().unwrap().push(handle);
        // Attach to dataplane if available
        let client_arc = self.client.clone();
        let tx2 = tx.clone();
        let _ = self.rt.block_on(async move {
            let c = client_arc.lock().unwrap();
            if let Some(dp) = c.dataplane() {
                dp.set_adapter_rx(tx2);
            }
        });

        // Spawn ARP retry worker
        let client_arc3 = self.client.clone();
        let arp_mgr2 = self.arp.clone();
        let probes2 = self.arp_probes.clone();
        let my_ip_arc2 = self.assigned_ip.clone();
        let src_mac2 = self.mac;
        let h = self.rt.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;
                let my_ip = my_ip_arc2
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
                // Snapshot keys to probe outside locks
                let keys: Vec<Ipv4Addr> = {
                    let mut rm: Vec<Ipv4Addr> = Vec::new();
                    let tbl = arp_mgr2.lock().unwrap();
                    let mut pr = probes2.lock().unwrap();
                    // Remove any keys that now have a MAC
                    for k in pr.keys().cloned().collect::<Vec<_>>() {
                        if tbl.lookup(k).is_some() {
                            rm.push(k);
                        }
                    }
                    for k in rm.iter() {
                        pr.remove(k);
                    }
                    pr.keys().cloned().collect()
                };
                if keys.is_empty() {
                    continue;
                }
                for nh in keys {
                    let mut send_now = false;
                    {
                        let mut pr = probes2.lock().unwrap();
                        let st = pr.entry(nh).or_insert_with(|| ProbeState {
                            last: Instant::now() - Duration::from_secs(10),
                            interval: Duration::from_millis(250),
                        });
                        if st.last.elapsed() >= st.interval {
                            send_now = true;
                            // backoff up to 5s
                            st.interval = std::cmp::min(st.interval * 2, Duration::from_secs(5));
                            st.last = Instant::now();
                        }
                    }
                    if send_now {
                        let arp = build_arp_request(src_mac2, my_ip, nh);
                        let c = client_arc3.lock().unwrap();
                        if let Some(dp) = c.dataplane() {
                            let _ = dp.send_frame(arp);
                        }
                    }
                }
            }
        });
        self.tasks.lock().unwrap().push(h);
    }
}
