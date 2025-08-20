use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine; // for STANDARD.decode()
use serde::Deserialize;
use tokio::runtime::Builder;
use tokio::sync::mpsc;

use config::ClientConfig as SharedConfig;
use vpnclient::{settings_json_with_kind, ClientEvent, ClientState, EventLevel};

use crate::arp::{ArpManager, ProbeState};
use crate::callbacks::{emit_event, EventCb, IpRxCb, RxCb, StateCb};
use crate::client_handle::ClientHandle;
use crate::utils::{derive_laa_mac_from_seed, pad_eth_min};

#[derive(Deserialize)]
struct FfiConfig {
    // mirror of config::ClientConfig; keep minimal for now
    server: String,
    port: u16,
    hub: String,
    username: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    password_hash: Option<String>,
    #[serde(default)]
    skip_tls_verify: bool,
    #[serde(default = "default_true")]
    use_compress: bool,
    #[serde(default = "default_true")]
    use_encrypt: bool,
    #[serde(default = "default_max_conn")]
    max_connections: u32,
}

fn default_true() -> bool {
    true
}
fn default_max_conn() -> u32 {
    1
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct softether_client_t {
    _private: [u8; 0],
}

fn make_shared_config(c: FfiConfig) -> SharedConfig {
    SharedConfig {
        server: c.server,
        port: c.port,
        hub: c.hub,
        username: c.username,
        password: c.password,
        password_hash: c.password_hash,
        skip_tls_verify: c.skip_tls_verify,
        use_compress: c.use_compress,
        use_encrypt: c.use_encrypt,
        max_connections: c.max_connections,
        udp_port: None,
    }
}

#[no_mangle]
pub extern "C" fn softether_client_create(json_config: *const c_char) -> *mut softether_client_t {
    if json_config.is_null() {
        return ptr::null_mut();
    }
    let cstr = unsafe { CStr::from_ptr(json_config) };
    let json = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let parsed: FfiConfig = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };

    // Build runtime
    let rt = match Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(_) => return ptr::null_mut(),
    };

    // Keep identity fields for MAC derivation before moving parsed
    let seed_server = parsed.server.clone();
    let seed_hub = parsed.hub.clone();
    let seed_username = parsed.username.clone();

    // Build vpnclient from shared config
    let cc = make_shared_config(parsed);
    let client = match vpnclient::VpnClient::from_shared_config(cc) {
        Ok(c) => c,
        Err(_) => return ptr::null_mut(),
    };

    // Derive a stable, locally-administered MAC from identity tuple (server|hub|username)
    let mac: [u8; 6] = {
        let ident = format!("{}|{}|{}", seed_server, seed_hub, seed_username);
        derive_laa_mac_from_seed(ident.as_bytes())
    };

    let handle = ClientHandle {
        rt,
        client: Arc::new(Mutex::new(client)),
        adapter_tx: Arc::new(Mutex::new(None)),
        rx_cb: Arc::new(Mutex::new(None)),
        ip_rx_cb: Arc::new(Mutex::new(None)),
        state_cb: Arc::new(Mutex::new(None)),
        event_cb: Arc::new(Mutex::new(None)),
        tasks: Arc::new(Mutex::new(Vec::new())),
        demux_running: Arc::new(Mutex::new(false)),
        last_error: Arc::new(Mutex::new(None)),
        mac,
        assigned_ip: Arc::new(Mutex::new(None)),
        netmask: Arc::new(Mutex::new(None)),
        gateway: Arc::new(Mutex::new(None)),
        arp: Arc::new(Mutex::new(ArpManager::default())),
        arp_probes: Arc::new(Mutex::new(std::collections::HashMap::new())),
    };
    Box::into_raw(Box::new(handle)) as *mut softether_client_t
}

#[no_mangle]
pub extern "C" fn softether_client_connect(handle: *mut softether_client_t) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let h = unsafe { &mut *(handle as *mut ClientHandle) };
    let client_arc = h.client.clone();
    let res = h.rt.block_on(async move {
        let mut c = client_arc.lock().unwrap();
        c.connect().await
    });
    let code = match res {
        Ok(_) => 0,
        Err(e) => {
            // Surface a descriptive error event to embedders
            {
                let mut le = h.last_error.lock().unwrap();
                *le = Some(format!("connect error: {}", e));
            }
            if let Some(msg) = h.last_error.lock().unwrap().clone() {
                if let Ok(cmsg) = CString::new(msg) {
                    if let Some(cb) = h.event_cb.lock().unwrap().as_ref().cloned() {
                        (cb.func)(2, 500, cmsg.as_ptr(), cb.user);
                    }
                }
            }
            -2
        }
    };
    if code == 0 {
        // If we had an RX callback registered before connect, wire the adapter sink now
        let client_arc2 = h.client.clone();
        let tx_opt = h.adapter_tx.lock().unwrap().clone();
        let _ = h.rt.block_on(async move {
            if let Some(tx) = tx_opt {
                let c = client_arc2.lock().unwrap();
                if let Some(dp) = c.dataplane() {
                    dp.set_adapter_rx(tx);
                }
            }
        });
        // No direct event emission here; rely on VpnClient's internal event channel (1001) if configured.
    }
    code
}

/// Register an event callback and subscribe the client to event stream.
#[no_mangle]
pub extern "C" fn softether_client_set_event_callback(
    handle: *mut softether_client_t,
    cb: Option<extern "C" fn(i32, i32, *const c_char, *mut std::ffi::c_void)>,
    user: *mut std::ffi::c_void,
) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let h = unsafe { &mut *(handle as *mut ClientHandle) };
    if let Some(func) = cb {
        *h.event_cb.lock().unwrap() = Some(Arc::new(EventCb { func, user }));
    } else {
        *h.event_cb.lock().unwrap() = None;
    }

    let (tx, mut rx) = mpsc::unbounded_channel::<ClientEvent>();
    {
        let mut c = h.client.lock().unwrap();
        c.set_event_channel(tx);
    }
    if let Some(cb) = h.event_cb.lock().unwrap().as_ref().cloned() {
        let handle = h.rt.spawn(async move {
            let cb_local = cb; // Arc<EventCb>
            while let Some(ev) = rx.recv().await {
                let level = match ev.level {
                    EventLevel::Info => 0,
                    EventLevel::Warn => 1,
                    EventLevel::Error => 2,
                };
                let cstr = CString::new(ev.message).unwrap_or_else(|_| CString::new("").unwrap());
                (cb_local.func)(level, ev.code, cstr.as_ptr(), cb_local.user);
            }
        });
        h.tasks.lock().unwrap().push(handle);
    }
    0
}

/// Get current network settings as a JSON string. Caller must free with softether_string_free.
#[no_mangle]
pub extern "C" fn softether_client_get_network_settings_json(
    handle: *mut softether_client_t,
) -> *mut c_char {
    if handle.is_null() {
        return ptr::null_mut();
    }
    let h = unsafe { &mut *(handle as *mut ClientHandle) };
    let client_arc = h.client.clone();
    let (s, ip, mask, gw) = h.rt.block_on(async move {
        let c = client_arc.lock().unwrap();
        let ns = c.get_network_settings();
        let s = settings_json_with_kind(ns.as_ref(), false);
        let (ip, mask, gw) = if let Some(ref ns) = ns {
            (ns.assigned_ipv4, ns.subnet_mask, ns.gateway)
        } else {
            (None, None, None)
        };
        (s, ip, mask, gw)
    });
    // Store L3 parameters for IP-mode
    {
        if let Some(ip) = ip {
            *h.assigned_ip.lock().unwrap() = Some(ip);
        }
        if let Some(m) = mask {
            *h.netmask.lock().unwrap() = Some(m);
        }
        if let Some(g) = gw {
            *h.gateway.lock().unwrap() = Some(g);
        }
    }
    CString::new(s)
        .map(|cs| cs.into_raw())
        .unwrap_or(ptr::null_mut())
}

/// Validate Base64 and decode into out_buf; returns number of bytes or negative error.
#[no_mangle]
pub extern "C" fn softether_b64_decode(
    b64: *const c_char,
    out_buf: *mut u8,
    out_cap: u32,
) -> c_int {
    if b64.is_null() || out_buf.is_null() {
        return -1;
    }
    let s = unsafe { CStr::from_ptr(b64) };
    let Ok(text) = s.to_str() else {
        return -2;
    };
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(text) else {
        return -3;
    };
    let cap = out_cap as usize;
    if bytes.len() > cap {
        return -4;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
    }
    bytes.len() as c_int
}

#[no_mangle]
pub extern "C" fn softether_client_disconnect(handle: *mut softether_client_t) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let h = unsafe { &mut *(handle as *mut ClientHandle) };
    let client_arc = h.client.clone();
    let res = h.rt.block_on(async move {
        let mut c = client_arc.lock().unwrap();
        c.disconnect().await
    });
    match res {
        Ok(_) => 0,
        Err(_) => -2,
    }
}

#[no_mangle]
pub extern "C" fn softether_client_free(handle: *mut softether_client_t) {
    if handle.is_null() {
        return;
    }
    unsafe {
        let boxed = Box::from_raw(handle as *mut ClientHandle);
        // Best-effort graceful disconnect
        let client_arc = boxed.client.clone();
        let _ = boxed.rt.block_on(async move {
            let mut c = client_arc.lock().unwrap();
            let _ = c.disconnect().await;
        });
        // Abort spawned tasks owned by FFI
        let tasks = std::mem::take(&mut *boxed.tasks.lock().unwrap());
        for t in tasks {
            t.abort();
        }
        // Drop occurs here
    }
}

/// Optional: retrieve a simple status string for diagnostics
#[no_mangle]
pub extern "C" fn softether_client_version() -> *mut c_char {
    let s = format!(
        "SoftEther Rust Client FFI v{}.{}",
        vpnclient::CLIENT_VERSION,
        vpnclient::CLIENT_BUILD
    );
    CString::new(s).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn softether_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}

/// Retrieve the LAA MAC used by this client. Writes 6 bytes into out_buf.
#[no_mangle]
pub extern "C" fn softether_client_get_mac(
    handle: *mut softether_client_t,
    out_buf: *mut u8,
) -> c_int {
    if handle.is_null() || out_buf.is_null() {
        return -1;
    }
    let h = unsafe { &mut *(handle as *mut ClientHandle) };
    unsafe {
        std::ptr::copy_nonoverlapping(h.mac.as_ptr(), out_buf, 6);
    }
    0
}

/// Retrieve and clear the last error message (if any). Caller must free with softether_string_free.
#[no_mangle]
pub extern "C" fn softether_client_last_error(handle: *mut softether_client_t) -> *mut c_char {
    if handle.is_null() {
        return ptr::null_mut();
    }
    let h = unsafe { &mut *(handle as *mut ClientHandle) };
    let msg = {
        let mut g = h.last_error.lock().unwrap();
        g.take()
    };
    if let Some(m) = msg {
        CString::new(m)
            .map(|cs| cs.into_raw())
            .unwrap_or(ptr::null_mut())
    } else {
        ptr::null_mut()
    }
}

/// Register an RX callback to receive frames from the tunnel.
#[no_mangle]
pub extern "C" fn softether_client_set_rx_callback(
    handle: *mut softether_client_t,
    cb: Option<extern "C" fn(*const u8, u32, *mut std::ffi::c_void)>,
    user: *mut std::ffi::c_void,
) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let h = unsafe { &mut *(handle as *mut ClientHandle) };
    {
        let mut g = h.rx_cb.lock().unwrap();
        *g = cb.map(|f| RxCb { func: f, user });
    }

    // Ensure a single demux task and channel are wired
    h.ensure_adapter_rx();
    0
}

/// Send an L2 frame via any TX-capable link.
#[no_mangle]
pub extern "C" fn softether_client_send_frame(
    handle: *mut softether_client_t,
    data: *const u8,
    len: u32,
) -> c_int {
    if handle.is_null() || data.is_null() {
        return -1;
    }
    let h = unsafe { &mut *(handle as *mut ClientHandle) };
    let slice = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let frame = slice.to_vec();
    let client_arc = h.client.clone();
    let ok = h.rt.block_on(async move {
        let c = client_arc.lock().unwrap();
        if let Some(dp) = c.dataplane() {
            return dp.send_frame(frame) as i32;
        }
        -2
    });
    ok
}

/// Register an IPv4 RX callback to receive IP packets (EtherType 0x0800 frames converted to IP payloads).
#[no_mangle]
pub extern "C" fn softether_client_set_ip_rx_callback(
    handle: *mut softether_client_t,
    cb: Option<extern "C" fn(*const u8, u32, *mut std::ffi::c_void)>,
    user: *mut std::ffi::c_void,
) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let h = unsafe { &mut *(handle as *mut ClientHandle) };
    {
        let mut g = h.ip_rx_cb.lock().unwrap();
        *g = cb.map(|f| IpRxCb { func: f, user });
    }
    // Ensure demux is wired (will no-op if already present)
    h.ensure_adapter_rx();
    0
}

/// Send a single IPv4 packet. For now, only DHCP (UDP 67/68) is wrapped into Ethernet and sent.
#[no_mangle]
pub extern "C" fn softether_client_send_ip_packet(
    handle: *mut softether_client_t,
    data: *const u8,
    len: u32,
) -> c_int {
    if handle.is_null() || data.is_null() {
        return -1;
    }
    let buf = unsafe { std::slice::from_raw_parts(data, len as usize) };
    if buf.len() < 20 {
        return -10;
    }
    let ver_ihl = buf[0];
    if (ver_ihl >> 4) != 4 {
        return -11; // non-IPv4
    }
    // Destination IP
    let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let h = unsafe { &mut *(handle as *mut ClientHandle) };
    let src_mac = h.mac;
    // Quick special cases: broadcast and multicast -> L2 broadcast
    let is_broadcast = dst_ip.octets() == [255, 255, 255, 255];
    let is_multicast = (dst_ip.octets()[0] & 0xf0) == 0xe0; // 224.0.0.0/4
    if is_broadcast || is_multicast {
        let mut frame = Vec::with_capacity(14 + buf.len());
        frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        frame.extend_from_slice(&src_mac);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(buf);
        let client_arc = h.client.clone();
        let res: i32 = h.rt.block_on(async move {
            let c = client_arc.lock().unwrap();
            if let Some(dp) = c.dataplane() {
                return if dp.send_frame(pad_eth_min(frame)) {
                    1
                } else {
                    0
                };
            }
            -2
        });
        return res;
    }

    // Compute next-hop: same subnet -> dst_ip, else -> gateway
    let assigned = h.assigned_ip.lock().unwrap().clone();
    let mask = h.netmask.lock().unwrap().clone();
    let gateway = h.gateway.lock().unwrap().clone();
    let next_hop = if let (Some(ip), Some(m)) = (assigned, mask) {
        let a = u32::from(ip);
        let b = u32::from(dst_ip);
        let mm = u32::from(m);
        if (a & mm) == (b & mm) {
            Some(dst_ip)
        } else {
            gateway
        }
    } else {
        // No assigned IP/mask yet: allow DHCP-like broadcast only (handled above)
        None
    };
    let Some(nh) = next_hop else {
        return -21; // no route (missing gateway or settings)
    };

    // Try ARP table first
    {
        let mac_opt = h.arp.lock().unwrap().lookup(nh);
        if let Some(dst_mac) = mac_opt {
            let mut frame = Vec::with_capacity(14 + buf.len());
            frame.extend_from_slice(&dst_mac);
            frame.extend_from_slice(&src_mac);
            frame.extend_from_slice(&0x0800u16.to_be_bytes());
            frame.extend_from_slice(buf);
            let client_arc = h.client.clone();
            let res: i32 = h.rt.block_on(async move {
                let c = client_arc.lock().unwrap();
                if let Some(dp) = c.dataplane() {
                    return if dp.send_frame(pad_eth_min(frame)) {
                        1
                    } else {
                        0
                    };
                }
                -2
            });
            return res;
        }
    }

    // Enqueue pending and emit ARP who-has
    // Enqueue for later flush once ARP resolves; if queue is full, report an error
    let enq_len = {
        let mut mgr = h.arp.lock().unwrap();
        mgr.enqueue(nh, buf.to_vec())
    };
    if enq_len.is_none() {
        return -30; // queue full, packet dropped
    }
    // If this is the first enqueued packet for this next-hop, emit a light event and start probes
    if let Some(1) = enq_len {
        emit_event(
            &h.event_cb,
            0,
            900, // ARP pending-started
            &format!(
                "pending queue started for next-hop {} (first packet enqueued)",
                nh
            ),
        );
        // Ensure periodic ARP retries are scheduled for this next-hop until it's learned
        let mut pr = h.arp_probes.lock().unwrap();
        pr.entry(nh).or_insert_with(|| ProbeState {
            // Force immediate send on next tick
            last: Instant::now() - Duration::from_secs(10),
            interval: Duration::from_millis(250),
        });
    }
    // Build and send ARP request
    let src_ip = assigned.unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
    let mut arp = Vec::with_capacity(14 + 28);
    // Ethernet header (broadcast)
    arp.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    arp.extend_from_slice(&src_mac);
    arp.extend_from_slice(&0x0806u16.to_be_bytes());
    // ARP payload
    // htype (Ethernet), ptype (IPv4), hlen=6, plen=4, oper=1 (request)
    arp.extend_from_slice(&0x0001u16.to_be_bytes()); // Ethernet
    arp.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    arp.push(6);
    arp.push(4);
    arp.extend_from_slice(&0x0001u16.to_be_bytes()); // request
                                                     // sha, spa, tha, tpa
    arp.extend_from_slice(&src_mac);
    arp.extend_from_slice(&src_ip.octets());
    arp.extend_from_slice(&[0u8; 6]);
    arp.extend_from_slice(&nh.octets());

    let client_arc = h.client.clone();
    let res: i32 = h.rt.block_on(async move {
        let c = client_arc.lock().unwrap();
        if let Some(dp) = c.dataplane() {
            let _ = dp.send_frame(pad_eth_min(arp));
            return 0; // queued, not yet sent
        }
        -2
    });
    res
}

/// Add a static ARP entry for a next-hop IPv4 address (big-endian u32) to MAC.
#[no_mangle]
pub extern "C" fn softether_client_arp_add(
    handle: *mut softether_client_t,
    ipv4_be: u32,
    mac: *const u8,
) -> c_int {
    if handle.is_null() || mac.is_null() {
        return -1;
    }
    let h = unsafe { &mut *(handle as *mut ClientHandle) };
    let ip = Ipv4Addr::from(ipv4_be);
    let m: [u8; 6] = unsafe { std::ptr::read(mac as *const [u8; 6]) };
    {
        let mut mgr = h.arp.lock().unwrap();
        mgr.learn(ip, m);
        // Flush pending immediately if any were queued for this next-hop
        if let Some(mut q) = mgr.pending.remove(&ip) {
            let mut batch = Vec::new();
            while let Some(pkt) = q.pop_front() {
                batch.push(pkt);
            }
            drop(mgr);
            let client_arc = h.client.clone();
            let src_mac = h.mac;
            let flushed = batch.len();
            let nh_ip = ip;
            let _ = h.rt.block_on(async move {
                let c = client_arc.lock().unwrap();
                if let Some(dp) = c.dataplane() {
                    for ip_pkt in batch {
                        let mut eth = Vec::with_capacity(14 + ip_pkt.len());
                        eth.extend_from_slice(&m);
                        eth.extend_from_slice(&src_mac);
                        eth.extend_from_slice(&0x0800u16.to_be_bytes());
                        eth.extend_from_slice(&ip_pkt);
                        let _ = dp.send_frame(pad_eth_min(eth));
                    }
                }
            });
            // Emit event after flush so embedders see the action
            emit_event(
                &h.event_cb,
                0,
                901,
                &format!(
                    "flushed {} pending IPv4 packet(s) for next-hop {} via {}",
                    flushed,
                    nh_ip,
                    crate::utils::mac_to_string(&m)
                ),
            );
        }
    }
    // Stop probing since we have the MAC now (avoid unnecessary ARP requests)
    {
        let mut pr = h.arp_probes.lock().unwrap();
        pr.remove(&ip);
    }
    0
}

/// Register a state change callback.
#[no_mangle]
pub extern "C" fn softether_client_set_state_callback(
    handle: *mut softether_client_t,
    cb: Option<extern "C" fn(i32, *mut std::ffi::c_void)>,
    user: *mut std::ffi::c_void,
) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let h = unsafe { &mut *(handle as *mut ClientHandle) };
    if let Some(func) = cb {
        *h.state_cb.lock().unwrap() = Some(Arc::new(StateCb { func, user }));
    } else {
        *h.state_cb.lock().unwrap() = None;
    }

    // Create a channel and subscribe VpnClient to state changes, forwarding to the C callback
    let (tx, mut rx) = mpsc::unbounded_channel::<ClientState>();
    {
        let mut c = h.client.lock().unwrap();
        c.set_state_channel(tx);
    }
    if let Some(cb) = h.state_cb.lock().unwrap().as_ref().cloned() {
        let handle = h.rt.spawn(async move {
            let cb_local = cb; // Arc<StateCb>
            while let Some(s) = rx.recv().await {
                (cb_local.func)(s as i32, cb_local.user);
            }
        });
        h.tasks.lock().unwrap().push(handle);
    }
    0
}
