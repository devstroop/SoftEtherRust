//! C API for SoftEther VPN Rust client
//! Minimal connect/disconnect and frame IO hooks.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::{Arc, Mutex};

use base64::Engine; // for STANDARD.decode()
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc;

use config::ClientConfig as SharedConfig;
use vpnclient::settings_json_with_kind;
use vpnclient::ClientState;
use vpnclient::VpnClient;
use vpnclient::{ClientEvent, EventLevel};

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
    #[serde(default)]
    nat_traversal: bool,
}

fn default_true() -> bool {
    true
}
fn default_max_conn() -> u32 {
    1
}

#[derive(Clone, Copy)]
struct RxCb {
    func: extern "C" fn(*const u8, u32, *mut std::ffi::c_void),
    user: *mut std::ffi::c_void,
}

unsafe impl Send for RxCb {}
unsafe impl Sync for RxCb {}

#[derive(Clone, Copy)]
struct StateCb {
    func: extern "C" fn(i32, *mut std::ffi::c_void),
    user: *mut std::ffi::c_void,
}

unsafe impl Send for StateCb {}
unsafe impl Sync for StateCb {}

#[derive(Clone, Copy)]
struct EventCb {
    func: extern "C" fn(i32, i32, *const c_char, *mut std::ffi::c_void),
    user: *mut std::ffi::c_void,
}

unsafe impl Send for EventCb {}
unsafe impl Sync for EventCb {}

#[derive(Clone, Copy)]
struct IpRxCb {
    func: extern "C" fn(*const u8, u32, *mut std::ffi::c_void),
    user: *mut std::ffi::c_void,
}

unsafe impl Send for IpRxCb {}
unsafe impl Sync for IpRxCb {}

fn gen_laa_mac() -> [u8; 6] {
    // Generate a pseudo-random but locally-administered, unicast MAC from time-based seed
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut x = now ^ ((now << 13) | (now >> 7));
    // xorshift-like mixing
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    let bytes = x.to_le_bytes();
    let mut mac = [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]];
    // Ensure locally administered (bit1 = 1) and unicast (bit0 = 0)
    mac[0] = (mac[0] | 0b0000_0010) & 0b1111_1110;
    mac
}

struct ClientHandle {
    rt: Runtime,
    client: Arc<Mutex<VpnClient>>, // guarded for FFI concurrency
    // Frame channels (optional wiring for future use)
    adapter_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    rx_cb: Arc<Mutex<Option<RxCb>>>,
    ip_rx_cb: Arc<Mutex<Option<IpRxCb>>>,
    state_cb: Option<Arc<StateCb>>,
    event_cb: Option<Arc<EventCb>>,
}

impl ClientHandle {
    /// Ensure a single adapter_rx channel is wired and a demux task is spawned
    /// that forwards L2 frames to rx_cb and IPv4 payloads to ip_rx_cb when set.
    fn ensure_adapter_rx(&mut self) {
        if self.adapter_tx.is_some() {
            return;
        }
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        self.adapter_tx = Some(tx.clone());
        let rx_cb = self.rx_cb.clone();
        let ip_cb = self.ip_rx_cb.clone();
        // Shared helper for demux
        self.rt.spawn(async move {
            while let Some(frame) = rx.recv().await {
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
        });
        // Attach to dataplane if available
        let client_arc = self.client.clone();
        let tx2 = tx.clone();
        let _ = self.rt.block_on(async move {
            let c = client_arc.lock().unwrap();
            if let Some(dp) = c.dataplane() {
                dp.set_adapter_rx(tx2);
            }
        });
    }
}

/// Extract IPv4 payload from an Ethernet frame (EtherType 0x0800)
fn eth_to_ipv4(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    if ether_type != 0x0800 {
        return None;
    }
    Some(&frame[14..])
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
        nat_traversal: c.nat_traversal,
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

    // Build vpnclient from shared config
    let cc = make_shared_config(parsed);
    let client = match vpnclient::VpnClient::from_shared_config(cc) {
        Ok(c) => c,
        Err(_) => return ptr::null_mut(),
    };

    let handle = ClientHandle {
        rt,
        client: Arc::new(Mutex::new(client)),
        adapter_tx: None,
        rx_cb: Arc::new(Mutex::new(None)),
        ip_rx_cb: Arc::new(Mutex::new(None)),
        state_cb: None,
        event_cb: None,
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
            if let Ok(msg) = CString::new(format!("connect error: {}", e)) {
                if let Some(cb) = &h.event_cb {
                    (cb.func)(2, 500, msg.as_ptr(), cb.user);
                }
            }
            -2
        }
    };
    if code == 0 {
        // If we had an RX callback registered before connect, wire the adapter sink now
        let client_arc2 = h.client.clone();
        let tx_opt = h.adapter_tx.clone();
        let _ = h.rt.block_on(async move {
            if let Some(tx) = tx_opt {
                let c = client_arc2.lock().unwrap();
                if let Some(dp) = c.dataplane() {
                    dp.set_adapter_rx(tx);
                }
            }
        });
        // Emit a JSON network settings snapshot if available right after connect
        if let Some(cb) = h.event_cb.clone() {
            let client_arc3 = h.client.clone();
            let _ = h.rt.spawn(async move {
                let c = client_arc3.lock().unwrap();
                let json = settings_json_with_kind(c.get_network_settings().as_ref(), true);
                let cstr = CString::new(json).unwrap_or_else(|_| CString::new("{}").unwrap());
                (cb.func)(0, 1001, cstr.as_ptr(), cb.user);
                // CString dropped after callback returns
            });
        }
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
        h.event_cb = Some(Arc::new(EventCb { func, user }));
    } else {
        h.event_cb = None;
    }

    let (tx, mut rx) = mpsc::unbounded_channel::<ClientEvent>();
    {
        let mut c = h.client.lock().unwrap();
        c.set_event_channel(tx);
    }
    if let Some(cb) = h.event_cb.clone() {
        let _ = h.rt.spawn(async move {
            let cb_local = cb;
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
    let s = h.rt.block_on(async move {
        let c = client_arc.lock().unwrap();
        settings_json_with_kind(c.get_network_settings().as_ref(), false)
    });
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
        let _ = Box::from_raw(handle as *mut ClientHandle);
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
    let ihl = ((ver_ihl & 0x0f) as usize) * 4;
    if ihl < 20 || buf.len() < ihl + 8 {
        return -10;
    }
    let proto = buf[9];
    if proto != 17 {
        return -12; // only UDP supported initially
    }
    let src_port = u16::from_be_bytes([buf[ihl], buf[ihl + 1]]);
    let dst_port = u16::from_be_bytes([buf[ihl + 2], buf[ihl + 3]]);
    let is_dhcp = (src_port == 67 || src_port == 68) || (dst_port == 67 || dst_port == 68);
    if !is_dhcp {
        return -12; // unsupported packet until full IP-mode exists
    }
    // Wrap IP payload in Ethernet broadcast frame
    let src_mac = gen_laa_mac();
    let mut frame = Vec::with_capacity(14 + buf.len());
    frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(buf);

    let h = unsafe { &mut *(handle as *mut ClientHandle) };
    let client_arc = h.client.clone();
    let res: i32 = h.rt.block_on(async move {
        let c = client_arc.lock().unwrap();
        if let Some(dp) = c.dataplane() {
            return if dp.send_frame(frame) { 1 } else { 0 };
        }
        -2
    });
    res
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
        h.state_cb = Some(Arc::new(StateCb { func, user }));
    } else {
        h.state_cb = None;
    }

    // Create a channel and subscribe VpnClient to state changes, forwarding to the C callback
    let (tx, mut rx) = mpsc::unbounded_channel::<ClientState>();
    {
        let mut c = h.client.lock().unwrap();
        c.set_state_channel(tx);
    }
    if let Some(cb) = h.state_cb.clone() {
        let _ = h.rt.spawn(async move {
            let cb_local = cb; // move Arc into task
            while let Some(s) = rx.recv().await {
                ((*cb_local).func)(s as i32, (*cb_local).user);
            }
        });
    }
    0
}
