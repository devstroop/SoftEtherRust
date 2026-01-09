//! Android platform bindings via JNI (Java Native Interface).
//!
//! This module provides JNI-compatible functions that can be called directly
//! from Kotlin/Java on Android. These functions wrap the C FFI layer.
//!
//! Similar to how ANE (Apple Network Extensions) provides iOS-specific helpers,
//! JNI provides Android-specific bindings between Kotlin/Java and native code.
//!
//! # Package Name
//! The JNI functions are named for package: `com.worxvpn.app.vpn`
//! Class: `SoftEtherBridge`

use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jlongArray};
use jni::JNIEnv;
use std::ffi::CString;

use super::callbacks::SoftEtherCallbacks;
use super::client::*;
use super::types::*;

/// Global reference holder for JNI callbacks
struct JniCallbackContext {
    /// The JVM reference for callbacks
    jvm: jni::JavaVM,
    /// Global reference to the SoftEtherBridge object
    bridge_ref: jni::objects::GlobalRef,
}

unsafe impl Send for JniCallbackContext {}
unsafe impl Sync for JniCallbackContext {}

// =============================================================================
// Helper Functions
// =============================================================================

/// Get a String from a JString, returning None if null or invalid
fn get_string(env: &mut JNIEnv, s: &JString) -> Option<String> {
    if s.is_null() {
        return None;
    }
    env.get_string(s).ok().map(|s| s.into())
}

/// Create a CString from a Rust string
fn to_cstring(s: &str) -> Option<CString> {
    CString::new(s).ok()
}

// =============================================================================
// JNI Callback Trampolines
// =============================================================================

extern "C" fn jni_on_state_changed(context: *mut std::ffi::c_void, state: SoftEtherState) {
    if context.is_null() {
        return;
    }

    let ctx = unsafe { &*(context as *const JniCallbackContext) };

    if let Ok(mut env) = ctx.jvm.attach_current_thread() {
        let _ = env.call_method(
            &ctx.bridge_ref,
            "onNativeStateChanged",
            "(I)V",
            &[JValue::Int(state as i32)],
        );
    }
}

extern "C" fn jni_on_connected(context: *mut std::ffi::c_void, session: *const SoftEtherSession) {
    if context.is_null() || session.is_null() {
        return;
    }

    let ctx = unsafe { &*(context as *const JniCallbackContext) };
    let session = unsafe { &*session };

    if let Ok(mut env) = ctx.jvm.attach_current_thread() {
        // Extract server IP string
        let server_ip = unsafe {
            std::ffi::CStr::from_ptr(session.connected_server_ip.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        let server_ip_jstring = env
            .new_string(&server_ip)
            .unwrap_or_else(|_| env.new_string("").unwrap());

        // Create MAC address byte array
        let mac_array = env
            .byte_array_from_slice(&session.mac_address)
            .unwrap_or_else(|_| env.byte_array_from_slice(&[0u8; 6]).unwrap());

        let _ = env.call_method(
            &ctx.bridge_ref,
            "onNativeConnected",
            "(IIIIILjava/lang/String;II[B)V",
            &[
                JValue::Int(session.ip_address as i32),
                JValue::Int(session.subnet_mask as i32),
                JValue::Int(session.gateway as i32),
                JValue::Int(session.dns1 as i32),
                JValue::Int(session.dns2 as i32),
                JValue::Object(&server_ip_jstring),
                JValue::Int(session.server_version as i32),
                JValue::Int(session.server_build as i32),
                JValue::Object(&mac_array),
            ],
        );
    }
}

extern "C" fn jni_on_disconnected(context: *mut std::ffi::c_void, result: SoftEtherResult) {
    if context.is_null() {
        return;
    }

    let ctx = unsafe { &*(context as *const JniCallbackContext) };

    if let Ok(mut env) = ctx.jvm.attach_current_thread() {
        let _ = env.call_method(
            &ctx.bridge_ref,
            "onNativeDisconnected",
            "(I)V",
            &[JValue::Int(result as i32)],
        );
    }
}

extern "C" fn jni_on_packets_received(
    context: *mut std::ffi::c_void,
    packets: *const u8,
    total_size: usize,
    packet_count: u32,
) {
    if context.is_null() || packets.is_null() || total_size == 0 {
        return;
    }

    let ctx = unsafe { &*(context as *const JniCallbackContext) };

    if let Ok(mut env) = ctx.jvm.attach_current_thread() {
        let data = unsafe { std::slice::from_raw_parts(packets, total_size) };

        if let Ok(byte_array) = env.byte_array_from_slice(data) {
            let _ = env.call_method(
                &ctx.bridge_ref,
                "onNativePacketsReceived",
                "([BI)V",
                &[
                    JValue::Object(&byte_array),
                    JValue::Int(packet_count as i32),
                ],
            );
        }
    }
}

extern "C" fn jni_on_log(
    context: *mut std::ffi::c_void,
    level: i32,
    message: *const std::ffi::c_char,
) {
    if context.is_null() || message.is_null() {
        return;
    }

    let ctx = unsafe { &*(context as *const JniCallbackContext) };
    let msg = unsafe { std::ffi::CStr::from_ptr(message).to_string_lossy() };

    if let Ok(mut env) = ctx.jvm.attach_current_thread() {
        if let Ok(msg_jstring) = env.new_string(msg.as_ref()) {
            let _ = env.call_method(
                &ctx.bridge_ref,
                "onNativeLog",
                "(ILjava/lang/String;)V",
                &[JValue::Int(level), JValue::Object(&msg_jstring)],
            );
        }
    }
}

extern "C" fn jni_protect_socket(context: *mut std::ffi::c_void, fd: i32) -> bool {
    if context.is_null() {
        return false;
    }

    let ctx = unsafe { &*(context as *const JniCallbackContext) };

    if let Ok(mut env) = ctx.jvm.attach_current_thread() {
        if let Ok(result) = env.call_method(
            &ctx.bridge_ref,
            "onProtectSocket",
            "(I)Z",
            &[JValue::Int(fd)],
        ) {
            if let Ok(protected) = result.z() {
                return protected;
            }
        }
    }
    false
}

extern "C" fn jni_exclude_ip(context: *mut std::ffi::c_void, ip: *const std::ffi::c_char) -> bool {
    if context.is_null() || ip.is_null() {
        return false;
    }

    let ctx = unsafe { &*(context as *const JniCallbackContext) };
    let ip_str = unsafe { std::ffi::CStr::from_ptr(ip) };
    let ip_string = match ip_str.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    if let Ok(mut env) = ctx.jvm.attach_current_thread() {
        if let Ok(ip_jstring) = env.new_string(ip_string) {
            if let Ok(result) = env.call_method(
                &ctx.bridge_ref,
                "onExcludeIp",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&ip_jstring)],
            ) {
                if let Ok(excluded) = result.z() {
                    return excluded;
                }
            }
        }
    }
    false
}

// =============================================================================
// JNI Native Methods
// =============================================================================

/// Create a new SoftEther client instance.
///
/// # Safety
/// Called from JNI - all parameters come from Java/Kotlin
#[no_mangle]
pub extern "system" fn Java_com_worxvpn_app_vpn_SoftEtherBridge_nativeCreate(
    mut env: JNIEnv,
    obj: JObject,
    server: JString,
    port: jint,
    hub: JString,
    username: JString,
    password_hash: JString,
    // TLS Settings
    skip_tls_verify: jboolean,
    custom_ca_pem: JString,
    cert_fingerprint_sha256: JString,
    // Connection Settings
    max_connections: jint,
    timeout_seconds: jint,
    mtu: jint,
    // Protocol Features
    use_encrypt: jboolean,
    use_compress: jboolean,
    udp_accel: jboolean,
    qos: jboolean,
    // Session Mode
    nat_traversal: jboolean,
    monitor_mode: jboolean,
    // Routing
    default_route: jboolean,
    accept_pushed_routes: jboolean,
    ipv4_include: JString,
    ipv4_exclude: JString,
    ipv6_include: JString,
    ipv6_exclude: JString,
    // Static IP Configuration
    static_ipv4_address: JString,
    static_ipv4_netmask: JString,
    static_ipv4_gateway: JString,
    static_ipv4_dns1: JString,
    static_ipv4_dns2: JString,
    static_ipv6_address: JString,
    static_ipv6_prefix_len: jint,
    static_ipv6_gateway: JString,
    static_ipv6_dns1: JString,
    static_ipv6_dns2: JString,
) -> jlong {
    // Get required strings
    let server_str = match get_string(&mut env, &server) {
        Some(s) => s,
        None => return 0,
    };
    let hub_str = match get_string(&mut env, &hub) {
        Some(s) => s,
        None => return 0,
    };
    let username_str = match get_string(&mut env, &username) {
        Some(s) => s,
        None => return 0,
    };
    let password_hash_str = match get_string(&mut env, &password_hash) {
        Some(s) => s,
        None => return 0,
    };

    // Get optional routing strings
    let ipv4_include_str = get_string(&mut env, &ipv4_include).unwrap_or_default();
    let ipv4_exclude_str = get_string(&mut env, &ipv4_exclude).unwrap_or_default();
    let ipv6_include_str = get_string(&mut env, &ipv6_include).unwrap_or_default();
    let ipv6_exclude_str = get_string(&mut env, &ipv6_exclude).unwrap_or_default();

    // Get optional TLS strings
    let custom_ca_pem_str = get_string(&mut env, &custom_ca_pem).unwrap_or_default();
    let cert_fingerprint_str = get_string(&mut env, &cert_fingerprint_sha256).unwrap_or_default();

    // Get optional static IP strings
    let static_ipv4_address_str = get_string(&mut env, &static_ipv4_address).unwrap_or_default();
    let static_ipv4_netmask_str = get_string(&mut env, &static_ipv4_netmask).unwrap_or_default();
    let static_ipv4_gateway_str = get_string(&mut env, &static_ipv4_gateway).unwrap_or_default();
    let static_ipv4_dns1_str = get_string(&mut env, &static_ipv4_dns1).unwrap_or_default();
    let static_ipv4_dns2_str = get_string(&mut env, &static_ipv4_dns2).unwrap_or_default();
    let static_ipv6_address_str = get_string(&mut env, &static_ipv6_address).unwrap_or_default();
    let static_ipv6_gateway_str = get_string(&mut env, &static_ipv6_gateway).unwrap_or_default();
    let static_ipv6_dns1_str = get_string(&mut env, &static_ipv6_dns1).unwrap_or_default();
    let static_ipv6_dns2_str = get_string(&mut env, &static_ipv6_dns2).unwrap_or_default();

    // Create CStrings for FFI
    let server_cstr = match to_cstring(&server_str) {
        Some(s) => s,
        None => return 0,
    };
    let hub_cstr = match to_cstring(&hub_str) {
        Some(s) => s,
        None => return 0,
    };
    let username_cstr = match to_cstring(&username_str) {
        Some(s) => s,
        None => return 0,
    };
    let password_hash_cstr = match to_cstring(&password_hash_str) {
        Some(s) => s,
        None => return 0,
    };
    let ipv4_include_cstr = to_cstring(&ipv4_include_str);
    let ipv4_exclude_cstr = to_cstring(&ipv4_exclude_str);
    let ipv6_include_cstr = to_cstring(&ipv6_include_str);
    let ipv6_exclude_cstr = to_cstring(&ipv6_exclude_str);
    let custom_ca_pem_cstr = to_cstring(&custom_ca_pem_str);
    let cert_fingerprint_cstr = to_cstring(&cert_fingerprint_str);

    // Create CStrings for static IP configuration
    let static_ipv4_address_cstr = to_cstring(&static_ipv4_address_str);
    let static_ipv4_netmask_cstr = to_cstring(&static_ipv4_netmask_str);
    let static_ipv4_gateway_cstr = to_cstring(&static_ipv4_gateway_str);
    let static_ipv4_dns1_cstr = to_cstring(&static_ipv4_dns1_str);
    let static_ipv4_dns2_cstr = to_cstring(&static_ipv4_dns2_str);
    let static_ipv6_address_cstr = to_cstring(&static_ipv6_address_str);
    let static_ipv6_gateway_cstr = to_cstring(&static_ipv6_gateway_str);
    let static_ipv6_dns1_cstr = to_cstring(&static_ipv6_dns1_str);
    let static_ipv6_dns2_cstr = to_cstring(&static_ipv6_dns2_str);

    // Create config with all options
    let config = SoftEtherConfig {
        server: server_cstr.as_ptr(),
        port: port as u32,
        hub: hub_cstr.as_ptr(),
        username: username_cstr.as_ptr(),
        password_hash: password_hash_cstr.as_ptr(),
        skip_tls_verify: if skip_tls_verify != 0 { 1 } else { 0 },
        custom_ca_pem: custom_ca_pem_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
        cert_fingerprint_sha256: cert_fingerprint_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
        max_connections: max_connections as u32,
        half_connection: 0, // Android doesn't expose this yet, default to false
        timeout_seconds: timeout_seconds as u32,
        mtu: mtu as u32,
        use_encrypt: if use_encrypt != 0 { 1 } else { 0 },
        use_compress: if use_compress != 0 { 1 } else { 0 },
        udp_accel: if udp_accel != 0 { 1 } else { 0 },
        qos: if qos != 0 { 1 } else { 0 },
        nat_traversal: if nat_traversal != 0 { 1 } else { 0 },
        monitor_mode: if monitor_mode != 0 { 1 } else { 0 },
        default_route: if default_route != 0 { 1 } else { 0 },
        accept_pushed_routes: if accept_pushed_routes != 0 { 1 } else { 0 },
        ipv4_include: ipv4_include_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
        ipv4_exclude: ipv4_exclude_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
        ipv6_include: ipv6_include_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
        ipv6_exclude: ipv6_exclude_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
        // Static IPv4 Configuration
        static_ipv4_address: static_ipv4_address_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
        static_ipv4_netmask: static_ipv4_netmask_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
        static_ipv4_gateway: static_ipv4_gateway_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
        static_ipv4_dns1: static_ipv4_dns1_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
        static_ipv4_dns2: static_ipv4_dns2_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
        // Static IPv6 Configuration
        static_ipv6_address: static_ipv6_address_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
        static_ipv6_prefix_len: static_ipv6_prefix_len as u32,
        static_ipv6_gateway: static_ipv6_gateway_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
        static_ipv6_dns1: static_ipv6_dns1_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
        static_ipv6_dns2: static_ipv6_dns2_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null()),
    };

    // Get JVM for callbacks
    let jvm = match env.get_java_vm() {
        Ok(jvm) => jvm,
        Err(_) => return 0,
    };

    // Create global reference to the bridge object
    let bridge_ref = match env.new_global_ref(obj) {
        Ok(r) => r,
        Err(_) => return 0,
    };

    // Create callback context
    let callback_ctx = Box::new(JniCallbackContext { jvm, bridge_ref });
    let callback_ctx_ptr = Box::into_raw(callback_ctx) as *mut std::ffi::c_void;

    // Create callbacks
    let callbacks = SoftEtherCallbacks {
        context: callback_ctx_ptr,
        on_state_changed: Some(jni_on_state_changed),
        on_connected: Some(jni_on_connected),
        on_disconnected: Some(jni_on_disconnected),
        on_packets_received: Some(jni_on_packets_received),
        on_log: Some(jni_on_log),
        protect_socket: Some(jni_protect_socket),
        exclude_ip: Some(jni_exclude_ip),
    };

    // Create client
    let handle = unsafe { softether_create(&config, &callbacks) };

    if handle.is_null() {
        // Clean up callback context on failure
        unsafe {
            let _ = Box::from_raw(callback_ctx_ptr as *mut JniCallbackContext);
        }
        return 0;
    }

    handle as jlong
}

/// Destroy a SoftEther client instance.
#[no_mangle]
pub extern "system" fn Java_com_worxvpn_app_vpn_SoftEtherBridge_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }

    unsafe {
        softether_destroy(handle as SoftEtherHandle);
    }
}

/// Connect to VPN server.
#[no_mangle]
pub extern "system" fn Java_com_worxvpn_app_vpn_SoftEtherBridge_nativeConnect(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    if handle == 0 {
        return SoftEtherResult::InvalidParam as jint;
    }

    unsafe { softether_connect(handle as SoftEtherHandle) as jint }
}

/// Disconnect from VPN server.
#[no_mangle]
pub extern "system" fn Java_com_worxvpn_app_vpn_SoftEtherBridge_nativeDisconnect(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    if handle == 0 {
        return SoftEtherResult::InvalidParam as jint;
    }

    unsafe { softether_disconnect(handle as SoftEtherHandle) as jint }
}

/// Get current connection state.
#[no_mangle]
pub extern "system" fn Java_com_worxvpn_app_vpn_SoftEtherBridge_nativeGetState(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    if handle == 0 {
        return SoftEtherState::Disconnected as jint;
    }

    unsafe { softether_get_state(handle as SoftEtherHandle) as jint }
}

/// Get session information as int array.
/// Returns [ip_address, subnet_mask, gateway, dns1, dns2, server_version, server_build]
#[no_mangle]
pub extern "system" fn Java_com_worxvpn_app_vpn_SoftEtherBridge_nativeGetSession<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jlongArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    let mut session = SoftEtherSession::default();
    let result =
        unsafe { softether_get_session(handle as SoftEtherHandle, &mut session as *mut _) };

    if result != SoftEtherResult::Ok {
        return std::ptr::null_mut();
    }

    let data: [i64; 7] = [
        session.ip_address as i64,
        session.subnet_mask as i64,
        session.gateway as i64,
        session.dns1 as i64,
        session.dns2 as i64,
        session.server_version as i64,
        session.server_build as i64,
    ];

    match env.new_long_array(7) {
        Ok(arr) => {
            let _ = env.set_long_array_region(&arr, 0, &data);
            arr.into_raw()
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get session server IP as string.
#[no_mangle]
pub extern "system" fn Java_com_worxvpn_app_vpn_SoftEtherBridge_nativeGetSessionServerIP<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> JString<'local> {
    if handle == 0 {
        return JString::default();
    }

    let mut session = SoftEtherSession::default();
    let result =
        unsafe { softether_get_session(handle as SoftEtherHandle, &mut session as *mut _) };

    if result != SoftEtherResult::Ok {
        return JString::default();
    }

    let server_ip = unsafe {
        std::ffi::CStr::from_ptr(session.connected_server_ip.as_ptr())
            .to_string_lossy()
            .into_owned()
    };

    env.new_string(&server_ip).unwrap_or_default()
}

/// Get session MAC address as byte array.
#[no_mangle]
pub extern "system" fn Java_com_worxvpn_app_vpn_SoftEtherBridge_nativeGetSessionMAC<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    let mut session = SoftEtherSession::default();
    let result =
        unsafe { softether_get_session(handle as SoftEtherHandle, &mut session as *mut _) };

    if result != SoftEtherResult::Ok {
        return std::ptr::null_mut();
    }

    match env.byte_array_from_slice(&session.mac_address) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get connection statistics as long array.
/// Returns [bytes_sent, bytes_received, packets_sent, packets_received, uptime_secs, active_connections, reconnect_count, packets_dropped]
#[no_mangle]
pub extern "system" fn Java_com_worxvpn_app_vpn_SoftEtherBridge_nativeGetStats<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jlongArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    let mut stats = SoftEtherStats::default();
    let result = unsafe { softether_get_stats(handle as SoftEtherHandle, &mut stats as *mut _) };

    if result != SoftEtherResult::Ok {
        return std::ptr::null_mut();
    }

    let data: [i64; 8] = [
        stats.bytes_sent as i64,
        stats.bytes_received as i64,
        stats.packets_sent as i64,
        stats.packets_received as i64,
        stats.uptime_secs as i64,
        stats.active_connections as i64,
        stats.reconnect_count as i64,
        stats.packets_dropped as i64,
    ];

    match env.new_long_array(8) {
        Ok(arr) => {
            let _ = env.set_long_array_region(&arr, 0, &data);
            arr.into_raw()
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Send packets to VPN server.
#[no_mangle]
pub extern "system" fn Java_com_worxvpn_app_vpn_SoftEtherBridge_nativeSendPackets(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    data: JByteArray,
    count: jint,
) -> jint {
    if handle == 0 || data.is_null() {
        return SoftEtherResult::InvalidParam as jint;
    }

    let data_vec = match env.convert_byte_array(data) {
        Ok(v) => v,
        Err(_) => return SoftEtherResult::InvalidParam as jint,
    };

    unsafe {
        softether_send_packets(
            handle as SoftEtherHandle,
            data_vec.as_ptr(),
            data_vec.len(),
            count,
        )
    }
}

/// Receive packets from VPN server (polling mode).
#[no_mangle]
pub extern "system" fn Java_com_worxvpn_app_vpn_SoftEtherBridge_nativeReceivePackets(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    buffer: JByteArray,
) -> jint {
    if handle == 0 || buffer.is_null() {
        return SoftEtherResult::InvalidParam as jint;
    }

    let buffer_len = match env.get_array_length(&buffer) {
        Ok(len) => len as usize,
        Err(_) => return SoftEtherResult::InvalidParam as jint,
    };

    let mut temp_buffer = vec![0u8; buffer_len];
    let mut count: i32 = 0;

    let result = unsafe {
        softether_receive_packets(
            handle as SoftEtherHandle,
            temp_buffer.as_mut_ptr(),
            buffer_len,
            &mut count as *mut _,
        )
    };

    if result > 0 {
        let signed_bytes: Vec<i8> = temp_buffer[..result as usize]
            .iter()
            .map(|&b| b as i8)
            .collect();
        let _ = env.set_byte_array_region(&buffer, 0, &signed_bytes);
    }

    result
}

/// Hash a password for SoftEther authentication.
#[no_mangle]
pub extern "system" fn Java_com_worxvpn_app_vpn_SoftEtherBridge_hashPassword<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    password: JString,
    username: JString,
) -> jbyteArray {
    let password_str = match get_string(&mut env, &password) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let username_str = match get_string(&mut env, &username) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let password_cstr = match to_cstring(&password_str) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let username_cstr = match to_cstring(&username_str) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let mut output = [0u8; 20];
    let result = unsafe {
        softether_hash_password(
            password_cstr.as_ptr(),
            username_cstr.as_ptr(),
            output.as_mut_ptr(),
        )
    };

    if result != SoftEtherResult::Ok {
        return std::ptr::null_mut();
    }

    match env.byte_array_from_slice(&output) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get library version.
#[no_mangle]
pub extern "system" fn Java_com_worxvpn_app_vpn_SoftEtherBridge_getVersion<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> JString<'local> {
    let version = unsafe {
        let ptr = softether_version();
        std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
    };

    env.new_string(&version).unwrap_or_default()
}
