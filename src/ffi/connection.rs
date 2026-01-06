//! Connection establishment helpers for FFI client.
//!
//! This module extracts connection setup logic from the main client to reduce
//! function complexity and improve code organization.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use super::callbacks::SoftEtherCallbacks;
use super::types::{SoftEtherSession, SoftEtherState};
use crate::packet::{DhcpConfig, Dhcpv6Config};
use crate::protocol::AuthResult;

/// Update atomic state and notify callback.
pub fn update_state(
    atomic_state: &Arc<AtomicU8>,
    callbacks: &SoftEtherCallbacks,
    state: SoftEtherState,
) {
    atomic_state.store(state as u8, Ordering::SeqCst);
    if let Some(cb) = callbacks.on_state_changed {
        cb(callbacks.context, state);
    }
}

/// Resolve hostname to IPv4 address.
pub fn resolve_server_ip(server: &str) -> crate::error::Result<Ipv4Addr> {
    if let Ok(ip) = server.parse::<Ipv4Addr>() {
        return Ok(ip);
    }

    use std::net::ToSocketAddrs;
    let addr_str = format!("{server}:443");
    match addr_str.to_socket_addrs() {
        Ok(mut addrs) => {
            for addr in addrs.by_ref() {
                if let std::net::SocketAddr::V4(v4) = addr {
                    return Ok(*v4.ip());
                }
            }
            Err(crate::error::Error::ConnectionFailed(format!(
                "No IPv4 address found for {server}"
            )))
        }
        Err(e) => Err(crate::error::Error::ConnectionFailed(format!(
            "Failed to resolve {server}: {e}"
        ))),
    }
}

/// Generate a random MAC address for the session.
pub fn generate_session_mac() -> [u8; 6] {
    let mut mac = [0u8; 6];
    crate::crypto::fill_random(&mut mac);
    mac[0] = (mac[0] | 0x02) & 0xFE; // Local/unicast
    mac
}

/// Create session info from DHCP and optional DHCPv6 config.
pub fn create_session_from_dhcp(
    dhcp: &DhcpConfig,
    dhcpv6: Option<&Dhcpv6Config>,
    server_ip: Ipv4Addr,
    mac: [u8; 6],
) -> SoftEtherSession {
    let mut server_ip_str = [0 as std::ffi::c_char; 64];
    let ip_string = format!("{server_ip}");
    for (i, b) in ip_string.bytes().enumerate() {
        if i < 63 {
            server_ip_str[i] = b as std::ffi::c_char;
        }
    }

    fn ip_to_u32(ip: Ipv4Addr) -> u32 {
        let octets = ip.octets();
        ((octets[0] as u32) << 24)
            | ((octets[1] as u32) << 16)
            | ((octets[2] as u32) << 8)
            | (octets[3] as u32)
    }

    // Extract IPv6 info if available
    let (ipv6_address, ipv6_prefix_len, dns1_v6, dns2_v6) = if let Some(v6) = dhcpv6 {
        (
            v6.ip.octets(),
            v6.prefix_len,
            v6.dns1.map(|ip| ip.octets()).unwrap_or([0; 16]),
            v6.dns2.map(|ip| ip.octets()).unwrap_or([0; 16]),
        )
    } else {
        ([0; 16], 0, [0; 16], [0; 16])
    };

    SoftEtherSession {
        ip_address: ip_to_u32(dhcp.ip),
        subnet_mask: ip_to_u32(dhcp.netmask),
        gateway: dhcp.gateway.map(ip_to_u32).unwrap_or(0),
        dns1: dhcp.dns1.map(ip_to_u32).unwrap_or(0),
        dns2: dhcp.dns2.map(ip_to_u32).unwrap_or(0),
        connected_server_ip: server_ip_str,
        server_version: 0,
        server_build: 0,
        mac_address: mac,
        gateway_mac: [0; 6],
        ipv6_address,
        ipv6_prefix_len,
        _padding: [0; 3],
        dns1_v6,
        dns2_v6,
    }
}

/// Initialize UDP acceleration from auth response.
pub fn init_udp_acceleration(
    auth: &AuthResult,
    callbacks: &SoftEtherCallbacks,
) -> Option<crate::net::UdpAccel> {
    let udp_response = auth.udp_accel_response.as_ref()?;

    match crate::net::UdpAccel::new(None, true, false) {
        Ok(mut accel) => {
            if let Err(e) = accel.init_from_response(udp_response) {
                callbacks.log_warn(&format!(
                    "[RUST] Failed to initialize UDP acceleration: {e}"
                ));
                None
            } else {
                callbacks.log_info(&format!(
                    "[RUST] UDP acceleration initialized: version={}, server={}:{}",
                    accel.version, udp_response.server_ip, udp_response.server_port
                ));
                Some(accel)
            }
        }
        Err(e) => {
            callbacks.log_warn(&format!("[RUST] Failed to create UDP socket: {e}"));
            None
        }
    }
}

/// Log encryption status.
pub fn log_encryption_status(
    auth: &AuthResult,
    config: &crate::config::VpnConfig,
    callbacks: &SoftEtherCallbacks,
) {
    if auth.rc4_key_pair.is_some() {
        callbacks.log_info("[RUST] RC4 tunnel encryption enabled (UseFastRC4 mode)");
    } else if config.use_encrypt {
        callbacks.log_info("[RUST] Using TLS-layer encryption (UseSSLDataEncryption mode)");
    } else {
        callbacks.log_info("[RUST] Encryption disabled");
    }
}
