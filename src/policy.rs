use crate::types::NetworkSettings;
use tracing::info;

/// Extract max_connections policy from parsed policies
pub(super) fn extract_policy_max_connections(ns: &NetworkSettings) -> Option<u32> {
    for (k, v) in &ns.policies {
        let kk = k.to_ascii_lowercase();
        if kk.contains("max_connection")
            || kk.contains("maxconnections")
            || kk.contains("maxconnection")
            || kk.contains("max-connection")
        {
            return Some(*v);
        }
    }
    None
}

/// Detect server mode based on policy flags
///
/// According to SoftEther protocol:
/// - NoBridge=1 AND NoRouting=1 = SecureNAT mode (L3 IP packets only)
/// - Otherwise = Bridge/Routing mode (L2 Ethernet frames)
///
/// This determines whether the server sends/expects:
/// - L2: Ethernet frames with 14-byte header (dst_mac + src_mac + ethertype) + IP packet
/// - L3: Raw IP packets without Ethernet header
pub(super) fn is_securenat_mode(ns: &NetworkSettings) -> bool {
    let mut no_bridge = false;
    let mut no_routing = false;

    for (k, v) in &ns.policies {
        let kk = k.to_ascii_lowercase();
        if kk.contains("nobridge") || kk.contains("no_bridge") {
            no_bridge = *v != 0;
        }
        if kk.contains("norouting") || kk.contains("no_routing") {
            no_routing = *v != 0;
        }
    }

    // Both flags must be set for SecureNAT mode
    let is_securenat = no_bridge && no_routing;

    if is_securenat {
        info!(
            "🔍 Server mode detected: SecureNAT (L3 IP packets, NoBridge={}, NoRouting={})",
            no_bridge as u8, no_routing as u8
        );
    } else {
        info!("🔍 Server mode detected: Bridge/Routing (L2 Ethernet frames, NoBridge={}, NoRouting={})", 
            no_bridge as u8, no_routing as u8);
    }

    is_securenat
}
