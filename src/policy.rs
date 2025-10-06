use crate::types::NetworkSettings;

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
