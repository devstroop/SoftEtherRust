use crate::{
    session_mgr::{SessionManager, SessionManagerAsync},
    ClusterRedirectInfo,
};
use log::{info, warn};

/// Handle server redirection by updating session state and reconnecting
pub async fn handle_redirect(sm: &SessionManager, info: ClusterRedirectInfo) {
    info!("Redirecting to host={} port={}", info.host, info.port);

    // Update session state to reflect redirection
    sm.begin_redirect(info.clone());

    // Attempt reconnection with ticket
    if let Some(ticket) = info.ticket {
        warn!("Using ticket for reconnection");
        // Implement reconnection logic using the ticket
        if let Err(e) = SessionManagerAsync::reconnect_with_ticket(sm, ticket).await {
            warn!("Reconnection failed: {e:?}");
        } else {
            info!("Reconnection successful");
        }
    } else {
        warn!("No ticket provided for redirection");
    }
}
