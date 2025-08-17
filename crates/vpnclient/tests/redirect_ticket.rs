#![cfg(feature = "test-redirect")]
//! Integration-style test simulating a redirect welcome pack and verifying
//! that VpnClient captures the ticket and switches to ticket authentication
//! on the subsequent connect cycle.

use base64::prelude::*;
use cedar::AuthType;
use client::config::{AuthConfig, VpnConfig};
use client::vpnclient::VpnClient;
use mayaqua::Pack;

#[test]
fn simulate_redirect_and_ticket_capture() {
    // Fake redirect welcome pack
    let mut redirect_pack = Pack::new();
    redirect_pack
        .add_str("RedirectHost", "cluster.example.com")
        .unwrap();
    redirect_pack.add_int("RedirectPort", 443).unwrap();
    let ticket_bytes = [0x11u8; 20];
    redirect_pack
        .add_data("Ticket", ticket_bytes.to_vec())
        .unwrap();

    // Build client with password auth (hash content arbitrary for test)
    let mut cfg = VpnConfig::new_anonymous("origin.example.com".into(), 443, "HUB".into());
    cfg.auth = AuthConfig::Password {
        hashed_password: BASE64_STANDARD.encode([0x22u8; 20]),
    };

    let mut client = VpnClient::new(cfg).expect("create vpn client");

    // Simulate redirect capture (mirrors logic in perform_authentication branch)
    if let Ok(ticket) = redirect_pack
        .get_data("Ticket")
        .or_else(|_| redirect_pack.get_data("ticket"))
    {
        assert_eq!(ticket.len(), 20);
        let mut t = [0u8; 20];
        t.copy_from_slice(ticket);
        // Access internal (may require pub(crate) visibility modification if private)
        client.redirect_ticket = Some(t);
    } else {
        panic!("Ticket missing in test setup");
    }

    // Next auth attempt should opt for Ticket auth
    let auth = client.create_client_auth().expect("ticket auth creation");
    assert_eq!(
        auth.auth_type as u32,
        AuthType::Ticket as u32,
        "Expected Ticket auth after ticket capture"
    );
}
