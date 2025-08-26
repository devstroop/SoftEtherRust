//! Handshake and login pack construction
//!
//! Minimal handshake builder to produce a Login pack compatible with SoftEther.

use crate::constants::{
    CEDAR_SIGNATURE_STR, PACK_ELEMENT_BUILD, PACK_ELEMENT_CLIENT_STR, PACK_ELEMENT_HALF_CONNECTION,
    PACK_ELEMENT_HUBNAME, PACK_ELEMENT_MAX_CONNECTION, PACK_ELEMENT_METHOD, PACK_ELEMENT_PASSWORD,
    PACK_ELEMENT_PROTOCOL, PACK_ELEMENT_USERNAME, PACK_ELEMENT_USE_COMPRESS,
    PACK_ELEMENT_USE_ENCRYPT, PACK_ELEMENT_VERSION,
};
use crate::{ClientAuth, ClientOption, SOFTETHER_BUILD, SOFTETHER_VER};
use mayaqua::crypto::{sha0, Sha1Sum};
use mayaqua::{Pack, Result};

/// Build the initial Login pack to start protocol negotiation.
pub fn build_login_pack(opt: &ClientOption, auth: &ClientAuth) -> Result<Pack> {
    opt.validate()?;
    auth.validate()?;

    let mut pack = Pack::new();

    // Required fields
    pack.add_str(PACK_ELEMENT_METHOD, "Login")?;
    pack.add_int(PACK_ELEMENT_VERSION, SOFTETHER_VER)?;
    pack.add_int(PACK_ELEMENT_BUILD, SOFTETHER_BUILD)?;
    pack.add_str(PACK_ELEMENT_CLIENT_STR, &client_string())?;
    pack.add_str(PACK_ELEMENT_HUBNAME, &opt.hubname)?;
    pack.add_str(PACK_ELEMENT_USERNAME, &auth.username)?;

    // Protocol signature and transport
    pack.add_str(PACK_ELEMENT_PROTOCOL, CEDAR_SIGNATURE_STR)?;

    // Options
    pack.add_int(PACK_ELEMENT_MAX_CONNECTION, opt.max_connection)?;
    pack.add_int(PACK_ELEMENT_USE_ENCRYPT, opt.use_encrypt as u32)?;
    pack.add_int(PACK_ELEMENT_USE_COMPRESS, opt.use_compress as u32)?;
    pack.add_int(PACK_ELEMENT_HALF_CONNECTION, opt.half_connection as u32)?;

    // Password: send SHA-1(password) initially; server returns random for SHA-0 obfuscation next
    if !auth.plain_password.is_empty() {
        let hash = mayaqua::crypto::sha1(auth.plain_password.as_bytes());
        pack.add_data(PACK_ELEMENT_PASSWORD, hash.to_vec())?;
    }

    Ok(pack)
}

/// Compute the obfuscated secure password as SHA-0(hash(password) || server_random)
pub fn secure_password(hashed_password: Sha1Sum, server_random: Sha1Sum) -> Sha1Sum {
    let mut buf = Vec::with_capacity(hashed_password.len() + server_random.len());
    buf.extend_from_slice(&hashed_password);
    buf.extend_from_slice(&server_random);
    sha0(&buf)
}

fn client_string() -> String {
    format!("SoftEther VPN Client (Rust) {SOFTETHER_VER}.{SOFTETHER_BUILD}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_login_pack_basic() {
        let opt = ClientOption::new("vpn.example.com", 443, "DEFAULT").unwrap();
        let auth = ClientAuth::new_password("user1", "pass123").unwrap();
        let pack = build_login_pack(&opt, &auth).unwrap();

        assert_eq!(pack.get_str(PACK_ELEMENT_METHOD).unwrap(), "Login");
        assert_eq!(pack.get_int(PACK_ELEMENT_VERSION).unwrap(), SOFTETHER_VER);
        assert_eq!(pack.get_int(PACK_ELEMENT_BUILD).unwrap(), SOFTETHER_BUILD);
        assert_eq!(pack.get_str(PACK_ELEMENT_HUBNAME).unwrap(), "DEFAULT");
        assert_eq!(pack.get_str(PACK_ELEMENT_USERNAME).unwrap(), "user1");
        assert_eq!(
            pack.get_str(PACK_ELEMENT_PROTOCOL).unwrap(),
            CEDAR_SIGNATURE_STR
        );
        assert_eq!(pack.get_int(PACK_ELEMENT_MAX_CONNECTION).unwrap(), 1);
    }

    #[test]
    fn test_secure_password_deterministic() {
        let hp = mayaqua::crypto::sha1(b"password");
        let rnd = [0x11u8; 20];
        let s1 = secure_password(hp, rnd);
        let s2 = secure_password(hp, rnd);
        assert_eq!(s1, s2);
    }
}
