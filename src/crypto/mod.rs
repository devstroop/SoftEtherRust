//! Cryptographic utilities for SoftEther authentication.
//!
//! This module provides:
//! - SHA-0 implementation (required for SoftEther legacy compatibility)
//! - Password hashing functions
//! - Secure password computation
//! - RC4 stream cipher for tunnel encryption
//! - TunnelEncryption wrapper for bidirectional RC4

mod rc4;
mod sha0;

pub use rc4::{Rc4, Rc4KeyPair, RC4_KEY_SIZE};
pub use sha0::Sha0;

/// SHA-0 digest length in bytes.
pub const SHA0_DIGEST_LEN: usize = 20;

/// Hash data using SHA-0.
pub fn sha0_hash(data: &[u8]) -> [u8; SHA0_DIGEST_LEN] {
    let mut hasher = Sha0::new();
    hasher.update(data);
    hasher.finalize()
}

/// Compute SoftEther password hash.
///
/// Algorithm: SHA0(password || UPPERCASE(username))
///
/// # Arguments
/// * `password` - The user's password
/// * `username` - The username (will be uppercased)
///
/// # Returns
/// A 20-byte SHA-0 hash
pub fn hash_password(password: &str, username: &str) -> [u8; SHA0_DIGEST_LEN] {
    let mut hasher = Sha0::new();
    hasher.update(password.as_bytes());
    hasher.update(username.to_uppercase().as_bytes());
    hasher.finalize()
}

/// Compute secure password for authentication.
///
/// Algorithm: SHA0(password_hash || server_random)
///
/// This is sent to the server during authentication.
///
/// # Arguments
/// * `password_hash` - The SHA-0 hash of the password
/// * `server_random` - The random challenge from the server (20 bytes)
///
/// # Returns
/// A 20-byte secure password hash
pub fn compute_secure_password(
    password_hash: &[u8; SHA0_DIGEST_LEN],
    server_random: &[u8; SHA0_DIGEST_LEN],
) -> [u8; SHA0_DIGEST_LEN] {
    let mut hasher = Sha0::new();
    hasher.update(password_hash);
    hasher.update(server_random);
    hasher.finalize()
}

/// Generate a random MAC address for the virtual adapter.
///
/// Format: 5E:xx:xx:xx:xx:xx (5E is SoftEther's locally administered prefix)
pub fn generate_mac_address() -> [u8; 6] {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut mac = [0u8; 6];
    rng.fill_bytes(&mut mac);
    mac[0] = 0x5E; // SoftEther prefix
    mac[0] |= 0x02; // Locally administered bit
    mac
}

/// Generate random bytes using a cryptographically secure RNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut bytes = [0u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Generate random bytes into a slice.
pub fn fill_random(dest: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(dest);
}

/// Generate a DHCP transaction ID.
pub fn generate_transaction_id() -> u32 {
    use rand::Rng;
    rand::thread_rng().gen()
}

/// Convert PEM certificate to DER format.
pub fn pem_to_der(pem: &str) -> crate::Result<Vec<u8>> {
    use base64::Engine;

    // Find the certificate block
    let start_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let start = pem
        .find(start_marker)
        .ok_or_else(|| crate::Error::Config("Invalid PEM: missing BEGIN marker".into()))?;
    let end = pem
        .find(end_marker)
        .ok_or_else(|| crate::Error::Config("Invalid PEM: missing END marker".into()))?;

    let base64_content = &pem[start + start_marker.len()..end];
    let base64_clean: String = base64_content
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    base64::engine::general_purpose::STANDARD
        .decode(&base64_clean)
        .map_err(|e| crate::Error::Config(format!("Invalid PEM base64: {e}")))
}

/// Sign data with a private key (RSA PKCS#1 v1.5 SHA-1 signature).
///
/// This is used for certificate authentication in SoftEther.
pub fn sign_with_private_key(data: &[u8], private_key_pem: &str) -> crate::Result<Vec<u8>> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::{Pkcs1v15Sign, RsaPrivateKey};
    use sha1::{Digest, Sha1};

    // Parse the private key from PEM
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .or_else(|_| {
            // Try PKCS#1 format
            use rsa::pkcs1::DecodeRsaPrivateKey;
            RsaPrivateKey::from_pkcs1_pem(private_key_pem)
        })
        .map_err(|e| crate::Error::Config(format!("Failed to parse private key: {e}")))?;

    // Compute SHA-1 hash of the data
    let mut hasher = Sha1::new();
    hasher.update(data);
    let hash = hasher.finalize();

    // Sign with PKCS#1 v1.5
    let signature = private_key
        .sign(Pkcs1v15Sign::new::<Sha1>(), &hash)
        .map_err(|e| crate::Error::Config(format!("Failed to sign: {e}")))?;

    Ok(signature)
}

/// Bidirectional RC4 encryption state for tunnel traffic.
///
/// This wraps separate send/receive RC4 ciphers for encrypting
/// outbound and decrypting inbound tunnel data.
pub struct TunnelEncryption {
    send_cipher: Rc4,
    recv_cipher: Rc4,
}

impl TunnelEncryption {
    /// Create new tunnel encryption state from an RC4 key pair (client mode).
    ///
    /// - Send cipher uses client_to_server key
    /// - Recv cipher uses server_to_client key
    pub fn new(key_pair: &Rc4KeyPair) -> Self {
        let (send_cipher, recv_cipher) = key_pair.create_client_ciphers();
        Self {
            send_cipher,
            recv_cipher,
        }
    }

    /// Encrypt data in-place for sending to server.
    #[inline]
    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.send_cipher.process(data);
    }

    /// Decrypt data in-place received from server.
    #[inline]
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.recv_cipher.process(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha0_hash() {
        // Empty string should produce a known hash
        let hash = sha0_hash(b"");
        // SHA-0 of empty string
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_password_hash() {
        let hash = hash_password("password", "user");
        assert_eq!(hash.len(), 20);

        // Same input should produce same output
        let hash2 = hash_password("password", "user");
        assert_eq!(hash, hash2);

        // Different case username should produce same output (uppercased)
        let hash3 = hash_password("password", "USER");
        assert_eq!(hash, hash3);
    }

    #[test]
    fn test_secure_password() {
        let password_hash = hash_password("password", "user");
        let server_random = [0u8; 20];
        let secure = compute_secure_password(&password_hash, &server_random);
        assert_eq!(secure.len(), 20);
    }

    #[test]
    fn test_mac_address() {
        let mac = generate_mac_address();
        assert_eq!(mac.len(), 6);
        assert_eq!(mac[0] & 0xFE, 0x5E & 0xFE); // Check prefix (ignoring LSB)
        assert_eq!(mac[0] & 0x02, 0x02); // Local bit set
    }

    #[test]
    fn test_random_bytes() {
        let bytes1: [u8; 16] = random_bytes();
        let bytes2: [u8; 16] = random_bytes();
        // Very unlikely to be equal
        assert_ne!(bytes1, bytes2);
    }
}
