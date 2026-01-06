//! RC4 stream cipher implementation for SoftEther tunnel encryption.
//!
//! SoftEther uses RC4 for inner-layer encryption within the TLS tunnel.
//! This provides defense-in-depth when `use_encrypt` is enabled.
//!
//! # Key Derivation
//!
//! The RC4 key is derived from the session key provided by the server:
//! - Send key: SHA-1(session_key || "send")
//! - Recv key: SHA-1(session_key || "recv")
//!
//! Note: The roles are swapped for client vs server perspective.
//!
//! # Security Note
//!
//! RC4 has known weaknesses and is considered deprecated for modern use.
//! However, this implementation is for compatibility with SoftEther protocol.
//! The outer TLS layer provides the primary security.

use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};

/// RC4 key length used by SoftEther (20 bytes = SHA-1 output)
pub const RC4_KEY_SIZE: usize = 20;

/// Initial keystream bytes to discard (mitigates RC4 biases)
const RC4_SKIP_BYTES: usize = 1024;

/// RC4 cipher state.
///
/// This implementation follows the standard RC4 algorithm with an
/// initial keystream discard for improved security.
#[derive(Clone)]
pub struct Rc4 {
    /// The permutation array (S-box)
    state: [u8; 256],
    /// Index i
    i: u8,
    /// Index j
    j: u8,
}

impl Rc4 {
    /// Create a new RC4 cipher with the given key.
    ///
    /// The key can be 1-256 bytes. For SoftEther, it's typically 20 bytes (SHA-1).
    /// This constructor automatically discards the first 1024 bytes of keystream
    /// to mitigate known RC4 biases.
    pub fn new(key: &[u8]) -> Self {
        let mut rc4 = Self::new_no_skip(key);
        // Discard initial keystream bytes to mitigate RC4 biases
        rc4.skip(RC4_SKIP_BYTES);
        rc4
    }

    /// Create a new RC4 cipher without skipping initial keystream.
    ///
    /// Use this only if you need exact compatibility with implementations
    /// that don't use the skip optimization.
    pub fn new_no_skip(key: &[u8]) -> Self {
        assert!(
            !key.is_empty() && key.len() <= 256,
            "Key must be 1-256 bytes"
        );

        // Key-scheduling algorithm (KSA)
        let mut state = [0u8; 256];
        for (i, s) in state.iter_mut().enumerate() {
            *s = i as u8;
        }

        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }

        Self { state, i: 0, j: 0 }
    }

    /// Skip n bytes of keystream.
    #[inline]
    fn skip(&mut self, n: usize) {
        for _ in 0..n {
            self.next_byte();
        }
    }

    /// Generate the next keystream byte.
    #[inline]
    fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[self.i as usize]);
        self.state.swap(self.i as usize, self.j as usize);
        self.state[(self.state[self.i as usize].wrapping_add(self.state[self.j as usize])) as usize]
    }

    /// Encrypt or decrypt data in place.
    ///
    /// RC4 is symmetric - the same operation encrypts and decrypts.
    #[inline]
    pub fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            *byte ^= self.next_byte();
        }
    }

    /// Encrypt or decrypt data, returning a new buffer.
    pub fn process_to_vec(&mut self, data: &[u8]) -> Vec<u8> {
        let mut result = data.to_vec();
        self.process(&mut result);
        result
    }

    /// Reset the cipher state with a new key.
    pub fn reset(&mut self, key: &[u8]) {
        *self = Self::new(key);
    }
}

impl std::fmt::Debug for Rc4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rc4")
            .field("i", &self.i)
            .field("j", &self.j)
            .finish_non_exhaustive()
    }
}

/// Tunnel encryption context for SoftEther.
///
/// Manages separate RC4 states for send and receive directions.
#[derive(Debug, Clone)]
pub struct TunnelCrypto {
    /// RC4 state for encrypting outgoing data (client -> server)
    send_cipher: Rc4,
    /// RC4 state for decrypting incoming data (server -> client)
    recv_cipher: Rc4,
    /// Whether encryption is enabled
    enabled: bool,
}

impl TunnelCrypto {
    /// Create a new tunnel crypto context from a session key.
    ///
    /// The session key is provided by the server during authentication.
    /// Two RC4 keys are derived:
    /// - Send key: SHA-1(session_key || "send")  -- for client->server
    /// - Recv key: SHA-1(session_key || "recv")  -- for server->client
    ///
    /// Note: From the client perspective, we send with "send" key and
    /// receive with "recv" key. The server does the opposite.
    pub fn new(session_key: &[u8]) -> Self {
        let send_key = derive_key(session_key, b"send");
        let recv_key = derive_key(session_key, b"recv");

        Self {
            send_cipher: Rc4::new(&send_key),
            recv_cipher: Rc4::new(&recv_key),
            enabled: true,
        }
    }

    /// Create a disabled (pass-through) tunnel crypto.
    pub fn disabled() -> Self {
        // Keys don't matter for disabled mode
        Self {
            send_cipher: Rc4::new(&[0u8; 20]),
            recv_cipher: Rc4::new(&[0u8; 20]),
            enabled: false,
        }
    }

    /// Check if encryption is enabled.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Encrypt data for sending to the server.
    ///
    /// Modifies data in place. If encryption is disabled, this is a no-op.
    #[inline]
    pub fn encrypt(&mut self, data: &mut [u8]) {
        if self.enabled {
            self.send_cipher.process(data);
        }
    }

    /// Decrypt data received from the server.
    ///
    /// Modifies data in place. If encryption is disabled, this is a no-op.
    #[inline]
    pub fn decrypt(&mut self, data: &mut [u8]) {
        if self.enabled {
            self.recv_cipher.process(data);
        }
    }

    /// Encrypt data for sending, returning a new buffer.
    pub fn encrypt_to_vec(&mut self, data: &[u8]) -> Vec<u8> {
        if self.enabled {
            self.send_cipher.process_to_vec(data)
        } else {
            data.to_vec()
        }
    }

    /// Decrypt data received, returning a new buffer.
    pub fn decrypt_to_vec(&mut self, data: &[u8]) -> Vec<u8> {
        if self.enabled {
            self.recv_cipher.process_to_vec(data)
        } else {
            data.to_vec()
        }
    }
}

/// Derive an RC4 key from session key and direction suffix.
///
/// Uses SHA-1 to derive a 20-byte key: SHA1(session_key || direction)
fn derive_key(session_key: &[u8], direction: &[u8]) -> [u8; RC4_KEY_SIZE] {
    let mut ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(session_key);
    ctx.update(direction);
    let digest = ctx.finish();

    let mut key = [0u8; RC4_KEY_SIZE];
    key.copy_from_slice(digest.as_ref());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4_basic() {
        // Basic test: verify RC4 produces keystream and is reversible
        let key = b"Key";
        let mut rc4_enc = Rc4::new_no_skip(key);
        let mut rc4_dec = Rc4::new_no_skip(key);

        let plaintext = b"Hello RC4 World!";
        let mut data = plaintext.to_vec();

        // Encrypt
        rc4_enc.process(&mut data);
        assert_ne!(&data[..], &plaintext[..], "Data should be encrypted");

        // Decrypt
        rc4_dec.process(&mut data);
        assert_eq!(
            &data[..],
            &plaintext[..],
            "Data should match original after decrypt"
        );
    }

    #[test]
    fn test_rc4_encrypt_decrypt() {
        let key = b"test_key_12345";
        let plaintext = b"Hello, World! This is a test message.";

        // Encrypt
        let mut rc4_enc = Rc4::new(key);
        let mut ciphertext = plaintext.to_vec();
        rc4_enc.process(&mut ciphertext);

        // Ciphertext should be different from plaintext
        assert_ne!(&ciphertext[..], &plaintext[..]);

        // Decrypt with fresh state
        let mut rc4_dec = Rc4::new(key);
        rc4_dec.process(&mut ciphertext);

        // Should match original
        assert_eq!(&ciphertext[..], &plaintext[..]);
    }

    #[test]
    fn test_rc4_streaming() {
        let key = b"streaming_key";
        let data1 = b"First chunk";
        let data2 = b"Second chunk";

        // Encrypt in chunks
        let mut rc4_enc = Rc4::new(key);
        let mut enc1 = data1.to_vec();
        let mut enc2 = data2.to_vec();
        rc4_enc.process(&mut enc1);
        rc4_enc.process(&mut enc2);

        // Decrypt in chunks with fresh state
        let mut rc4_dec = Rc4::new(key);
        rc4_dec.process(&mut enc1);
        rc4_dec.process(&mut enc2);

        assert_eq!(&enc1[..], &data1[..]);
        assert_eq!(&enc2[..], &data2[..]);
    }

    #[test]
    fn test_tunnel_crypto() {
        let session_key = b"test_session_key_123";

        // Create client and server crypto contexts
        // For testing, we swap send/recv keys to simulate server side
        let mut client = TunnelCrypto::new(session_key);

        // Server uses opposite keys
        let send_key = derive_key(session_key, b"recv"); // Server sends with recv key
        let recv_key = derive_key(session_key, b"send"); // Server receives with send key
        let mut server_send = Rc4::new(&send_key);
        let mut server_recv = Rc4::new(&recv_key);

        // Client sends to server
        let original = b"Client to server message";
        let mut data = original.to_vec();
        client.encrypt(&mut data);

        // Server decrypts
        server_recv.process(&mut data);
        assert_eq!(&data[..], &original[..]);

        // Server sends to client
        let original2 = b"Server to client message";
        let mut data2 = original2.to_vec();
        server_send.process(&mut data2);

        // Client decrypts
        client.decrypt(&mut data2);
        assert_eq!(&data2[..], &original2[..]);
    }

    #[test]
    fn test_tunnel_crypto_disabled() {
        let mut crypto = TunnelCrypto::disabled();
        assert!(!crypto.is_enabled());

        let original = b"Test data";
        let mut data = original.to_vec();

        // Should be no-op when disabled
        crypto.encrypt(&mut data);
        assert_eq!(&data[..], &original[..]);

        crypto.decrypt(&mut data);
        assert_eq!(&data[..], &original[..]);
    }

    #[test]
    fn test_key_derivation() {
        let session_key = b"session123";

        let send_key = derive_key(session_key, b"send");
        let recv_key = derive_key(session_key, b"recv");

        // Keys should be different
        assert_ne!(send_key, recv_key);

        // Keys should be deterministic
        let send_key2 = derive_key(session_key, b"send");
        assert_eq!(send_key, send_key2);
    }

    #[test]
    fn test_rc4_clone() {
        let key = b"clone_test_key";
        let mut rc4 = Rc4::new(key);

        // Process some data
        let mut data1 = vec![0u8; 100];
        rc4.process(&mut data1);

        // Clone and process more
        let mut rc4_clone = rc4.clone();
        let mut data2a = vec![0u8; 50];
        let mut data2b = vec![0u8; 50];

        rc4.process(&mut data2a);
        rc4_clone.process(&mut data2b);

        // Both should produce same keystream after clone point
        assert_eq!(data2a, data2b);
    }

    #[test]
    fn test_process_to_vec() {
        let key = b"vec_test_key";
        let mut rc4 = Rc4::new(key);

        let data = b"Original data";
        let encrypted = rc4.process_to_vec(data);

        assert_ne!(&encrypted[..], &data[..]);
        assert_eq!(encrypted.len(), data.len());
    }
}
