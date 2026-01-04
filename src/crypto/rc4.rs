//! RC4 stream cipher implementation for SoftEther VPN tunnel encryption.
//!
//! SoftEther uses RC4 for "fast encryption" mode (`UseFastRC4`).
//! Each TCP socket has separate SendKey and RecvKey contexts.
//!
//! Based on SoftEther's Encrypt.c implementation.

/// RC4 key size used by SoftEther (16 bytes).
pub const RC4_KEY_SIZE: usize = 16;

/// RC4 stream cipher state.
///
/// This is a streaming cipher - each call to `process()` continues
/// from where the last call left off. Do NOT reset between packets.
#[derive(Clone)]
pub struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Create a new RC4 cipher with the given key.
    ///
    /// Key can be 1-256 bytes, but SoftEther uses 16-byte keys.
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty() && key.len() <= 256, "RC4 key must be 1-256 bytes");

        let mut state = [0u8; 256];
        
        // Initialize state array (KSA - Key Scheduling Algorithm)
        for (i, s) in state.iter_mut().enumerate() {
            *s = i as u8;
        }

        // Key scheduling
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }

        Self { state, i: 0, j: 0 }
    }

    /// Process data in-place (encrypt or decrypt - RC4 is symmetric).
    ///
    /// This modifies the internal state, so subsequent calls continue
    /// the keystream. This is correct for SoftEther's streaming usage.
    #[inline]
    pub fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[self.i as usize]);
            self.state.swap(self.i as usize, self.j as usize);
            
            let k = self.state[(self.state[self.i as usize].wrapping_add(self.state[self.j as usize])) as usize];
            *byte ^= k;
        }
    }

    /// Process data from source to destination.
    ///
    /// Source and destination can be the same slice for in-place operation.
    #[inline]
    pub fn process_to(&mut self, src: &[u8], dst: &mut [u8]) {
        assert_eq!(src.len(), dst.len(), "Source and destination must have same length");
        
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[self.i as usize]);
            self.state.swap(self.i as usize, self.j as usize);
            
            let k = self.state[(self.state[self.i as usize].wrapping_add(self.state[self.j as usize])) as usize];
            *d = *s ^ k;
        }
    }

    /// Skip n bytes of keystream without processing any data.
    ///
    /// Useful for synchronizing state if bytes were lost.
    pub fn skip(&mut self, n: usize) {
        for _ in 0..n {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[self.i as usize]);
            self.state.swap(self.i as usize, self.j as usize);
        }
    }
}

/// RC4 key pair for SoftEther tunnel encryption.
///
/// SoftEther uses separate keys for each direction:
/// - ClientToServerKey: Client uses for sending, server uses for receiving
/// - ServerToClientKey: Server uses for sending, client uses for receiving
#[derive(Clone)]
pub struct Rc4KeyPair {
    /// Key for client-to-server direction (16 bytes).
    pub client_to_server: [u8; RC4_KEY_SIZE],
    /// Key for server-to-client direction (16 bytes).
    pub server_to_client: [u8; RC4_KEY_SIZE],
}

impl Rc4KeyPair {
    /// Create from raw key data.
    pub fn new(client_to_server: [u8; RC4_KEY_SIZE], server_to_client: [u8; RC4_KEY_SIZE]) -> Self {
        Self {
            client_to_server,
            server_to_client,
        }
    }

    /// Create RC4 ciphers for client mode.
    ///
    /// Returns (send_cipher, recv_cipher) for the client.
    /// - Send cipher uses client_to_server key
    /// - Recv cipher uses server_to_client key
    pub fn create_client_ciphers(&self) -> (Rc4, Rc4) {
        let send = Rc4::new(&self.client_to_server);
        let recv = Rc4::new(&self.server_to_client);
        (send, recv)
    }

    /// Create RC4 ciphers for server mode.
    ///
    /// Returns (send_cipher, recv_cipher) for the server.
    /// - Send cipher uses server_to_client key
    /// - Recv cipher uses client_to_server key
    pub fn create_server_ciphers(&self) -> (Rc4, Rc4) {
        let send = Rc4::new(&self.server_to_client);
        let recv = Rc4::new(&self.client_to_server);
        (send, recv)
    }
}

impl Default for Rc4KeyPair {
    fn default() -> Self {
        Self {
            client_to_server: [0u8; RC4_KEY_SIZE],
            server_to_client: [0u8; RC4_KEY_SIZE],
        }
    }
}

impl std::fmt::Debug for Rc4KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't print actual keys in debug output
        f.debug_struct("Rc4KeyPair")
            .field("client_to_server", &"[redacted]")
            .field("server_to_client", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4_encrypt_decrypt() {
        let key = b"0123456789abcdef";
        let plaintext = b"Hello, SoftEther VPN!";
        
        // Encrypt
        let mut encrypt = Rc4::new(key);
        let mut ciphertext = plaintext.to_vec();
        encrypt.process(&mut ciphertext);
        
        // Ciphertext should be different from plaintext
        assert_ne!(&ciphertext[..], plaintext);
        
        // Decrypt with fresh cipher (same key)
        let mut decrypt = Rc4::new(key);
        decrypt.process(&mut ciphertext);
        
        // Should get back plaintext
        assert_eq!(&ciphertext[..], plaintext);
    }

    #[test]
    fn test_rc4_streaming() {
        // RC4 is a streaming cipher - processing in chunks should give same result
        let key = b"test_key_16bytes";
        let data = b"This is a longer message that we'll process in chunks";
        
        // Process all at once
        let mut cipher1 = Rc4::new(key);
        let mut result1 = data.to_vec();
        cipher1.process(&mut result1);
        
        // Process in chunks
        let mut cipher2 = Rc4::new(key);
        let mut result2 = data.to_vec();
        cipher2.process(&mut result2[..10]);
        cipher2.process(&mut result2[10..25]);
        cipher2.process(&mut result2[25..]);
        
        // Results should be identical
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_rc4_key_pair_client() {
        let c2s_key = [1u8; RC4_KEY_SIZE];
        let s2c_key = [2u8; RC4_KEY_SIZE];
        let pair = Rc4KeyPair::new(c2s_key, s2c_key);
        
        let (send, recv) = pair.create_client_ciphers();
        
        // Verify by encrypting known data
        let mut send_data = [0u8; 16];
        let mut recv_data = [0u8; 16];
        
        let mut send_cipher = send;
        let mut recv_cipher = recv;
        
        send_cipher.process(&mut send_data);
        recv_cipher.process(&mut recv_data);
        
        // Send and recv should use different keys, so results differ
        assert_ne!(send_data, recv_data);
    }

    #[test]
    fn test_rc4_skip() {
        let key = b"test_key_16bytes";
        
        // Process with skip
        let mut cipher1 = Rc4::new(key);
        cipher1.skip(100);
        let mut data1 = [0u8; 16];
        cipher1.process(&mut data1);
        
        // Process by actually encrypting 100 bytes then our data
        let mut cipher2 = Rc4::new(key);
        let mut skip_data = [0u8; 100];
        cipher2.process(&mut skip_data);
        let mut data2 = [0u8; 16];
        cipher2.process(&mut data2);
        
        // Results should be identical
        assert_eq!(data1, data2);
    }

    #[test]
    fn test_rc4_process_to() {
        let key = b"test_key_16bytes";
        let src = b"Hello World!";
        
        let mut cipher1 = Rc4::new(key);
        let mut dst1 = [0u8; 12];
        cipher1.process_to(src, &mut dst1);
        
        let mut cipher2 = Rc4::new(key);
        let mut dst2 = src.to_vec();
        cipher2.process(&mut dst2);
        
        assert_eq!(&dst1[..], &dst2[..]);
    }

    /// Test vector from RFC 6229 (RC4 test vectors)
    #[test]
    fn test_rc4_rfc6229_vector() {
        // Key: 0102030405
        let key = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut cipher = Rc4::new(&key);
        
        // First 16 bytes of keystream
        let mut output = [0u8; 16];
        cipher.process(&mut output);
        
        // Expected keystream (first 16 bytes)
        let expected = [
            0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
            0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8,
        ];
        
        assert_eq!(output, expected);
    }
}
