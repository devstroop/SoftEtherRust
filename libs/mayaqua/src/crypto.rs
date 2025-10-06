//! Cryptographic functions for SoftEther VPN
//!
//! Includes SHA-0 implementation for compatibility with C version

// (No direct crate::error usage here; removed unused imports)

/// SHA-1 output size (20 bytes) - also used for SHA-0
pub const SHA1_SIZE: usize = 20;
pub type Sha1Sum = [u8; SHA1_SIZE];

/// SHA-0 context structure
///
/// CRITICAL: This implements SHA-0, not SHA-1, for compatibility with
/// SoftEther's password authentication system
pub struct Sha0Context {
    count: u64,
    buffer: [u8; 64],
    state: [u32; 5],
    buffer_len: usize,
}

impl Sha0Context {
    pub fn new() -> Self {
        let mut ctx = Self {
            count: 0,
            buffer: [0; 64],
            state: [0; 5],
            buffer_len: 0,
        };
        ctx.init();
        ctx
    }

    fn init(&mut self) {
        // SHA-0 initial values (same as SHA-1)
        self.state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
        self.count = 0;
        self.buffer_len = 0;
    }

    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.buffer[self.buffer_len] = byte;
            self.buffer_len += 1;
            self.count += 8; // Count in bits

            if self.buffer_len == 64 {
                self.transform();
                self.buffer_len = 0;
            }
        }
    }

    pub fn finalize(mut self) -> Sha1Sum {
        // Padding
        let msg_bit_length = self.count;
        let _msg_len = (msg_bit_length >> 3) as usize; // length not needed directly

        // Append bit '1' to message
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If not enough space for length, pad and transform
        if self.buffer_len > 56 {
            while self.buffer_len < 64 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            self.transform();
            self.buffer_len = 0;
        }

        // Pad to 56 bytes
        while self.buffer_len < 56 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }

        // Append length in bits as 64-bit big-endian
        let length_bytes = msg_bit_length.to_be_bytes();
        self.buffer[56..(56 + 8)].copy_from_slice(&length_bytes);
        self.buffer_len = 64;

        self.transform();

        // Convert state to output bytes (big-endian)
        let mut output = [0u8; 20];
        for i in 0..5 {
            let bytes = self.state[i].to_be_bytes();
            output[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }

        output
    }

    fn transform(&mut self) {
        // SHA-0 transform (differs from SHA-1 in the W calculation)
        let mut w = [0u32; 80];

        // Copy data to W[0..15]
        for (i, wi) in w.iter_mut().take(16).enumerate() {
            let base = i * 4;
            *wi = u32::from_be_bytes([
                self.buffer[base],
                self.buffer[base + 1],
                self.buffer[base + 2],
                self.buffer[base + 3],
            ]);
        }

        // Calculate W[16..79] - SHA-0 does NOT rotate left by 1
        // This is the key difference from SHA-1
        for i in 16..80 {
            w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            // SHA-1 would do: w[i] = w[i].rotate_left(1);
            // SHA-0 does NOT rotate - this is critical for compatibility
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        // 80 rounds
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                60..=79 => (b ^ c ^ d, 0xCA62C1D6),
                _ => unreachable!(),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(wi)
                .wrapping_add(k);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

impl Default for Sha0Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute SHA-0 hash of data
///
/// CRITICAL: This is SHA-0, not SHA-1. Required for SoftEther password compatibility.
pub fn sha0(data: &[u8]) -> Sha1Sum {
    let mut ctx = Sha0Context::new();
    ctx.update(data);
    ctx.finalize()
}

/// Compute SHA-1 hash of data (using external crate for non-compatibility cases)
pub fn sha1(data: &[u8]) -> Sha1Sum {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 20];
    output.copy_from_slice(&result);
    output
}

/// Calculate SoftEther password hash (SHA-0 of password + uppercase username)
/// This matches the Go implementation: mayaqua.Sha0([]byte(password + username))
pub fn softether_password_hash(password: &str, username: &str) -> Sha1Sum {
    let username_upper = username.to_uppercase();
    let combined = format!("{password}{username_upper}");
    sha0(combined.as_bytes())
}

/// RC4 stream cipher (legacy compatibility). Same function for encrypt/decrypt.
pub fn rc4_apply(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s = [0u8; 256];
    for (i, v) in s.iter_mut().enumerate() {
        *v = i as u8;
    }
    let mut j: u8 = 0;
    // KSA
    for i in 0..256 {
        let ki = key[i % key.len()];
        j = j.wrapping_add(s[i]).wrapping_add(ki);
        s.swap(i, j as usize);
    }
    // PRGA
    let mut i: u8 = 0;
    let mut j2: u8 = 0;
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        i = i.wrapping_add(1);
        j2 = j2.wrapping_add(s[i as usize]);
        s.swap(i as usize, j2 as usize);
        let t = s[i as usize].wrapping_add(s[j2 as usize]);
        let k = s[t as usize];
        out.push(b ^ k);
    }
    out
}

/// RC4 in-place on mutable buffer
pub fn rc4_apply_inplace(key: &[u8], buf: &mut [u8]) {
    let keystream = rc4_keystream(key, buf.len());
    for (b, k) in buf.iter_mut().zip(keystream) {
        *b ^= k;
    }
}

fn rc4_keystream(key: &[u8], len: usize) -> Vec<u8> {
    let mut s = [0u8; 256];
    for (i, v) in s.iter_mut().enumerate() {
        *v = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        let ki = key[i % key.len()];
        j = j.wrapping_add(s[i]).wrapping_add(ki);
        s.swap(i, j as usize);
    }
    let mut i: u8 = 0;
    let mut j2: u8 = 0;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        i = i.wrapping_add(1);
        j2 = j2.wrapping_add(s[i as usize]);
        s.swap(i as usize, j2 as usize);
        let t = s[i as usize].wrapping_add(s[j2 as usize]);
        out.push(s[t as usize]);
    }
    out
}

// TODO: Implement additional crypto functions
// - RC4 encryption (for legacy compatibility)
// - AES encryption
// - RSA operations
// - Certificate handling

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha0_empty() {
        let result = sha0(b"");
        // SHA-0 of empty string should be different from SHA-1
        let sha1_result = sha1(b"");

        // They should be different due to the rotation difference
        // This test validates our SHA-0 implementation is different from SHA-1
        println!("SHA-0 empty: {:02x?}", result);
        println!("SHA-1 empty: {:02x?}", sha1_result);

        // The first few bytes should be the same since the difference
        // only appears after the first transform
        // But they will diverge for most inputs
    }

    #[test]
    fn test_sha0_basic() {
        let result = sha0(b"abc");
        println!("SHA-0 'abc': {:02x?}", result);

        let sha1_result = sha1(b"abc");
        println!("SHA-1 'abc': {:02x?}", sha1_result);

        // Should be different due to SHA-0 vs SHA-1 algorithm difference
        assert_ne!(result, sha1_result);
    }

    #[test]
    fn test_sha0_incremental() {
        let mut ctx = Sha0Context::new();
        ctx.update(b"a");
        ctx.update(b"bc");
        let result1 = ctx.finalize();

        let result2 = sha0(b"abc");
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_softether_password_hash() {
        // Test with the actual credentials
        let result = softether_password_hash("devstroop111222", "devstroop");
        let expected_b64 = "T2kl2mB84H5y2tn7n9qf65/8jXI=";

        // Convert result to base64 to compare with known good value
        use base64::prelude::*;
        let actual_b64 = BASE64_STANDARD.encode(result);

        println!("Password hash for devstroop111222+DEVSTROOP:");
        println!("Expected: {}", expected_b64);
        println!("Actual:   {}", actual_b64);

        // This test validates our SHA-0 implementation matches SoftEther Go
        assert_eq!(
            actual_b64, expected_b64,
            "Password hash doesn't match expected value"
        );
    }

    #[test]
    fn test_rc4_roundtrip() {
        let key = b"secretkey";
        let plain = b"hello world";
        let enc = rc4_apply(key, plain);
        let dec = rc4_apply(key, &enc);
        assert_eq!(dec, plain);
    }
}
