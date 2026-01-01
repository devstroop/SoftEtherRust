//! SHA-0 hash implementation.
//!
//! SHA-0 is an obsolete cryptographic hash function that was superseded by SHA-1.
//! SoftEther VPN uses SHA-0 for password hashing for legacy compatibility.
//!
//! The key difference from SHA-1 is that SHA-0 does NOT rotate the message
//! schedule words (w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16] without rotation).

/// SHA-0 block size in bytes.
const BLOCK_SIZE: usize = 64;

/// SHA-0 digest length in bytes.
pub const DIGEST_LEN: usize = 20;

/// Initial hash values (same as SHA-1).
const H0: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

/// Round constants.
const K: [u32; 4] = [
    0x5A827999, // Rounds 0-19
    0x6ED9EBA1, // Rounds 20-39
    0x8F1BBCDC, // Rounds 40-59
    0xCA62C1D6, // Rounds 60-79
];

/// SHA-0 hasher.
#[derive(Clone)]
pub struct Sha0 {
    state: [u32; 5],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: u64,
}

impl Sha0 {
    /// Create a new SHA-0 hasher.
    pub fn new() -> Self {
        Self {
            state: H0,
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Update the hasher with input data.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;

        // Fill buffer first
        if self.buffer_len > 0 {
            let space = BLOCK_SIZE - self.buffer_len;
            let to_copy = data.len().min(space);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            data = &data[to_copy..];

            if self.buffer_len == BLOCK_SIZE {
                self.process_block(&self.buffer.clone());
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while data.len() >= BLOCK_SIZE {
            self.process_block(data[..BLOCK_SIZE].try_into().unwrap());
            data = &data[BLOCK_SIZE..];
        }

        // Store remaining bytes
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Finalize the hash and return the digest.
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let total_bits = self.total_len * 8;

        // Pad with 0x80
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If not enough space for length, pad and process
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            self.process_block(&self.buffer.clone());
            self.buffer_len = 0;
        }

        // Pad with zeros until length position
        self.buffer[self.buffer_len..56].fill(0);

        // Append length in bits (big-endian)
        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        self.process_block(&self.buffer.clone());

        // Extract digest
        let mut digest = [0u8; DIGEST_LEN];
        for (i, &h) in self.state.iter().enumerate() {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&h.to_be_bytes());
        }
        digest
    }

    /// Process a single 512-bit block.
    fn process_block(&mut self, block: &[u8; BLOCK_SIZE]) {
        let mut w = [0u32; 80];

        // Load first 16 words (big-endian)
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
        }

        // SHA-0: NO rotation in message schedule
        // This is the key difference from SHA-1!
        for i in 16..80 {
            w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            // SHA-1 would have: w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1)
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        #[allow(clippy::needless_range_loop)]
        for i in 0..80 {
            let (f, k) = if i < 20 {
                ((b & c) | ((!b) & d), K[0])
            } else if i < 40 {
                (b ^ c ^ d, K[1])
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), K[2])
            } else {
                (b ^ c ^ d, K[3])
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);

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

    /// Hash data in one call.
    pub fn hash(data: &[u8]) -> [u8; DIGEST_LEN] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Sha0 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha0_empty() {
        let hash = Sha0::hash(b"");
        // SHA-0 hash of empty string (note: different from SHA-1 due to no rotation in W expansion)
        let expected = [
            0xf9, 0x6c, 0xea, 0x19, 0x8a, 0xd1, 0xdd, 0x56, 0x17, 0xac, 0x08, 0x4a, 0x3d, 0x92,
            0xc6, 0x10, 0x77, 0x08, 0xc0, 0xef,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha0_abc() {
        let hash = Sha0::hash(b"abc");
        // SHA-0 hash of "abc"
        let expected = [
            0x01, 0x64, 0xb8, 0xa9, 0x14, 0xcd, 0x2a, 0x5e, 0x74, 0xc4, 0xf7, 0xff, 0x08, 0x2c,
            0x4d, 0x97, 0xf1, 0xed, 0xf8, 0x80,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha0_incremental() {
        let mut hasher = Sha0::new();
        hasher.update(b"ab");
        hasher.update(b"c");
        let hash = hasher.finalize();

        let direct = Sha0::hash(b"abc");
        assert_eq!(hash, direct);
    }

    #[test]
    fn test_sha0_long_message() {
        // Test with a message longer than one block
        let data = b"The quick brown fox jumps over the lazy dog";
        let hash = Sha0::hash(data);
        assert_eq!(hash.len(), DIGEST_LEN);
    }
}
