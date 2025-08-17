//! Memory management utilities
//!
//! Safe Rust alternatives to C malloc/free patterns

use crate::error::{Error, Result};

/// Safe buffer management
pub struct Buffer {
    data: Vec<u8>,
    capacity: usize,
}

impl Buffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            capacity,
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        if self.data.len() + data.len() > self.capacity {
            return Err(Error::NoMemory);
        }
        self.data.extend_from_slice(data);
        Ok(())
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }
}

/// Zero-on-drop buffer for sensitive data
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0; size],
        }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Zero out memory on drop for security
        self.data.fill(0);
    }
}

// TODO: Implement additional memory utilities
// - Memory pools for high-frequency allocations
// - Ring buffers for network I/O
// - Reference counting helpers
