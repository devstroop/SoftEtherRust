//! PenCore - Dummy random data handling
//!
//! In SoftEther VPN protocol, "pencore" is a random data field added to PACK messages
//! for obfuscation purposes. It has no semantic meaning and is simply validated as
//! being present and having reasonable size.

use crate::{Error, Result};

/// PenCore represents dummy random data sent in protocol messages
#[derive(Debug, Clone)]
pub struct Pencore {
    data: Vec<u8>,
}

impl Pencore {
    /// Parse pencore data from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        // Pencore is just random data, no specific format to parse
        // Just verify it's not too large (sanity check)
        const MAX_PENCORE_SIZE: usize = 1024 * 1024; // 1MB max

        if data.len() > MAX_PENCORE_SIZE {
            return Err(Error::ProtocolError);
        }

        Ok(Self {
            data: data.to_vec(),
        })
    }

    /// Validate the pencore data
    /// Since it's dummy data, validation is minimal
    pub fn validate(&self) -> Result<()> {
        // Just check it's not empty and not too large
        if self.data.is_empty() {
            return Err(Error::ProtocolError);
        }

        Ok(())
    }

    /// Get the raw data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the size of pencore data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if pencore is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pencore_parse() {
        let data = vec![1, 2, 3, 4, 5];
        let pencore = Pencore::parse(&data).unwrap();
        assert_eq!(pencore.len(), 5);
        assert_eq!(pencore.data(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_pencore_validate() {
        let data = vec![0; 100];
        let pencore = Pencore::parse(&data).unwrap();
        assert!(pencore.validate().is_ok());
    }

    #[test]
    fn test_pencore_empty() {
        let data = vec![];
        let pencore = Pencore::parse(&data).unwrap();
        assert!(pencore.validate().is_err());
    }

    #[test]
    fn test_pencore_too_large() {
        let data = vec![0; 2 * 1024 * 1024]; // 2MB
        assert!(Pencore::parse(&data).is_err());
    }
}
