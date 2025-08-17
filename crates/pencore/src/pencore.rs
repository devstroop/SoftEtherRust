//! Pencore Module
//!
//! Handles parsing, validation, serialization, and deserialization of the `pencore` field.

use anyhow::Result;

/// Represents a parsed Pencore structure
#[derive(Debug, Clone)]
pub struct Pencore {
    pub raw_data: Vec<u8>,
}

impl Pencore {
    /// Parse a `pencore` field from raw data
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            anyhow::bail!("Pencore data is empty");
        }

        Ok(Self {
            raw_data: data.to_vec(),
        })
    }
    /// Validate the `pencore` field
    pub fn validate(&self) -> Result<()> {
        if self.raw_data.len() < 10 {
            anyhow::bail!("Pencore data is too short");
        }

        // Add additional validation logic as needed
        Ok(())
    }

    /// Serialize the `pencore` field to raw data
    pub fn serialize(&self) -> Vec<u8> {
        self.raw_data.clone()
    }

    /// Deserialize raw data into a `Pencore` structure
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        Self::parse(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pencore_parse() {
        let data = vec![1, 2, 3, 4, 5];
        let pencore = Pencore::parse(&data).unwrap();
        assert_eq!(pencore.raw_data, data);
    }

    #[test]
    fn test_pencore_validate() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let pencore = Pencore::parse(&data).unwrap();
        assert!(pencore.validate().is_ok());
    }

    #[test]
    fn test_pencore_serialize_deserialize() {
        let data = vec![1, 2, 3, 4, 5];
        let pencore = Pencore::parse(&data).unwrap();
        let serialized = pencore.serialize();
        let deserialized = Pencore::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.raw_data, data);
    }
}
// End of module
