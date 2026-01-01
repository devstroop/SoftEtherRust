//! SoftEther Pack serialization format.
//!
//! Pack is SoftEther's binary serialization format used for RPC communication.
//!
//! ## Binary Format
//!
//! - Pack: `[num_elements:u32] [element...]`
//! - Element: `[name_len:u32] [name:bytes] [type:u32] [num_values:u32] [value...]`
//! - Value types:
//!   - INT (0): `[value:u32]`
//!   - DATA (1): `[size:u32] [bytes...]`
//!   - STR (2): `[len:u32] [utf8_bytes...]`
//!   - UNISTR (3): `[size:u32] [utf8_bytes... 0x00]`
//!   - INT64 (4): `[value:u64]`

use super::constants::*;
use crate::error::{Error, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;

/// Pack value types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PackValueType {
    Int = 0,
    Data = 1,
    Str = 2,
    UniStr = 3,
    Int64 = 4,
}

impl TryFrom<u32> for PackValueType {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Int),
            1 => Ok(Self::Data),
            2 => Ok(Self::Str),
            3 => Ok(Self::UniStr),
            4 => Ok(Self::Int64),
            _ => Err(Error::pack(format!("Invalid Pack value type: {}", value))),
        }
    }
}

/// A value in a Pack.
#[derive(Debug, Clone, PartialEq)]
pub enum PackValue {
    Int(u32),
    Int64(u64),
    Str(String),
    UniStr(String),
    Data(Bytes),
}

impl PackValue {
    /// Get the value type.
    pub fn value_type(&self) -> PackValueType {
        match self {
            Self::Int(_) => PackValueType::Int,
            Self::Int64(_) => PackValueType::Int64,
            Self::Str(_) => PackValueType::Str,
            Self::UniStr(_) => PackValueType::UniStr,
            Self::Data(_) => PackValueType::Data,
        }
    }

    /// Try to get as u32.
    pub fn as_int(&self) -> Option<u32> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as u64.
    pub fn as_int64(&self) -> Option<u64> {
        match self {
            Self::Int64(v) => Some(*v),
            Self::Int(v) => Some(*v as u64),
            _ => None,
        }
    }

    /// Try to get as string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) | Self::UniStr(s) => Some(s),
            _ => None,
        }
    }

    /// Try to get as bytes.
    pub fn as_data(&self) -> Option<&Bytes> {
        match self {
            Self::Data(d) => Some(d),
            _ => None,
        }
    }

    /// Try to get as bool.
    pub fn as_bool(&self) -> Option<bool> {
        self.as_int().map(|v| v != 0)
    }
}

/// A Pack element (named list of values).
#[derive(Debug, Clone)]
pub struct PackElement {
    pub name: String,
    pub value_type: PackValueType,
    pub values: Vec<PackValue>,
}

/// SoftEther Pack - binary serialization format.
#[derive(Debug, Clone, Default)]
pub struct Pack {
    elements: HashMap<String, PackElement>,
    // Maintain insertion order for deterministic serialization
    order: Vec<String>,
}

impl Pack {
    /// Create a new empty Pack.
    pub fn new() -> Self {
        Self::default()
    }

    // ========================================================================
    // Add Methods
    // ========================================================================

    /// Add an integer value.
    pub fn add_int(&mut self, name: &str, value: u32) {
        self.add_value(name, PackValue::Int(value));
    }

    /// Add a 64-bit integer value.
    pub fn add_int64(&mut self, name: &str, value: u64) {
        self.add_value(name, PackValue::Int64(value));
    }

    /// Add a string value.
    pub fn add_str(&mut self, name: &str, value: impl Into<String>) {
        self.add_value(name, PackValue::Str(value.into()));
    }

    /// Add a Unicode string value.
    pub fn add_unistr(&mut self, name: &str, value: impl Into<String>) {
        self.add_value(name, PackValue::UniStr(value.into()));
    }

    /// Add binary data.
    pub fn add_data(&mut self, name: &str, value: impl Into<Bytes>) {
        self.add_value(name, PackValue::Data(value.into()));
    }

    /// Add a boolean value (stored as int).
    pub fn add_bool(&mut self, name: &str, value: bool) {
        self.add_int(name, if value { 1 } else { 0 });
    }

    /// Add a raw value.
    fn add_value(&mut self, name: &str, value: PackValue) {
        let name_lower = name.to_lowercase();
        if let Some(elem) = self.elements.get_mut(&name_lower) {
            elem.values.push(value);
        } else {
            let elem = PackElement {
                name: name.to_string(),
                value_type: value.value_type(),
                values: vec![value],
            };
            self.order.push(name_lower.clone());
            self.elements.insert(name_lower, elem);
        }
    }

    // ========================================================================
    // Get Methods
    // ========================================================================

    /// Get an integer value.
    pub fn get_int(&self, name: &str) -> Option<u32> {
        self.get_value(name).and_then(|v| v.as_int())
    }

    /// Get a 64-bit integer value.
    pub fn get_int64(&self, name: &str) -> Option<u64> {
        self.get_value(name).and_then(|v| v.as_int64())
    }

    /// Get a string value.
    pub fn get_str(&self, name: &str) -> Option<&str> {
        self.get_value(name).and_then(|v| v.as_str())
    }

    /// Get binary data.
    pub fn get_data(&self, name: &str) -> Option<&Bytes> {
        self.get_value(name).and_then(|v| v.as_data())
    }

    /// Get a boolean value.
    pub fn get_bool(&self, name: &str) -> Option<bool> {
        self.get_value(name).and_then(|v| v.as_bool())
    }

    /// Get the first value for a name.
    pub fn get_value(&self, name: &str) -> Option<&PackValue> {
        self.elements
            .get(&name.to_lowercase())
            .and_then(|e| e.values.first())
    }

    /// Get all values for a name.
    pub fn get_values(&self, name: &str) -> Option<&[PackValue]> {
        self.elements
            .get(&name.to_lowercase())
            .map(|e| e.values.as_slice())
    }

    /// Check if an element exists.
    pub fn contains(&self, name: &str) -> bool {
        self.elements.contains_key(&name.to_lowercase())
    }

    /// Get the number of elements.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Check if the Pack is empty.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Get all element names (keys).
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.order.iter().map(|s| s.as_str())
    }

    // ========================================================================
    // Serialization
    // ========================================================================

    /// Serialize the Pack to bytes.
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1024);

        // Write number of elements
        buf.put_u32(self.elements.len() as u32);

        // Write each element in insertion order
        for key in &self.order {
            if let Some(elem) = self.elements.get(key) {
                self.write_element(&mut buf, elem);
            }
        }

        buf.freeze()
    }

    /// Write a single element.
    fn write_element(&self, buf: &mut BytesMut, elem: &PackElement) {
        // Write name (length includes null terminator, but we don't write it)
        let name_bytes = elem.name.as_bytes();
        buf.put_u32((name_bytes.len() + 1) as u32);
        buf.put_slice(name_bytes);

        // Write type
        buf.put_u32(elem.value_type as u32);

        // Write number of values
        buf.put_u32(elem.values.len() as u32);

        // Write each value
        for value in &elem.values {
            self.write_value(buf, value);
        }
    }

    /// Write a single value.
    fn write_value(&self, buf: &mut BytesMut, value: &PackValue) {
        match value {
            PackValue::Int(v) => {
                buf.put_u32(*v);
            }
            PackValue::Int64(v) => {
                buf.put_u64(*v);
            }
            PackValue::Str(s) => {
                let bytes = s.as_bytes();
                buf.put_u32(bytes.len() as u32);
                buf.put_slice(bytes);
            }
            PackValue::UniStr(s) => {
                let bytes = s.as_bytes();
                buf.put_u32((bytes.len() + 1) as u32); // +1 for null
                buf.put_slice(bytes);
                buf.put_u8(0); // null terminator
            }
            PackValue::Data(d) => {
                buf.put_u32(d.len() as u32);
                buf.put_slice(d);
            }
        }
    }

    /// Deserialize a Pack from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut buf = data;
        Self::parse(&mut buf)
    }

    /// Alias for from_bytes for compatibility.
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        Self::from_bytes(data)
    }

    /// Parse a Pack from a buffer.
    fn parse(buf: &mut &[u8]) -> Result<Self> {
        if buf.remaining() < 4 {
            return Err(Error::pack("Unexpected end of Pack data"));
        }

        let num_elements = buf.get_u32();
        if num_elements as usize > MAX_ELEMENTS {
            return Err(Error::pack(format!("Too many elements: {}", num_elements)));
        }

        let mut pack = Pack::new();

        for _ in 0..num_elements {
            let elem = Self::parse_element(buf)?;
            let name_lower = elem.name.to_lowercase();
            pack.order.push(name_lower.clone());
            pack.elements.insert(name_lower, elem);
        }

        Ok(pack)
    }

    /// Parse a single element.
    fn parse_element(buf: &mut &[u8]) -> Result<PackElement> {
        if buf.remaining() < 4 {
            return Err(Error::pack("Unexpected end of Pack data"));
        }

        // Read name length
        let name_len = buf.get_u32() as usize;
        if !(1..=4096).contains(&name_len) {
            return Err(Error::pack(format!("Invalid name length: {}", name_len)));
        }

        // Name length includes null terminator which isn't written
        let actual_len = name_len - 1;
        if buf.remaining() < actual_len {
            return Err(Error::pack("Unexpected end of Pack data"));
        }

        let name = if actual_len == 0 {
            String::new()
        } else {
            let name_bytes = &buf[..actual_len];
            buf.advance(actual_len);
            String::from_utf8_lossy(name_bytes).into_owned()
        };

        if buf.remaining() < 8 {
            return Err(Error::pack("Unexpected end of Pack data"));
        }

        // Read type
        let type_int = buf.get_u32();
        let value_type = PackValueType::try_from(type_int)?;

        // Read number of values
        let num_values = buf.get_u32() as usize;
        if num_values > MAX_VALUE_NUM {
            return Err(Error::pack(format!("Too many values: {}", num_values)));
        }

        let mut values = Vec::with_capacity(num_values);
        for _ in 0..num_values {
            let value = Self::parse_value(buf, value_type)?;
            values.push(value);
        }

        Ok(PackElement {
            name,
            value_type,
            values,
        })
    }

    /// Parse a single value.
    fn parse_value(buf: &mut &[u8], value_type: PackValueType) -> Result<PackValue> {
        match value_type {
            PackValueType::Int => {
                if buf.remaining() < 4 {
                    return Err(Error::pack("Unexpected end of Pack data"));
                }
                Ok(PackValue::Int(buf.get_u32()))
            }
            PackValueType::Int64 => {
                if buf.remaining() < 8 {
                    return Err(Error::pack("Unexpected end of Pack data"));
                }
                Ok(PackValue::Int64(buf.get_u64()))
            }
            PackValueType::Str => {
                if buf.remaining() < 4 {
                    return Err(Error::pack("Unexpected end of Pack data"));
                }
                let len = buf.get_u32() as usize;
                if len > MAX_VALUE_SIZE {
                    return Err(Error::pack(format!("String too long: {}", len)));
                }
                if buf.remaining() < len {
                    return Err(Error::pack("Unexpected end of Pack data"));
                }
                let s = String::from_utf8_lossy(&buf[..len]).into_owned();
                buf.advance(len);
                Ok(PackValue::Str(s))
            }
            PackValueType::UniStr => {
                if buf.remaining() < 4 {
                    return Err(Error::pack("Unexpected end of Pack data"));
                }
                let size = buf.get_u32() as usize;
                if size > MAX_VALUE_SIZE {
                    return Err(Error::pack(format!("UniStr too long: {}", size)));
                }
                if size == 0 {
                    return Ok(PackValue::UniStr(String::new()));
                }
                if buf.remaining() < size {
                    return Err(Error::pack("Unexpected end of Pack data"));
                }
                // Remove null terminator if present
                let actual_len = if size > 0 && buf[size - 1] == 0 {
                    size - 1
                } else {
                    size
                };
                let s = String::from_utf8_lossy(&buf[..actual_len]).into_owned();
                buf.advance(size);
                Ok(PackValue::UniStr(s))
            }
            PackValueType::Data => {
                if buf.remaining() < 4 {
                    return Err(Error::pack("Unexpected end of Pack data"));
                }
                let size = buf.get_u32() as usize;
                if size > MAX_VALUE_SIZE {
                    return Err(Error::pack(format!("Data too large: {}", size)));
                }
                if buf.remaining() < size {
                    return Err(Error::pack("Unexpected end of Pack data"));
                }
                let data = Bytes::copy_from_slice(&buf[..size]);
                buf.advance(size);
                Ok(PackValue::Data(data))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_roundtrip() {
        let mut pack = Pack::new();
        pack.add_int("version", 123);
        pack.add_str("hello", "world");
        pack.add_bool("enabled", true);
        pack.add_data("bytes", vec![1, 2, 3, 4]);

        let bytes = pack.to_bytes();
        let parsed = Pack::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.get_int("version"), Some(123));
        assert_eq!(parsed.get_str("hello"), Some("world"));
        assert_eq!(parsed.get_bool("enabled"), Some(true));
        assert_eq!(
            parsed.get_data("bytes").map(|b| b.to_vec()),
            Some(vec![1, 2, 3, 4])
        );
    }

    #[test]
    fn test_pack_case_insensitive() {
        let mut pack = Pack::new();
        pack.add_int("MyValue", 42);

        assert_eq!(pack.get_int("myvalue"), Some(42));
        assert_eq!(pack.get_int("MYVALUE"), Some(42));
        assert_eq!(pack.get_int("MyValue"), Some(42));
    }

    #[test]
    fn test_pack_empty() {
        let pack = Pack::new();
        let bytes = pack.to_bytes();
        let parsed = Pack::from_bytes(&bytes).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_pack_int64() {
        let mut pack = Pack::new();
        pack.add_int64("big", 0x123456789ABCDEF0);

        let bytes = pack.to_bytes();
        let parsed = Pack::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.get_int64("big"), Some(0x123456789ABCDEF0));
    }
}
