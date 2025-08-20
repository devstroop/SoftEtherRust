//! Pack system for SoftEther VPN protocol
//!
//! Binary serialization format compatible with the C implementation.
//! Note: This implementation uses big-endian for scalar fields per SoftEther wire format.

use crate::error::{Error, Result};
use std::io::{Cursor, Read};

/// Value types in the pack system (from C Pack.h)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ValueType {
    Int = 0,    // 32-bit integer
    Data = 1,   // Binary data blob
    Str = 2,    // ANSI string
    UniStr = 3, // Unicode string (currently unimplemented in C)
    Int64 = 4,  // 64-bit integer
}

impl ValueType {
    pub fn from_u32(value: u32) -> Result<Self> {
        match value {
            0 => Ok(ValueType::Int),
            1 => Ok(ValueType::Data),
            2 => Ok(ValueType::Str),
            3 => Ok(ValueType::UniStr),
            4 => Ok(ValueType::Int64),
            _ => Err(Error::InvalidPack),
        }
    }
}

/// A value in the pack system
#[derive(Debug, Clone)]
pub struct Value {
    pub int_value: u32,
    pub int64_value: u64,
    pub data: Vec<u8>,
    pub str_value: String,
    pub uni_str: String, // Unicode string support
}

impl Value {
    pub fn new_int(value: u32) -> Self {
        Self {
            int_value: value,
            int64_value: 0,
            data: Vec::new(),
            str_value: String::new(),
            uni_str: String::new(),
        }
    }

    pub fn new_int64(value: u64) -> Self {
        Self {
            int_value: 0,
            int64_value: value,
            data: Vec::new(),
            str_value: String::new(),
            uni_str: String::new(),
        }
    }

    pub fn new_data(data: Vec<u8>) -> Self {
        Self {
            int_value: 0,
            int64_value: 0,
            data,
            str_value: String::new(),
            uni_str: String::new(),
        }
    }

    pub fn new_str(s: String) -> Self {
        Self {
            int_value: 0,
            int64_value: 0,
            data: Vec::new(),
            str_value: s,
            uni_str: String::new(),
        }
    }

    pub fn new_uni_str(s: String) -> Self {
        Self {
            int_value: 0,
            int64_value: 0,
            data: Vec::new(),
            str_value: String::new(),
            uni_str: s,
        }
    }

    /// Write value to buffer (big-endian for integer scalars).
    pub fn write_to_buffer(&self, buffer: &mut Vec<u8>, value_type: ValueType) -> Result<()> {
        match value_type {
            ValueType::Int => {
                buffer.extend_from_slice(&self.int_value.to_be_bytes());
            }
            ValueType::Int64 => {
                buffer.extend_from_slice(&self.int64_value.to_be_bytes());
            }
            ValueType::Data => {
                buffer.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
                buffer.extend_from_slice(&self.data);
            }
            ValueType::Str => {
                // Length (little-endian), then string bytes (no null terminator)
                let bytes = self.str_value.as_bytes();
                buffer.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                buffer.extend_from_slice(bytes);
            }
            ValueType::UniStr => {
                // Convert to UTF-8, write size, then UTF-8 bytes
                let bytes = self.uni_str.as_bytes();
                buffer.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                buffer.extend_from_slice(bytes);
            }
        }
        Ok(())
    }

    /// Read value from buffer based on type (big-endian)
    pub fn read_from_buffer(reader: &mut dyn Read, value_type: ValueType) -> Result<Self> {
        let mut value = Value::new_int(0);

        match value_type {
            ValueType::Int => {
                let mut bytes = [0u8; 4];
                reader.read_exact(&mut bytes)?;
                value.int_value = u32::from_be_bytes(bytes);
            }
            ValueType::Int64 => {
                let mut bytes = [0u8; 8];
                reader.read_exact(&mut bytes)?;
                value.int64_value = u64::from_be_bytes(bytes);
            }
            ValueType::Data => {
                let mut len_bytes = [0u8; 4];
                reader.read_exact(&mut len_bytes)?;
                let len = u32::from_be_bytes(len_bytes) as usize;

                if len > crate::MAX_VALUE_SIZE {
                    return Err(Error::SizeOver);
                }

                let mut data = vec![0u8; len];
                reader.read_exact(&mut data)?;
                value.data = data;
            }
            ValueType::Str => {
                let mut len_bytes = [0u8; 4];
                reader.read_exact(&mut len_bytes)?;
                let len = u32::from_be_bytes(len_bytes) as usize;

                if len > crate::MAX_VALUE_SIZE {
                    return Err(Error::SizeOver);
                }

                let mut string_bytes = vec![0u8; len];
                reader.read_exact(&mut string_bytes)?;
                value.str_value = String::from_utf8(string_bytes)?;
            }
            ValueType::UniStr => {
                let mut len_bytes = [0u8; 4];
                reader.read_exact(&mut len_bytes)?;
                let len = u32::from_be_bytes(len_bytes) as usize;

                if len > crate::MAX_VALUE_SIZE {
                    return Err(Error::SizeOver);
                }

                let mut string_bytes = vec![0u8; len];
                reader.read_exact(&mut string_bytes)?;
                value.uni_str = String::from_utf8(string_bytes)?;
            }
        }

        Ok(value)
    }
}

/// An element in the pack system
#[derive(Debug, Clone)]
pub struct Element {
    pub name: String,          // Element name (max 63 chars)
    pub value_type: ValueType, // Type of values stored
    pub values: Vec<Value>,    // Array of values

    // JSON conversion hints (for future use)
    pub json_hint_is_array: bool,
    pub json_hint_is_bool: bool,
    pub json_hint_is_datetime: bool,
    pub json_hint_is_ip: bool,
    pub json_hint_group_name: String,
}

impl Element {
    pub fn new(name: String, value_type: ValueType) -> Result<Self> {
        if name.len() > crate::MAX_ELEMENT_NAME_LEN as usize {
            return Err(Error::InvalidParameter);
        }

        Ok(Self {
            name,
            value_type,
            values: Vec::new(),
            json_hint_is_array: false,
            json_hint_is_bool: false,
            json_hint_is_datetime: false,
            json_hint_is_ip: false,
            json_hint_group_name: String::new(),
        })
    }

    pub fn add_value(&mut self, value: Value) -> Result<()> {
        if self.values.len() >= crate::MAX_VALUE_NUM as usize {
            return Err(Error::SizeOver);
        }
        self.values.push(value);
        Ok(())
    }

    /// Write element to buffer: name_len (BE, includes virtual null), name bytes (no NUL), value_type (BE), value_count (BE), then values.
    pub fn write_to_buffer(&self, buffer: &mut Vec<u8>) -> Result<()> {
        let name_bytes = self.name.as_bytes();
        if name_bytes.len() + 1 > crate::MAX_ELEMENT_NAME_LEN as usize {
            return Err(Error::SizeOver);
        }
        // SoftEther writes length = (len + 1) including a virtual null terminator, but does NOT write the null byte itself.
        let stored_len = (name_bytes.len() + 1) as u32;
        buffer.extend_from_slice(&stored_len.to_be_bytes());
        buffer.extend_from_slice(name_bytes); // no trailing NUL
                                              // value type (big-endian)
        buffer.extend_from_slice(&(self.value_type as u32).to_be_bytes());
        // value count (big-endian)
        buffer.extend_from_slice(&(self.values.len() as u32).to_be_bytes());
        // values
        for value in &self.values {
            value.write_to_buffer(buffer, self.value_type)?;
        }
        Ok(())
    }

    /// Read element from buffer using BE name length.
    pub fn read_from_buffer(reader: &mut dyn Read) -> Result<Self> {
        let mut len_bytes = [0u8; 4];
        reader.read_exact(&mut len_bytes)?;
        let name_len_with_null = u32::from_be_bytes(len_bytes) as usize;
        if name_len_with_null == 0 || name_len_with_null - 1 > crate::MAX_ELEMENT_NAME_LEN as usize
        {
            return Err(Error::InvalidPack);
        }
        let name_len = name_len_with_null - 1; // actual bytes present
        let mut raw_name_bytes = vec![0u8; name_len];
        reader.read_exact(&mut raw_name_bytes)?;
        if raw_name_bytes.contains(&0) {
            return Err(Error::InvalidPack);
        }
        let name = String::from_utf8(raw_name_bytes)?;
        // value type
        let mut type_bytes = [0u8; 4];
        reader.read_exact(&mut type_bytes)?;
        let value_type = ValueType::from_u32(u32::from_be_bytes(type_bytes))?;
        // value count (big-endian)
        let mut count_bytes = [0u8; 4];
        reader.read_exact(&mut count_bytes)?;
        let value_count = u32::from_be_bytes(count_bytes) as usize;
        if value_count > crate::MAX_VALUE_NUM as usize {
            return Err(Error::SizeOver);
        }
        let mut element = Element::new(name, value_type)?;
        for _ in 0..value_count {
            let v = Value::read_from_buffer(reader, value_type)?;
            element.add_value(v)?;
        }
        Ok(element)
    }

    /// Read element using length-prefixed name (reader is a Cursor over the full buffer so we can bounds check)
    pub fn read_from_buffer_lenpref(reader: &mut Cursor<&[u8]>) -> Result<Self> {
        let total = reader.get_ref().len();
        if total - (reader.position() as usize) < 4 {
            return Err(Error::InvalidPack);
        }
        let mut len_bytes = [0u8; 4];
        reader.read_exact(&mut len_bytes)?;
        let name_len_with_null = u32::from_be_bytes(len_bytes) as usize;
        if name_len_with_null == 0 || name_len_with_null - 1 > crate::MAX_ELEMENT_NAME_LEN as usize
        {
            return Err(Error::InvalidPack);
        }
        let name_len = name_len_with_null - 1;
        if total - (reader.position() as usize) < name_len {
            return Err(Error::InvalidPack);
        }
        let mut raw_name_bytes = vec![0u8; name_len];
        reader.read_exact(&mut raw_name_bytes)?;
        if raw_name_bytes.contains(&0) {
            return Err(Error::InvalidPack);
        }
        let name = String::from_utf8(raw_name_bytes)?;
        if total - (reader.position() as usize) < 8 {
            return Err(Error::InvalidPack);
        }
        let after_name_pos = reader.position() as usize;
        let lookahead =
            &reader.get_ref()[after_name_pos..after_name_pos + 8.min(total - after_name_pos)];
        let mut type_bytes = [0u8; 4];
        reader.read_exact(&mut type_bytes)?;
        let value_type = ValueType::from_u32(u32::from_be_bytes(type_bytes))?;
        let mut cnt_bytes = [0u8; 4];
        reader.read_exact(&mut cnt_bytes)?;
        let value_count = u32::from_be_bytes(cnt_bytes) as usize;
        if value_count > crate::MAX_VALUE_NUM as usize {
            return Err(Error::SizeOver);
        }
        if std::env::var("RUST_TRACE").is_ok() {
            eprintln!("[RUST_TRACE][Pack] element(name='{name}', raw_next8={lookahead:02x?}, type={value_type:?}, count={value_count} bytes={type_bytes:02x?} {cnt_bytes:02x?}");
        }
        let mut element = Element::new(name, value_type)?;
        for _ in 0..value_count {
            let v = Value::read_from_buffer(reader, value_type)?;
            element.add_value(v)?;
        }
        Ok(element)
    }

    /// Read element using legacy null-terminated name (without length prefix)
    pub fn read_from_buffer_nullname(reader: &mut Cursor<&[u8]>) -> Result<Self> {
        let total = reader.get_ref().len();
        let _start = reader.position();
        let mut name_bytes = Vec::new();
        while (reader.position() as usize) < total {
            let mut b = [0u8; 1];
            reader.read_exact(&mut b)?;
            if b[0] == 0 {
                break;
            }
            name_bytes.push(b[0]);
            if name_bytes.len() > crate::MAX_ELEMENT_NAME_LEN as usize {
                return Err(Error::InvalidPack);
            }
        }
        if name_bytes.is_empty() {
            return Err(Error::InvalidPack);
        }
        let name = String::from_utf8(name_bytes)?;
        if total - (reader.position() as usize) < 8 {
            return Err(Error::InvalidPack);
        }
        let mut type_bytes = [0u8; 4];
        reader.read_exact(&mut type_bytes)?;
        let value_type = ValueType::from_u32(u32::from_be_bytes(type_bytes))?;
        let mut cnt_bytes = [0u8; 4];
        reader.read_exact(&mut cnt_bytes)?;
        let value_count = u32::from_be_bytes(cnt_bytes) as usize;
        if value_count > crate::MAX_VALUE_NUM as usize {
            return Err(Error::SizeOver);
        }
        if std::env::var("RUST_TRACE").is_ok() {
            eprintln!(
                "[RUST_TRACE][Pack] element(null-name='{name}', type={value_type:?}, count={value_count})"
            );
        }
        let mut element = Element::new(name, value_type)?;
        for _ in 0..value_count {
            let v = Value::read_from_buffer(reader, value_type)?;
            element.add_value(v)?;
        }
        Ok(element)
    }
}

/// The main Pack structure for SoftEther protocol
#[derive(Debug, Clone)]
pub struct Pack {
    pub elements: Vec<Element>,
    pub json_subitem_names: Vec<String>,
    pub current_json_hint_group_name: String,
}

impl Pack {
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
            json_subitem_names: Vec::new(),
            current_json_hint_group_name: String::new(),
        }
    }

    pub fn add_element(&mut self, element: Element) -> Result<()> {
        if self.elements.len() >= crate::MAX_ELEMENT_NUM as usize {
            return Err(Error::SizeOver);
        }
        self.elements.push(element);
        Ok(())
    }

    /// Find element by name
    pub fn find_element(&self, name: &str) -> Option<&Element> {
        self.elements.iter().find(|e| e.name == name)
    }

    /// Find element by name (mutable)
    pub fn find_element_mut(&mut self, name: &str) -> Option<&mut Element> {
        self.elements.iter_mut().find(|e| e.name == name)
    }

    /// Serialize pack to binary buffer (SoftEther format - little-endian)
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Write element count (big-endian)
        buffer.extend_from_slice(&(self.elements.len() as u32).to_be_bytes());

        // Write each element
        for element in &self.elements {
            element.write_to_buffer(&mut buffer)?;
        }

        // Check total size limit
        if buffer.len() > crate::MAX_PACK_SIZE {
            return Err(Error::SizeOver);
        }

        Ok(buffer)
    }

    /// Deserialize pack from binary buffer (big-endian)
    pub fn from_buffer(data: &[u8]) -> Result<Self> {
        if data.len() > crate::MAX_PACK_SIZE {
            return Err(Error::SizeOver);
        }

        let mut reader = Cursor::new(data);

        // Read element count (big-endian)
        let mut element_count_bytes = [0u8; 4];
        reader.read_exact(&mut element_count_bytes)?;
        let element_count = u32::from_be_bytes(element_count_bytes) as usize;
        let trace = std::env::var("RUST_TRACE").is_ok();
        if trace {
            eprintln!(
                "[RUST_TRACE][Pack] first16={:02x?} elem_count={}",
                &data[..data.len().min(16)],
                element_count
            );
        }
        if element_count > crate::MAX_ELEMENT_NUM as usize {
            return Err(Error::SizeOver);
        }

        let mut pack = Pack::new();

        // Read each element (length-prefixed form)
        for _ in 0..element_count {
            let el = Element::read_from_buffer_lenpref(&mut reader)?;
            pack.add_element(el)?;
        }
        if trace {
            eprintln!("[RUST_TRACE][Pack] elements: {}", pack.debug_dump());
        }

        Ok(pack)
    }

    /// Produce a verbose string listing all field names and brief value previews for debugging.
    pub fn debug_dump(&self) -> String {
        let mut out = String::new();
        for el in &self.elements {
            use std::fmt::Write;
            let _ = write!(out, "{}=", el.name);
            if el.values.is_empty() {
                out.push_str("<empty>");
            } else {
                let v = &el.values[0];
                if !v.str_value.is_empty() {
                    let _ = write!(out, "{}", v.str_value);
                } else if !v.data.is_empty() {
                    let mut hexs = String::new();
                    for b in v.data.iter().take(8) {
                        let _ = write!(hexs, "{b:02x}");
                    }
                    if v.data.len() > 8 {
                        hexs.push_str("...");
                    }
                    let _ = write!(out, "0x{hexs}(len={})", v.data.len());
                } else {
                    let _ = write!(out, "{}", v.int_value);
                }
            }
            out.push_str(", ");
        }
        if out.ends_with(", ") {
            out.truncate(out.len() - 2);
        }
        out
    }

    // Convenience methods for common operations

    /// Add integer value
    pub fn add_int(&mut self, name: &str, value: u32) -> Result<()> {
        if let Some(element) = self.find_element_mut(name) {
            if element.value_type != ValueType::Int {
                return Err(Error::ValueTypeError);
            }
            element.add_value(Value::new_int(value))?;
        } else {
            let mut element = Element::new(name.to_string(), ValueType::Int)?;
            element.add_value(Value::new_int(value))?;
            self.add_element(element)?;
        }
        Ok(())
    }

    /// Add boolean value as Int(0/1)
    pub fn add_bool(&mut self, name: &str, value: bool) -> Result<()> {
        self.add_int(name, if value { 1 } else { 0 })
    }

    /// Add string value
    pub fn add_str(&mut self, name: &str, value: &str) -> Result<()> {
        if let Some(element) = self.find_element_mut(name) {
            if element.value_type != ValueType::Str {
                return Err(Error::ValueTypeError);
            }
            element.add_value(Value::new_str(value.to_string()))?;
        } else {
            let mut element = Element::new(name.to_string(), ValueType::Str)?;
            element.add_value(Value::new_str(value.to_string()))?;
            self.add_element(element)?;
        }
        Ok(())
    }

    /// Add binary data value
    pub fn add_data(&mut self, name: &str, data: Vec<u8>) -> Result<()> {
        if let Some(element) = self.find_element_mut(name) {
            if element.value_type != ValueType::Data {
                return Err(Error::ValueTypeError);
            }
            element.add_value(Value::new_data(data))?;
        } else {
            let mut element = Element::new(name.to_string(), ValueType::Data)?;
            element.add_value(Value::new_data(data))?;
            self.add_element(element)?;
        }
        Ok(())
    }

    /// Add an array of integers under the same element name
    pub fn add_int_array(&mut self, name: &str, values: &[u32]) -> Result<()> {
        if let Some(e) = self.find_element_mut(name) {
            if e.value_type != ValueType::Int {
                return Err(Error::ValueTypeError);
            }
            for v in values {
                e.add_value(Value::new_int(*v))?;
            }
            Ok(())
        } else {
            let mut element = Element::new(name.to_string(), ValueType::Int)?;
            for v in values {
                element.add_value(Value::new_int(*v))?;
            }
            self.add_element(element)
        }
    }

    /// Add 64-bit integer value
    pub fn add_int64(&mut self, name: &str, value: u64) -> Result<()> {
        if let Some(element) = self.find_element_mut(name) {
            if element.value_type != ValueType::Int64 {
                return Err(Error::ValueTypeError);
            }
            element.add_value(Value::new_int64(value))?;
        } else {
            let mut element = Element::new(name.to_string(), ValueType::Int64)?;
            element.add_value(Value::new_int64(value))?;
            self.add_element(element)?;
        }
        Ok(())
    }

    /// Get first integer value for element
    pub fn get_int(&self, name: &str) -> Result<u32> {
        let element = self.find_element(name).ok_or(Error::ElementNotFound)?;
        if element.value_type != ValueType::Int {
            return Err(Error::ValueTypeError);
        }
        if element.values.is_empty() {
            return Err(Error::ElementNotFound);
        }
        Ok(element.values[0].int_value)
    }

    /// Get boolean value (non-zero => true)
    pub fn get_bool(&self, name: &str) -> Result<bool> {
        Ok(self.get_int(name)? != 0)
    }

    /// Get first string value for element
    pub fn get_str(&self, name: &str) -> Result<&str> {
        let element = self.find_element(name).ok_or(Error::ElementNotFound)?;
        if element.value_type != ValueType::Str {
            return Err(Error::ValueTypeError);
        }
        if element.values.is_empty() {
            return Err(Error::ElementNotFound);
        }
        Ok(&element.values[0].str_value)
    }

    /// Get first data value for element
    pub fn get_data(&self, name: &str) -> Result<&[u8]> {
        let element = self.find_element(name).ok_or(Error::ElementNotFound)?;
        if element.value_type != ValueType::Data {
            return Err(Error::ValueTypeError);
        }
        if element.values.is_empty() {
            return Err(Error::ElementNotFound);
        }
        Ok(&element.values[0].data)
    }

    /// Get first 64-bit integer value for element
    pub fn get_int64(&self, name: &str) -> Result<u64> {
        let element = self.find_element(name).ok_or(Error::ElementNotFound)?;
        if element.value_type != ValueType::Int64 {
            return Err(Error::ValueTypeError);
        }
        if element.values.is_empty() {
            return Err(Error::ElementNotFound);
        }
        Ok(element.values[0].int64_value)
    }
}

impl Default for Pack {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_types() {
        assert_eq!(ValueType::Int as u32, 0);
        assert_eq!(ValueType::Data as u32, 1);
        assert_eq!(ValueType::Str as u32, 2);

        assert_eq!(ValueType::from_u32(0).unwrap(), ValueType::Int);
        assert_eq!(ValueType::from_u32(1).unwrap(), ValueType::Data);
        assert!(ValueType::from_u32(999).is_err());
    }

    #[test]
    fn test_pack_basic_operations() {
        let mut pack = Pack::new();

        // Add some values
        pack.add_int("test_int", 42).unwrap();
        pack.add_str("test_str", "hello").unwrap();
        pack.add_data("test_data", vec![1, 2, 3, 4]).unwrap();

        // Read them back
        assert_eq!(pack.get_int("test_int").unwrap(), 42);
        assert_eq!(pack.get_str("test_str").unwrap(), "hello");
        assert_eq!(pack.get_data("test_data").unwrap(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_pack_serialization() {
        let mut pack = Pack::new();
        pack.add_int("version", 1).unwrap();
        pack.add_str("method", "connect").unwrap();
        pack.add_int64("ts", 0x0102030405060708).unwrap();

        // Serialize
        let buffer = pack.to_buffer().unwrap();
        assert!(!buffer.is_empty());

        // Deserialize
        let pack2 = Pack::from_buffer(&buffer).unwrap();
        assert_eq!(pack2.get_int("version").unwrap(), 1);
        assert_eq!(pack2.get_str("method").unwrap(), "connect");
        assert_eq!(pack2.get_int64("ts").unwrap(), 0x0102030405060708);
    }

    #[test]
    fn test_size_limits() {
        let mut pack = Pack::new();

        // Test element name length limit
        let long_name = "a".repeat(100);
        let result = pack.add_int(&long_name, 1);
        assert!(result.is_err());

        // Test valid name length
        let valid_name = "a".repeat(60);
        assert!(pack.add_int(&valid_name, 1).is_ok());
    }

    #[test]
    fn test_value_type_errors() {
        let mut pack = Pack::new();
        pack.add_int("test", 42).unwrap();

        // Try to read as wrong type
        assert!(pack.get_str("test").is_err());
        assert!(pack.get_data("test").is_err());
    }
}
