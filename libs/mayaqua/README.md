# mayaqua

**Foundation Layer** - Core utilities and platform abstraction

Based on the original SoftEther Mayaqua kernel, this module provides:

## Core Components
- **Memory Management**: Safe Rust alternatives to C malloc/free patterns
- **Error Handling**: Unified error types and result handling
- **Logging**: Structured logging with configurable outputs 
- **Threading**: Async/await and thread pool abstractions
- **Platform Abstraction**: OS-specific functionality (Windows/Linux/macOS/iOS/Android)

## Data Structures
- **Pack System**: Binary serialization compatible with SoftEther protocol
- **Network Primitives**: TCP/UDP socket abstractions
- **Time/Tick**: High-resolution timing and intervals
- **String/Buffer**: UTF-8 string handling and byte buffer management

## Critical Pack System Implementation

### Pack Serialization Constants
```rust
const MAX_VALUE_SIZE: u32 = 384 * 1024 * 1024;  // 384MB per VALUE
const MAX_VALUE_NUM: u32 = 262144;              // Max VALUEs per ELEMENT
const MAX_ELEMENT_NAME_LEN: u32 = 63;           // Element name length  
const MAX_ELEMENT_NUM: u32 = 262144;            // Max ELEMENTs per PACK
const MAX_PACK_SIZE: u32 = 512 * 1024 * 1024;   // 512MB total pack size
```

### Value Type System
```rust
#[repr(u32)]
enum ValueType {
    Int = 0,        // 32-bit integer
    Data = 1,       // Binary data blob
    Str = 2,        // ANSI string  
    UniStr = 3,     // Unicode string (currently unimplemented)
    Int64 = 4,      // 64-bit integer
}

struct Value {
    int_value: u32,
    int64_value: u64,
    data: Vec<u8>,
    str_value: String,
    uni_str: String,  // Unicode string support
}
```

### Pack Structure
```rust
struct Element {
    name: String,           // Element name (max 63 chars)
    value_type: ValueType,  // Type of values stored
    values: Vec<Value>,     // Array of values
    
    // JSON conversion hints
    json_hint_is_array: bool,
    json_hint_is_bool: bool,
    json_hint_is_datetime: bool,
    json_hint_is_ip: bool,
    json_hint_group_name: String,
}

struct Pack {
    elements: Vec<Element>,
    json_subitem_names: Vec<String>,
    current_json_hint_group_name: String,
}
```

### Binary Serialization Format
```rust
// Pack binary format (big-endian):
// [num_elements: u32]
// For each element:
//   [name_length: u32][name_bytes: [u8]]
//   [value_type: u32]  
//   [num_values: u32]
//   For each value:
//     [value_data] // Format depends on value_type

impl Pack {
    fn to_buffer(&self) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::new();
        
        // Write element count (big-endian)
        buffer.extend_from_slice(&(self.elements.len() as u32).to_be_bytes());
        
        for element in &self.elements {
            element.write_to_buffer(&mut buffer)?;
        }
        
        Ok(buffer)
    }
}
```

### HTTP Transport Integration
```rust
const HTTP_PACK_RAND_SIZE_MAX: u32 = 1000;  // Random padding size

// Add random padding to HTTP packs for obfuscation
fn add_http_pack_padding(data: &mut Vec<u8>) {
    let rand_size = rand::random::<u32>() % HTTP_PACK_RAND_SIZE_MAX;
    let padding: Vec<u8> = (0..rand_size).map(|_| rand::random()).collect();
    data.extend(padding);
}
```

## Network Primitives

### Socket Abstractions
```rust
trait SocketInterface {
    async fn connect(addr: SocketAddr) -> Result<Self, Error>;
    async fn send(&mut self, data: &[u8]) -> Result<usize, Error>;
    async fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, Error>;
    fn close(&mut self) -> Result<(), Error>;
}

// Platform-specific implementations for TCP/UDP/TLS
struct TcpSocket { /* ... */ }
struct UdpSocket { /* ... */ }
struct TlsSocket { /* ... */ }
```

## Time and Timing

### High-Resolution Timing
```rust
// Tick64 equivalent - 64-bit millisecond timestamp
type Tick64 = u64;

fn get_tick64() -> Tick64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// Traffic monitoring intervals  
const TRAFFIC_CHECK_SPAN: Tick64 = 1000;  // 1 second
const KEEPALIVE_INTERVAL: Tick64 = 30000; // 30 seconds
```

## String and Buffer Management

### Buffer String Operations
```rust
// Read length-prefixed string from buffer
fn read_buf_str(reader: &mut dyn Read) -> Result<String, Error> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes);
    
    if len > MAX_VALUE_SIZE {
        return Err(Error::SizeOver);
    }
    
    let mut string_bytes = vec![0u8; len as usize];
    reader.read_exact(&mut string_bytes)?;
    
    String::from_utf8(string_bytes)
        .map_err(|_| Error::InvalidString)
}

// Write length-prefixed string to buffer
fn write_buf_str(writer: &mut dyn Write, s: &str) -> Result<(), Error> {
    let bytes = s.as_bytes();
    let len = bytes.len() as u32;
    
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(bytes)?;
    Ok(())
}
```

## SHA-0 Implementation (Critical)

### Custom SHA-0 for SoftEther Compatibility
```rust
// CRITICAL: SHA-0 implementation required for password authentication
type Sha1Sum = [u8; 20];  // Same size as SHA-1 output

struct Sha0Context {
    count: u64,
    buffer: [u8; 64],
    state: [u32; 5],
}

impl Sha0Context {
    fn init(&mut self) {
        self.state = [
            0x67452301,
            0xEFCDAB89, 
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        ];
        self.count = 0;
    }
    
    fn transform(&mut self) {
        // SHA-0 transform implementation
        // CRITICAL: Uses SHA-0 algorithm, not SHA-1
        // Key difference: No left rotation in W[t] calculation
    }
}

fn sha0(data: &[u8]) -> Sha1Sum {
    let mut ctx = Sha0Context::new();
    ctx.init();
    ctx.update(data);
    ctx.finalize()
}
```

## Key Differences from C Implementation
- **Memory Safety**: Leverages Rust's ownership system instead of manual memory management
- **Error Propagation**: Uses `Result<T, E>` instead of return codes and global error states
- **Concurrency**: Built on async/await instead of manual thread management
- **Type Safety**: Strong typing prevents many categories of bugs present in C version

## Platform Abstraction Examples

### Cross-Platform File Operations
```rust
#[cfg(windows)]
fn get_system_directory() -> PathBuf {
    // Windows-specific implementation
}

#[cfg(unix)]
fn get_system_directory() -> PathBuf {
    // Unix-specific implementation  
}

#[cfg(target_os = "macos")]
fn get_system_directory() -> PathBuf {
    // macOS-specific implementation
}
```

## Critical Implementation Notes

1. **Pack Compatibility**: Binary format must exactly match C/Go implementations
2. **SHA-0 Requirement**: Custom SHA-0 implementation essential for authentication
3. **Big-Endian**: All pack serialization uses big-endian byte order
4. **Size Limits**: Strict enforcement of pack size limits prevents memory exhaustion
5. **String Encoding**: UTF-8 for Rust strings, with proper error handling for invalid data
