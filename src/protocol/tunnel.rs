//! SoftEther tunnel data channel protocol.
//!
//! After authentication, SoftEther switches to a binary tunnel protocol
//! for transmitting Ethernet frames.
//!
//! ## Wire Format
//!
//! Data frame:
//! ```text
//! [num_blocks:u32] [block...]*
//! ```
//!
//! Each block:
//! ```text
//! [block_size:u32] [data:bytes]
//! ```
//!
//! Keep-alive frame:
//! ```text
//! [0xFFFFFFFF:u32] [size:u32] [padding:bytes]
//! ```
//!
//! ## Compression
//!
//! When compression is enabled, each block is zlib-compressed.
//! Compressed data starts with zlib header (0x78 0x9C typically).
//!
//! ## Zero-Copy Design (from SoftEtherZig)
//!
//! For high performance, we provide zero-copy methods that:
//! - Write directly to pre-allocated buffers
//! - Avoid intermediate allocations
//! - Wrap IP packets in Ethernet frames in-place

use super::constants::*;
use crate::error::{Error, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Read, Write};

/// Tunnel protocol constants.
pub struct TunnelConstants;

impl TunnelConstants {
    /// Magic number indicating keep-alive packet.
    pub const KEEPALIVE_MAGIC: u32 = 0xFFFFFFFF;

    /// Maximum Ethernet frame size.
    pub const MAX_PACKET_SIZE: usize = MAX_PACKET_SIZE;

    /// Maximum keep-alive data size.
    pub const MAX_KEEPALIVE_SIZE: usize = MAX_KEEPALIVE_SIZE;

    /// Maximum blocks per frame.
    pub const MAX_BLOCKS: usize = MAX_RECV_BLOCKS;
}

/// Check if data is zlib compressed (starts with zlib magic header).
/// Common zlib headers: 0x78 0x01 (no compression), 0x78 0x9C (default), 0x78 0xDA (best)
#[inline]
pub fn is_compressed(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    // zlib header check: first byte is 0x78, second byte has specific patterns
    data[0] == 0x78 && (data[1] == 0x01 || data[1] == 0x5E || data[1] == 0x9C || data[1] == 0xDA)
}

/// Decompress zlib-compressed data.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::with_capacity(data.len() * 2);
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| Error::Protocol(format!("Decompression failed: {}", e)))?;
    Ok(decompressed)
}

/// Decompress zlib-compressed data into a pre-allocated buffer (zero-copy).
/// Returns the number of bytes written to the buffer.
#[inline]
pub fn decompress_into(data: &[u8], buffer: &mut [u8]) -> Result<usize> {
    use std::io::Cursor;
    let mut decoder = ZlibDecoder::new(data);
    let mut cursor = Cursor::new(buffer);
    std::io::copy(&mut decoder, &mut cursor)
        .map_err(|e| Error::Protocol(format!("Decompression failed: {}", e)))?;
    Ok(cursor.position() as usize)
}

/// Compress data with zlib.
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| Error::Protocol(format!("Compression failed: {}", e)))?;
    encoder
        .finish()
        .map_err(|e| Error::Protocol(format!("Compression finish failed: {}", e)))
}

/// Tunnel frame type.
#[derive(Debug, Clone)]
pub enum TunnelFrame {
    /// Data frame containing Ethernet packets.
    Data(Vec<Bytes>),
    /// Keep-alive frame.
    Keepalive(usize),
}

impl TunnelFrame {
    /// Create a data frame from a single packet.
    pub fn single(data: Bytes) -> Self {
        Self::Data(vec![data])
    }

    /// Create a data frame from multiple packets.
    pub fn batch(packets: Vec<Bytes>) -> Self {
        Self::Data(packets)
    }

    /// Create a keep-alive frame.
    pub fn keepalive(size: usize) -> Self {
        Self::Keepalive(size)
    }

    /// Check if this is a keep-alive frame.
    pub fn is_keepalive(&self) -> bool {
        matches!(self, Self::Keepalive(_))
    }

    /// Check if this is a data frame.
    pub fn is_data(&self) -> bool {
        matches!(self, Self::Data(_))
    }

    /// Get the packets if this is a data frame.
    pub fn packets(&self) -> Option<&[Bytes]> {
        match self {
            Self::Data(packets) => Some(packets),
            _ => None,
        }
    }

    /// Serialize the frame to bytes.
    pub fn encode(&self) -> Bytes {
        match self {
            Self::Data(packets) => {
                // Calculate total size
                let total_size = 4 + packets.iter().map(|p| 4 + p.len()).sum::<usize>();
                let mut buf = BytesMut::with_capacity(total_size);

                // Write number of blocks
                buf.put_u32(packets.len() as u32);

                // Write each block
                for packet in packets {
                    buf.put_u32(packet.len() as u32);
                    buf.put_slice(packet);
                }

                buf.freeze()
            }
            Self::Keepalive(size) => {
                let mut buf = BytesMut::with_capacity(8 + *size);
                buf.put_u32(TunnelConstants::KEEPALIVE_MAGIC);
                buf.put_u32(*size as u32);

                // Random padding
                if *size > 0 {
                    let mut padding = vec![0u8; *size];
                    crate::crypto::fill_random(&mut padding);
                    buf.put_slice(&padding);
                }

                buf.freeze()
            }
        }
    }
}

/// Tunnel frame codec (streaming decoder).
#[derive(Debug, Default)]
pub struct TunnelCodec {
    /// Internal buffer for incomplete frames.
    buffer: BytesMut,
    /// Current decode state.
    state: DecodeState,
    /// Accumulated packets for current frame.
    packets: Vec<Bytes>,
    /// Remaining blocks to read.
    remaining_blocks: usize,
    /// Maximum batch size for output.
    max_batch_size: usize,
}

#[derive(Debug, Default)]
enum DecodeState {
    /// Waiting for frame header.
    #[default]
    Header,
    /// Reading data blocks.
    DataBlocks,
    /// Reading keepalive padding.
    KeepalivePadding { size: usize },
}

impl TunnelCodec {
    /// Create a new tunnel codec.
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(65536),
            state: DecodeState::Header,
            packets: Vec::with_capacity(64),
            remaining_blocks: 0,
            max_batch_size: 64,
        }
    }

    /// Set the maximum batch size.
    pub fn set_max_batch_size(&mut self, size: usize) {
        self.max_batch_size = size;
    }

    /// Reset the codec state.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.state = DecodeState::Header;
        self.packets.clear();
        self.remaining_blocks = 0;
    }

    /// Feed data into the codec.
    ///
    /// Returns decoded frames. May return multiple frames if data contains
    /// complete frames.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<TunnelFrame>> {
        self.buffer.extend_from_slice(data);
        let mut frames = Vec::new();

        loop {
            match &self.state {
                DecodeState::Header => {
                    if self.buffer.remaining() < 4 {
                        return Ok(frames);
                    }

                    let header = self.buffer.get_u32();

                    if header == TunnelConstants::KEEPALIVE_MAGIC {
                        // Keepalive frame
                        if self.buffer.remaining() < 4 {
                            // Need more data for size
                            self.state = DecodeState::Header;
                            return Ok(frames);
                        }
                        let size = self.buffer.get_u32() as usize;

                        if size > TunnelConstants::MAX_KEEPALIVE_SIZE {
                            return Err(Error::protocol("Keepalive size too large"));
                        }

                        if size == 0 {
                            frames.push(TunnelFrame::Keepalive(0));
                            continue;
                        }

                        self.state = DecodeState::KeepalivePadding { size };
                    } else if header == 0 {
                        // Empty data frame
                        frames.push(TunnelFrame::Data(Vec::new()));
                        continue;
                    } else if header as usize > TunnelConstants::MAX_BLOCKS {
                        return Err(Error::protocol(format!("Too many blocks: {}", header)));
                    } else {
                        // Data frame
                        self.remaining_blocks = header as usize;
                        self.packets.clear();
                        self.state = DecodeState::DataBlocks;
                    }
                }

                DecodeState::DataBlocks => {
                    while self.remaining_blocks > 0 {
                        if self.buffer.remaining() < 4 {
                            return Ok(frames);
                        }

                        // Peek at block size without consuming
                        let block_size = (&self.buffer[..4]).get_u32() as usize;

                        if block_size == 0 {
                            self.buffer.advance(4);
                            self.remaining_blocks -= 1;
                            continue;
                        }

                        if block_size > TunnelConstants::MAX_PACKET_SIZE * 2 {
                            return Err(Error::protocol(format!(
                                "Packet too large: {}",
                                block_size
                            )));
                        }

                        if self.buffer.remaining() < 4 + block_size {
                            return Ok(frames);
                        }

                        // Consume size
                        self.buffer.advance(4);

                        // Read block data
                        let block_data = self.buffer.copy_to_bytes(block_size);
                        self.packets.push(block_data);
                        self.remaining_blocks -= 1;

                        // Emit partial batch if we've accumulated enough
                        if self.packets.len() >= self.max_batch_size {
                            frames.push(TunnelFrame::Data(std::mem::take(&mut self.packets)));
                            self.packets.reserve(64);
                        }
                    }

                    // All blocks read
                    if !self.packets.is_empty() {
                        frames.push(TunnelFrame::Data(std::mem::take(&mut self.packets)));
                        self.packets.reserve(64);
                    }
                    self.state = DecodeState::Header;
                }

                DecodeState::KeepalivePadding { size } => {
                    let size = *size;
                    if self.buffer.remaining() < size {
                        return Ok(frames);
                    }
                    self.buffer.advance(size);
                    frames.push(TunnelFrame::Keepalive(size));
                    self.state = DecodeState::Header;
                }
            }
        }
    }

    /// Encode multiple packets into a single data frame.
    pub fn encode_batch(packets: &[Bytes]) -> Bytes {
        TunnelFrame::batch(packets.to_vec()).encode()
    }

    /// Encode a single packet into a data frame.
    pub fn encode_single(packet: Bytes) -> Bytes {
        TunnelFrame::single(packet).encode()
    }

    /// Encode a keep-alive frame.
    pub fn encode_keepalive_sized(size: usize) -> Bytes {
        TunnelFrame::keepalive(size).encode()
    }

    /// Decode tunnel data and return raw packet data.
    ///
    /// This is a convenience method that extracts raw Bytes from frames.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<Bytes>> {
        let frames = self.feed(data)?;
        let mut result = Vec::new();
        for frame in frames {
            if let TunnelFrame::Data(packets) = frame {
                result.extend(packets);
            }
        }
        Ok(result)
    }

    /// Encode multiple packets into tunnel wire format.
    pub fn encode(&self, packets: &[&[u8]]) -> Bytes {
        let packets: Vec<Bytes> = packets.iter().map(|p| Bytes::copy_from_slice(p)).collect();
        TunnelFrame::batch(packets).encode()
    }

    /// Encode a keep-alive frame with default padding.
    pub fn encode_keepalive(&self) -> Bytes {
        TunnelFrame::keepalive(rand::random::<usize>() % 64 + 1).encode()
    }

    // =========================================================================
    // Zero-copy methods (inspired by SoftEtherZig)
    // =========================================================================

    /// Encode a single IP packet wrapped in Ethernet directly into a buffer.
    ///
    /// This is the most efficient path for sending:
    /// 1. Writes tunnel header (num_blocks=1, block_size) directly
    /// 2. Writes Ethernet header (dst/src MAC, EtherType)
    /// 3. Copies IP packet data once
    ///
    /// Returns the slice of the buffer that was written, ready for sending.
    ///
    /// # Arguments
    /// * `ip_packet` - The IP packet to send
    /// * `dst_mac` - Destination MAC address (gateway MAC)
    /// * `src_mac` - Source MAC address (our MAC)
    /// * `buffer` - Pre-allocated send buffer (at least 8 + 14 + ip_packet.len())
    #[inline]
    pub fn encode_single_packet_direct<'a>(
        ip_packet: &[u8],
        dst_mac: &[u8; 6],
        src_mac: &[u8; 6],
        buffer: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        if ip_packet.is_empty() || ip_packet.len() > MAX_PACKET_SIZE {
            return None;
        }

        let eth_len = 14 + ip_packet.len();
        let total_len = 4 + 4 + eth_len; // num_blocks + block_size + eth_frame

        if buffer.len() < total_len {
            return None;
        }

        // Determine IP version
        let ip_version = (ip_packet[0] >> 4) & 0x0F;
        if ip_version != 4 && ip_version != 6 {
            return None;
        }

        // num_blocks = 1
        buffer[0..4].copy_from_slice(&1u32.to_be_bytes());

        // block_size = eth_len
        buffer[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());

        // Ethernet header (14 bytes)
        buffer[8..14].copy_from_slice(dst_mac); // dst MAC
        buffer[14..20].copy_from_slice(src_mac); // src MAC

        // EtherType
        if ip_version == 4 {
            buffer[20] = 0x08;
            buffer[21] = 0x00;
        } else {
            buffer[20] = 0x86;
            buffer[21] = 0xDD;
        }

        // IP packet (single copy)
        buffer[22..22 + ip_packet.len()].copy_from_slice(ip_packet);

        Some(&buffer[..total_len])
    }

    /// Encode multiple Ethernet frames into a buffer using zero-copy.
    ///
    /// # Arguments
    /// * `frames` - Slices of Ethernet frames to encode
    /// * `buffer` - Pre-allocated send buffer
    ///
    /// Returns the slice of the buffer that was written.
    #[inline]
    pub fn encode_batch_direct<'a>(frames: &[&[u8]], buffer: &'a mut [u8]) -> Option<&'a [u8]> {
        if frames.is_empty() {
            return None;
        }

        // Calculate total size needed
        let mut total_size: usize = 4; // num_blocks
        for frame in frames {
            total_size += 4 + frame.len(); // size + data
        }

        if buffer.len() < total_size {
            return None;
        }

        let mut offset: usize = 0;

        // Write number of blocks
        buffer[offset..offset + 4].copy_from_slice(&(frames.len() as u32).to_be_bytes());
        offset += 4;

        // Write each block
        for frame in frames {
            buffer[offset..offset + 4].copy_from_slice(&(frame.len() as u32).to_be_bytes());
            offset += 4;
            buffer[offset..offset + frame.len()].copy_from_slice(frame);
            offset += frame.len();
        }

        Some(&buffer[..offset])
    }

    /// Encode a keep-alive packet directly into a buffer.
    ///
    /// # Arguments
    /// * `padding_size` - Size of random padding (0-512)
    /// * `buffer` - Pre-allocated buffer (at least 8 + padding_size)
    #[inline]
    pub fn encode_keepalive_direct(padding_size: usize, buffer: &mut [u8]) -> Option<&[u8]> {
        let padding_size = padding_size.min(TunnelConstants::MAX_KEEPALIVE_SIZE);
        let total_size = 8 + padding_size;

        if buffer.len() < total_size {
            return None;
        }

        // KEEP_ALIVE_MAGIC
        buffer[0..4].copy_from_slice(&TunnelConstants::KEEPALIVE_MAGIC.to_be_bytes());

        // Padding size
        buffer[4..8].copy_from_slice(&(padding_size as u32).to_be_bytes());

        // Random padding
        if padding_size > 0 {
            crate::crypto::fill_random(&mut buffer[8..8 + padding_size]);
        }

        Some(&buffer[..total_size])
    }

    /// Decode blocks from a buffer without allocation.
    ///
    /// Uses a callback to process each block, avoiding the need to collect into a Vec.
    ///
    /// # Arguments
    /// * `data` - Raw tunnel data
    /// * `callback` - Called for each decoded block with the block data
    ///
    /// Returns number of blocks processed, or error.
    pub fn decode_with_callback<F>(&mut self, data: &[u8], mut callback: F) -> Result<usize>
    where
        F: FnMut(&[u8]),
    {
        self.buffer.extend_from_slice(data);
        let mut block_count = 0;

        loop {
            match &self.state {
                DecodeState::Header => {
                    if self.buffer.remaining() < 4 {
                        return Ok(block_count);
                    }

                    let header = self.buffer.get_u32();

                    if header == TunnelConstants::KEEPALIVE_MAGIC {
                        if self.buffer.remaining() < 4 {
                            return Ok(block_count);
                        }
                        let size = self.buffer.get_u32() as usize;
                        if size > TunnelConstants::MAX_KEEPALIVE_SIZE {
                            return Err(Error::protocol("Keepalive size too large"));
                        }
                        self.state = DecodeState::KeepalivePadding { size };
                    } else if header == 0 {
                        continue;
                    } else if header as usize > TunnelConstants::MAX_BLOCKS {
                        return Err(Error::protocol(format!("Too many blocks: {}", header)));
                    } else {
                        self.remaining_blocks = header as usize;
                        self.state = DecodeState::DataBlocks;
                    }
                }

                DecodeState::DataBlocks => {
                    while self.remaining_blocks > 0 {
                        if self.buffer.remaining() < 4 {
                            return Ok(block_count);
                        }

                        let block_size = (&self.buffer[..4]).get_u32() as usize;

                        if block_size == 0 {
                            self.buffer.advance(4);
                            self.remaining_blocks -= 1;
                            continue;
                        }

                        if block_size > TunnelConstants::MAX_PACKET_SIZE * 2 {
                            return Err(Error::protocol(format!(
                                "Packet too large: {}",
                                block_size
                            )));
                        }

                        if self.buffer.remaining() < 4 + block_size {
                            return Ok(block_count);
                        }

                        self.buffer.advance(4);

                        // Call callback with the block data (zero-copy reference)
                        callback(&self.buffer[..block_size]);

                        self.buffer.advance(block_size);
                        self.remaining_blocks -= 1;
                        block_count += 1;
                    }

                    self.state = DecodeState::Header;
                }

                DecodeState::KeepalivePadding { size } => {
                    let size = *size;
                    if self.buffer.remaining() < size {
                        return Ok(block_count);
                    }
                    self.buffer.advance(size);
                    self.state = DecodeState::Header;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_single_packet() {
        let packet = Bytes::from_static(b"hello world");
        let frame = TunnelFrame::single(packet.clone());
        let encoded = frame.encode();

        // Decode
        let mut codec = TunnelCodec::new();
        let frames = codec.feed(&encoded).unwrap();

        assert_eq!(frames.len(), 1);
        let packets = frames[0].packets().unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], packet);
    }

    #[test]
    fn test_encode_batch() {
        let packets = vec![
            Bytes::from_static(b"packet1"),
            Bytes::from_static(b"packet2"),
            Bytes::from_static(b"packet3"),
        ];
        let frame = TunnelFrame::batch(packets.clone());
        let encoded = frame.encode();

        // Decode
        let mut codec = TunnelCodec::new();
        let frames = codec.feed(&encoded).unwrap();

        assert_eq!(frames.len(), 1);
        let decoded = frames[0].packets().unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], packets[0]);
        assert_eq!(decoded[1], packets[1]);
        assert_eq!(decoded[2], packets[2]);
    }

    #[test]
    fn test_keepalive() {
        let frame = TunnelFrame::keepalive(64);
        let encoded = frame.encode();

        // Should start with magic
        assert_eq!(&encoded[..4], &[0xFF, 0xFF, 0xFF, 0xFF]);

        // Decode
        let mut codec = TunnelCodec::new();
        let frames = codec.feed(&encoded).unwrap();

        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_keepalive());
    }

    #[test]
    fn test_streaming_decode() {
        let packet = Bytes::from_static(b"hello");
        let frame = TunnelFrame::single(packet.clone());
        let encoded = frame.encode();

        let mut codec = TunnelCodec::new();

        // Feed partial data
        let frames = codec.feed(&encoded[..2]).unwrap();
        assert!(frames.is_empty());

        // Feed more partial data
        let frames = codec.feed(&encoded[2..6]).unwrap();
        assert!(frames.is_empty());

        // Feed rest
        let frames = codec.feed(&encoded[6..]).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].packets().unwrap()[0], packet);
    }

    #[test]
    fn test_empty_frame() {
        let frame = TunnelFrame::Data(Vec::new());
        let encoded = frame.encode();

        let mut codec = TunnelCodec::new();
        let frames = codec.feed(&encoded).unwrap();

        assert_eq!(frames.len(), 1);
        assert!(frames[0].packets().unwrap().is_empty());
    }

    // =========================================================================
    // Zero-copy method tests
    // =========================================================================

    #[test]
    fn test_encode_single_packet_direct_ipv4() {
        // Minimal IPv4 packet
        let ip_packet: [u8; 20] = [
            0x45, 0x00, 0x00, 0x14, // version=4, IHL=5, total_len=20
            0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8, 0x01,
            0x64, // src: 192.168.1.100
            0xC0, 0xA8, 0x01, 0x01, // dst: 192.168.1.1
        ];
        let dst_mac = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let src_mac = [0x02, 0x00, 0x5E, 0x00, 0x00, 0x01];
        let mut buffer = [0u8; 2048];

        let result =
            TunnelCodec::encode_single_packet_direct(&ip_packet, &dst_mac, &src_mac, &mut buffer);

        assert!(result.is_some());
        let encoded = result.unwrap();

        // Total: 4 (num_blocks) + 4 (block_size) + 14 (eth) + 20 (ip) = 42
        assert_eq!(encoded.len(), 42);

        // Verify num_blocks = 1
        assert_eq!(&encoded[0..4], &[0, 0, 0, 1]);

        // Verify block_size = 34 (14 + 20)
        assert_eq!(&encoded[4..8], &[0, 0, 0, 34]);

        // Verify dst MAC
        assert_eq!(&encoded[8..14], &dst_mac);

        // Verify src MAC
        assert_eq!(&encoded[14..20], &src_mac);

        // Verify EtherType is IPv4
        assert_eq!(&encoded[20..22], &[0x08, 0x00]);

        // Verify IP packet is intact
        assert_eq!(&encoded[22..], &ip_packet);
    }

    #[test]
    fn test_encode_single_packet_direct_ipv6() {
        // Minimal IPv6 packet
        let mut ip_packet = [0u8; 40];
        ip_packet[0] = 0x60; // version=6

        let dst_mac = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let src_mac = [0x02, 0x00, 0x5E, 0x00, 0x00, 0x01];
        let mut buffer = [0u8; 2048];

        let result =
            TunnelCodec::encode_single_packet_direct(&ip_packet, &dst_mac, &src_mac, &mut buffer);

        assert!(result.is_some());
        let encoded = result.unwrap();

        // Verify EtherType is IPv6
        assert_eq!(&encoded[20..22], &[0x86, 0xDD]);
    }

    #[test]
    fn test_encode_single_packet_direct_invalid_version() {
        let ip_packet = [0x00u8; 20]; // Invalid IP version
        let dst_mac = [0xFF; 6];
        let src_mac = [0x02; 6];
        let mut buffer = [0u8; 2048];

        let result =
            TunnelCodec::encode_single_packet_direct(&ip_packet, &dst_mac, &src_mac, &mut buffer);

        assert!(result.is_none());
    }

    #[test]
    fn test_encode_single_packet_direct_buffer_too_small() {
        let ip_packet = [0x45u8; 20];
        let dst_mac = [0xFF; 6];
        let src_mac = [0x02; 6];
        let mut buffer = [0u8; 30]; // Too small

        let result =
            TunnelCodec::encode_single_packet_direct(&ip_packet, &dst_mac, &src_mac, &mut buffer);

        assert!(result.is_none());
    }

    #[test]
    fn test_encode_batch_direct() {
        let frame1: &[u8] = b"frame1";
        let frame2: &[u8] = b"frame2";
        let frames: &[&[u8]] = &[frame1, frame2];
        let mut buffer = [0u8; 1024];

        let result = TunnelCodec::encode_batch_direct(frames, &mut buffer);

        assert!(result.is_some());
        let encoded = result.unwrap();

        // Verify num_blocks = 2
        assert_eq!(&encoded[0..4], &[0, 0, 0, 2]);

        // Verify first block size = 6
        assert_eq!(&encoded[4..8], &[0, 0, 0, 6]);

        // Verify first block data
        assert_eq!(&encoded[8..14], b"frame1");

        // Verify second block size = 6
        assert_eq!(&encoded[14..18], &[0, 0, 0, 6]);

        // Verify second block data
        assert_eq!(&encoded[18..24], b"frame2");
    }

    #[test]
    fn test_encode_keepalive_direct() {
        let mut buffer = [0u8; 100];

        let result = TunnelCodec::encode_keepalive_direct(32, &mut buffer);

        assert!(result.is_some());
        let encoded = result.unwrap();

        assert_eq!(encoded.len(), 8 + 32);

        // Verify magic
        assert_eq!(&encoded[0..4], &[0xFF, 0xFF, 0xFF, 0xFF]);

        // Verify padding size
        assert_eq!(&encoded[4..8], &[0, 0, 0, 32]);
    }

    #[test]
    fn test_decode_with_callback() {
        let frame1 = Bytes::from_static(b"packet1");
        let frame2 = Bytes::from_static(b"packet2");
        let frame = TunnelFrame::batch(vec![frame1.clone(), frame2.clone()]);
        let encoded = frame.encode();

        let mut codec = TunnelCodec::new();
        let mut received: Vec<Vec<u8>> = Vec::new();

        let count = codec
            .decode_with_callback(&encoded, |data| {
                received.push(data.to_vec());
            })
            .unwrap();

        assert_eq!(count, 2);
        assert_eq!(received[0], b"packet1");
        assert_eq!(received[1], b"packet2");
    }

    #[test]
    fn test_roundtrip_direct_encode_decode() {
        // Encode using zero-copy
        let ip_packet: [u8; 20] = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8,
            0x01, 0x64, 0xC0, 0xA8, 0x01, 0x01,
        ];
        let dst_mac = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let src_mac = [0x02, 0x00, 0x5E, 0x00, 0x00, 0x01];
        let mut buffer = [0u8; 2048];

        let encoded =
            TunnelCodec::encode_single_packet_direct(&ip_packet, &dst_mac, &src_mac, &mut buffer)
                .unwrap();

        // Decode
        let mut codec = TunnelCodec::new();
        let frames = codec.feed(encoded).unwrap();

        assert_eq!(frames.len(), 1);
        let packets = frames[0].packets().unwrap();
        assert_eq!(packets.len(), 1);

        // Verify Ethernet frame
        let eth_frame = &packets[0];
        assert_eq!(&eth_frame[0..6], &dst_mac);
        assert_eq!(&eth_frame[6..12], &src_mac);
        assert_eq!(&eth_frame[12..14], &[0x08, 0x00]); // IPv4
        assert_eq!(&eth_frame[14..], &ip_packet);
    }
}
