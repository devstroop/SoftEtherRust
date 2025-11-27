//! Error types for VirtualTapRust

use thiserror::Error;

/// VirtualTap error type
#[derive(Error, Debug)]
pub enum VTapError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Failed to create utun device: {0}")]
    UtunCreation(String),
    
    #[error("Failed to configure interface: {0}")]
    Configuration(String),
    
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),
    
    #[error("Ring buffer full")]
    BufferFull,
    
    #[error("Ring buffer empty")]
    BufferEmpty,
    
    #[error("Invalid MAC address")]
    InvalidMac,
    
    #[error("MTU too large: {0} > {1}")]
    MtuTooLarge(usize, usize),
}

/// Result type alias for VirtualTap operations
pub type VTapResult<T> = Result<T, VTapError>;
