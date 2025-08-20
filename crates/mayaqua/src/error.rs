//! Error handling for SoftEther VPN Rust implementation
//!
//! Unified error types that map to SoftEther error codes from the C implementation.

use std::fmt;
use std::io;

/// Main error type for SoftEther operations
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    // Core errors (matching C implementation error codes)
    NoError,              // ERR_NO_ERROR = 0
    InternalError,        // ERR_INTERNAL_ERROR = 1
    ObjectNotFound,       // ERR_OBJECT_NOT_FOUND = 2
    InvalidParameter,     // ERR_INVALID_PARAMETER = 3
    TimeOut,              // ERR_TIME_OUT = 4
    NoMemory,             // ERR_NO_MEMORY = 5
    DisconnectedError,    // ERR_DISCONNECTED = 6
    AuthTypeNotSupported, // ERR_AUTHTYPE_NOT_SUPPORTED = 7

    // Pack system errors
    SizeOver,        // Pack/value size exceeds limits
    InvalidPack,     // Corrupted pack data
    ElementNotFound, // Element not found in pack
    ValueTypeError,  // Wrong value type accessed

    // Network errors
    ConnectFailed, // Network connection failed
    SocketError,   // Generic socket error
    TlsError,      // TLS/SSL error

    // Protocol errors
    ProtocolError,        // Protocol violation
    InvalidSignature,     // Invalid protocol signature
    AuthenticationFailed, // Authentication failed

    // Crypto errors
    CryptoError,        // Cryptographic operation failed
    InvalidCertificate, // Certificate validation failed

    // I/O errors
    IoError(String), // I/O operation failed
    InvalidString,   // String encoding error

    // Platform-specific errors
    /// Pack-related errors
    Pack(String),

    /// Network communication errors
    Network(String),

    /// HTTP protocol errors  
    Http(String),

    // Platform-specific errors
    PlatformError(String), // Platform-specific error
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoError => write!(f, "No error"),
            Error::InternalError => write!(f, "Internal error"),
            Error::ObjectNotFound => write!(f, "Object not found"),
            Error::InvalidParameter => write!(f, "Invalid parameter"),
            Error::TimeOut => write!(f, "Operation timed out"),
            Error::NoMemory => write!(f, "Out of memory"),
            Error::DisconnectedError => write!(f, "Connection disconnected"),
            Error::AuthTypeNotSupported => write!(f, "Authentication type not supported"),
            Error::SizeOver => write!(f, "Size exceeds maximum limit"),
            Error::InvalidPack => write!(f, "Invalid pack data"),
            Error::ElementNotFound => write!(f, "Element not found"),
            Error::ValueTypeError => write!(f, "Value type mismatch"),
            Error::ConnectFailed => write!(f, "Connection failed"),
            Error::SocketError => write!(f, "Socket error"),
            Error::TlsError => write!(f, "TLS error"),
            Error::ProtocolError => write!(f, "Protocol error"),
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::AuthenticationFailed => write!(f, "Authentication failed"),
            Error::CryptoError => write!(f, "Cryptographic error"),
            Error::InvalidCertificate => write!(f, "Invalid certificate"),
            Error::IoError(msg) => write!(f, "I/O error: {msg}"),
            Error::InvalidString => write!(f, "Invalid string encoding"),
            Error::Pack(msg) => write!(f, "Pack error: {msg}"),
            Error::Network(msg) => write!(f, "Network error: {msg}"),
            Error::Http(msg) => write!(f, "HTTP error: {msg}"),
            Error::PlatformError(msg) => write!(f, "Platform error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IoError(err.to_string())
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(_: std::string::FromUtf8Error) -> Self {
        Error::InvalidString
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(_: std::str::Utf8Error) -> Self {
        Error::InvalidString
    }
}

/// Result type alias for SoftEther operations
pub type Result<T> = std::result::Result<T, Error>;

// Error code constants matching C implementation
impl Error {
    /// Convert to numeric error code (compatible with C implementation)
    pub fn to_code(&self) -> u32 {
        match self {
            Error::NoError => 0,
            Error::InternalError => 1,
            Error::ObjectNotFound => 2,
            Error::InvalidParameter => 3,
            Error::TimeOut => 4,
            Error::NoMemory => 5,
            Error::DisconnectedError => 6,
            Error::AuthTypeNotSupported => 7,
            // Custom error codes for Rust-specific errors
            Error::SizeOver => 100,
            Error::InvalidPack => 101,
            Error::ElementNotFound => 102,
            Error::ValueTypeError => 103,
            Error::ConnectFailed => 200,
            Error::SocketError => 201,
            Error::TlsError => 202,
            Error::ProtocolError => 300,
            Error::InvalidSignature => 301,
            Error::AuthenticationFailed => 302,
            Error::CryptoError => 400,
            Error::InvalidCertificate => 401,
            Error::IoError(_) => 500,
            Error::InvalidString => 501,
            Error::Pack(_) => 502,
            Error::Network(_) => 503,
            Error::Http(_) => 504,
            Error::PlatformError(_) => 600,
        }
    }

    /// Create error from numeric code
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => Error::NoError,
            1 => Error::InternalError,
            2 => Error::ObjectNotFound,
            3 => Error::InvalidParameter,
            4 => Error::TimeOut,
            5 => Error::NoMemory,
            6 => Error::DisconnectedError,
            7 => Error::AuthTypeNotSupported,
            _ => Error::InternalError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(Error::NoError.to_code(), 0);
        assert_eq!(Error::InternalError.to_code(), 1);
        assert_eq!(Error::InvalidParameter.to_code(), 3);
    }

    #[test]
    fn test_error_from_code() {
        assert_eq!(Error::from_code(0), Error::NoError);
        assert_eq!(Error::from_code(1), Error::InternalError);
        assert_eq!(Error::from_code(999), Error::InternalError); // Unknown codes -> InternalError
    }

    #[test]
    fn test_error_display() {
        let err = Error::InvalidParameter;
        assert!(err.to_string().contains("Invalid parameter"));
    }
}
