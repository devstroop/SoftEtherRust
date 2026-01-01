//! Error types for the SoftEther Rust client.

use thiserror::Error;

/// Result type alias using our Error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for the SoftEther client.
#[derive(Error, Debug)]
pub enum Error {
    /// Connection errors
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Already connected
    #[error("Client is already connected")]
    AlreadyConnected,

    /// Not connected
    #[error("Client is not connected")]
    NotConnected,

    /// TLS errors
    #[error("TLS error: {0}")]
    Tls(String),

    /// I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Server returned an error
    #[error("Server error: {0}")]
    ServerError(String),

    /// Server returned an error with code
    #[error("Server error: {message} (code: {code})")]
    ServerErrorCode { code: u32, message: String },

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// User already logged in (error code 20)
    #[error("User already logged in - session in use")]
    UserAlreadyLoggedIn,

    /// Invalid response from server
    #[error("Invalid server response: {0}")]
    InvalidResponse(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// DHCP configuration failed
    #[error("DHCP configuration failed: {0}")]
    DhcpFailed(String),

    /// Timeout
    #[error("Operation timed out")]
    Timeout,

    /// Timeout with message
    #[error("Operation timed out: {0}")]
    TimeoutMessage(String),

    /// Pack serialization error
    #[error("Pack error: {0}")]
    Pack(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// TUN device error
    #[error("TUN device error: {0}")]
    TunDevice(String),

    /// DNS resolution error
    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    /// Channel closed
    #[error("Internal channel closed unexpectedly")]
    ChannelClosed,
}

impl Error {
    /// Create a new connection error.
    pub fn connection<S: Into<String>>(msg: S) -> Self {
        Self::ConnectionFailed(msg.into())
    }

    /// Create a new protocol error.
    pub fn protocol<S: Into<String>>(msg: S) -> Self {
        Self::Protocol(msg.into())
    }

    /// Create a new invalid response error.
    pub fn invalid_response<S: Into<String>>(msg: S) -> Self {
        Self::InvalidResponse(msg.into())
    }

    /// Create a new pack error.
    pub fn pack<S: Into<String>>(msg: S) -> Self {
        Self::Pack(msg.into())
    }

    /// Create a new server error.
    pub fn server(code: u32, message: impl Into<String>) -> Self {
        Self::ServerErrorCode {
            code,
            message: message.into(),
        }
    }

    /// Create a new authentication error.
    pub fn auth<S: Into<String>>(msg: S) -> Self {
        Self::AuthenticationFailed(msg.into())
    }

    /// Create a new invalid state error.
    pub fn invalid_state<S: Into<String>>(msg: S) -> Self {
        Self::Protocol(format!("Invalid state: {}", msg.into()))
    }

    /// Check if this is a retriable error.
    pub fn is_retriable(&self) -> bool {
        matches!(
            self,
            Self::ConnectionFailed(_)
                | Self::Io(_)
                | Self::Timeout
                | Self::TimeoutMessage(_)
                | Self::ChannelClosed
                | Self::UserAlreadyLoggedIn
        )
    }
}

/// Convert from anyhow::Error for convenience.
impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Self::Protocol(err.to_string())
    }
}
