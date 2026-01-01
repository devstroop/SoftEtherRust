//! VPN connection handling with TLS support.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

use crate::config::VpnConfig;
use crate::error::{Error, Result};
use crate::protocol::{HttpCodec, HttpRequest, HttpResponse};

/// Connection type (either plain TCP or TLS).
pub enum Connection {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl Connection {
    /// Read data from the connection.
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf).await,
            Self::Tls(stream) => stream.read(buf).await,
        }
    }

    /// Write data to the connection.
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.write_all(buf).await,
            Self::Tls(stream) => stream.write_all(buf).await,
        }
    }

    /// Flush the connection.
    pub async fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush().await,
            Self::Tls(stream) => stream.flush().await,
        }
    }

    /// Set TCP_NODELAY option.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.set_nodelay(nodelay),
            Self::Tls(stream) => stream.get_ref().0.set_nodelay(nodelay),
        }
    }
}

/// VPN connection with protocol handling.
pub struct VpnConnection {
    connection: Connection,
    http_codec: HttpCodec,
    read_buffer: Vec<u8>,
}

impl VpnConnection {
    /// Connect to the VPN server.
    pub async fn connect(config: &VpnConfig) -> Result<Self> {
        let connect_timeout = config.connect_timeout();

        // Resolve address
        let addr = Self::resolve_address(&config.server, config.port).await?;
        info!("Connecting to {} ({})", config.server, addr);

        // Connect with timeout
        let stream = timeout(connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)?;

        // Set TCP_NODELAY for VPN traffic
        stream.set_nodelay(true)?;

        // SoftEther always uses TLS/HTTPS
        let tls_stream = Self::wrap_tls(stream, config).await?;
        let connection = Connection::Tls(tls_stream);

        info!("Connected to VPN server");

        Ok(Self {
            connection,
            http_codec: HttpCodec::new(),
            read_buffer: vec![0u8; 65536],
        })
    }

    /// Reconnect to a different server (for cluster redirect).
    pub async fn reconnect(&mut self, host: &str, port: u16, config: &VpnConfig) -> Result<()> {
        let addr = Self::resolve_address(host, port).await?;
        info!("Reconnecting to {} ({})", host, addr);

        let connect_timeout = config.connect_timeout();

        let stream = timeout(connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)?;

        stream.set_nodelay(true)?;

        // SoftEther always uses TLS/HTTPS
        let tls_stream = Self::wrap_tls(stream, config).await?;
        self.connection = Connection::Tls(tls_stream);

        self.http_codec.reset();
        info!("Reconnected successfully");

        Ok(())
    }

    /// Send an HTTP request.
    pub async fn send_http(&mut self, request: &HttpRequest, host: &str) -> Result<()> {
        let data = request.build(host);
        self.connection.write_all(&data).await?;
        self.connection.flush().await?;
        debug!("Sent HTTP request: {} {}", request.method, request.path);
        Ok(())
    }

    /// Receive an HTTP response.
    pub async fn receive_http(&mut self, read_timeout: Duration) -> Result<HttpResponse> {
        self.http_codec.reset();

        loop {
            let read_result = timeout(read_timeout, self.connection.read(&mut self.read_buffer))
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(Error::Io)?;

            if read_result == 0 {
                return Err(Error::connection("Connection closed"));
            }

            if let Some(response) = self.http_codec.feed(&self.read_buffer[..read_result])? {
                debug!("Received HTTP response: {}", response.status_code);
                return Ok(response);
            }
        }
    }

    /// Send raw bytes.
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.connection.write_all(data).await?;
        self.connection.flush().await?;
        Ok(())
    }

    /// Receive raw bytes.
    ///
    /// Returns the number of bytes read.
    pub async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.connection.read(buf).await?;
        if n == 0 {
            return Err(Error::connection("Connection closed"));
        }
        Ok(n)
    }

    /// Receive raw bytes with timeout.
    pub async fn receive_timeout(&mut self, buf: &mut [u8], timeout_duration: Duration) -> Result<usize> {
        let n = timeout(timeout_duration, self.connection.read(buf))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)?;

        if n == 0 {
            return Err(Error::connection("Connection closed"));
        }
        Ok(n)
    }

    /// Get mutable reference to the underlying connection.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    /// Resolve hostname to socket address.
    async fn resolve_address(host: &str, port: u16) -> Result<SocketAddr> {
        // Try parsing as IP address first
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }

        // DNS lookup
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", host, port))
            .await
            .map_err(|e| Error::DnsResolution(e.to_string()))?
            .collect();

        addrs.into_iter().next().ok_or_else(|| {
            Error::DnsResolution(format!("No addresses found for {}", host))
        })
    }

    /// Wrap a TCP stream in TLS.
    async fn wrap_tls(stream: TcpStream, config: &VpnConfig) -> Result<TlsStream<TcpStream>> {
        let mut root_store = rustls::RootCertStore::empty();

        if !config.skip_tls_verify {
            // Use webpki roots for verification
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        let tls_config = if config.skip_tls_verify {
            // Create a config that doesn't verify certificates
            // SoftEther often uses self-signed certificates
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(tls_config));
        
        // Handle SNI: use dummy hostname for IP addresses, actual hostname for domains
        let server_name = if config.server.parse::<std::net::IpAddr>().is_ok() {
            // For IP addresses, use a dummy SNI hostname
            // SoftEther servers accept any SNI for IP connections
            ServerName::try_from("softether".to_string())
                .map_err(|_| Error::Tls("Failed to create SNI hostname".to_string()))?
        } else {
            ServerName::try_from(config.server.clone())
                .map_err(|_| Error::Tls(format!("Invalid server name for TLS: {}", config.server)))?
        };

        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(Error::Io)?;

        debug!("TLS handshake completed");
        Ok(tls_stream)
    }
}

/// Certificate verifier that accepts any certificate.
/// Used when `verify_tls` is false (SoftEther often uses self-signed certs).
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
