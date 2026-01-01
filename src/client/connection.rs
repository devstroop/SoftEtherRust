//! VPN network connection.

use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use rustls;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

use crate::config::VpnConfig;
use crate::error::{Error, Result};

/// A dangerous verifier that accepts all certificates.
/// Only use this for development or when connecting to servers with self-signed certs.
#[derive(Debug)]
struct NoVerifier;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::ServerCertVerified,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        vec![
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA512,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA512,
            tokio_rustls::rustls::SignatureScheme::ED25519,
        ]
    }
}

/// VPN connection wrapper that handles both plain and TLS connections.
pub enum VpnConnection {
    /// Plain TCP connection.
    Plain(TcpStream),
    /// TLS-encrypted connection.
    Tls(TlsStream<TcpStream>),
}

impl VpnConnection {
    /// Connect to the VPN server.
    pub async fn connect(config: &VpnConfig) -> Result<Self> {
        let addr = format!("{}:{}", config.server, config.port);

        // Resolve address
        let socket_addr = addr
            .to_socket_addrs()
            .map_err(|e| Error::ConnectionFailed(format!("Failed to resolve {}: {}", addr, e)))?
            .next()
            .ok_or_else(|| Error::ConnectionFailed(format!("No addresses found for {}", addr)))?;

        debug!("Connecting to {}", socket_addr);

        // Connect with timeout
        let timeout = Duration::from_secs(config.timeout_seconds);
        let stream = tokio::time::timeout(timeout, TcpStream::connect(socket_addr))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| Error::ConnectionFailed(format!("TCP connect failed: {}", e)))?;

        // Set TCP options
        stream.set_nodelay(true)?;

        // SoftEther always uses TLS/HTTPS
        // Get the ring crypto provider
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        // Build TLS config
        let tls_config = if config.skip_tls_verify {
            // Accept any certificate (needed for self-signed certs)
            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            // Use system root certificates
            let root_store = RootCertStore::empty();
            // In production, you'd load system certs here
            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(tls_config));

        // Handle both hostname and IP address for SNI
        let server_name = if config.server.parse::<std::net::IpAddr>().is_ok() {
            // For IP addresses, use a dummy hostname for SNI
            // SoftEther servers typically accept any SNI or no SNI for IP connections
            ServerName::try_from("softether")
                .map_err(|_| Error::Tls("Failed to create server name".to_string()))?
        } else {
            ServerName::try_from(config.server.clone())
                .map_err(|_| Error::Tls(format!("Invalid server name: {}", config.server)))?
        };

        debug!("TLS connecting with SNI: {:?}", server_name);

        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| Error::Tls(format!("TLS handshake failed: {}", e)))?;

        info!("TLS connection established");
        Ok(VpnConnection::Tls(tls_stream))
    }

    /// Read data from the connection.
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            VpnConnection::Plain(stream) => stream.read(buf).await,
            VpnConnection::Tls(stream) => stream.read(buf).await,
        }
    }

    /// Write data to the connection.
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            VpnConnection::Plain(stream) => stream.write_all(buf).await,
            VpnConnection::Tls(stream) => stream.write_all(buf).await,
        }
    }

    /// Flush the connection.
    pub async fn flush(&mut self) -> io::Result<()> {
        match self {
            VpnConnection::Plain(stream) => stream.flush().await,
            VpnConnection::Tls(stream) => stream.flush().await,
        }
    }

    /// Shutdown the connection.
    pub async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            VpnConnection::Plain(stream) => stream.shutdown().await,
            VpnConnection::Tls(stream) => stream.shutdown().await,
        }
    }
}
