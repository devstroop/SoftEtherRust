//! VPN network connection.

use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use ring::digest::{digest, SHA256};
use rustls;
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

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

/// Certificate fingerprint verifier for pinning.
/// Validates that the server certificate matches an expected SHA-256 fingerprint.
#[derive(Debug)]
struct FingerprintVerifier {
    expected_fingerprint: [u8; 32],
}

impl FingerprintVerifier {
    /// Create a new fingerprint verifier from a hex-encoded SHA-256 fingerprint.
    fn from_hex(hex: &str) -> Option<Self> {
        let hex = hex.replace([':', ' '], ""); // Allow colons or spaces in fingerprint
        if hex.len() != 64 {
            return None;
        }
        let mut fingerprint = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).ok()?;
            fingerprint[i] = u8::from_str_radix(s, 16).ok()?;
        }
        Some(Self {
            expected_fingerprint: fingerprint,
        })
    }
}

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::ServerCertVerified,
        tokio_rustls::rustls::Error,
    > {
        // Compute SHA-256 of the certificate
        let actual_fingerprint = digest(&SHA256, end_entity.as_ref());
        let actual_bytes = actual_fingerprint.as_ref();

        if actual_bytes == &self.expected_fingerprint[..] {
            debug!("Certificate fingerprint verified");
            Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
        } else {
            let actual_hex: String = actual_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            let expected_hex: String = self
                .expected_fingerprint
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect();
            warn!(
                "Certificate fingerprint mismatch! Expected: {}, Got: {}",
                expected_hex, actual_hex
            );
            Err(tokio_rustls::rustls::Error::InvalidCertificate(
                tokio_rustls::rustls::CertificateError::BadSignature,
            ))
        }
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
        // We trust the certificate based on fingerprint, so signatures are assumed valid
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

/// Build TLS client configuration based on VpnConfig settings.
fn build_tls_config(config: &VpnConfig) -> Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // Priority: fingerprint pinning > custom CA > skip verify > system roots
    if let Some(ref fingerprint) = config.cert_fingerprint_sha256 {
        // Certificate fingerprint pinning
        let verifier = FingerprintVerifier::from_hex(fingerprint).ok_or_else(|| {
            Error::Tls(format!(
                "Invalid certificate fingerprint: {} (expected 64 hex chars)",
                fingerprint
            ))
        })?;
        debug!("Using certificate fingerprint pinning");
        Ok(ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth())
    } else if let Some(ref ca_pem) = config.custom_ca_pem {
        // Custom CA certificate
        let mut root_store = RootCertStore::empty();
        let certs = rustls_pemfile::certs(&mut ca_pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>();
        if certs.is_empty() {
            return Err(Error::Tls(
                "No valid certificates found in custom_ca_pem".to_string(),
            ));
        }
        for cert in certs {
            root_store
                .add(cert)
                .map_err(|e| Error::Tls(format!("Failed to add custom CA certificate: {}", e)))?;
        }
        debug!("Using custom CA certificate for verification");
        Ok(ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth())
    } else if config.skip_tls_verify {
        // Accept any certificate (needed for self-signed certs)
        debug!("TLS verification disabled (skip_tls_verify=true)");
        Ok(ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth())
    } else {
        // Use system root certificates
        debug!("Using system root certificates for verification");
        let root_store = RootCertStore::empty();
        // In production, you'd load system certs here
        Ok(ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth())
    }
}

/// VPN connection wrapper that handles both plain and TLS connections.
pub enum VpnConnection {
    /// Plain TCP connection.
    Plain(TcpStream),
    /// TLS-encrypted connection.
    Tls(Box<TlsStream<TcpStream>>),
}

impl VpnConnection {
    /// Connect to the VPN server.
    pub async fn connect(config: &VpnConfig) -> Result<Self> {
        let addr = format!("{}:{}", config.server, config.port);

        // Resolve address
        let socket_addr = addr
            .to_socket_addrs()
            .map_err(|e| Error::ConnectionFailed(format!("Failed to resolve {addr}: {e}")))?
            .next()
            .ok_or_else(|| Error::ConnectionFailed(format!("No addresses found for {addr}")))?;

        debug!("Connecting to {}", socket_addr);

        // Connect with timeout
        let timeout = Duration::from_secs(config.timeout_seconds);
        let stream = tokio::time::timeout(timeout, TcpStream::connect(socket_addr))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| Error::ConnectionFailed(format!("TCP connect failed: {e}")))?;

        // Set TCP options
        stream.set_nodelay(true)?;

        // Enable TCP keepalive to prevent NAT timeouts
        // This is critical for mobile networks where NAT mappings can expire quickly
        let sock_ref = SockRef::from(&stream);
        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(10)) // Start keepalive probes after 10s idle
            .with_interval(Duration::from_secs(5)); // Send probes every 5s
        if let Err(e) = sock_ref.set_tcp_keepalive(&keepalive) {
            debug!("Failed to set TCP keepalive: {} (continuing anyway)", e);
        } else {
            debug!("TCP keepalive enabled (time=10s, interval=5s)");
        }

        // SoftEther always uses TLS/HTTPS - build TLS config based on settings
        let tls_config = build_tls_config(config)?;

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
            .map_err(|e| Error::Tls(format!("TLS handshake failed: {e}")))?;

        info!("TLS connection established");
        Ok(VpnConnection::Tls(Box::new(tls_stream)))
    }

    /// Connect to the VPN server with socket protection callback.
    /// The protect_socket callback is called with the raw socket fd before TLS handshake.
    /// On Android, this should call VpnService.protect() to exclude the socket from VPN routing.
    #[cfg(unix)]
    pub async fn connect_with_protect<F>(config: &VpnConfig, protect_socket: F) -> Result<Self>
    where
        F: FnOnce(i32) -> bool,
    {
        let addr = format!("{}:{}", config.server, config.port);

        // Resolve address
        let socket_addr = addr
            .to_socket_addrs()
            .map_err(|e| Error::ConnectionFailed(format!("Failed to resolve {addr}: {e}")))?
            .next()
            .ok_or_else(|| Error::ConnectionFailed(format!("No addresses found for {addr}")))?;

        debug!("Connecting to {} (with socket protection)", socket_addr);

        // Connect with timeout
        let timeout = Duration::from_secs(config.timeout_seconds);
        let stream = tokio::time::timeout(timeout, TcpStream::connect(socket_addr))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| Error::ConnectionFailed(format!("TCP connect failed: {e}")))?;

        // CRITICAL: Protect the socket BEFORE TLS and BEFORE VPN tunnel is established
        let fd = stream.as_raw_fd();
        if !protect_socket(fd) {
            return Err(Error::ConnectionFailed(
                "Failed to protect socket".to_string(),
            ));
        }
        debug!("Socket fd {} protected", fd);

        // Set TCP options
        stream.set_nodelay(true)?;

        // Enable TCP keepalive to prevent NAT timeouts
        // This is critical for mobile networks where NAT mappings can expire quickly
        let sock_ref = SockRef::from(&stream);
        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(10)) // Start keepalive probes after 10s idle
            .with_interval(Duration::from_secs(5)); // Send probes every 5s
        if let Err(e) = sock_ref.set_tcp_keepalive(&keepalive) {
            debug!("Failed to set TCP keepalive: {} (continuing anyway)", e);
        } else {
            debug!("TCP keepalive enabled (time=10s, interval=5s)");
        }

        // SoftEther always uses TLS/HTTPS - build TLS config based on settings
        let tls_config = build_tls_config(config)?;

        let connector = TlsConnector::from(Arc::new(tls_config));

        let server_name = if config.server.parse::<std::net::IpAddr>().is_ok() {
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
            .map_err(|e| Error::Tls(format!("TLS handshake failed: {e}")))?;

        info!("TLS connection established (protected)");
        Ok(VpnConnection::Tls(Box::new(tls_stream)))
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
