//! VPN network connection.

use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use rustls;
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
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
    Tls(Box<TlsStream<TcpStream>>),
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

        // SoftEther always uses TLS/HTTPS
        // Get the ring crypto provider
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        // Build TLS config - Force TLS 1.3 only (like Swift's NWProtocolTLS)
        let tls_versions: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
        
        let tls_config = if config.skip_tls_verify {
            // Accept any certificate (needed for self-signed certs)
            ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&tls_versions)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            // Use system root certificates
            let root_store = RootCertStore::empty();
            // In production, you'd load system certs here
            ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&tls_versions)
                .unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(tls_config));

        // Determine SNI hostname: use sni_hostname if provided, otherwise server
        // This is important for cluster redirect where we connect to IP but need original hostname for TLS
        let sni_name = config.sni_hostname.as_ref().unwrap_or(&config.server);
        
        let server_name = if sni_name.parse::<std::net::IpAddr>().is_ok() {
            // SNI name is also an IP, use placeholder
            ServerName::try_from("softether")
                .map_err(|_| Error::Tls("Failed to create server name".to_string()))?
        } else {
            // Use the hostname for SNI
            ServerName::try_from(sni_name.clone())
                .map_err(|_| Error::Tls(format!("Invalid server name: {}", sni_name)))?
        };

        debug!("TLS connecting with SNI: {:?}", server_name);

        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| Error::Tls(format!("TLS handshake failed: {}", e)))?;

        info!("TLS connection established");
        Ok(VpnConnection::Tls(Box::new(tls_stream)))
    }

    /// Connect to the VPN server with socket protection callback.
    /// The protect_socket callback is called with the raw socket fd before TLS handshake.
    /// On Android, this should call VpnService.protect() to exclude the socket from VPN routing.
    /// On iOS, we set SO_NET_SERVICE_TYPE to NET_SERVICE_TYPE_VPN to mark the socket as VPN control.
    #[cfg(unix)]
    pub async fn connect_with_protect<F>(config: &VpnConfig, protect_socket: F) -> Result<Self>
    where
        F: FnOnce(i32) -> bool,
    {
        let addr = format!("{}:{}", config.server, config.port);

        // Resolve address
        let socket_addr = addr
            .to_socket_addrs()
            .map_err(|e| Error::ConnectionFailed(format!("Failed to resolve {}: {}", addr, e)))?
            .next()
            .ok_or_else(|| Error::ConnectionFailed(format!("No addresses found for {}", addr)))?;

        debug!("Connecting to {} (with socket protection)", socket_addr);

        // Determine socket domain based on address type
        let domain = if socket_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        // Create socket with socket2 for better control
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| Error::ConnectionFailed(format!("Failed to create socket: {}", e)))?;

        // Apple platforms (iOS/macOS): Set SO_NET_SERVICE_TYPE to NET_SERVICE_TYPE_VPN
        // This marks the socket as VPN control traffic, which should bypass the VPN tunnel
        // in Network Extension context.
        #[cfg(target_vendor = "apple")]
        {
            // SO_NET_SERVICE_TYPE = 0x1016 (4118 decimal)
            // NET_SERVICE_TYPE_VPN = 6
            const SO_NET_SERVICE_TYPE: libc::c_int = 0x1016;
            const NET_SERVICE_TYPE_VPN: libc::c_int = 6;
            
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    SO_NET_SERVICE_TYPE,
                    &NET_SERVICE_TYPE_VPN as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if result == 0 {
                info!("Apple: Set SO_NET_SERVICE_TYPE to NET_SERVICE_TYPE_VPN (6) on fd {}", socket.as_raw_fd());
            } else {
                info!("Apple: Failed to set SO_NET_SERVICE_TYPE on fd {}, errno={}", 
                       socket.as_raw_fd(), std::io::Error::last_os_error());
            }
        }

        // Set socket to non-blocking for async connect
        socket.set_nonblocking(true)
            .map_err(|e| Error::ConnectionFailed(format!("Failed to set non-blocking: {}", e)))?;

        // Start connection (non-blocking)
        match socket.connect(&socket_addr.into()) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {
                // Connection in progress - this is expected for non-blocking
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Also normal for non-blocking
            }
            Err(e) => {
                return Err(Error::ConnectionFailed(format!("Connect failed: {}", e)));
            }
        }

        // Convert to std TcpStream then to tokio TcpStream
        let std_stream: std::net::TcpStream = socket.into();
        let stream = TcpStream::from_std(std_stream)
            .map_err(|e| Error::ConnectionFailed(format!("Failed to convert to async: {}", e)))?;

        // Wait for connection to complete with timeout
        let timeout_dur = Duration::from_secs(config.timeout_seconds);
        let connect_result = tokio::time::timeout(timeout_dur, stream.writable()).await;
        match connect_result {
            Ok(Ok(())) => {
                // Check if connection actually succeeded
                if let Err(e) = stream.peer_addr() {
                    return Err(Error::ConnectionFailed(format!("Connection failed: {}", e)));
                }
            }
            Ok(Err(e)) => {
                return Err(Error::ConnectionFailed(format!("Connection failed: {}", e)));
            }
            Err(_) => {
                return Err(Error::Timeout);
            }
        }

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

        // SoftEther always uses TLS/HTTPS
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        // Build TLS config - Force TLS 1.3 only (like Swift's NWProtocolTLS)
        // This is critical for compatibility with SoftEther cluster servers
        let tls_versions: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
        
        let tls_config = if config.skip_tls_verify {
            ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(tls_versions)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            let root_store = RootCertStore::empty();
            ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(tls_versions)
                .unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(tls_config));

        // Determine SNI hostname: use sni_hostname if provided, otherwise server
        // This is important for cluster redirect where we connect to IP but need original hostname for TLS
        let sni_name = config.sni_hostname.as_ref().unwrap_or(&config.server);
        
        let server_name = if sni_name.parse::<std::net::IpAddr>().is_ok() {
            // SNI name is also an IP, use placeholder
            ServerName::try_from("softether")
                .map_err(|_| Error::Tls("Failed to create server name".to_string()))?
        } else {
            // Use the hostname for SNI
            ServerName::try_from(sni_name.clone())
                .map_err(|_| Error::Tls(format!("Invalid server name: {}", sni_name)))?
        };

        debug!("TLS connecting with SNI: {:?}", server_name);

        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| Error::Tls(format!("TLS handshake failed: {}", e)))?;

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
