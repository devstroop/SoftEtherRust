//! TLS backend abstraction layer
//! 
//! Provides a unified interface for both native-tls and rustls implementations.
//! The backend is selected at compile time via feature flags.

use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[cfg(feature = "use-native-tls")]
mod native_impl {
    use super::*;
    use native_tls::{TlsConnector, TlsStream as NativeTlsStream};
    use std::sync::Once;
    use tracing::warn;

    pub struct TlsStream {
        inner: NativeTlsStream<TcpStream>,
    }

    impl TlsStream {
        pub fn connect(
            host: &str,
            mut tcp_stream: TcpStream,
            skip_verify: bool,
        ) -> Result<Self> {
            let mut builder = TlsConnector::builder();
            
            if skip_verify {
                static WARN_ONCE: Once = Once::new();
                WARN_ONCE.call_once(|| {
                    warn!("TLS certificate verification disabled (insecure)");
                });
                builder.danger_accept_invalid_certs(true);
                builder.danger_accept_invalid_hostnames(true);
            }

            let connector = builder.build()
                .context("Failed to build TLS connector")?;
            
            // Ensure TCP stream is in blocking mode for TLS operations
            tcp_stream.set_nonblocking(false)
                .context("Failed to set blocking mode")?;
            
            let stream = connector.connect(host, tcp_stream)
                .context("TLS handshake failed")?;

            Ok(Self { inner: stream })
        }

        pub fn get_ref(&self) -> &TcpStream {
            self.inner.get_ref()
        }
        
        /// Extract the underlying TcpStream, consuming the TLS session.
        /// Use this after protocol handshake when switching to raw TCP (e.g., SoftEther data links).
        /// 
        /// NOTE: native-tls doesn't provide a way to extract the inner stream, so we use
        /// shutdown() to close the TLS session and then clone the socket via dup(). This is
        /// a workaround since the stream will be closed. In practice, rustls is used instead.
        pub fn into_tcp_stream(self) -> TcpStream {
            // native-tls doesn't expose into_inner(), so we have to use try_clone
            // This is only compiled for native-tls backend (not used in production)
            self.inner.get_ref().try_clone().expect("Failed to clone TcpStream")
        }

        pub fn peer_certificate_der(&self) -> Result<Option<Vec<u8>>> {
            if let Ok(Some(cert)) = self.inner.peer_certificate() {
                cert.to_der().map(Some).context("Failed to get certificate DER")
            } else {
                Ok(None)
            }
        }

        pub fn backend_name() -> &'static str {
            "native-tls"
        }
    }

    impl Read for TlsStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl Write for TlsStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }
}

#[cfg(feature = "use-rustls")]
mod rustls_impl {
    use super::*;
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerName};
    use std::io::{self, ErrorKind};
    use std::sync::Arc;
    use tracing::warn;

    pub struct TlsStream {
        conn: ClientConnection,
        stream: TcpStream,
    }

    impl TlsStream {
        pub fn connect(
            host: &str,
            mut tcp_stream: TcpStream,
            skip_verify: bool,
        ) -> Result<Self> {
            tracing::info!("🔧 Using rustls TLS backend");
            
            // Build rustls config
            let mut root_store = RootCertStore::empty();
            
            if skip_verify {
                warn!("TLS certificate verification disabled (insecure)");
                // Use dangerous config that accepts any certificate
                let mut config = ClientConfig::builder()
                    .with_safe_defaults()
                    .with_custom_certificate_verifier(Arc::new(NoVerifier))
                    .with_no_client_auth();
                
                // NOTE: max_fragment_size only accepts None or values: 512, 1024, 2048, 4096
                // SoftEther needs larger records, so we can't use this extension.
                // Leave as None (default 16KB) and rely on TCP-level buffering.
                config.max_fragment_size = None;
                
                let server_name = ServerName::try_from(host)
                    .map_err(|e| anyhow::anyhow!("Invalid DNS name: {}", e))?;
                
                tracing::debug!("Creating ClientConnection with ServerName: {:?}", server_name);
                
                // Ensure TCP stream is in blocking mode for handshake
                tcp_stream.set_nonblocking(false)
                    .context("Failed to set blocking mode")?;
                
                tracing::debug!("About to call ClientConnection::new()");
                let conn_result = ClientConnection::new(Arc::new(config), server_name);
                
                if let Err(ref e) = conn_result {
                    tracing::error!("ClientConnection::new() failed: {:?}", e);
                }
                
                let conn = conn_result.context("Failed to create TLS connection")?;
                tracing::debug!("ClientConnection created successfully");
                
                let mut tls = Self {
                    conn,
                    stream: tcp_stream,
                };
                
                // Complete handshake
                tracing::debug!("Starting rustls handshake...");
                tls.complete_handshake()
                    .context("Handshake completion failed")?;
                
                tracing::info!("✅ rustls TLS handshake completed successfully (skip_verify={})", skip_verify);
                Ok(tls)
            } else {
                // Use system certificates
                root_store.add_trust_anchors(
                    webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject,
                            ta.spki,
                            ta.name_constraints,
                        )
                    })
                );

                let mut config = ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();
                
                // NOTE: max_fragment_size only accepts None or values: 512, 1024, 2048, 4096
                // SoftEther needs larger records, so we can't use this extension.
                // Leave as None (default 16KB) and rely on TCP-level buffering.
                config.max_fragment_size = None;

                let server_name = ServerName::try_from(host)
                    .map_err(|e| anyhow::anyhow!("Invalid DNS name: {}", e))?;
                
                // Ensure TCP stream is in blocking mode for handshake
                tcp_stream.set_nonblocking(false)
                    .context("Failed to set blocking mode")?;

                let conn = ClientConnection::new(Arc::new(config), server_name)
                    .context("Failed to create TLS connection")?;

                let mut tls = Self {
                    conn,
                    stream: tcp_stream,
                };
                
                // Complete handshake
                tracing::debug!("Starting rustls handshake (verified)...");
                tls.complete_handshake()
                    .context("Handshake completion failed")?;
                
                tracing::info!("✅ rustls TLS handshake completed successfully (verified)");
                Ok(tls)
            }
        }

        fn complete_handshake(&mut self) -> Result<()> {
            // Perform TLS handshake
            while self.conn.is_handshaking() {
                // Write any pending data
                while self.conn.wants_write() {
                    match self.conn.write_tls(&mut self.stream) {
                        Ok(n) => tracing::debug!("TLS handshake: wrote {} bytes", n),
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => {
                            tracing::error!("TLS write failed during handshake: {}", e);
                            return Err(e).context("TLS write failed during handshake");
                        }
                    }
                }

                // Read any pending data
                if self.conn.wants_read() {
                    match self.conn.read_tls(&mut self.stream) {
                        Ok(n) => tracing::debug!("TLS handshake: read {} bytes", n),
                        Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                        Err(e) => {
                            tracing::error!("TLS read failed during handshake: {}", e);
                            return Err(e).context("TLS read failed during handshake");
                        }
                    }
                    
                    if let Err(e) = self.conn.process_new_packets() {
                        tracing::error!("TLS process_new_packets failed: {}", e);
                        return Err(anyhow::anyhow!("TLS error: {}", e));
                    }
                }
            }
            
            Ok(())
        }

        pub fn get_ref(&self) -> &TcpStream {
            &self.stream
        }
        
        /// Extract the underlying TcpStream, consuming the TLS session.
        /// Use this after protocol handshake when switching to raw TCP (e.g., SoftEther data links).
        pub fn into_tcp_stream(self) -> TcpStream {
            self.stream
        }

        pub fn peer_certificate_der(&self) -> Result<Option<Vec<u8>>> {
            if let Some(certs) = self.conn.peer_certificates() {
                if let Some(cert) = certs.first() {
                    return Ok(Some(cert.0.clone()));
                }
            }
            Ok(None)
        }

        pub fn backend_name() -> &'static str {
            "rustls"
        }
    }

    impl Read for TlsStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            // Read decrypted application data
            loop {
                // Try to read from rustls buffer first
                match self.conn.reader().read(buf) {
                    Ok(0) => {
                        // No data available, need to read more TLS records
                        if self.conn.wants_read() {
                            match self.conn.read_tls(&mut self.stream) {
                                Ok(0) => return Ok(0), // EOF
                                Ok(_) => {
                                    self.conn.process_new_packets()
                                        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
                                    // Try reading again
                                    continue;
                                }
                                Err(e) => return Err(e),
                            }
                        } else {
                            return Ok(0);
                        }
                    }
                    Ok(n) => return Ok(n),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        // Need more data
                        if self.conn.wants_read() {
                            match self.conn.read_tls(&mut self.stream) {
                                Ok(0) => return Ok(0),
                                Ok(_) => {
                                    self.conn.process_new_packets()
                                        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
                                    continue;
                                }
                                Err(e) => return Err(e),
                            }
                        } else {
                            return Err(e);
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    impl Write for TlsStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            // Write plaintext data to rustls
            let len = self.conn.writer().write(buf)?;
            
            // Flush TLS records to TCP stream
            while self.conn.wants_write() {
                match self.conn.write_tls(&mut self.stream) {
                    Ok(_) => {},
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
            
            Ok(len)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.conn.writer().flush()?;
            
            // Flush all pending TLS data
            while self.conn.wants_write() {
                self.conn.write_tls(&mut self.stream)?;
            }
            
            self.stream.flush()
        }
    }

    // Dangerous: Accept all certificates
    struct NoVerifier;

    impl rustls::client::ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}

// Re-export the selected implementation
#[cfg(feature = "use-native-tls")]
pub use native_impl::TlsStream;

#[cfg(feature = "use-rustls")]
pub use rustls_impl::TlsStream;

// Compile-time check to ensure exactly one TLS backend is selected
#[cfg(all(feature = "use-native-tls", feature = "use-rustls"))]
compile_error!("Cannot enable both use-native-tls and use-rustls features simultaneously");

#[cfg(not(any(feature = "use-native-tls", feature = "use-rustls")))]
compile_error!("Must enable either use-native-tls or use-rustls feature");
