//! Network communication handling for SoftEther VPN client

use anyhow::{Context, Result};
use base64::prelude::*;
use cedar::WATERMARK;
use tracing::{debug, info, warn};
use mayaqua::{HttpRequest, HttpResponse, Pack};
use native_tls::{TlsConnector, TlsStream};
use pencore::Pencore;
use rand::RngCore;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Once;
use std::time::Duration;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Secure TLS connection wrapper
pub struct SecureConnection {
    stream: TlsStream<TcpStream>,
    server_version: u32,
    server_build: u32,
    server_random: Option<[u8; 20]>,
    host: String,
    port: u16,
}

impl SecureConnection {
    /// Establish a new TLS connection to the server
    pub fn connect(
        host: &str,
        port: u16,
        insecure_skip_verify: bool,
        timeout: Duration,
        sni_override: Option<&str>,
    ) -> Result<Self> {
        if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
            info!(
                "[INFO] connect_attempt host={} port={} proto=SoftEther",
                host, port
            );
        } else {
            debug!(
                "connect_attempt host={} port={} proto=SoftEther",
                host, port
            );
        }

        // Resolve hostname to socket address
        let addr = format!("{}:{}", host, port)
            .to_socket_addrs()
            .context("Failed to resolve hostname")?
            .next()
            .context("No valid address found")?;

        debug!("Resolved to address: {}", addr);

        // Establish TCP connection with timeout
        let tcp_stream =
            connect_with_timeout(addr, timeout).context("Failed to establish TCP connection")?;

        // Configure TLS connector
        let mut tls_builder = TlsConnector::builder();
        if insecure_skip_verify {
            static TLS_INSECURE_WARN_ONCE: Once = Once::new();
            TLS_INSECURE_WARN_ONCE
                .call_once(|| warn!("TLS certificate verification disabled (insecure)"));
            tls_builder.danger_accept_invalid_certs(true);
            tls_builder.danger_accept_invalid_hostnames(true);
        }

        let tls_connector = tls_builder
            .build()
            .context("Failed to build TLS connector")?;

        // Establish TLS connection
        debug!("Establishing TLS handshake");
        let sni_host = sni_override.unwrap_or(host);
        let tls_stream = tls_connector
            .connect(sni_host, tcp_stream)
            .context("TLS handshake failed")?;

        if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
            info!(
                "[INFO] link_established host={} port={} transport=tcp",
                host, port
            );
        } else {
            debug!("link_established host={} port={} transport=tcp", host, port);
        }
        if sni_override.is_some() {
            debug!("TLS SNI set to '{}' (original host '{}')", sni_host, host);
        }
        // Log local address (ip:port) of the TCP socket for visibility
        if let Ok(sockaddr) = tls_stream.get_ref().local_addr() {
            if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                info!("Local address {}", sockaddr);
            } else {
                debug!("Local address {}", sockaddr);
            }
        }
        // Try to dump server certificate subjects like third-party logs
        if let Ok(peer) = tls_stream.peer_certificate() {
            if let Some(cert) = peer {
                // native-tls exposes end-entity; no chain. Try to parse and log subject.
                if let Ok(der) = cert.to_der() {
                    if let Ok((_rem, x509)) = X509Certificate::from_der(&der) {
                        let cn = x509
                            .subject()
                            .iter_common_name()
                            .next()
                            .and_then(|cn| cn.as_str().ok())
                            .unwrap_or("");
                        if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
                            info!(
                                "Cert 0 {}",
                                if cn.is_empty() {
                                    x509.subject().to_string()
                                } else {
                                    cn.to_string()
                                }
                            );
                        } else {
                            debug!(
                                "Cert 0 {}",
                                if cn.is_empty() {
                                    x509.subject().to_string()
                                } else {
                                    cn.to_string()
                                }
                            );
                        }
                    }
                }
            }
        }

        Ok(Self {
            stream: tls_stream,
            server_version: 0,
            server_build: 0,
            server_random: None,
            host: host.to_string(),
            port,
        })
    }

    /// Get the local socket address of this TLS connection (client side)
    pub fn local_addr(&self) -> Option<SocketAddr> {
        // native_tls::TlsStream<TcpStream> exposes get_ref() to access the underlying TcpStream
        self.stream.get_ref().local_addr().ok()
    }

    /// Get the peer (server) socket address of this TLS connection
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.stream.get_ref().peer_addr().ok()
    }
    /// Send an HTTP request and receive the response
    pub fn send_request(&mut self, request: &HttpRequest) -> Result<HttpResponse> {
        debug!("Sending HTTP request: {} {}", request.method, request.path);

        // Send request
        let request_data = request.to_bytes();
        self.stream
            .write_all(&request_data)
            .context("Failed to send HTTP request")?;

        debug!("Sent {} bytes", request_data.len());

        // Read response
        let response =
            HttpResponse::from_stream(&mut self.stream).context("Failed to read HTTP response")?;

        debug!("Received HTTP response: {}", response.status_code);

        Ok(response)
    }

    /// Send a PACK and receive a PACK response
    pub fn send_pack(&mut self, pack: &Pack) -> Result<Pack> {
        // Serialize pack to binary
        let pack_data = pack.to_buffer().context("Failed to serialize pack")?;
        // Diagnostic: hex dump first bytes of outgoing pack
        if std::env::var("RUST_TRACE").is_ok() {
            let preview_len = pack_data.len().min(128);
            let mut hexs = String::new();
            for b in pack_data.iter().take(preview_len) {
                use std::fmt::Write;
                let _ = write!(&mut hexs, "{:02x}", b);
            }
            if pack_data.len() > preview_len {
                hexs.push_str("...");
            }
            debug!(
                "send_pack size={} hex={} fields={}",
                pack_data.len(),
                hexs,
                pack.debug_dump()
            );
        }

        // Create HTTP request with pack data
        let mut request = HttpRequest {
            method: "POST".to_string(),
            path: "/vpnsvc/vpn.cgi".to_string(),
            headers: vec![
                (
                    "Content-Type".to_string(),
                    "application/octet-stream".to_string(),
                ),
                ("Content-Length".to_string(), pack_data.len().to_string()),
            ],
            body: pack_data,
        };
    // Use persistent connections; omit Keep-Alive 'max' to avoid forced closures
    request.add_header("Connection".to_string(), "keep-alive".to_string());
        // Add Host header for HTTP/1.1 compliance
        request.add_header("Host".to_string(), format!("{}:{}", self.host, self.port));

        // Send request and get response
        let response = self.send_request(&request)?;

        if response.status_code != 200 {
            anyhow::bail!("HTTP error: {}", response.status_code);
        }

        // Parse response body as pack
        let response_pack = match Pack::from_buffer(&response.body) {
            Ok(p) => p,
            Err(e) => {
                // Dump raw body hex preview for diagnostics
                let preview_len = response.body.len().min(256);
                let mut hexs = String::new();
                for b in response.body.iter().take(preview_len) {
                    use std::fmt::Write;
                    let _ = write!(&mut hexs, "{:02x}", b);
                }
                if response.body.len() > preview_len {
                    hexs.push_str("...");
                }
                debug!(
                    "PACK_PARSE_FAIL size={} preview_hex={} err={}",
                    response.body.len(),
                    hexs,
                    e
                );
                return Err(e).context("Failed to parse response pack");
            }
        };
        debug!("recv_pack fields: {}", response_pack.debug_dump());

        Ok(response_pack)
    }

    /// Perform the initial handshake: upload watermark (signature image) and parse the server 'hello' PACK
    /// The SoftEther server responds to the connect.cgi POST directly with the hello pack, so we must
    /// parse that response body instead of sending an extra 'signature' method pack (which caused ERR_PROTOCOL_ERROR=4).
    pub fn initial_hello(&mut self) -> Result<Pack> {
        debug!("Starting initial handshake (watermark + hello)");

        // Random padding up to 2000 bytes (Go reference client behavior)
        const HTTP_PACK_RAND_SIZE_MAX: usize = 1000;
        let mut rng = rand::rng();
        let rand_raw = rng.next_u32();
        let rand_size = (rand_raw as usize) % (HTTP_PACK_RAND_SIZE_MAX * 2);
        let mut body = Vec::with_capacity(WATERMARK.len() + rand_size);
        body.extend_from_slice(WATERMARK);
        if rand_size > 0 {
            let mut pad = vec![0u8; rand_size];
            rng.fill_bytes(&mut pad);
            body.extend_from_slice(&pad);
        }

        let mut req = HttpRequest::new("POST".to_string(), "/vpnsvc/connect.cgi".to_string());
        req.add_header("Content-Type".to_string(), "image/jpeg".to_string());
    // Persistent connection across watermark and auth
    req.add_header("Connection".to_string(), "keep-alive".to_string());
        req.add_header("Host".to_string(), format!("{}:{}", self.host, self.port));
        req.set_body(body);
        let resp = self.send_request(&req)?;
        if resp.status_code != 200 {
            anyhow::bail!("Watermark upload failed HTTP status {}", resp.status_code);
        }
        debug!("Watermark uploaded ({} bytes incl pad)", req.body.len());

        // Parse the response body as hello pack
        let hello_pack = Pack::from_buffer(&resp.body)
            .context("Failed to parse hello pack from watermark response")?;
        debug!("hello_pack fields: {}", hello_pack.debug_dump());

        // Extract version/build/random using field names used by legacy implementations
        if let Ok(ver) = hello_pack
            .get_int("version")
            .or_else(|_| hello_pack.get_int("server_ver"))
        {
            self.server_version = ver;
        }
        if let Ok(build) = hello_pack
            .get_int("build")
            .or_else(|_| hello_pack.get_int("server_build"))
        {
            self.server_build = build;
        }
        if let Ok(data) = hello_pack
            .get_data("random")
            .or_else(|_| hello_pack.get_data("server_random"))
        {
            if data.len() == 20 {
                let mut r = [0u8; 20];
                r.copy_from_slice(data);
                self.server_random = Some(r);
                debug!("Captured server random from hello pack");
            }
        }

        if std::env::var("RUST_3RD_LOG").ok().as_deref() == Some("1") {
            info!(
                "Initial hello received (ver={} build={})",
                self.server_version, self.server_build
            );
        } else {
            debug!(
                "Initial hello received (ver={} build={})",
                self.server_version, self.server_build
            );
        }
        Ok(hello_pack)
    }

    // (legacy upload_watermark removed; incorporated into initial_hello)

    /// Download server hello
    pub fn download_hello(&mut self) -> Result<Pack> {
        debug!("Downloading server hello");

        let mut pack = Pack::new();
        pack.add_str("method", "hello")?;

        let response = self.send_pack(&pack)?;

        // Extract server version information
        if let Ok(ver) = response.get_int("server_ver") {
            self.server_version = ver;
        }
        if let Ok(build) = response.get_int("server_build") {
            self.server_build = build;
        }

        if self.server_version > 0 && self.server_build > 0 {
            info!(
                "Server version: {}.{}",
                self.server_version as f64 / 100.0,
                self.server_build
            );
        }

        // Attempt to capture server random (20 bytes). Various field name possibilities.
        // Common canonical name inferred from legacy client: "server_random".
        if let Ok(data) = response.get_data("server_random") {
            if data.len() == 20 {
                let mut r = [0u8; 20];
                r.copy_from_slice(data);
                self.server_random = Some(r);
                debug!("Captured server_random from hello pack");
            }
        } else if let Ok(data) = response.get_data("random") {
            // fallback heuristic
            if data.len() == 20 {
                let mut r = [0u8; 20];
                r.copy_from_slice(data);
                self.server_random = Some(r);
                debug!("Captured server random from 'random' field (heuristic)");
            }
        }

        Ok(response)
    }

    /// Upload authentication information
    pub fn upload_auth(&mut self, auth_pack: Pack) -> Result<Pack> {
        debug!("Uploading authentication");

        let response = self.send_pack(&auth_pack)?;
        debug!("welcome_pack fields: {}", response.debug_dump());

        // Check for authentication errors
        if let Ok(error_code) = response.get_int("error") {
            if error_code != 0 {
                anyhow::bail!("Authentication failed: error code {}", error_code);
            }
        }

        info!("Authentication successful");
        Ok(response)
    }

    /// Get server version
    pub fn server_version(&self) -> (u32, u32) {
        (self.server_version, self.server_build)
    }

    /// Get server random (if provided in hello)
    pub fn server_random(&self) -> Option<[u8; 20]> {
        self.server_random
    }

    /// Send a lightweight keep-alive PACK. Include both 'keep_alive' and 'noop' plus a tick64.
    pub fn send_noop(&mut self) -> Result<()> {
        let mut pack = Pack::new();
        let _ = pack.add_int("keep_alive", 1);
        let _ = pack.add_int("noop", 1);
        let _ = pack.add_int64("tick64", mayaqua::get_tick64());
        if std::env::var("RUST_TRACE").is_ok() {
            debug!("sending keep-alive noop pack");
        }
        let response = self.send_pack(&pack)?;
        if std::env::var("RUST_TRACE").is_ok() {
            debug!("noop response fields: {}", response.debug_dump());
        }
        Ok(())
    }

    /// Adjust underlying TCP socket timeouts. Pass None to disable the timeout.
    pub fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> Result<()> {
        // native_tls::TlsStream<TcpStream> allows access to the inner TcpStream via get_ref()
        let tcp = self.stream.get_ref();
        tcp.set_read_timeout(read)
            .context("Failed to set read timeout")?;
        tcp.set_write_timeout(write)
            .context("Failed to set write timeout")?;
        Ok(())
    }

    /// Read raw bytes from the connection
    pub fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.stream
            .read(buffer)
            .context("Failed to read from connection")
    }

    /// Write raw bytes to the connection
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        self.stream
            .write(data)
            .context("Failed to write to connection")
    }

    /// Close the connection
    pub fn close(self) -> Result<()> {
        // TLS stream will be closed when dropped
        debug!("Connection closed");
        Ok(())
    }

    /// Extract the underlying TLS stream; this consumes the SecureConnection.
    /// Intended for future data-plane integration to hand off the bonded socket.
    pub fn into_tls_stream(self) -> TlsStream<TcpStream> {
        self.stream
    }

    /// Parse and validate the `pencore` field from server responses
    pub fn handle_pencore(&self, data: &[u8]) -> Result<()> {
        let pencore = Pencore::parse(data).context("Failed to parse pencore")?;
        pencore.validate().context("Pencore validation failed")?;
        debug!("Pencore successfully parsed and validated: {:?}", pencore);
        Ok(())
    }
}

/// Connect to a socket address with timeout
fn connect_with_timeout(addr: SocketAddr, timeout: Duration) -> Result<TcpStream> {
    let stream = TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("Failed to connect to {}", addr))?;

    // Set additional socket options
    stream
        .set_read_timeout(Some(timeout))
        .context("Failed to set read timeout")?;

    stream
        .set_write_timeout(Some(timeout))
        .context("Failed to set write timeout")?;

    Ok(stream)
}

/// HTTP proxy connection handler
pub struct ProxyConnection {
    #[allow(dead_code)]
    stream: TcpStream,
}

impl ProxyConnection {
    /// Connect through an HTTP proxy
    pub fn connect_through_proxy(
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        proxy_username: Option<&str>,
        proxy_password: Option<&str>,
        timeout: Duration,
    ) -> Result<TcpStream> {
        info!("Connecting through proxy {}:{}", proxy_host, proxy_port);

        // Connect to proxy
        let proxy_addr = format!("{}:{}", proxy_host, proxy_port)
            .to_socket_addrs()
            .context("Failed to resolve proxy hostname")?
            .next()
            .context("No valid proxy address found")?;

        let mut stream =
            connect_with_timeout(proxy_addr, timeout).context("Failed to connect to proxy")?;

        // Send CONNECT request
        let connect_request = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
            target_host, target_port, target_host, target_port
        );

        let mut request = connect_request;

        // Add proxy authentication if provided
        if let (Some(username), Some(password)) = (proxy_username, proxy_password) {
            let auth_string =
                base64::prelude::BASE64_STANDARD.encode(format!("{}:{}", username, password));
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", auth_string));
        }

        request.push_str("\r\n");

        // Send request
        stream
            .write_all(request.as_bytes())
            .context("Failed to send CONNECT request to proxy")?;

        // Read response
        let mut response = Vec::new();
        let mut buffer = [0u8; 1024];

        loop {
            let bytes_read = stream
                .read(&mut buffer)
                .context("Failed to read proxy response")?;

            if bytes_read == 0 {
                anyhow::bail!("Proxy closed connection unexpectedly");
            }

            response.extend_from_slice(&buffer[..bytes_read]);

            // Check if we have the complete response headers
            if response.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        // Parse response
        let response_str = String::from_utf8_lossy(&response);
        let first_line = response_str
            .lines()
            .next()
            .context("Empty proxy response")?;

        if !first_line.contains("200") {
            anyhow::bail!("Proxy connection failed: {}", first_line);
        }

        info!(
            "Proxy tunnel established to {}:{}",
            target_host, target_port
        );
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_connect_with_timeout() {
        // Test with a non-routable address to ensure timeout works
        let addr = "192.0.2.1:80".parse().unwrap();
        let timeout = Duration::from_millis(100);

        let result = connect_with_timeout(addr, timeout);
        assert!(result.is_err());
    }

    #[test]
    fn test_pack_serialization() -> Result<()> {
        let mut pack = Pack::new();
        pack.add_str("method", "test")?;
        pack.add_int("value", 42)?;

        let data = pack.to_buffer()?;
        let parsed = Pack::from_buffer(&data)?;

        assert_eq!(parsed.get_str("method")?, "test");
        assert_eq!(parsed.get_int("value")?, 42);

        Ok(())
    }
}
