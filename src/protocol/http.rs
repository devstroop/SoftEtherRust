//! HTTP codec for SoftEther handshake.
//!
//! SoftEther uses HTTP/1.1 for the initial handshake before switching
//! to the tunnel protocol.

use crate::error::Result;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;

/// HTTP response from server.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status_code: u16,
    /// Response headers.
    pub headers: HashMap<String, String>,
    /// Response body.
    pub body: Bytes,
}

impl HttpResponse {
    /// Check if the response indicates success (2xx).
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    /// Get a header value (case-insensitive).
    pub fn get_header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Get Content-Length header.
    pub fn content_length(&self) -> Option<usize> {
        self.get_header("content-length")
            .and_then(|v| v.parse().ok())
    }
}

/// HTTP request builder.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Request headers.
    pub headers: HashMap<String, String>,
    /// Request body.
    pub body: Bytes,
}

impl HttpRequest {
    /// Create a new POST request.
    pub fn post(path: &str) -> Self {
        Self {
            method: "POST".to_string(),
            path: path.to_string(),
            headers: HashMap::new(),
            body: Bytes::new(),
        }
    }

    /// Set a header.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Set the request body.
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Build the HTTP request bytes.
    pub fn build(&self, host: &str) -> Bytes {
        use std::fmt::Write;

        let mut request = String::with_capacity(512);

        // Request line
        writeln!(request, "{} {} HTTP/1.1\r", self.method, self.path).unwrap();

        // Host header
        writeln!(request, "Host: {}\r", host).unwrap();

        // Content-Type if present
        if let Some(ct) = self.headers.get("Content-Type") {
            writeln!(request, "Content-Type: {}\r", ct).unwrap();
        }

        // Connection header
        let connection = self
            .headers
            .get("Connection")
            .map(|s| s.as_str())
            .unwrap_or("Keep-Alive");
        writeln!(request, "Connection: {}\r", connection).unwrap();

        // Other headers
        for (key, value) in &self.headers {
            if key != "Content-Type" && key != "Connection" && key != "Content-Length" {
                writeln!(request, "{}: {}\r", key, value).unwrap();
            }
        }

        // Content-Length
        writeln!(request, "Content-Length: {}\r", self.body.len()).unwrap();

        // End of headers (blank line)
        write!(request, "\r\n").unwrap();

        // Combine headers and body
        let mut buf = BytesMut::with_capacity(request.len() + self.body.len());
        buf.extend_from_slice(request.as_bytes());
        buf.extend_from_slice(&self.body);

        buf.freeze()
    }
}

/// HTTP response codec (streaming parser).
#[derive(Debug, Default)]
pub struct HttpCodec {
    state: CodecState,
    buffer: BytesMut,
    status_code: u16,
    headers: HashMap<String, String>,
}

#[derive(Debug, Default)]
enum CodecState {
    #[default]
    StatusLine,
    Headers,
    Body {
        content_length: usize,
    },
    Complete,
}

impl HttpCodec {
    /// Create a new HTTP codec.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset the codec for a new response.
    pub fn reset(&mut self) {
        self.state = CodecState::StatusLine;
        self.buffer.clear();
        self.status_code = 0;
        self.headers.clear();
    }

    /// Feed data into the codec.
    ///
    /// Returns `Some(HttpResponse)` when a complete response is parsed.
    pub fn feed(&mut self, data: &[u8]) -> Result<Option<HttpResponse>> {
        self.buffer.extend_from_slice(data);

        loop {
            match &self.state {
                CodecState::StatusLine => {
                    if let Some(pos) = self.find_crlf() {
                        let line = self.take_line(pos);
                        self.parse_status_line(&line)?;
                        self.state = CodecState::Headers;
                    } else {
                        return Ok(None);
                    }
                }
                CodecState::Headers => {
                    if let Some(pos) = self.find_crlf() {
                        if pos == 0 {
                            // Empty line - end of headers
                            self.buffer.advance(2); // Skip \r\n

                            let content_length = self
                                .headers
                                .get("content-length")
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(0);

                            self.state = CodecState::Body { content_length };
                        } else {
                            let line = self.take_line(pos);
                            self.parse_header(&line);
                        }
                    } else {
                        return Ok(None);
                    }
                }
                CodecState::Body { content_length } => {
                    let content_length = *content_length;
                    if self.buffer.len() >= content_length {
                        let body = self.buffer.split_to(content_length).freeze();
                        self.state = CodecState::Complete;

                        let response = HttpResponse {
                            status_code: self.status_code,
                            headers: std::mem::take(&mut self.headers),
                            body,
                        };

                        // Don't reset - keep remaining bytes in buffer
                        // Caller should use take_remaining() if needed
                        return Ok(Some(response));
                    } else {
                        return Ok(None);
                    }
                }
                CodecState::Complete => {
                    return Ok(None);
                }
            }
        }
    }

    /// Find position of \r\n in buffer.
    fn find_crlf(&self) -> Option<usize> {
        self.buffer.windows(2).position(|w| w == b"\r\n")
    }

    /// Take a line from the buffer (excluding \r\n).
    fn take_line(&mut self, pos: usize) -> String {
        let line = String::from_utf8_lossy(&self.buffer[..pos]).into_owned();
        self.buffer.advance(pos + 2); // Skip line + \r\n
        line
    }

    /// Parse the status line.
    fn parse_status_line(&mut self, line: &str) -> Result<()> {
        // "HTTP/1.1 200 OK"
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            self.status_code = parts[1].parse().unwrap_or(0);
        }
        Ok(())
    }

    /// Parse a header line.
    fn parse_header(&mut self, line: &str) {
        if let Some(pos) = line.find(':') {
            let key = line[..pos].trim().to_lowercase();
            let value = line[pos + 1..].trim().to_string();
            self.headers.insert(key, value);
        }
    }

    /// Take any remaining bytes from the buffer after parsing.
    /// This is useful when the server sends additional data after the HTTP response
    /// (e.g., tunnel data right after authentication).
    pub fn take_remaining(&mut self) -> Vec<u8> {
        let remaining = self.buffer.to_vec();
        self.buffer.clear();
        remaining
    }

    /// Check if there are remaining bytes in the buffer.
    pub fn has_remaining(&self) -> bool {
        !self.buffer.is_empty()
    }

    /// Get the number of remaining bytes.
    pub fn remaining_len(&self) -> usize {
        self.buffer.len()
    }
}

use bytes::Buf;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_request_build() {
        let request = HttpRequest::post("/test")
            .header("Content-Type", "text/plain")
            .body("hello");

        let bytes = request.build("example.com");
        let text = String::from_utf8_lossy(&bytes);

        assert!(text.contains("POST /test HTTP/1.1"));
        assert!(text.contains("Host: example.com"));
        assert!(text.contains("Content-Length: 5"));
        assert!(text.contains("hello"));
    }

    #[test]
    fn test_http_codec_parse() {
        let mut codec = HttpCodec::new();

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let result = codec.feed(response).unwrap();

        assert!(result.is_some());
        let response = result.unwrap();
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body.as_ref(), b"hello");
    }

    #[test]
    fn test_http_codec_streaming() {
        let mut codec = HttpCodec::new();

        // Feed partial data
        assert!(codec.feed(b"HTTP/1.1 200 OK\r\n").unwrap().is_none());
        assert!(codec.feed(b"Content-Length: 5\r\n").unwrap().is_none());
        assert!(codec.feed(b"\r\n").unwrap().is_none());
        assert!(codec.feed(b"hel").unwrap().is_none());

        // Complete response
        let result = codec.feed(b"lo").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().body.as_ref(), b"hello");
    }
}
