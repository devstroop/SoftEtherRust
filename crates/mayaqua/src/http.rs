//! HTTP utilities for SoftEther VPN protocol communication

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};

/// HTTP request structure
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// HTTP response structure
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Create a new HTTP request
    pub fn new(method: String, path: String) -> Self {
        Self {
            method,
            path,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Add a header to the request
    pub fn add_header(&mut self, name: String, value: String) {
        self.headers.push((name, value));
    }

    /// Set the request body
    pub fn set_body(&mut self, body: Vec<u8>) {
        let body_len = body.len();
        self.body = body;
        self.add_header("Content-Length".to_string(), body_len.to_string());
    }

    /// Convert the request to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut request = format!("{} {} HTTP/1.1\r\n", self.method, self.path);

        // Add headers
        for (name, value) in &self.headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }

        // End headers
        request.push_str("\r\n");

        // Convert to bytes and append body
        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(&self.body);

        bytes
    }
}

impl HttpResponse {
    /// Parse an HTTP response from a stream
    pub fn from_stream<R: Read>(stream: &mut R) -> Result<Self> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();

        // Read status line
        reader
            .read_line(&mut line)
            .map_err(|e| Error::Network(format!("Failed to read status line: {e}")))?;

        let status_parts: Vec<&str> = line.split_whitespace().collect();
        if status_parts.len() < 2 {
            return Err(Error::Network("Invalid HTTP status line".to_string()));
        }

        let status_code = status_parts[1]
            .parse::<u16>()
            .map_err(|e| Error::Network(format!("Invalid status code: {e}")))?;

        // Read headers
        let mut headers = HashMap::new();
        let mut content_length = 0;

        loop {
            line.clear();
            reader
                .read_line(&mut line)
                .map_err(|e| Error::Network(format!("Failed to read header: {e}")))?;

            let line = line.trim();
            if line.is_empty() {
                break; // End of headers
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();

                if name == "content-length" {
                    content_length = value
                        .parse::<usize>()
                        .map_err(|e| Error::Network(format!("Invalid content-length: {e}")))?;
                }

                headers.insert(name, value);
            }
        }

        // Read body
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader
                .read_exact(&mut body)
                .map_err(|e| Error::Network(format!("Failed to read body: {e}")))?;
        }

        Ok(Self {
            status_code,
            headers,
            body,
        })
    }

    /// Get a header value
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_lowercase())
    }

    /// Check if the response is successful (2xx status code)
    pub fn is_success(&self) -> bool {
        self.status_code >= 200 && self.status_code < 300
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_http_request_creation() {
        let mut request = HttpRequest::new("GET".to_string(), "/test".to_string());
        request.add_header("Host".to_string(), "example.com".to_string());
        request.set_body(b"test body".to_vec());

        let bytes = request.to_bytes();
        let request_str = String::from_utf8_lossy(&bytes);

        assert!(request_str.contains("GET /test HTTP/1.1"));
        assert!(request_str.contains("Host: example.com"));
        assert!(request_str.contains("Content-Length: 9"));
        assert!(request_str.ends_with("test body"));
    }

    #[test]
    fn test_http_response_parsing() -> Result<()> {
        let response_data =
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nContent-Type: text/plain\r\n\r\nHello World";
        let mut cursor = Cursor::new(response_data);

        let response = HttpResponse::from_stream(&mut cursor)?;

        assert_eq!(response.status_code, 200);
        assert_eq!(
            response.get_header("content-length"),
            Some(&"11".to_string())
        );
        assert_eq!(
            response.get_header("content-type"),
            Some(&"text/plain".to_string())
        );
        assert_eq!(response.body, b"Hello World");
        assert!(response.is_success());

        Ok(())
    }

    #[test]
    fn test_http_response_no_body() -> Result<()> {
        let response_data = b"HTTP/1.1 204 No Content\r\n\r\n";
        let mut cursor = Cursor::new(response_data);

        let response = HttpResponse::from_stream(&mut cursor)?;

        assert_eq!(response.status_code, 204);
        assert!(response.body.is_empty());
        assert!(response.is_success());

        Ok(())
    }
}
