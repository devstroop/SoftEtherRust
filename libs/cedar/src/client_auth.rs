//! Client authentication data structures matching C implementation

use crate::constants::AuthType;
use crate::{MAX_PASSWORD_LEN, MAX_USERNAME_LEN, SHA1_SIZE};
use mayaqua::{Error, Result};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Client authentication data (matches CLIENT_AUTH structure)
#[derive(Clone)]
pub struct ClientAuth {
    pub auth_type: AuthType,
    pub username: String,
    pub hashed_password: [u8; SHA1_SIZE], // SHA1 hash of password or ticket
    pub plain_password: String,           // Plaintext password (for some auth modes)
    pub client_cert: Option<Vec<u8>>,     // Client certificate (X.509 DER)
    pub client_key: Option<Vec<u8>>,      // Client private key
    pub secure_public_cert_name: String,  // Secure device cert name
    pub secure_private_key_name: String,  // Secure device key name
}

impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAuth")
            .field("auth_type", &self.auth_type)
            .field("username", &self.username)
            .field("hashed_password", &"<redacted>")
            .field("plain_password", &"<redacted>")
            .field(
                "client_cert",
                &self
                    .client_cert
                    .as_ref()
                    .map(|c| format!("{} bytes", c.len())),
            )
            .field(
                "client_key",
                &self
                    .client_key
                    .as_ref()
                    .map(|k| format!("{} bytes", k.len())),
            )
            .field("secure_public_cert_name", &self.secure_public_cert_name)
            .field("secure_private_key_name", &self.secure_private_key_name)
            .finish()
    }
}

impl Drop for ClientAuth {
    fn drop(&mut self) {
        // Zeroize sensitive fields on drop
        self.hashed_password.zeroize();
        self.plain_password.zeroize();
    }
}

impl ClientAuth {
    /// Create new anonymous authentication
    pub fn new_anonymous() -> Self {
        Self {
            auth_type: AuthType::Anonymous,
            username: String::new(),
            hashed_password: [0u8; SHA1_SIZE],
            plain_password: String::new(),
            client_cert: None,
            client_key: None,
            secure_public_cert_name: String::new(),
            secure_private_key_name: String::new(),
        }
    }

    /// Create new password authentication
    pub fn new_password(username: &str, password: &str) -> Result<Self> {
        if username.len() > MAX_USERNAME_LEN {
            return Err(Error::InvalidParameter);
        }
        if password.len() > MAX_PASSWORD_LEN {
            return Err(Error::InvalidParameter);
        }

        // Hash the password using SHA-0 with username (SoftEther format)
        let hashed_password = Self::hash_password_with_username(password, username);

        Ok(Self {
            auth_type: AuthType::Password,
            username: username.to_string(),
            hashed_password,
            plain_password: password.to_string(),
            client_cert: None,
            client_key: None,
            secure_public_cert_name: String::new(),
            secure_private_key_name: String::new(),
        })
    }

    /// Create new certificate authentication
    pub fn new_certificate(username: &str, cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<Self> {
        if username.len() > MAX_USERNAME_LEN {
            return Err(Error::InvalidParameter);
        }

        Ok(Self {
            auth_type: AuthType::Certificate,
            username: username.to_string(),
            hashed_password: [0u8; SHA1_SIZE],
            plain_password: String::new(),
            client_cert: Some(cert_der),
            client_key: Some(key_der),
            secure_public_cert_name: String::new(),
            secure_private_key_name: String::new(),
        })
    }

    /// Create new secure device authentication
    pub fn new_secure_device(username: &str, cert_name: &str, key_name: &str) -> Result<Self> {
        if username.len() > MAX_USERNAME_LEN {
            return Err(Error::InvalidParameter);
        }

        Ok(Self {
            auth_type: AuthType::SecureDevice,
            username: username.to_string(),
            hashed_password: [0u8; SHA1_SIZE],
            plain_password: String::new(),
            client_cert: None,
            client_key: None,
            secure_public_cert_name: cert_name.to_string(),
            secure_private_key_name: key_name.to_string(),
        })
    }

    /// Create new ticket authentication (cluster redirect reuse)
    pub fn new_ticket(username: &str, ticket: &[u8]) -> Result<Self> {
        if username.len() > MAX_USERNAME_LEN {
            return Err(Error::InvalidParameter);
        }
        if ticket.len() != SHA1_SIZE {
            // ticket expected 20 bytes like session key
            return Err(Error::InvalidParameter);
        }
        let mut ticket_bytes = [0u8; SHA1_SIZE];
        ticket_bytes.copy_from_slice(ticket);
        Ok(Self {
            auth_type: AuthType::Ticket,
            username: username.to_string(),
            hashed_password: ticket_bytes, // reuse hashed_password field to carry ticket
            plain_password: String::new(),
            client_cert: None,
            client_key: None,
            secure_public_cert_name: String::new(),
            secure_private_key_name: String::new(),
        })
    }

    /// Hash password using SoftEther method (SHA-0 of password + uppercase username)
    /// This matches the original SoftEther VPN implementation
    pub fn hash_password_with_username(password: &str, username: &str) -> [u8; SHA1_SIZE] {
        mayaqua::crypto::softether_password_hash(password, username)
    }

    /// Hash password using SoftEther method (SHA-0 of UTF-8 bytes only - legacy)
    /// NOTE: For proper SoftEther hashing, use hash_password_with_username instead
    fn hash_password(password: &str) -> [u8; SHA1_SIZE] {
        mayaqua::crypto::sha0(password.as_bytes())
    }

    /// Validate authentication data
    pub fn validate(&self) -> Result<()> {
        // Check username length
        if self.username.len() > MAX_USERNAME_LEN {
            return Err(Error::InvalidParameter);
        }

        match self.auth_type {
            AuthType::Anonymous => {
                // Anonymous auth is always valid
                Ok(())
            }
            AuthType::Password | AuthType::PlainPassword => {
                if self.username.is_empty() {
                    return Err(Error::InvalidParameter);
                }
                if self.plain_password.len() > MAX_PASSWORD_LEN {
                    return Err(Error::InvalidParameter);
                }
                Ok(())
            }
            AuthType::Certificate => {
                if self.username.is_empty() {
                    return Err(Error::InvalidParameter);
                }
                if self.client_cert.is_none() || self.client_key.is_none() {
                    return Err(Error::InvalidParameter);
                }
                Ok(())
            }
            AuthType::SecureDevice => {
                if self.username.is_empty() {
                    return Err(Error::InvalidParameter);
                }
                if self.secure_public_cert_name.is_empty()
                    || self.secure_private_key_name.is_empty()
                {
                    return Err(Error::InvalidParameter);
                }
                Ok(())
            }
            AuthType::Ticket => {
                if self.username.is_empty() {
                    return Err(Error::InvalidParameter);
                }
                // Ensure ticket material present (stored in hashed_password)
                if self
                    .hashed_password
                    .as_slice()
                    .ct_eq(&[0u8; SHA1_SIZE])
                    .into()
                {
                    return Err(Error::InvalidParameter);
                }
                Ok(())
            }
        }
    }

    /// Check if authentication has credentials
    pub fn has_credentials(&self) -> bool {
        match self.auth_type {
            AuthType::Anonymous => true,
            AuthType::Password | AuthType::PlainPassword => {
                !self.username.is_empty() && !self.plain_password.is_empty()
            }
            AuthType::Certificate => {
                !self.username.is_empty() && self.client_cert.is_some() && self.client_key.is_some()
            }
            AuthType::SecureDevice => {
                !self.username.is_empty()
                    && !self.secure_public_cert_name.is_empty()
                    && !self.secure_private_key_name.is_empty()
            }
            AuthType::Ticket => {
                // For now require only username; ticket material handled elsewhere
                !self.username.is_empty()
            }
        }
    }

    /// Get the authentication type as u32 for protocol
    pub fn get_auth_type_u32(&self) -> u32 {
        self.auth_type as u32
    }
}

impl Default for ClientAuth {
    fn default() -> Self {
        Self::new_anonymous()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymous_auth() {
        let auth = ClientAuth::new_anonymous();
        assert_eq!(auth.auth_type, AuthType::Anonymous);
        assert!(auth.has_credentials());
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_password_auth() {
        let auth = ClientAuth::new_password("user1", "password123").unwrap();
        assert_eq!(auth.auth_type, AuthType::Password);
        assert_eq!(auth.username, "user1");
        assert_eq!(auth.plain_password, "password123");
        assert!(auth.has_credentials());
        assert!(auth.validate().is_ok());

        // Check that password is hashed
        assert_ne!(auth.hashed_password, [0u8; SHA1_SIZE]);
    }

    #[test]
    fn test_certificate_auth() {
        let cert_data = vec![1, 2, 3, 4]; // Dummy cert data
        let key_data = vec![5, 6, 7, 8]; // Dummy key data

        let auth =
            ClientAuth::new_certificate("user1", cert_data.clone(), key_data.clone()).unwrap();
        assert_eq!(auth.auth_type, AuthType::Certificate);
        assert_eq!(auth.username, "user1");
        assert_eq!(auth.client_cert.as_ref().unwrap(), &cert_data);
        assert!(auth.has_credentials());
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_secure_device_auth() {
        let auth = ClientAuth::new_secure_device("user1", "cert_name", "key_name").unwrap();
        assert_eq!(auth.auth_type, AuthType::SecureDevice);
        assert_eq!(auth.username, "user1");
        assert_eq!(auth.secure_public_cert_name, "cert_name");
        assert_eq!(auth.secure_private_key_name, "key_name");
        assert!(auth.has_credentials());
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validation_errors() {
        // Test empty username for password auth
        let mut auth = ClientAuth::new_password("user1", "pass").unwrap();
        auth.username.clear();
        assert!(auth.validate().is_err());

        // Test missing certificate for cert auth
        let mut auth = ClientAuth::new_certificate("user1", vec![1, 2, 3], vec![4, 5, 6]).unwrap();
        auth.client_cert = None;
        assert!(auth.validate().is_err());
    }

    #[test]
    fn test_password_hashing() {
        let auth1 = ClientAuth::new_password("user", "password").unwrap();
        let auth2 = ClientAuth::new_password("user", "password").unwrap();

        // Same password should produce same hash
        assert_eq!(auth1.hashed_password, auth2.hashed_password);

        let auth3 = ClientAuth::new_password("user", "different").unwrap();
        // Different password should produce different hash
        assert_ne!(auth1.hashed_password, auth3.hashed_password);
    }
}
