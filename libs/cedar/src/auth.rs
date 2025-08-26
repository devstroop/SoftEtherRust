use crate::AuthType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialKind {
    PasswordHash(Vec<u8>),
    Certificate { der: Vec<u8>, key_der: Vec<u8> },
    Ticket(Vec<u8>),
    Anonymous,
}

#[derive(Debug, Clone)]
pub struct CredentialSet {
    pub username: String,
    pub hub: String,
    pub kind: CredentialKind,
}

impl CredentialSet {
    pub fn auth_type(&self) -> AuthType {
        match self.kind {
            CredentialKind::Anonymous => AuthType::Anonymous,
            CredentialKind::PasswordHash(_) => AuthType::Password,
            CredentialKind::Certificate { .. } => AuthType::Certificate,
            CredentialKind::Ticket(_) => AuthType::Ticket,
        }
    }
}
