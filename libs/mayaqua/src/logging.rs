//! Logging utilities including redaction helpers for sensitive fields.
//!
//! Provides redact_pack for masking sensitive Pack elements when tracing.

use crate::Pack;

/// List of element names (case-insensitive) that should be redacted in logs.
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "secure_password",
    "plain_password",
    "ticket",
    "cert",
    "key",
    "private_key",
];

/// Produce a redacted debug string of a Pack. Names preserved, sensitive values replaced.
pub fn redact_pack(pack: &Pack) -> String {
    let mut parts = Vec::new();
    for el in &pack.elements {
        let name_l = el.name.to_lowercase();
        let sensitive = SENSITIVE_KEYS.iter().any(|k| name_l.contains(k));
        if sensitive {
            parts.push(format!("{}=<redacted>", el.name));
        } else {
            // Show small preview for non-sensitive data types
            if el.values.is_empty() {
                parts.push(format!("{}=<empty>", el.name));
            } else {
                // Limit preview to first value
                let v = &el.values[0];
                let preview = if !v.str_value.is_empty() {
                    v.str_value.clone()
                } else if !v.data.is_empty() {
                    let hex_len = v.data.len().min(8);
                    let mut s = String::with_capacity(2 * hex_len + 4);
                    for b in &v.data[..hex_len] {
                        use std::fmt::Write;
                        let _ = write!(&mut s, "{b:02x}");
                    }
                    if v.data.len() > 8 {
                        s.push_str("...");
                    }
                    format!("0x{s}")
                } else {
                    v.int_value.to_string()
                };
                parts.push(format!("{}={}", el.name, preview));
            }
        }
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Pack, Result};

    #[test]
    fn test_redact_pack() -> Result<()> {
        let mut p = Pack::new();
        p.add_str("username", "alice")?;
        p.add_data("password", vec![1, 2, 3, 4])?;
        p.add_int("qos", 1)?;
        let out = redact_pack(&p);
        assert!(out.contains("username=alice"));
        assert!(out.contains("password=<redacted>"));
        Ok(())
    }
}
