use crate::{ConfigError, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;

pub fn load_json<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T> {
    let data = mayaqua::fs::read_all(path).map_err(|e| ConfigError::Io(e.to_string()))?;
    serde_json::from_slice(&data).map_err(|e| ConfigError::Json(e.to_string()))
}

pub fn save_json<T: Serialize, P: AsRef<Path>>(path: P, value: &T) -> Result<()> {
    let data = serde_json::to_vec_pretty(value).map_err(|e| ConfigError::Json(e.to_string()))?;
    mayaqua::fs::write_all_atomic(path, &data).map_err(|e| ConfigError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::NamedTempFile;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Demo {
        a: u32,
        b: String,
    }

    #[test]
    fn roundtrip() {
        let tmp = NamedTempFile::new().unwrap();
        let p = tmp.path();
        let v = Demo {
            a: 1,
            b: "x".into(),
        };
        save_json(p, &v).unwrap();
        let v2: Demo = load_json(p).unwrap();
        assert_eq!(v, v2);
    }
}
