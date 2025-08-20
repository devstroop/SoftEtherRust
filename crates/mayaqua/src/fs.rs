//! File I/O utilities: atomic write, safe read, and basic permissions.

use crate::error::{Error, Result};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Ensure a directory exists (create if missing)
pub fn ensure_dir<P: AsRef<Path>>(dir: P) -> Result<()> {
    fs::create_dir_all(&dir).map_err(|e| Error::IoError(e.to_string()))
}

/// Read entire file into memory
pub fn read_all<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let mut f = File::open(&path).map_err(|e| Error::IoError(e.to_string()))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .map_err(|e| Error::IoError(e.to_string()))?;
    Ok(buf)
}

/// Atomically write data to a file by writing to a temp file and renaming.
pub fn write_all_atomic<P: AsRef<Path>>(path: P, data: &[u8]) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }

    let mut tmp = PathBuf::from(path);
    tmp.set_extension("tmp");

    {
        let mut f = File::create(&tmp).map_err(|e| Error::IoError(e.to_string()))?;
        f.write_all(data)
            .map_err(|e| Error::IoError(e.to_string()))?;
        f.flush().map_err(|e| Error::IoError(e.to_string()))?;
    }

    fs::rename(tmp, path).map_err(|e| Error::IoError(e.to_string()))
}

/// Set file permissions to user read/write only (best-effort, Unix only)
pub fn set_user_rw_only<P: AsRef<Path>>(path: P) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(&path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(&path, perms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_atomic_write_and_read() {
        let dir = std::env::temp_dir().join("mayaqua_fs_test");
        let file = dir.join("config.bin");
        let data = b"hello world";
        write_all_atomic(&file, data).unwrap();
        set_user_rw_only(&file);
        let read = read_all(&file).unwrap();
        assert_eq!(read, data);
        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir_all(&dir);
    }
}
