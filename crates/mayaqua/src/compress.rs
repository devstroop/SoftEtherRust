//! Compression helpers (zlib/deflate) used by SoftEther PACK/dataplane.
//! Minimal, stateless API now; can be swapped to stream-based later.

use crate::error::{Error, Result};

pub fn compress_deflate(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data)
        .map_err(|e| Error::IoError(e.to_string()))?;
    enc.finish().map_err(|e| Error::IoError(e.to_string()))
}

pub fn decompress_deflate(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| Error::IoError(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = b"hello hello hello";
        let c = compress_deflate(data).unwrap();
        let d = decompress_deflate(&c).unwrap();
        assert_eq!(d, data);
    }
}
