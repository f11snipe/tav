use std::path::Path;
use anyhow::Result;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

const CHUNK: usize = 65536; // 64 KiB

/// Stream-hash a file without loading it fully into RAM.
pub async fn stream_sha256(path: &Path) -> Result<String> {
    let mut file   = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf    = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Synchronous variant for use inside `tokio::task::spawn_blocking`.
pub fn stream_sha256_sync(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file   = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf    = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Parse a 64-char hex string into a fixed 32-byte array.
pub fn hex_to_bytes32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s)?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("expected 32-byte SHA-256, got {} bytes", s.len() / 2))
}
