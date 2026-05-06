use std::collections::HashSet;
use std::path::Path;
use anyhow::Result;
use crate::util::{hex_to_bytes32, stream_sha256};

pub enum HashCheckResult {
    Blocked { hash: String },
    Allowed  { hash: String },
    Unknown  { hash: String },
}

pub struct HashChecker {
    blocklist: HashSet<[u8; 32]>,
    allowlist: HashSet<[u8; 32]>,
}

impl HashChecker {
    pub fn new(blocklist: HashSet<[u8; 32]>, allowlist: HashSet<[u8; 32]>) -> Self {
        Self { blocklist, allowlist }
    }

    pub fn empty() -> Self {
        Self { blocklist: HashSet::new(), allowlist: HashSet::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.blocklist.is_empty() && self.allowlist.is_empty()
    }

    /// Stream-hash `path` and check it against allow/blocklists.
    /// Allowlist takes priority — if allowed, returns `Allowed` regardless of blocklist.
    pub async fn check_file(&self, path: &Path) -> Result<HashCheckResult> {
        let hash_hex   = stream_sha256(path).await?;
        let hash_bytes = hex_to_bytes32(&hash_hex)?;

        let result = if self.allowlist.contains(&hash_bytes) {
            HashCheckResult::Allowed { hash: hash_hex }
        } else if self.blocklist.contains(&hash_bytes) {
            HashCheckResult::Blocked { hash: hash_hex }
        } else {
            HashCheckResult::Unknown { hash: hash_hex }
        };
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn sha256_of(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(data).into()
    }

    #[tokio::test]
    async fn detects_blocked_file() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"malware payload").unwrap();
        let hash_bytes = sha256_of(b"malware payload");
        let checker = HashChecker::new(
            std::collections::HashSet::from([hash_bytes]),
            std::collections::HashSet::new(),
        );
        assert!(matches!(checker.check_file(f.path()).await.unwrap(), HashCheckResult::Blocked { .. }));
    }

    #[tokio::test]
    async fn allowlist_wins_over_blocklist() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"legit file").unwrap();
        let hash_bytes = sha256_of(b"legit file");
        let checker = HashChecker::new(
            std::collections::HashSet::from([hash_bytes]),  // also in blocklist
            std::collections::HashSet::from([hash_bytes]),  // but also allowlisted
        );
        assert!(matches!(checker.check_file(f.path()).await.unwrap(), HashCheckResult::Allowed { .. }));
    }

    #[tokio::test]
    async fn unknown_for_unrecognized_file() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"totally clean").unwrap();
        let checker = HashChecker::empty();
        assert!(matches!(checker.check_file(f.path()).await.unwrap(), HashCheckResult::Unknown { .. }));
    }
}
