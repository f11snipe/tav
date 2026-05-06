use std::collections::HashSet;
use std::path::Path;
use anyhow::{Context, Result};
use rusqlite::{params, Connection};

pub struct IntelDb {
    conn: Connection,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS hash_intel (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256    TEXT NOT NULL UNIQUE,
    list_type TEXT NOT NULL CHECK(list_type IN ('blocklist','allowlist')),
    note      TEXT,
    added_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_hash ON hash_intel(sha256, list_type);

CREATE TABLE IF NOT EXISTS domain_intel (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    domain    TEXT NOT NULL UNIQUE,
    list_type TEXT NOT NULL CHECK(list_type IN ('blocklist','allowlist')),
    note      TEXT,
    added_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_domain ON domain_intel(domain, list_type);
";

#[derive(Debug)]
pub struct IntelEntry {
    pub value:     String,
    pub list_type: String,
    pub note:      Option<String>,
    pub added_at:  String,
}

impl IntelDb {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening intel DB at {}", path.display()))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    // ── Snapshot loaders (called at startup → Arc<HashChecker>) ───────────

    pub fn load_blocklist(&self) -> Result<HashSet<[u8; 32]>> {
        self.load_hash_set("blocklist")
    }

    pub fn load_allowlist(&self) -> Result<HashSet<[u8; 32]>> {
        self.load_hash_set("allowlist")
    }

    pub fn load_blocked_domains(&self) -> Result<HashSet<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT domain FROM domain_intel WHERE list_type = 'blocklist'"
        )?;
        let domains = stmt.query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<HashSet<_>, _>>()?;
        Ok(domains)
    }

    fn load_hash_set(&self, list_type: &str) -> Result<HashSet<[u8; 32]>> {
        let mut stmt = self.conn.prepare(
            "SELECT sha256 FROM hash_intel WHERE list_type = ?1"
        )?;
        let mut set = HashSet::new();
        for row in stmt.query_map(params![list_type], |row| row.get::<_, String>(0))? {
            let hex = row?;
            if let Ok(bytes) = crate::util::hex_to_bytes32(&hex) {
                set.insert(bytes);
            }
        }
        Ok(set)
    }

    // ── Management (tav intel commands) ───────────────────────────────────

    pub fn add_hash(&self, hex: &str, list_type: &str, note: Option<&str>) -> Result<()> {
        // Validate it's a real SHA-256
        crate::util::hex_to_bytes32(hex).context("invalid SHA-256 hex")?;
        self.conn.execute(
            "INSERT OR REPLACE INTO hash_intel (sha256, list_type, note) VALUES (?1, ?2, ?3)",
            params![hex.to_lowercase(), list_type, note],
        )?;
        Ok(())
    }

    pub fn add_domain(&self, domain: &str, list_type: &str, note: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO domain_intel (domain, list_type, note) VALUES (?1, ?2, ?3)",
            params![domain.to_lowercase(), list_type, note],
        )?;
        Ok(())
    }

    /// Import a flat file of sha256 hex strings (one per line, # comments ok).
    pub fn import_hashes_from_str(&self, content: &str, list_type: &str) -> Result<usize> {
        let mut count = 0;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            // Some feeds prefix with "sha256:" or include a filename after whitespace
            let hex = line.split_whitespace().next().unwrap_or(line);
            let hex = hex.trim_start_matches("sha256:");
            if hex.len() == 64 {
                if self.add_hash(hex, list_type, None).is_ok() {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Import a flat file of domain names (one per line, # comments ok).
    pub fn import_domains_from_str(&self, content: &str, list_type: &str) -> Result<usize> {
        let mut count = 0;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let domain = line.split_whitespace().last().unwrap_or(line);
            if self.add_domain(domain, list_type, None).is_ok() {
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn list_hashes(&self, list_type: Option<&str>, limit: usize) -> Result<Vec<IntelEntry>> {
        self.list_table("hash_intel", "sha256", list_type, limit)
    }

    pub fn list_domains(&self, list_type: Option<&str>, limit: usize) -> Result<Vec<IntelEntry>> {
        self.list_table("domain_intel", "domain", list_type, limit)
    }

    fn list_table(&self, table: &str, col: &str, list_type: Option<&str>, limit: usize) -> Result<Vec<IntelEntry>> {
        let lim = limit as i64;
        // Build the full query string up front so `stmt` can be prepared once.
        let (sql, filter) = match list_type {
            Some(t) => (
                format!("SELECT {col}, list_type, note, added_at FROM {table} WHERE list_type = ?1 ORDER BY added_at DESC LIMIT ?2"),
                Some(t.to_string()),
            ),
            None => (
                format!("SELECT {col}, list_type, note, added_at FROM {table} ORDER BY added_at DESC LIMIT ?1"),
                None,
            ),
        };

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = match filter {
            Some(ref t) => stmt.query_map(params![t, lim], Self::map_entry)?,
            None        => stmt.query_map(params![lim],    Self::map_entry)?,
        };
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    fn map_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<IntelEntry> {
        Ok(IntelEntry {
            value:     row.get(0)?,
            list_type: row.get(1)?,
            note:      row.get(2)?,
            added_at:  row.get(3)?,
        })
    }

    pub fn count_hashes(&self) -> Result<(usize, usize)> {
        let bl: usize = self.conn.query_row(
            "SELECT COUNT(*) FROM hash_intel WHERE list_type='blocklist'", [], |r| r.get(0))?;
        let al: usize = self.conn.query_row(
            "SELECT COUNT(*) FROM hash_intel WHERE list_type='allowlist'", [], |r| r.get(0))?;
        Ok((bl, al))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_hash() {
        let db = IntelDb::open_in_memory().unwrap();
        let sha = "a".repeat(64);
        db.add_hash(&sha, "blocklist", Some("test")).unwrap();
        let bl = db.load_blocklist().unwrap();
        assert_eq!(bl.len(), 1);
        let al = db.load_allowlist().unwrap();
        assert!(al.is_empty());
    }

    #[test]
    fn import_hash_file() {
        let db = IntelDb::open_in_memory().unwrap();
        let content = "# comment\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
        let n = db.import_hashes_from_str(content, "blocklist").unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn roundtrip_domain() {
        let db = IntelDb::open_in_memory().unwrap();
        db.add_domain("evil.example.com", "blocklist", None).unwrap();
        let domains = db.load_blocked_domains().unwrap();
        assert!(domains.contains("evil.example.com"));
    }
}
