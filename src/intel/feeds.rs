use std::path::Path;
use anyhow::Result;
use super::db::IntelDb;

/// Import a flat-file hash list into the DB asynchronously.
pub async fn import_hash_file(db_path: &Path, file_path: &Path, list_type: &str) -> Result<usize> {
    let content  = tokio::fs::read_to_string(file_path).await?;
    let db_path  = db_path.to_path_buf();
    let list     = list_type.to_string();
    tokio::task::spawn_blocking(move || {
        let db = IntelDb::open(&db_path)?;
        db.import_hashes_from_str(&content, &list)
    }).await?
}

/// Import a flat-file domain list into the DB asynchronously.
pub async fn import_domain_file(db_path: &Path, file_path: &Path, list_type: &str) -> Result<usize> {
    let content = tokio::fs::read_to_string(file_path).await?;
    let db_path = db_path.to_path_buf();
    let list    = list_type.to_string();
    tokio::task::spawn_blocking(move || {
        let db = IntelDb::open(&db_path)?;
        db.import_domains_from_str(&content, &list)
    }).await?
}
