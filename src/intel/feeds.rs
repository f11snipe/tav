use std::path::Path;
use anyhow::{bail, Result};
use super::db::IntelDb;
use crate::config::FeedConfig;

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

/// Fetch a remote feed and import it into the DB. Returns number of records imported.
pub async fn fetch_and_import(db_path: &Path, feed: &FeedConfig) -> Result<usize> {
    if !feed.enabled {
        return Ok(0);
    }

    let client = reqwest::Client::builder()
        .user_agent("tav/1.1.0 threat-intel-updater")
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    tracing::info!("intel: fetching feed '{}' from {}", feed.name, feed.url);
    let resp = client.get(&feed.url).send().await?;
    if !resp.status().is_success() {
        bail!("feed '{}': HTTP {}", feed.name, resp.status());
    }
    let content = resp.text().await?;

    let db_path   = db_path.to_path_buf();
    let list_type = "blocklist".to_string();
    let feed_type = feed.feed_type.clone();
    let feed_name = feed.name.clone();
    let feed_url  = feed.url.clone();

    tokio::task::spawn_blocking(move || {
        let db = IntelDb::open(&db_path)?;
        let count = match feed_type.as_str() {
            "hash"   => db.import_hashes_from_str(&content, &list_type)?,
            "domain" => import_stevenblack_or_plain(&db, &content, &list_type)?,
            "ip"     => db.import_ips_from_str(&content, &list_type, Some(&feed_name))?,
            other    => bail!("unknown feed_type '{}' for feed '{}'", other, feed_name),
        };
        db.upsert_feed_meta(&feed_name, &feed_url, &feed_type, count)?;
        Ok(count)
    }).await?
}

/// Handle both plain domain lists and StevenBlack /etc/hosts-style format.
/// StevenBlack format: "0.0.0.0 example.com  # comment"
/// Plain format: "example.com"
fn import_stevenblack_or_plain(db: &IntelDb, content: &str, list_type: &str) -> Result<usize> {
    let mut count = 0;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }

        // Hosts format: detect by first token being an IP-like string
        let mut parts = line.split_whitespace();
        let first = parts.next().unwrap_or("");

        let domain = if first == "0.0.0.0" || first == "127.0.0.1" {
            // Hosts format — domain is second token
            match parts.next() {
                Some(d) if !d.starts_with('#') => d,
                _ => continue,
            }
        } else if first.contains('/') || first.contains(':') {
            // Looks like an IP/CIDR — skip
            continue;
        } else {
            first
        };

        if domain.is_empty() || domain == "localhost" || domain == "local" { continue; }

        if db.add_domain(domain, list_type, None).is_ok() {
            count += 1;
        }
    }
    Ok(count)
}
