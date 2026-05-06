use std::path::PathBuf;
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use crate::config::{ActionName, Config};
use crate::engine::event::{Subject, ThreatEvent};
use super::ActionHandler;

/// Metadata written alongside each quarantined file as `<UUID>.meta.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct QuarantineMeta {
    pub id:             Uuid,
    pub original_path:  PathBuf,
    pub quarantined_at: DateTime<Utc>,
    pub sha256:         String,
    pub matched_rule:   String,
    pub event_id:       Uuid,
}

pub struct QuarantineAction;

#[async_trait]
impl ActionHandler for QuarantineAction {
    fn action_name(&self) -> ActionName { ActionName::Quarantine }

    async fn execute(&self, event: &ThreatEvent, config: &Config) -> Result<()> {
        let path = match &event.subject {
            Subject::File { path, .. } => path.clone(),
            _ => return Ok(()), // quarantine only applies to files
        };

        if !path.exists() {
            return Ok(());
        }

        let qdir = config.quarantine_dir();
        tokio::fs::create_dir_all(&qdir).await?;

        let bytes = tokio::fs::read(&path).await?;
        let sha256 = hex::encode(Sha256::digest(&bytes));

        let qid   = Uuid::new_v4();
        let qfile = qdir.join(qid.to_string());
        let qmeta = qdir.join(format!("{}.meta.json", qid));

        move_file(&path, &qfile).await?;

        let meta = QuarantineMeta {
            id:             qid,
            original_path:  path,
            quarantined_at: Utc::now(),
            sha256,
            matched_rule:   event.matched_rule.clone(),
            event_id:       event.id,
        };
        let meta_json = serde_json::to_string_pretty(&meta)?;
        tokio::fs::write(&qmeta, meta_json).await?;

        tracing::info!("QUARANTINE: {} -> {}", meta.original_path.display(), qfile.display());
        Ok(())
    }
}

/// Move a file, falling back to copy+remove on cross-device renames (EXDEV).
async fn move_file(src: &PathBuf, dst: &PathBuf) -> Result<()> {
    match tokio::fs::rename(src, dst).await {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(18) => {
            // EXDEV — source and destination are on different filesystems
            tokio::fs::copy(src, dst).await?;
            tokio::fs::remove_file(src).await?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}
