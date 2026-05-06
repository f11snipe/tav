use anyhow::Result;
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use crate::config::{ActionName, Config};
use crate::engine::event::ThreatEvent;
use super::ActionHandler;

pub struct AuditAction;

#[async_trait]
impl ActionHandler for AuditAction {
    fn action_name(&self) -> ActionName { ActionName::Alert }

    async fn execute(&self, event: &ThreatEvent, config: &Config) -> Result<()> {
        let log_path = config.audit_log();
        if let Some(parent) = log_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut line = serde_json::to_string(event)?;
        line.push('\n');
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .await?;
        file.write_all(line.as_bytes()).await?;
        Ok(())
    }
}
