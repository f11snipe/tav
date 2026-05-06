use anyhow::Result;
use async_trait::async_trait;
use crate::config::{ActionName, Config};
use crate::engine::event::ThreatEvent;
use super::ActionHandler;

pub struct WatchOnlyAction;

#[async_trait]
impl ActionHandler for WatchOnlyAction {
    fn action_name(&self) -> ActionName { ActionName::WatchOnly }

    async fn execute(&self, event: &ThreatEvent, _config: &Config) -> Result<()> {
        tracing::info!(
            monitor  = %event.monitor,
            severity = ?event.severity,
            rule     = %event.matched_rule,
            "WatchOnly: observed, no action taken"
        );
        Ok(())
    }
}
