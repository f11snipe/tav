pub mod audit;
pub mod kill;
pub mod output;
pub mod quarantine;
pub mod watch_only;

use anyhow::Result;
use async_trait::async_trait;
use crate::config::{ActionName, Config};
use crate::engine::event::ThreatEvent;

#[async_trait]
pub trait ActionHandler: Send + Sync {
    fn action_name(&self) -> ActionName;
    async fn execute(&self, event: &ThreatEvent, config: &Config) -> Result<()>;
}
