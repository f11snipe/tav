pub mod filesystem;
pub mod processes;
pub mod ports;
pub mod dns;

#[cfg(feature = "pcap")]
pub mod pcap;

use std::sync::Arc;
use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::{watch, RwLock};
use tokio_util::sync::CancellationToken;
use crate::config::Config;
use crate::engine::event::EventSender;

/// Everything a monitor needs, bundled together.
/// Cheap to clone — all inner types are Arc or primitive.
#[derive(Clone)]
pub struct MonitorContext {
    pub config:         Arc<RwLock<Config>>,
    pub tx:             EventSender,
    pub cancel:         CancellationToken,
    /// Fires whenever the config file is reloaded. Monitors use this to
    /// know when to recompile their RuleSet without polling the config.
    pub config_changed: watch::Receiver<()>,
}

/// The single interface every monitor implements.
/// `run` should respect `ctx.cancel` — either via `ctx.cancel.cancelled().await`
/// or by checking `ctx.cancel.is_cancelled()` in polling loops.
#[async_trait]
pub trait Monitor: Send + Sync {
    /// Short stable identifier used in ThreatEvent.monitor.
    fn name(&self) -> &str;

    /// Long-running async task. Returns Ok(()) on clean shutdown (cancel
    /// token fired), or Err on unrecoverable error.
    async fn run(&self, ctx: MonitorContext) -> Result<()>;
}
