pub mod event;

use std::sync::Arc;
use anyhow::Result;
use tokio::sync::{broadcast, watch, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::error;
use crate::actions::ActionHandler;
use crate::config::{ActionName, Config};
use crate::engine::event::{new_event_bus, ThreatEvent};
use crate::monitors::{Monitor, MonitorContext};

const BUS_CAPACITY: usize = 256;

pub struct Engine {
    config:   Arc<RwLock<Config>>,
    monitors: Vec<Box<dyn Monitor>>,
    actions:  Vec<Box<dyn ActionHandler>>,
    /// Receives a tick whenever the config file is reloaded.
    config_changed_rx: watch::Receiver<()>,
}

impl Engine {
    pub fn new(config: Arc<RwLock<Config>>, config_changed_rx: watch::Receiver<()>) -> Self {
        Self {
            config,
            monitors: Vec::new(),
            actions:  Vec::new(),
            config_changed_rx,
        }
    }

    pub fn add_monitor(mut self, m: impl Monitor + 'static) -> Self {
        self.monitors.push(Box::new(m));
        self
    }

    pub fn add_action(mut self, a: impl ActionHandler + 'static) -> Self {
        self.actions.push(Box::new(a));
        self
    }

    pub async fn run(self) -> Result<()> {
        let (tx, _initial_rx) = new_event_bus(BUS_CAPACITY);
        let cancel = CancellationToken::new();
        let actions = Arc::new(self.actions);
        let config  = self.config.clone();

        // Spawn each monitor as an independent tokio task
        let mut handles = Vec::new();
        for monitor in self.monitors {
            let ctx = MonitorContext {
                config:         config.clone(),
                tx:             tx.clone(),
                cancel:         cancel.clone(),
                config_changed: self.config_changed_rx.clone(),
            };
            let h = tokio::spawn(async move { monitor.run(ctx).await });
            handles.push(h);
        }

        // Spawn action dispatcher — subscribes to the broadcast bus
        {
            let mut rx      = tx.subscribe();
            let actions_ref = actions.clone();
            let config_ref  = config.clone();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(mut event) => {
                            dispatch_actions(&mut event, &actions_ref, &config_ref).await;
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("action dispatcher lagged by {} events", n);
                            // Continue — do not break; we just missed some events
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
        }

        // Wait for Ctrl-C, then cancel all monitors
        tokio::signal::ctrl_c().await?;
        tracing::info!("tav: shutting down...");
        cancel.cancel();

        for h in handles {
            let _ = h.await;
        }
        Ok(())
    }
}

async fn dispatch_actions(
    event:   &mut ThreatEvent,
    actions: &[Box<dyn ActionHandler>],
    config:  &Arc<RwLock<Config>>,
) {
    let cfg    = config.read().await;
    let policy = resolve_policy(&cfg, &event.monitor);

    for action_name in &policy {
        if let Some(handler) = actions.iter().find(|a| &a.action_name() == action_name) {
            match handler.execute(event, &cfg).await {
                Ok(()) => { event.action_taken = Some(action_name.clone()); }
                Err(e) => error!("action {:?} failed for event {}: {:?}", action_name, event.id, e),
            }
        }
    }
}

fn resolve_policy(cfg: &Config, monitor: &str) -> Vec<ActionName> {
    let default = default_policy_for(monitor);
    match monitor {
        "filesystem" | "filesystem/hash" => {
            cfg.resolve_policy(cfg.filesystem.policy.as_ref(), &default)
        }
        "filesystem/script" => {
            // Script matches use the scripts sub-policy, falling back to filesystem policy.
            let p = cfg.filesystem.scripts.policy.as_ref()
                .or(cfg.filesystem.policy.as_ref());
            cfg.resolve_policy(p, &default)
        }
        "processes" => {
            cfg.resolve_policy(cfg.processes.policy.as_ref(), &default)
        }
        "network/ports" => {
            cfg.resolve_policy(cfg.ports.policy.as_ref(), &default)
        }
        "network/dns" => {
            cfg.resolve_policy(cfg.dns.policy.as_ref(), &default)
        }
        _ => default,
    }
}

fn default_policy_for(monitor: &str) -> Vec<ActionName> {
    match monitor {
        "filesystem" | "filesystem/hash" | "filesystem/script"
            => vec![ActionName::Quarantine, ActionName::Alert],
        "processes"
            => vec![ActionName::Kill, ActionName::Alert],
        "network/ports" | "network/dns"
            => vec![ActionName::Alert],
        _   => vec![ActionName::Alert],
    }
}
