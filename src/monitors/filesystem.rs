use anyhow::Result;
use async_trait::async_trait;
use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
use walkdir::WalkDir;
use crate::detectors::RuleSet;
use crate::engine::event::{Severity, Subject, ThreatEvent};
use super::{Monitor, MonitorContext};

pub struct FilesystemMonitor;

#[async_trait]
impl Monitor for FilesystemMonitor {
    fn name(&self) -> &str { "filesystem" }

    async fn run(&self, ctx: MonitorContext) -> Result<()> {
        // Build initial RuleSet from config
        let ruleset = build_ruleset(&ctx).await?;
        let watchlist = get_watchlist(&ctx).await;

        if ruleset.is_empty() || watchlist.is_empty() {
            tracing::info!("filesystem monitor: nothing configured, sleeping");
            ctx.cancel.cancelled().await;
            return Ok(());
        }

        // ── Initial walk ────────────────────────────────────────────────────
        for dir in &watchlist {
            let dir_clone    = dir.clone();
            let rules_clone  = ruleset.clone();
            let tx_clone     = ctx.tx.clone();
            let monitor_name = self.name().to_string();
            tokio::task::spawn_blocking(move || {
                tracing::info!("filesystem: walking {}", dir_clone);
                walk_dir(&dir_clone, &rules_clone, &tx_clone, &monitor_name);
            });
        }

        // ── Continuous watch ────────────────────────────────────────────────
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(128);

        // notify watcher must live on a blocking thread
        let watchlist_clone = watchlist.clone();
        let _watcher_handle = tokio::task::spawn_blocking(move || {
            let tx = notify_tx.clone();
            let mut watcher = match RecommendedWatcher::new(
                move |res| { let _ = tx.blocking_send(res); },
                NotifyConfig::default(),
            ) {
                Ok(w) => w,
                Err(e) => { tracing::error!("filesystem watcher init failed: {:?}", e); return; }
            };
            for dir in &watchlist_clone {
                if let Err(e) = watcher.watch(std::path::Path::new(dir), RecursiveMode::Recursive) {
                    tracing::error!("filesystem: failed to watch {}: {:?}", dir, e);
                }
            }
            tracing::info!("filesystem: watching {} directories", watchlist_clone.len());
            // Keep watcher alive until the channel is closed (drop signals shutdown)
            std::thread::park();
        });

        let mut current_ruleset = ruleset;
        let mut config_changed  = ctx.config_changed.clone();

        loop {
            tokio::select! {
                _ = ctx.cancel.cancelled() => {
                    tracing::info!("filesystem monitor: shutting down");
                    break;
                }
                // Recompile RuleSet when config reloads
                Ok(()) = config_changed.changed() => {
                    match build_ruleset(&ctx).await {
                        Ok(rs) => { current_ruleset = rs; tracing::info!("filesystem: ruleset reloaded"); }
                        Err(e) => tracing::warn!("filesystem: ruleset reload failed: {:?}", e),
                    }
                }
                Some(event_result) = notify_rx.recv() => {
                    match event_result {
                        Ok(event) => {
                            if event.kind.is_remove() { continue; }
                            for path in event.paths {
                                if !path.exists() { continue; }
                                let subject_str = path.to_string_lossy();
                                if let Some(rule) = current_ruleset.first_match(&subject_str) {
                                    let threat = ThreatEvent::new(
                                        self.name(),
                                        Severity::High,
                                        Subject::File { path: path.clone(), hash: None },
                                        rule,
                                    );
                                    tracing::info!("filesystem: match '{}' -> {}", rule, path.display());
                                    let _ = ctx.tx.send(threat);
                                }
                            }
                        }
                        Err(e) => tracing::warn!("filesystem watch error: {:?}", e),
                    }
                }
            }
        }

        Ok(())
    }
}

fn walk_dir(
    dir:         &str,
    rules:       &RuleSet,
    tx:          &crate::engine::event::EventSender,
    monitor_name: &str,
) {
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        let path_str = path.to_string_lossy();
        if let Some(rule) = rules.first_match(&path_str) {
            let threat = ThreatEvent::new(
                monitor_name,
                Severity::High,
                Subject::File { path: path.to_path_buf(), hash: None },
                rule,
            );
            tracing::info!("filesystem walk: match '{}' -> {}", rule, path.display());
            let _ = tx.send(threat);
        }
    }
}

async fn build_ruleset(ctx: &MonitorContext) -> Result<RuleSet> {
    let cfg = ctx.config.read().await;
    let patterns = cfg.fs.blacklist.clone().unwrap_or_default();
    RuleSet::compile(&patterns)
}

async fn get_watchlist(ctx: &MonitorContext) -> Vec<String> {
    let cfg = ctx.config.read().await;
    cfg.fs.watch.clone().unwrap_or_default()
}
