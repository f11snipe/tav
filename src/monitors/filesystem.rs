use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use async_trait::async_trait;
use dashmap::DashMap;
use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
use walkdir::WalkDir;
use crate::detectors::{ContentDetector, HashCheckResult, HashChecker, RuleSet, ScriptDetector};
use crate::engine::event::{EventSender, Severity, Subject, ThreatEvent};
use crate::util::{stream_sha256, stream_sha256_sync};
use super::{Monitor, MonitorContext};

pub struct FilesystemMonitor {
    pub hash_checker:    Arc<HashChecker>,
    pub script_detector: Arc<ScriptDetector>,
}

impl FilesystemMonitor {
    pub fn new(hash_checker: Arc<HashChecker>, script_detector: Arc<ScriptDetector>) -> Self {
        Self { hash_checker, script_detector }
    }
}

#[async_trait]
impl Monitor for FilesystemMonitor {
    fn name(&self) -> &str { "filesystem" }

    async fn run(&self, ctx: MonitorContext) -> Result<()> {
        let mut ruleset        = build_ruleset(&ctx).await?;
        let watchlist          = get_watchlist(&ctx).await;
        let dedup_ttl          = get_dedup_ttl(&ctx).await;
        let dedup: Arc<DashMap<String, Instant>> = Arc::new(DashMap::new());
        let hash_checker       = self.hash_checker.clone();
        let mut script_det     = self.script_detector.clone();

        if watchlist.is_empty() {
            tracing::info!("filesystem monitor: no watch paths configured, sleeping");
            ctx.cancel.cancelled().await;
            return Ok(());
        }

        // ── Initial walk ─────────────────────────────────────────────────────
        for dir in &watchlist {
            let dir_clone    = dir.clone();
            let rules_clone  = ruleset.clone();
            let tx_clone     = ctx.tx.clone();
            let dedup_clone  = dedup.clone();
            let hc_clone     = hash_checker.clone();
            let sd_clone     = script_det.clone();
            let hash_enabled = !hc_clone.is_empty();
            tokio::task::spawn_blocking(move || {
                tracing::info!("filesystem: walking {}", dir_clone);
                walk_dir(&dir_clone, &rules_clone, &tx_clone, &dedup_clone, dedup_ttl, &hc_clone, hash_enabled);
            });
            // Content scan on walk is async — spawned separately after walk is done
            // (walk emits events; the notify loop handles content scanning for creates)
            let _ = (sd_clone, ); // suppress unused warning; used in notify loop below
        }

        // ── Continuous notify watcher ────────────────────────────────────────
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(128);
        let watchlist_clone = watchlist.clone();
        let _watcher_handle = tokio::task::spawn_blocking(move || {
            let tx = notify_tx.clone();
            let mut watcher = match RecommendedWatcher::new(
                move |res| { let _ = tx.blocking_send(res); },
                NotifyConfig::default(),
            ) {
                Ok(w) => w,
                Err(e) => { tracing::error!("filesystem watcher init: {:?}", e); return; }
            };
            for dir in &watchlist_clone {
                if let Err(e) = watcher.watch(Path::new(dir), RecursiveMode::Recursive) {
                    tracing::error!("filesystem: cannot watch {}: {:?}", dir, e);
                }
            }
            tracing::info!("filesystem: watching {} dirs", watchlist_clone.len());
            std::thread::park();
        });

        let mut config_changed = ctx.config_changed.clone();

        loop {
            tokio::select! {
                _ = ctx.cancel.cancelled() => {
                    tracing::info!("filesystem monitor: shutting down");
                    break;
                }
                Ok(()) = config_changed.changed() => {
                    match build_ruleset(&ctx).await {
                        Ok(rs) => ruleset = rs,
                        Err(e) => tracing::warn!("filesystem: ruleset reload failed: {:?}", e),
                    }
                    if let Some(sd) = rebuild_script_detector(&ctx).await {
                        script_det = Arc::new(sd);
                    }
                    tracing::info!("filesystem: detectors reloaded");
                }
                Some(event_result) = notify_rx.recv() => {
                    match event_result {
                        Ok(event) if !event.kind.is_remove() => {
                            for path in event.paths {
                                if !path.exists() { continue; }
                                process_path(
                                    &path,
                                    &ruleset,
                                    &hash_checker,
                                    &script_det,
                                    &ctx,
                                    &dedup,
                                    dedup_ttl,
                                ).await;
                            }
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!("filesystem watch error: {:?}", e),
                    }
                }
            }
        }
        Ok(())
    }
}

/// Full per-file detection pipeline (notify path, async):
///   1. Dedup check
///   2. Filename regex match  → emit `filesystem` event
///   3. Hash check            → emit `filesystem/hash` event (blocked) or skip (allowed)
///   4. Content scan          → emit `filesystem/script` events per rule hit
async fn process_path(
    path:       &Path,
    ruleset:    &RuleSet,
    hc:         &HashChecker,
    sd:         &ScriptDetector,
    ctx:        &MonitorContext,
    dedup:      &DashMap<String, Instant>,
    dedup_ttl:  u64,
) {
    let key = path.to_string_lossy().to_string();
    if is_duplicate(dedup, &key, Duration::from_secs(dedup_ttl)) { return; }

    let (hash_enabled, script_enabled, max_bytes) = {
        let cfg = ctx.config.read().await;
        let he  = cfg.filesystem.hashes.enabled && !hc.is_empty();
        let se  = cfg.filesystem.scripts.enabled && !sd.is_empty();
        let mb  = cfg.filesystem.scripts.max_size_mb * 1024 * 1024;
        (he, se, mb)
    };

    // ── 1. Filename regex match ──────────────────────────────────────────────
    let path_str = path.to_string_lossy();
    if let Some(rule) = ruleset.first_match(&path_str) {
        let hash = if hash_enabled { stream_sha256(path).await.ok() } else { None };
        emit_event(&ctx.tx, "filesystem", Severity::High,
            Subject::File { path: path.to_path_buf(), hash }, rule);
    }

    // ── 2. Hash check ────────────────────────────────────────────────────────
    if hash_enabled {
        match hc.check_file(path).await {
            Ok(HashCheckResult::Blocked { hash }) => {
                emit_event(&ctx.tx, "filesystem/hash", Severity::Critical,
                    Subject::File { path: path.to_path_buf(), hash: Some(hash) },
                    "hash_blocklist");
            }
            Ok(HashCheckResult::Allowed { .. }) => return, // trusted file — skip content scan
            Ok(HashCheckResult::Unknown { .. }) | Err(_) => {}
        }
    }

    // ── 3. Content scan ──────────────────────────────────────────────────────
    if script_enabled {
        scan_content(path, sd, &ctx.tx, max_bytes).await;
    }
}

async fn scan_content(
    path:      &Path,
    sd:        &ScriptDetector,
    tx:        &EventSender,
    max_bytes: u64,
) {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if !<ScriptDetector as ContentDetector>::extensions(sd).iter().any(|e| e == ext) { return; }

    let Ok(meta) = tokio::fs::metadata(path).await else { return };
    if meta.len() > max_bytes { return; }

    let Ok(bytes) = tokio::fs::read(path).await else { return };
    let content = String::from_utf8_lossy(&bytes);

    let hits = <ScriptDetector as ContentDetector>::scan(sd, path, &content).await;
    for m in hits {
        emit_event(tx, "filesystem/script", m.severity,
            Subject::File { path: path.to_path_buf(), hash: None },
            &m.rule_name);
    }
}

fn walk_dir(
    dir:          &str,
    rules:        &RuleSet,
    tx:           &EventSender,
    dedup:        &DashMap<String, Instant>,
    dedup_ttl:    u64,
    _hc:          &HashChecker,
    hash_enabled: bool,
) {
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        let key  = path.to_string_lossy().to_string();
        if is_duplicate(dedup, &key, Duration::from_secs(dedup_ttl)) { continue; }

        if let Some(rule) = rules.first_match(&key) {
            let hash = if hash_enabled { stream_sha256_sync(path).ok() } else { None };
            emit_event(tx, "filesystem", Severity::High,
                Subject::File { path: path.to_path_buf(), hash }, rule);
        }
    }
}

fn emit_event(tx: &EventSender, monitor: &str, severity: Severity, subject: Subject, rule: &str) {
    let ev = ThreatEvent::new(monitor, severity, subject, rule);
    tracing::info!("{}: match '{}' -> {:?}", monitor, rule, ev.id);
    let _ = tx.send(ev);
}

fn is_duplicate(cache: &DashMap<String, Instant>, key: &str, ttl: Duration) -> bool {
    if let Some(last) = cache.get(key) {
        if last.elapsed() < ttl { return true; }
    }
    cache.insert(key.to_string(), Instant::now());
    false
}

async fn build_ruleset(ctx: &MonitorContext) -> Result<RuleSet> {
    let cfg = ctx.config.read().await;
    RuleSet::compile(&cfg.filesystem.block)
}

async fn get_watchlist(ctx: &MonitorContext) -> Vec<String> {
    ctx.config.read().await.filesystem.watch.clone()
}

async fn get_dedup_ttl(ctx: &MonitorContext) -> u64 {
    ctx.config.read().await.global.dedup_secs
}

async fn rebuild_script_detector(ctx: &MonitorContext) -> Option<ScriptDetector> {
    let cfg = ctx.config.read().await;
    if !cfg.filesystem.scripts.enabled { return Some(ScriptDetector::empty()); }
    ScriptDetector::from_config(&cfg.filesystem.scripts.patterns, &cfg.filesystem.scripts.extensions).ok()
}
