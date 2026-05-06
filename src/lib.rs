//! # tav
//!
//! `tav` is a minimal, portable terminal antivirus

use std::path::Path;
use anyhow::Result;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

pub mod util;
pub mod config;
pub mod intel;
pub mod engine;
pub mod monitors;
pub mod detectors;
pub mod actions;

pub mod cli;
pub mod cmd;
pub mod data;
pub use data::CmdExit;

/// Display the parsed config for `tav config` subcommand.
pub fn config_display(config_file: &str) -> Result<(), serde_yaml::Error> {
    use std::fs::File;
    use std::io::BufReader;
    let file = File::open(config_file).expect("Missing config file");
    let cfg: config::Config = serde_yaml::from_reader(BufReader::new(file))?;
    println!("Loaded Config: {:?}", config_file);
    dbg!(cfg);
    Ok(())
}

/// Async entry point for `tav run`.
pub async fn run_async(config_file: &Path) -> Result<()> {
    use config::loader::{load_shared, watch_config};
    use engine::Engine;
    use std::collections::HashSet;
    use std::sync::Arc;
    use detectors::{HashChecker, ScriptDetector};
    use monitors::{
        filesystem::FilesystemMonitor,
        processes::ProcessMonitor,
        ports::PortMonitor,
        dns::DnsMonitor,
    };
    use actions::{audit::AuditAction, kill::KillAction, quarantine::QuarantineAction, watch_only::WatchOnlyAction};

    let shared = load_shared(config_file).await?;
    let (changed_tx, changed_rx) = watch::channel(());
    let cancel = CancellationToken::new();

    let watcher_cancel = cancel.clone();
    tokio::spawn(watch_config(
        config_file.to_path_buf(),
        shared.clone(),
        watcher_cancel,
        changed_tx,
    ));

    // Load intel DB once; build hash checker and domain blocklist together.
    let db_path = config::Config::intel_db_path();
    let (hash_checker, blocked_domains) = if db_path.exists() {
        let db = tokio::task::spawn_blocking(move || intel::IntelDb::open(&db_path)).await??;
        let bl      = db.load_blocklist()?;
        let al      = db.load_allowlist()?;
        let domains = db.load_blocked_domains()?;
        (Arc::new(HashChecker::new(bl, al)), Arc::new(domains))
    } else {
        (Arc::new(HashChecker::empty()), Arc::new(HashSet::new()))
    };

    // Build script detector from config
    let script_detector = {
        let cfg = shared.read().await;
        if cfg.scripts.enabled {
            Arc::new(ScriptDetector::from_config(&cfg.scripts.patterns, &cfg.scripts.extensions)
                .unwrap_or_else(|_| ScriptDetector::empty()))
        } else {
            Arc::new(ScriptDetector::empty())
        }
    };

    Engine::new(shared, changed_rx)
        .add_monitor(FilesystemMonitor::new(hash_checker, script_detector))
        .add_monitor(ProcessMonitor)
        .add_monitor(PortMonitor)
        .add_monitor(DnsMonitor::new(blocked_domains))
        .add_action(QuarantineAction)
        .add_action(KillAction)
        .add_action(WatchOnlyAction)
        .add_action(AuditAction)
        .run()
        .await
}
