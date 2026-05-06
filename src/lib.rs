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
    use detectors::{ContentDetector, HashChecker, ScriptDetector};
    use monitors::{
        filesystem::FilesystemMonitor,
        processes::ProcessMonitor,
        ports::PortMonitor,
        dns::DnsMonitor,
    };
    #[cfg(feature = "pcap")]
    use monitors::pcap::PcapMonitor;
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

    // Load intel DB once; build hash checker, domain blocklist, and IP blocklist together.
    let db_path = config::Config::intel_db_path();
    let (hash_checker, blocked_domains, blocked_ips) = if db_path.exists() {
        let db = tokio::task::spawn_blocking(move || intel::IntelDb::open(&db_path)).await??;
        let bl      = db.load_blocklist()?;
        let al      = db.load_allowlist()?;
        let domains = db.load_blocked_domains()?;
        let ips     = db.load_blocked_ips()?;
        (Arc::new(HashChecker::new(bl, al)), Arc::new(domains), Arc::new(ips))
    } else {
        (Arc::new(HashChecker::empty()), Arc::new(HashSet::new()), Arc::new(Vec::new()))
    };

    // Build script detector from config
    let script_detector = {
        let cfg = shared.read().await;
        if cfg.filesystem.scripts.enabled {
            Arc::new(ScriptDetector::from_config(
                &cfg.filesystem.scripts.patterns,
                &cfg.filesystem.scripts.extensions,
            ).unwrap_or_else(|_| ScriptDetector::empty()))
        } else {
            Arc::new(ScriptDetector::empty())
        }
    };

    // Build YARA detector if the feature is compiled in and enabled in config.
    #[cfg(feature = "yara")]
    let yara_detector: Option<Arc<dyn ContentDetector>> = {
        use detectors::YaraDetector;
        let cfg = shared.read().await;
        if cfg.filesystem.yara.enabled {
            let rules_dir = config::Config::expand_path(&cfg.filesystem.yara.rules_dir);
            match YaraDetector::from_rules_dir(&rules_dir) {
                Ok(d)  => Some(Arc::new(d) as Arc<dyn ContentDetector>),
                Err(e) => { tracing::warn!("yara: failed to load rules: {:#}", e); None }
            }
        } else {
            None
        }
    };
    #[cfg(not(feature = "yara"))]
    let yara_detector: Option<Arc<dyn ContentDetector>> = None;

    // Build PCAP monitor if the feature is compiled in and enabled in config.
    #[cfg(feature = "pcap")]
    let pcap_monitor = {
        let cfg = shared.read().await;
        if cfg.pcap.enabled {
            Some(PcapMonitor::new(blocked_domains.clone(), blocked_ips.clone()))
        } else {
            None
        }
    };

    let engine = Engine::new(shared, changed_rx)
        .add_monitor(FilesystemMonitor::new(hash_checker, script_detector, yara_detector))
        .add_monitor(ProcessMonitor)
        .add_monitor(PortMonitor::new(blocked_ips))
        .add_monitor(DnsMonitor::new(blocked_domains))
        .add_action(QuarantineAction)
        .add_action(KillAction)
        .add_action(WatchOnlyAction)
        .add_action(AuditAction);

    #[cfg(feature = "pcap")]
    let engine = if let Some(pm) = pcap_monitor {
        engine.add_monitor(pm)
    } else {
        engine
    };

    engine.run().await
}
