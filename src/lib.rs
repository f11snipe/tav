//! # tav
//!
//! `tav` is a minimal, portable terminal antivirus

use std::path::{Path, PathBuf};
use std::sync::Arc;
use anyhow::Result;
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
    run_impl(config_file, None).await
}

/// Async entry point for `tav daemon start` — also starts the IPC socket server.
pub async fn run_daemon_async(config_file: &Path, socket_path: &Path) -> Result<()> {
    run_impl(config_file, Some(socket_path)).await
}

async fn run_impl(config_file: &Path, socket_path: Option<&Path>) -> Result<()> {
    use config::loader::{load_shared, watch_config};
    use engine::Engine;
    use std::collections::HashSet;
    use detectors::{ContentDetector, HashChecker, ScriptDetector};
    use monitors::{
        filesystem::FilesystemMonitor,
        processes::ProcessMonitor,
        ports::PortMonitor,
        dns::DnsMonitor,
    };
    #[cfg(feature = "pcap")]
    use monitors::pcap::PcapMonitor;
    use actions::{
        audit::AuditAction,
        kill::KillAction,
        output::OutputAction,
        quarantine::QuarantineAction,
        watch_only::WatchOnlyAction,
    };

    let shared = load_shared(config_file).await?;
    let (changed_tx_inner, changed_rx) = tokio::sync::watch::channel(());
    // Wrap in Arc so multiple tasks can share the sender without ownership issues.
    let changed_tx = Arc::new(changed_tx_inner);
    let cancel = CancellationToken::new();

    let watcher_cancel = cancel.clone();
    tokio::spawn(watch_config(
        config_file.to_path_buf(),
        shared.clone(),
        watcher_cancel,
        changed_tx.clone(),
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

    // Start IPC socket + SIGHUP reload handler when running as daemon.
    if let Some(sock) = socket_path {
        let started_at = std::time::Instant::now();
        let ipc_shared = shared.clone();
        let ipc_config = config_file.to_path_buf();
        let ipc_sock   = sock.to_path_buf();
        let ipc_cancel = cancel.clone();
        let ipc_reload = changed_tx.clone();
        tokio::spawn(ipc_server(ipc_sock, ipc_shared, ipc_config, ipc_reload, ipc_cancel, started_at));

        // SIGHUP → config reload (Unix only)
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let hup_shared = shared.clone();
            let hup_path   = config_file.to_path_buf();
            let hup_tx     = changed_tx.clone();
            tokio::spawn(async move {
                if let Ok(mut sighup) = signal(SignalKind::hangup()) {
                    while sighup.recv().await.is_some() {
                        if let Ok(text) = tokio::fs::read_to_string(&hup_path).await {
                            if let Ok(new_cfg) = serde_yaml::from_str::<config::Config>(&text) {
                                *hup_shared.write().await = new_cfg;
                                hup_tx.send(()).ok();
                                tracing::info!("config reloaded via SIGHUP");
                            }
                        }
                    }
                }
            });
        }
    }

    let engine = Engine::new(shared, changed_rx)
        .add_monitor(FilesystemMonitor::new(hash_checker, script_detector, yara_detector))
        .add_monitor(ProcessMonitor)
        .add_monitor(PortMonitor::new(blocked_ips))
        .add_monitor(DnsMonitor::new(blocked_domains))
        .add_action(QuarantineAction)
        .add_action(KillAction)
        .add_action(WatchOnlyAction)
        .add_action(AuditAction)
        .add_action(OutputAction::new());

    #[cfg(feature = "pcap")]
    let engine = if let Some(pm) = pcap_monitor {
        engine.add_monitor(pm)
    } else {
        engine
    };

    engine.run().await
}

// ── IPC socket server (daemon mode) ──────────────────────────────────────────

async fn ipc_server(
    socket_path: PathBuf,
    shared:      config::loader::SharedConfig,
    config_path: PathBuf,
    reload_tx:   config::loader::ChangedSender,
    cancel:      CancellationToken,
    started_at:  std::time::Instant,
) {
    use tokio::net::UnixListener;

    let _ = tokio::fs::remove_file(&socket_path).await;
    let listener = match UnixListener::bind(&socket_path) {
        Ok(l)  => l,
        Err(e) => { tracing::error!("ipc: cannot bind {}: {}", socket_path.display(), e); return; }
    };
    tracing::info!("ipc: listening on {}", socket_path.display());

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let shared      = shared.clone();
                        let config_path = config_path.clone();
                        let reload_tx   = reload_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_ipc_client(
                                stream, shared, config_path, reload_tx, started_at
                            ).await {
                                tracing::debug!("ipc client error: {}", e);
                            }
                        });
                    }
                    Err(e) => tracing::warn!("ipc: accept error: {}", e),
                }
            }
        }
    }

    let _ = tokio::fs::remove_file(&socket_path).await;
}

async fn handle_ipc_client(
    stream:      tokio::net::UnixStream,
    shared:      config::loader::SharedConfig,
    config_path: PathBuf,
    reload_tx:   config::loader::ChangedSender,
    started_at:  std::time::Instant,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let response = match line.trim() {
            "status" => {
                let uptime = started_at.elapsed().as_secs();
                format!(
                    r#"{{"status":"running","pid":{},"uptime_secs":{}}}"#,
                    std::process::id(),
                    uptime,
                )
            }
            "reload" => {
                match tokio::fs::read_to_string(&config_path).await {
                    Ok(text) => match serde_yaml::from_str::<config::Config>(&text) {
                        Ok(new_cfg) => {
                            *shared.write().await = new_cfg;
                            reload_tx.send(()).ok();
                            tracing::info!("config reloaded via IPC");
                            r#"{"ok":true,"message":"config reloaded"}"#.to_string()
                        }
                        Err(e) => format!(r#"{{"ok":false,"error":"parse: {}"}}"#, e),
                    }
                    Err(e) => format!(r#"{{"ok":false,"error":"read: {}"}}"#, e),
                }
            }
            cmd => format!(r#"{{"error":"unknown command: {}"}}"#, cmd),
        };
        writer.write_all(format!("{}\n", response).as_bytes()).await?;
    }

    Ok(())
}
