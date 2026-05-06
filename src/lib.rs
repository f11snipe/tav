//! # tav
//!
//! `tav` is a minimal, portable terminal antivirus

use std::path::Path;
use anyhow::Result;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

pub mod config;
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
    use monitors::{filesystem::FilesystemMonitor, processes::ProcessMonitor};
    use actions::{audit::AuditAction, kill::KillAction, quarantine::QuarantineAction};

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

    Engine::new(shared, changed_rx)
        .add_monitor(FilesystemMonitor)
        .add_monitor(ProcessMonitor)
        .add_action(QuarantineAction)
        .add_action(KillAction)
        .add_action(AuditAction)
        .run()
        .await
}
