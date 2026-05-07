use std::path::{Path, PathBuf};
use std::sync::Arc;
use anyhow::Result;
use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::{watch, RwLock};
use tokio_util::sync::CancellationToken;
use crate::config::Config;

/// A cloneable handle to the config-changed watch sender.
pub type ChangedSender = Arc<watch::Sender<()>>;

pub type SharedConfig = Arc<RwLock<Config>>;

pub async fn load_config(path: &Path) -> Result<Config> {
    let text = tokio::fs::read_to_string(path).await?;
    let config: Config = serde_yaml::from_str(&text)?;
    Ok(config)
}

pub async fn load_shared(path: &Path) -> Result<SharedConfig> {
    let config = load_config(path).await?;
    Ok(Arc::new(RwLock::new(config)))
}

/// Watch the config file for changes and reload into `shared` on modify.
/// Fires `changed_tx` after each successful reload so monitors can recompile.
/// Returns when `cancel` is triggered.
pub async fn watch_config(
    path:       PathBuf,
    shared:     SharedConfig,
    cancel:     CancellationToken,
    changed_tx: ChangedSender,
) -> Result<()> {
    let (notify_tx, mut notify_rx) =
        tokio::sync::mpsc::channel::<notify::Result<notify::Event>>(32);

    // A std channel whose sender is dropped when the async loop exits — this
    // signals the blocking thread to return rather than parking indefinitely,
    // which would prevent the Tokio runtime from completing its shutdown.
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();

    let path_clone = path.clone();
    let _watcher_handle = tokio::task::spawn_blocking(move || {
        let tx = notify_tx.clone();
        let mut watcher = match RecommendedWatcher::new(
            move |res| { let _ = tx.blocking_send(res); },
            NotifyConfig::default(),
        ) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("config watcher init failed: {:?}", e);
                return;
            }
        };
        if let Err(e) = watcher.watch(&path_clone, RecursiveMode::NonRecursive) {
            tracing::error!("config watcher watch failed: {:?}", e);
            return;
        }
        tracing::debug!("config watcher: watching {:?}", path_clone);
        // Block until shutdown_tx is dropped (on cancel) — then this thread exits
        // cleanly and the runtime can finish shutting down.
        let _ = shutdown_rx.recv();
    });

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            Some(result) = notify_rx.recv() => {
                match result {
                    Ok(event) if event.kind.is_modify() || event.kind.is_create() => {
                        match load_config(&path).await {
                            Ok(new_cfg) => {
                                *shared.write().await = new_cfg;
                                changed_tx.send(()).ok();
                                tracing::info!("config reloaded from {:?}", path);
                            }
                            Err(e) => {
                                tracing::warn!("config reload failed (keeping old): {:?}", e);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    drop(shutdown_tx); // unblocks the watcher thread so it can exit
    Ok(())
}
