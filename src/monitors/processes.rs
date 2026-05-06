use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use anyhow::Result;
use async_trait::async_trait;
use sysinfo::{Process, System, Users};
use crate::detectors::RuleSet;
use crate::engine::event::{Severity, Subject, ThreatEvent};
use super::{Monitor, MonitorContext};

pub struct ProcessMonitor;

#[async_trait]
impl Monitor for ProcessMonitor {
    fn name(&self) -> &str { "processes" }

    async fn run(&self, ctx: MonitorContext) -> Result<()> {
        let mut config_changed = ctx.config_changed.clone();

        // Read initial config values
        let (mut watchlist, mut blacklist_rules, mut prohibit, mut poll_ms) =
            read_config(&ctx).await;

        loop {
            let poll_dur = Duration::from_millis(poll_ms);

            tokio::select! {
                _ = ctx.cancel.cancelled() => {
                    tracing::info!("process monitor: shutting down");
                    break;
                }
                Ok(()) = config_changed.changed() => {
                    (watchlist, blacklist_rules, prohibit, poll_ms) = read_config(&ctx).await;
                    tracing::info!("process monitor: config reloaded");
                }
                _ = tokio::time::sleep(poll_dur) => {
                    let watch_clone    = watchlist.clone();
                    let bl_clone       = blacklist_rules.clone();
                    let prohibit_clone = prohibit.clone();
                    let monitor_name   = self.name().to_string();

                    let events = tokio::task::spawn_blocking(move || {
                        scan_processes(&watch_clone, &bl_clone, &prohibit_clone, &monitor_name)
                    }).await?;

                    for ev in events {
                        let _ = ctx.tx.send(ev);
                    }
                }
            }
        }

        Ok(())
    }
}

fn scan_processes(
    watchlist:    &[String],
    blacklist:    &RuleSet,
    prohibit:     &HashMap<String, Vec<String>>,
    monitor_name: &str,
) -> Vec<ThreatEvent> {
    let mut sys   = System::new_all();
    sys.refresh_all();
    let users = Users::new_with_refreshed_list();
    let mut events = Vec::new();

    for (_pid, process) in sys.processes() {
        let pid  = process.pid().as_u32();
        let name = process.name().to_string();
        let cmd  = process.cmd().join(" ");
        let user = get_user(process, &users);

        // ── Watch list: log only, no action ─────────────────────────────────
        for pattern in watchlist {
            if ps_match(process, pattern) {
                tracing::info!("FOUND: [{}] {} ({}) {:?}", pid, name, cmd, user);
            }
        }

        // ── Blacklist: kill ──────────────────────────────────────────────────
        if let Some(rule) = blacklist_match(process, blacklist) {
            events.push(ThreatEvent::new(
                monitor_name,
                Severity::Critical,
                Subject::Process { pid, name: name.clone(), cmdline: cmd.clone(), user: user.clone() },
                rule,
            ));
        }

        // ── Prohibit: user-specific kill ─────────────────────────────────────
        if let Some(username) = &user {
            if let Some(banned_paths) = prohibit.get(username) {
                for path in banned_paths {
                    if ps_match(process, path) {
                        events.push(ThreatEvent::new(
                            monitor_name,
                            Severity::High,
                            Subject::Process { pid, name: name.clone(), cmdline: cmd.clone(), user: user.clone() },
                            path,
                        ));
                        break;
                    }
                }
            }
        }
    }

    events
}

fn ps_match(process: &Process, pattern: &str) -> bool {
    let search = pattern.to_lowercase();
    let cmd    = process.cmd().join(" ").to_lowercase();
    let exe    = process.exe()
        .unwrap_or_else(|| Path::new(""))
        .to_str()
        .unwrap_or("")
        .to_lowercase();
    let name   = process.name().to_lowercase();
    cmd.contains(&search) || exe.contains(&search) || name.contains(&search)
}

fn blacklist_match<'a>(process: &Process, rules: &'a RuleSet) -> Option<&'a str> {
    let cmd  = process.cmd().join(" ");
    let exe  = process.exe()
        .unwrap_or_else(|| Path::new(""))
        .to_str()
        .unwrap_or("")
        .to_string();
    let name = process.name().to_string();
    rules.first_match(&cmd)
        .or_else(|| rules.first_match(&exe))
        .or_else(|| rules.first_match(&name))
}

fn get_user(process: &Process, users: &Users) -> Option<String> {
    let uid  = process.effective_user_id()?;
    let user = users.get_user_by_id(uid)?;
    Some(user.name().to_string())
}

async fn read_config(
    ctx: &MonitorContext,
) -> (Vec<String>, RuleSet, HashMap<String, Vec<String>>, u64) {
    let cfg       = ctx.config.read().await;
    let watchlist = cfg.ps.watch.clone().unwrap_or_default();
    let bl_pats   = cfg.ps.blacklist.clone().unwrap_or_default();
    let prohibit  = cfg.ps.prohibit.clone().unwrap_or_default();
    let poll_ms   = cfg.poll_ms_for(&cfg.ps);
    let rules     = RuleSet::compile(&bl_pats).unwrap_or_else(|e| {
        tracing::warn!("process monitor: bad blacklist pattern, using empty ruleset: {:?}", e);
        RuleSet::compile(&[]).unwrap()
    });
    (watchlist, rules, prohibit, poll_ms)
}
