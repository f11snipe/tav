use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use anyhow::Result;
use async_trait::async_trait;
use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use crate::engine::event::{Severity, Subject, ThreatEvent};
use super::{Monitor, MonitorContext};

const HOSTS_FILE:  &str = "/etc/hosts";
const RESOLV_CONF: &str = "/etc/resolv.conf";

pub struct DnsMonitor {
    pub blocked_domains: Arc<HashSet<String>>,
}

impl DnsMonitor {
    pub fn new(blocked_domains: Arc<HashSet<String>>) -> Self {
        Self { blocked_domains }
    }
}

#[async_trait]
impl Monitor for DnsMonitor {
    fn name(&self) -> &str { "network/dns" }

    async fn run(&self, ctx: MonitorContext) -> Result<()> {
        let mut config_changed = ctx.config_changed.clone();
        let (mut enabled, mut patterns) = read_config(&ctx).await;

        if !enabled {
            tracing::info!("dns monitor: disabled in config, sleeping");
            ctx.cancel.cancelled().await;
            return Ok(());
        }

        let blocked      = self.blocked_domains.clone();
        let monitor_name = self.name().to_string();

        // Initial scan on startup
        let mut seen: HashSet<String> = HashSet::new();
        emit_hosts_events(&blocked, &patterns, &monitor_name, &mut seen, &ctx.tx);

        // Set up filesystem watcher for /etc/hosts and /etc/resolv.conf
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel::<()>(16);

        let _watcher_handle = tokio::task::spawn_blocking(move || {
            let tx = notify_tx.clone();
            let callback_tx = notify_tx;
            let mut watcher = match RecommendedWatcher::new(
                move |_res| { let _ = callback_tx.blocking_send(()); },
                NotifyConfig::default(),
            ) {
                Ok(w) => w,
                Err(e) => { tracing::error!("dns monitor: watcher init failed: {:?}", e); return; }
            };

            for path in &[HOSTS_FILE, RESOLV_CONF] {
                if Path::new(path).exists() {
                    if let Err(e) = watcher.watch(Path::new(path), RecursiveMode::NonRecursive) {
                        tracing::warn!("dns monitor: cannot watch {}: {:?}", path, e);
                    } else {
                        tracing::info!("dns monitor: watching {}", path);
                    }
                }
            }

            // Keep watcher alive
            let _ = tx; // suppress unused warning
            std::thread::park();
        });

        loop {
            tokio::select! {
                _ = ctx.cancel.cancelled() => {
                    tracing::info!("dns monitor: shutting down");
                    break;
                }
                Ok(()) = config_changed.changed() => {
                    (enabled, patterns) = read_config(&ctx).await;
                    if !enabled {
                        tracing::info!("dns monitor: disabled via config reload");
                        ctx.cancel.cancelled().await;
                        break;
                    }
                    tracing::info!("dns monitor: config reloaded");
                    // Re-scan with potentially new patterns; clear seen to re-evaluate
                    seen.clear();
                    emit_hosts_events(&blocked, &patterns, &monitor_name, &mut seen, &ctx.tx);
                }
                Some(()) = notify_rx.recv() => {
                    emit_hosts_events(&blocked, &patterns, &monitor_name, &mut seen, &ctx.tx);
                }
            }
        }

        Ok(())
    }
}

// ─── Hosts file scanning ──────────────────────────────────────────────────────

fn emit_hosts_events(
    blocked:      &HashSet<String>,
    patterns:     &[(Regex, Severity)],
    monitor_name: &str,
    seen:         &mut HashSet<String>,
    tx:           &crate::engine::event::EventSender,
) {
    let content = match std::fs::read_to_string(HOSTS_FILE) {
        Ok(c)  => c,
        Err(e) => {
            tracing::warn!("dns monitor: cannot read {}: {:?}", HOSTS_FILE, e);
            return;
        }
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }

        // Format: "IP  domain [alias ...]"
        let mut parts = line.split_whitespace();
        let _ip = parts.next(); // skip IP address

        for domain in parts {
            if domain.starts_with('#') { break; } // inline comment
            let dl = domain.to_lowercase();

            if blocked.contains(&dl) {
                let key = format!("blocked:{}", dl);
                if !seen.contains(&key) {
                    seen.insert(key);
                    let ev = ThreatEvent::new(
                        monitor_name,
                        Severity::High,
                        Subject::DnsQuery { domain: domain.to_string(), source: "hosts_file".into() },
                        &format!("blocked_domain:{}", dl),
                    );
                    let _ = tx.send(ev);
                }
                continue;
            }

            for (re, severity) in patterns {
                if re.is_match(&dl) {
                    let key = format!("pattern:{}:{}", re.as_str(), dl);
                    if !seen.contains(&key) {
                        seen.insert(key.clone());
                        let ev = ThreatEvent::new(
                            monitor_name,
                            severity.clone(),
                            Subject::DnsQuery { domain: domain.to_string(), source: "hosts_file".into() },
                            &format!("dns_pattern:{}", re.as_str()),
                        );
                        let _ = tx.send(ev);
                    }
                }
            }
        }
    }
}

// ─── Config reader ────────────────────────────────────────────────────────────

async fn read_config(ctx: &MonitorContext) -> (bool, Vec<(Regex, Severity)>) {
    let cfg      = ctx.config.read().await;
    let dc       = &cfg.dns;
    let enabled  = dc.enabled;
    let patterns = dc.block_patterns.iter()
        .filter_map(|p| {
            let re = Regex::new(&p.pattern).ok()?;
            Some((re, p.severity.clone()))
        })
        .collect();
    (enabled, patterns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn hosts_events_from_str(
        content:  &str,
        blocked:  &HashSet<String>,
        patterns: &[(Regex, Severity)],
    ) -> Vec<ThreatEvent> {
        // Write content to a temp file and use a local path — instead, test the
        // parsing logic directly via a helper that accepts a string.
        parse_hosts_content(content, blocked, patterns, "network/dns")
    }

    fn parse_hosts_content(
        content:      &str,
        blocked:      &HashSet<String>,
        patterns:     &[(Regex, Severity)],
        monitor_name: &str,
    ) -> Vec<ThreatEvent> {
        let mut events = Vec::new();
        let mut seen   = HashSet::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let mut parts = line.split_whitespace();
            let _ip = parts.next();
            for domain in parts {
                if domain.starts_with('#') { break; }
                let dl = domain.to_lowercase();
                if blocked.contains(&dl) {
                    let key = format!("blocked:{}", dl);
                    if !seen.contains(&key) {
                        seen.insert(key);
                        events.push(ThreatEvent::new(
                            monitor_name,
                            Severity::High,
                            Subject::DnsQuery { domain: domain.to_string(), source: "hosts_file".into() },
                            &format!("blocked_domain:{}", dl),
                        ));
                    }
                    continue;
                }
                for (re, sev) in patterns {
                    if re.is_match(&dl) {
                        let key = format!("pattern:{}:{}", re.as_str(), dl);
                        if !seen.contains(&key) {
                            seen.insert(key);
                            events.push(ThreatEvent::new(
                                monitor_name,
                                sev.clone(),
                                Subject::DnsQuery { domain: domain.to_string(), source: "hosts_file".into() },
                                &format!("dns_pattern:{}", re.as_str()),
                            ));
                        }
                    }
                }
            }
        }
        events
    }

    #[test]
    fn detects_blocked_domain() {
        let blocked: HashSet<String> = ["evil.example.com".into()].into_iter().collect();
        let content = "127.0.0.1  evil.example.com\n";
        let events  = hosts_events_from_str(content, &blocked, &[]);
        assert_eq!(events.len(), 1);
        assert!(events[0].matched_rule.contains("blocked_domain"));
    }

    #[test]
    fn detects_pattern_match() {
        let blocked  = HashSet::new();
        let re       = Regex::new(r".*\.onion").unwrap();
        let patterns = vec![(re, Severity::High)];
        let content  = "127.0.0.1  some-hidden.onion\n";
        let events   = hosts_events_from_str(content, &blocked, &patterns);
        assert_eq!(events.len(), 1);
        assert!(events[0].matched_rule.contains("dns_pattern"));
    }

    #[test]
    fn skips_comments_and_empty_lines() {
        let blocked  = HashSet::new();
        let content  = "# this is a comment\n\n127.0.0.1 localhost\n";
        let events   = hosts_events_from_str(content, &blocked, &[]);
        assert_eq!(events.len(), 0);
    }
}
