use anyhow::Result;
use async_trait::async_trait;
use crate::config::{ActionName, Config, Severity};
use crate::engine::event::{Subject, ThreatEvent};
use super::ActionHandler;

pub struct OutputAction {
    client: reqwest::Client,
}

impl OutputAction {
    pub fn new() -> Self {
        Self { client: reqwest::Client::new() }
    }
}

#[async_trait]
impl ActionHandler for OutputAction {
    fn action_name(&self) -> ActionName { ActionName::Alert }

    async fn execute(&self, event: &ThreatEvent, config: &Config) -> Result<()> {
        let cfg = &config.output;

        if cfg.json_stdout {
            println!("{}", serde_json::to_string(event)?);
        }

        if cfg.syslog {
            let priority = match event.severity {
                Severity::Critical => "daemon.crit",
                Severity::High     => "daemon.err",
                Severity::Medium   => "daemon.warning",
                Severity::Low      => "daemon.notice",
                Severity::Info     => "daemon.info",
            };
            let subject = match &event.subject {
                Subject::File { path, .. } =>
                    format!("file={}", path.display()),
                Subject::Process { name, pid, .. } =>
                    format!("process={} pid={}", name, pid),
                Subject::Connection { local_addr, remote_addr, .. } =>
                    format!("conn={}->{}", local_addr, remote_addr.as_deref().unwrap_or("?")),
                Subject::DnsQuery { domain, .. } =>
                    format!("domain={}", domain),
            };
            let msg = format!("monitor={} rule={} {}", event.monitor, event.matched_rule, subject);
            let _ = tokio::process::Command::new("logger")
                .args(["-t", "tav", "-p", priority, &msg])
                .output()
                .await;
        }

        if let Some(ref url) = cfg.webhook {
            let body = serde_json::to_value(event)?;
            if let Err(e) = self.client.post(url).json(&body).send().await {
                tracing::warn!("output: webhook POST failed: {}", e);
            }
        }

        Ok(())
    }
}
