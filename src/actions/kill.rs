use anyhow::Result;
use async_trait::async_trait;
use sysinfo::{Pid, Signal, System};
use crate::config::{ActionName, Config};
use crate::engine::event::{Subject, ThreatEvent};
use super::ActionHandler;

pub struct KillAction;

#[async_trait]
impl ActionHandler for KillAction {
    fn action_name(&self) -> ActionName { ActionName::Kill }

    async fn execute(&self, event: &ThreatEvent, _config: &Config) -> Result<()> {
        let pid = match &event.subject {
            Subject::Process { pid, .. } => *pid,
            _ => return Ok(()), // kill only applies to processes
        };

        tokio::task::spawn_blocking(move || {
            let mut sys = System::new();
            let sysinfo_pid = Pid::from(pid as usize);
            sys.refresh_process(sysinfo_pid);
            if let Some(process) = sys.process(sysinfo_pid) {
                process.kill_with(Signal::Kill);
                tracing::info!("KILLED: [{}] {}", pid, process.name());
            }
        })
        .await?;

        Ok(())
    }
}
