use std::path::PathBuf;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;
use crate::config::ActionName;

// Re-export so existing `use crate::engine::event::Severity` imports keep working.
pub use crate::config::Severity;

/// Every detection produces one ThreatEvent published on the event bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id:           Uuid,
    pub timestamp:    DateTime<Utc>,
    /// Short name of the monitor that produced this event (e.g. "filesystem").
    pub monitor:      String,
    pub severity:     Severity,
    pub subject:      Subject,
    /// The original pattern string from config that matched.
    pub matched_rule: String,
    /// Filled in by the action engine after dispatch.
    pub action_taken: Option<ActionName>,
}

impl ThreatEvent {
    pub fn new(monitor: &str, severity: Severity, subject: Subject, rule: &str) -> Self {
        Self {
            id:           Uuid::new_v4(),
            timestamp:    Utc::now(),
            monitor:      monitor.to_string(),
            severity,
            subject,
            matched_rule: rule.to_string(),
            action_taken: None,
        }
    }
}

/// What was matched. New monitor types add variants here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Subject {
    File {
        path: PathBuf,
        /// SHA-256 hex string; computed lazily by the quarantine action.
        hash: Option<String>,
    },
    Process {
        pid:     u32,
        name:    String,
        cmdline: String,
        user:    Option<String>,
    },
    Connection {
        local_addr:   String,
        remote_addr:  Option<String>,
        proto:        String,
        state:        String,
        pid:          Option<u32>,
        process_name: Option<String>,
    },
    DnsQuery {
        domain: String,
        /// Where the domain was found, e.g. "hosts_file".
        source: String,
    },
}

pub type EventSender   = broadcast::Sender<ThreatEvent>;
pub type EventReceiver = broadcast::Receiver<ThreatEvent>;

pub fn new_event_bus(capacity: usize) -> (EventSender, EventReceiver) {
    broadcast::channel(capacity)
}
