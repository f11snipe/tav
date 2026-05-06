pub mod loader;

use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

/// Top-level config file structure.
/// Old YAML (only `fs:` and `ps:` keys) deserializes correctly:
///   - `global` becomes None (via Option + default)
///   - `policies` becomes empty HashMap (via default)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, rename = "tav")]
    pub global: Option<GlobalConfig>,

    pub fs: MonitorConfig,
    pub ps: MonitorConfig,

    #[serde(default)]
    pub policies: HashMap<String, PolicyDef>,

    #[serde(default)]
    pub hashes: HashConfig,

    #[serde(default)]
    pub scripts: ScriptConfig,
}

/// Optional `tav:` top-level section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_quarantine_dir")]
    pub quarantine_dir: String,

    #[serde(default = "default_audit_log")]
    pub audit_log: String,

    #[serde(default = "default_poll_ms")]
    pub poll_interval_ms: u64,

    /// Suppress duplicate events for the same file/process within this window.
    #[serde(default = "default_dedup_ttl")]
    pub dedup_ttl_secs: u64,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            quarantine_dir:  default_quarantine_dir(),
            audit_log:       default_audit_log(),
            poll_interval_ms: default_poll_ms(),
            dedup_ttl_secs:  default_dedup_ttl(),
        }
    }
}

fn default_quarantine_dir() -> String { "~/.tav/quarantine".into() }
fn default_audit_log()      -> String { "~/.tav/audit.jsonl".into() }
fn default_poll_ms()         -> u64   { 500 }
fn default_dedup_ttl()       -> u64   { 30 }

/// Replaces the old `ConfigGroup`. YAML keys (`watch`, `blacklist`, `prohibit`)
/// are unchanged — new fields are optional with sensible defaults.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MonitorConfig {
    #[serde(default)]
    pub watch: Option<Vec<String>>,

    #[serde(default)]
    pub blacklist: Option<Vec<String>>,

    /// Only meaningful for the `ps:` section; silently ignored by `fs:`.
    #[serde(default)]
    pub prohibit: Option<HashMap<String, Vec<String>>>,

    /// Named policy from the `policies:` map. Falls back to built-in default.
    #[serde(default)]
    pub policy: Option<String>,

    /// Per-monitor poll interval override (ms). Falls back to GlobalConfig value.
    #[serde(default)]
    pub poll_interval_ms: Option<u64>,
}

/// A named policy is an ordered list of action names.
/// Example YAML:  `quarantine_and_alert: [quarantine, alert]`
pub type PolicyDef = Vec<ActionName>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionName {
    Quarantine,
    Kill,
    Alert,
    WatchOnly,
}

// ─── Config helpers ───────────────────────────────────────────────────────────

impl Config {
    /// Resolve effective poll interval with fallback chain:
    /// monitor-level → global section → hardcoded 500 ms
    pub fn poll_ms_for(&self, monitor_cfg: &MonitorConfig) -> u64 {
        monitor_cfg
            .poll_interval_ms
            .or_else(|| self.global.as_ref().map(|g| g.poll_interval_ms))
            .unwrap_or(500)
    }

    /// Resolve effective policy for a monitor. Returns cloned Vec<ActionName>.
    /// Falls back to `default` if the monitor has no `policy:` key or if the
    /// named policy doesn't exist in the `policies:` map.
    pub fn policy_for(&self, monitor_cfg: &MonitorConfig, default: &[ActionName]) -> Vec<ActionName> {
        let name = match &monitor_cfg.policy {
            Some(n) => n,
            None    => return default.to_vec(),
        };
        self.policies.get(name).cloned().unwrap_or_else(|| default.to_vec())
    }

    /// Expand a leading `~/` in a path to the home directory.
    pub fn expand_path(p: &str) -> PathBuf {
        if let Some(rest) = p.strip_prefix("~/") {
            if let Some(home) = std::env::var_os("HOME") {
                return PathBuf::from(home).join(rest);
            }
        }
        PathBuf::from(p)
    }

    pub fn quarantine_dir(&self) -> PathBuf {
        Self::expand_path(
            self.global
                .as_ref()
                .map(|g| g.quarantine_dir.as_str())
                .unwrap_or("~/.tav/quarantine"),
        )
    }

    pub fn audit_log(&self) -> PathBuf {
        Self::expand_path(
            self.global
                .as_ref()
                .map(|g| g.audit_log.as_str())
                .unwrap_or("~/.tav/audit.jsonl"),
        )
    }

    pub fn intel_db_path() -> PathBuf {
        Self::expand_path("~/.tav/intel/hashes.db")
    }
}

// ─── Hash checking config ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct HashConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Path to a flat-file import list (one sha256 hex per line).
    pub blocklist: Option<String>,
    pub allowlist: Option<String>,

    #[serde(default)]
    pub virustotal: VirusTotalConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct VirusTotalConfig {
    #[serde(default)]
    pub enabled: bool,
    pub api_key: Option<String>,
    #[serde(default = "default_vt_threshold")]
    pub threshold: u32,
}
fn default_vt_threshold() -> u32 { 3 }

// ─── Script content scanning config ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScriptConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_max_script_bytes")]
    pub max_file_size_bytes: u64,

    #[serde(default = "default_script_extensions")]
    pub extensions: Vec<String>,

    #[serde(default)]
    pub patterns: Vec<ScriptPattern>,

    pub policy: Option<String>,
}

impl Default for ScriptConfig {
    fn default() -> Self {
        Self {
            enabled:             false,
            max_file_size_bytes: default_max_script_bytes(),
            extensions:          default_script_extensions(),
            patterns:            Vec::new(),
            policy:              None,
        }
    }
}

fn default_max_script_bytes() -> u64 { 10 * 1024 * 1024 } // 10 MiB
fn default_script_extensions() -> Vec<String> {
    ["sh", "py", "ps1", "js", "rb", "php", "pl"]
        .iter().map(|s| s.to_string()).collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScriptPattern {
    pub name:     String,
    pub regex:    String,
    /// "info" | "low" | "medium" | "high" | "critical" — parsed by ScriptDetector
    #[serde(default = "default_severity_str")]
    pub severity: String,
}
fn default_severity_str() -> String { "medium".into() }

#[cfg(test)]
mod tests {
    use super::*;

    const OLD_YAML: &str = r#"
fs:
  watch:
    - /tmp
  blacklist:
    - badfile.*
ps:
  watch:
    - python
  blacklist:
    - malwareps
  prohibit:
    www-data:
      - /bin/sh
"#;

    #[test]
    fn old_config_deserializes() {
        let cfg: Config = serde_yaml::from_str(OLD_YAML).unwrap();
        assert!(cfg.global.is_none());
        assert!(cfg.policies.is_empty());
        assert_eq!(cfg.fs.watch, Some(vec!["/tmp".into()]));
        assert_eq!(cfg.fs.blacklist, Some(vec!["badfile.*".into()]));
        assert_eq!(cfg.ps.prohibit.as_ref().unwrap().get("www-data").unwrap(),
                   &vec!["/bin/sh".to_string()]);
    }

    #[test]
    fn expand_path_replaces_tilde() {
        let p = Config::expand_path("~/.tav/quarantine");
        let home = std::env::var("HOME").unwrap();
        assert_eq!(p, PathBuf::from(home).join(".tav/quarantine"));
    }
}
