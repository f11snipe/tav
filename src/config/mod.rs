pub mod loader;

use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

// ── Shared primitive types ────────────────────────────────────────────────────

/// Threat severity level. Used in pattern definitions and ThreatEvents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Default for Severity {
    fn default() -> Self { Self::Medium }
}

/// An action the engine can take when a ThreatEvent is dispatched.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionName {
    Quarantine,
    Kill,
    Alert,
    WatchOnly,
}

/// A policy can be specified inline as a list of actions, or as a named
/// reference to an entry in the top-level `policies:` map.
///
/// ```yaml
/// policy: [quarantine, alert]   # inline
/// policy: strict                # named reference
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicyRef {
    Named(String),
    Inline(Vec<ActionName>),
}

// ── Top-level config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub global: GlobalConfig,

    /// Named, reusable action policies. Referenced by name in monitor `policy:` fields.
    #[serde(default)]
    pub policies: HashMap<String, Vec<ActionName>>,

    #[serde(default)]
    pub filesystem: FilesystemConfig,

    #[serde(default)]
    pub processes: ProcessConfig,

    #[serde(default)]
    pub ports: PortConfig,

    #[serde(default)]
    pub dns: DnsConfig,

    #[serde(default)]
    pub intel: IntelConfig,

    #[serde(default)]
    pub pcap: PcapConfig,

    #[serde(default)]
    pub output: OutputConfig,
}

// ── Global settings ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_quarantine_dir")]
    pub quarantine_dir: String,

    #[serde(default = "default_audit_log")]
    pub audit_log: String,

    /// Suppress repeat events for the same subject within this window (seconds).
    #[serde(default = "default_dedup_secs")]
    pub dedup_secs: u64,

    /// Hard upper limit on file size for any content scan.
    /// Files larger than this are skipped before per-detector limits are checked (MB).
    #[serde(default = "default_max_scan_size_mb")]
    pub max_scan_size_mb: u64,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            quarantine_dir:   default_quarantine_dir(),
            audit_log:        default_audit_log(),
            dedup_secs:       default_dedup_secs(),
            max_scan_size_mb: default_max_scan_size_mb(),
        }
    }
}

fn default_quarantine_dir()   -> String { "~/.tav/quarantine".into() }
fn default_audit_log()        -> String { "~/.tav/audit.jsonl".into() }
fn default_dedup_secs()       -> u64    { 30 }
fn default_max_scan_size_mb() -> u64    { 100 }

// ── Filesystem monitor ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilesystemConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub policy: Option<PolicyRef>,

    /// Directories to recursively walk and watch for file events.
    #[serde(default)]
    pub watch: Vec<String>,

    /// Regex patterns matched against file paths. Triggers policy on match.
    #[serde(default)]
    pub block: Vec<String>,

    #[serde(default)]
    pub hashes: HashConfig,

    #[serde(default)]
    pub scripts: ScriptConfig,

    #[serde(default)]
    pub yara: YaraConfig,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            policy:  None,
            watch:   Vec::new(),
            block:   Vec::new(),
            hashes:  HashConfig::default(),
            scripts: ScriptConfig::default(),
            yara:    YaraConfig::default(),
        }
    }
}

// ── Process monitor ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub policy: Option<PolicyRef>,

    #[serde(default = "default_ps_poll_ms")]
    pub poll_ms: u64,

    /// Process names/cmdlines to log (no action taken).
    #[serde(default)]
    pub watch: Vec<String>,

    /// Regex patterns matched against name/cmdline. Triggers policy on match.
    #[serde(default)]
    pub block: Vec<String>,

    /// Kill specific binaries when run by specific users.
    /// Map of `username → [path, ...]`.
    #[serde(default)]
    pub prohibit: HashMap<String, Vec<String>>,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            enabled:  false,
            policy:   None,
            poll_ms:  default_ps_poll_ms(),
            watch:    Vec::new(),
            block:    Vec::new(),
            prohibit: HashMap::new(),
        }
    }
}

fn default_ps_poll_ms() -> u64 { 500 }

// ── Port/socket monitor ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub policy: Option<PolicyRef>,

    #[serde(default = "default_port_poll_ms")]
    pub poll_ms: u64,

    /// Expected listening ports. Anything else triggers an alert.
    /// Empty list disables the unexpected-listener check.
    #[serde(default)]
    pub expected_listeners: Vec<u16>,

    /// CIDR ranges blocked as connection destinations (e.g. "10.0.0.0/8").
    #[serde(default)]
    pub block_destinations: Vec<String>,

    /// Alert when named processes open specific socket types.
    #[serde(default)]
    pub process_rules: Vec<ProcessPortRule>,
}

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            enabled:            false,
            policy:             None,
            poll_ms:            default_port_poll_ms(),
            expected_listeners: Vec::new(),
            block_destinations: Vec::new(),
            process_rules:      Vec::new(),
        }
    }
}

fn default_port_poll_ms() -> u64 { 5000 }

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessPortRule {
    /// Substring matched against the process command name.
    pub name:     String,
    pub alert_on: AlertOn,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertOn {
    AnyListen,
    AnyConnect,
}

// ── DNS monitor ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default)]
    pub enabled: bool,

    /// "passive" = watch /etc/hosts for suspicious entries.
    #[serde(default = "default_dns_mode")]
    pub mode: String,

    #[serde(default)]
    pub policy: Option<PolicyRef>,

    /// Regex patterns applied to domains found in monitored files.
    #[serde(default)]
    pub block_patterns: Vec<DnsBlockPattern>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled:        false,
            mode:           default_dns_mode(),
            policy:         None,
            block_patterns: Vec::new(),
        }
    }
}

fn default_dns_mode() -> String { "passive".into() }

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsBlockPattern {
    pub pattern:  String,
    #[serde(default)]
    pub severity: Severity,
}

// ── Hash checking (filesystem sub-detector) ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct HashConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Flat file of SHA-256 hex strings to seed the DB blocklist.
    pub block_list: Option<String>,
    /// Flat file of SHA-256 hex strings to seed the DB allowlist.
    pub allow_list: Option<String>,

    #[serde(default)]
    pub virustotal: VirusTotalConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct VirusTotalConfig {
    #[serde(default)]
    pub enabled: bool,
    pub api_key: Option<String>,
    /// Flag file if ≥ N engines detect it.
    #[serde(default = "default_vt_threshold")]
    pub threshold: u32,
}

fn default_vt_threshold() -> u32 { 3 }

// ── YARA scanning (filesystem sub-detector, feature = "yara") ─────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct YaraConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Directory containing `.yar` / `.yara` rule files (compiled at startup).
    #[serde(default = "default_yara_rules_dir")]
    pub rules_dir: String,

    /// Maximum file size to scan in megabytes (default 50 MB).
    #[serde(default = "default_yara_max_size_mb")]
    pub max_size_mb: u64,

    /// Overrides `filesystem.policy` for YARA hits.
    #[serde(default)]
    pub policy: Option<PolicyRef>,
}

impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            enabled:     false,
            rules_dir:   default_yara_rules_dir(),
            max_size_mb: default_yara_max_size_mb(),
            policy:      None,
        }
    }
}

fn default_yara_rules_dir()    -> String { "~/.tav/rules/yara".into() }
fn default_yara_max_size_mb()  -> u64   { 50 }

// ── Script content scanning (filesystem sub-detector) ─────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScriptConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Overrides `filesystem.policy` for script matches.
    #[serde(default)]
    pub policy: Option<PolicyRef>,

    /// Maximum file size to scan in megabytes.
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u64,

    #[serde(default = "default_script_extensions")]
    pub extensions: Vec<String>,

    #[serde(default)]
    pub patterns: Vec<ScriptPattern>,
}

impl Default for ScriptConfig {
    fn default() -> Self {
        Self {
            enabled:     false,
            policy:      None,
            max_size_mb: default_max_size_mb(),
            extensions:  default_script_extensions(),
            patterns:    Vec::new(),
        }
    }
}

fn default_max_size_mb() -> u64 { 10 }
fn default_script_extensions() -> Vec<String> {
    ["sh", "py", "ps1", "js", "rb", "php", "pl"]
        .iter().map(|s| s.to_string()).collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScriptPattern {
    pub name:    String,
    pub regex:   String,
    #[serde(default)]
    pub severity: Severity,
}

// ── Threat intelligence ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntelConfig {
    /// Automatically pull feeds on `tav run` startup if > `update_interval_hours` old.
    #[serde(default)]
    pub auto_update: bool,

    #[serde(default = "default_intel_update_interval")]
    pub update_interval_hours: u64,

    #[serde(default)]
    pub feeds: Vec<FeedConfig>,
}

impl Default for IntelConfig {
    fn default() -> Self {
        Self {
            auto_update:           false,
            update_interval_hours: default_intel_update_interval(),
            feeds:                 Vec::new(),
        }
    }
}

fn default_intel_update_interval() -> u64 { 24 }

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedConfig {
    pub name:      String,
    pub url:       String,
    /// "hash" | "domain" | "ip"
    pub feed_type: String,
    #[serde(default = "default_true")]
    pub enabled:   bool,
}

fn default_true() -> bool { true }

// ── Live PCAP monitor (feature = "pcap", requires root) ───────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PcapConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Network interface to capture on. Use "any" to pick the default.
    #[serde(default = "default_pcap_interface")]
    pub interface: String,

    /// BPF filter string applied to the capture (empty = capture all).
    #[serde(default)]
    pub bpf_filter: String,

    /// Overrides the global default policy for PCAP threat events.
    #[serde(default)]
    pub policy: Option<PolicyRef>,

    #[serde(default)]
    pub detectors: PcapDetectors,
}

impl Default for PcapConfig {
    fn default() -> Self {
        Self {
            enabled:    false,
            interface:  default_pcap_interface(),
            bpf_filter: String::new(),
            policy:     None,
            detectors:  PcapDetectors::default(),
        }
    }
}

fn default_pcap_interface() -> String { "any".into() }

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PcapDetectors {
    /// Alert on DNS queries for blocked or suspicious domains.
    #[serde(default = "default_true")]
    pub dns_queries: bool,

    /// Extract HTTP Host headers and check against intel.
    #[serde(default = "default_true")]
    pub http_hosts: bool,

    /// Extract TLS SNI from ClientHello and check against intel.
    #[serde(default = "default_true")]
    pub tls_sni: bool,

    /// Detect regular-interval (beaconing) connections to a single destination.
    #[serde(default)]
    pub beaconing: bool,

    /// Detect SYN-flood port scan patterns from a single source.
    #[serde(default)]
    pub port_scans: bool,
}

impl Default for PcapDetectors {
    fn default() -> Self {
        Self {
            dns_queries: true,
            http_hosts:  true,
            tls_sni:     true,
            beaconing:   false,
            port_scans:  false,
        }
    }
}

// ── Output modes ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Emit every ThreatEvent as a JSON line to stdout (NDJSON).
    #[serde(default)]
    pub json_stdout: bool,

    /// Send events to syslog via the `logger` command (daemon.warning priority).
    #[serde(default)]
    pub syslog: bool,

    /// HTTP POST JSON events to this URL.
    #[serde(default)]
    pub webhook: Option<String>,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            json_stdout: false,
            syslog:      false,
            webhook:     None,
        }
    }
}

// ── Config helpers ────────────────────────────────────────────────────────────

impl Config {
    /// Resolve a `PolicyRef` to an ordered list of actions.
    /// Falls back to `default` when the ref is `None` or a named policy doesn't exist.
    pub fn resolve_policy(&self, policy_ref: Option<&PolicyRef>, default: &[ActionName]) -> Vec<ActionName> {
        match policy_ref {
            None => default.to_vec(),
            Some(PolicyRef::Named(name)) => {
                self.policies.get(name).cloned().unwrap_or_else(|| default.to_vec())
            }
            Some(PolicyRef::Inline(actions)) => actions.clone(),
        }
    }

    /// Expand a leading `~/` to the home directory.
    pub fn expand_path(p: &str) -> PathBuf {
        if let Some(rest) = p.strip_prefix("~/") {
            if let Some(home) = std::env::var_os("HOME") {
                return PathBuf::from(home).join(rest);
            }
        }
        PathBuf::from(p)
    }

    pub fn quarantine_dir(&self) -> PathBuf {
        Self::expand_path(&self.global.quarantine_dir)
    }

    pub fn audit_log(&self) -> PathBuf {
        Self::expand_path(&self.global.audit_log)
    }

    pub fn intel_db_path() -> PathBuf {
        Self::expand_path("~/.tav/intel/hashes.db")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_yaml_gets_all_defaults() {
        let cfg: Config = serde_yaml::from_str("{}").unwrap();
        assert!(!cfg.filesystem.enabled);
        assert!(!cfg.processes.enabled);
        assert!(!cfg.ports.enabled);
        assert!(!cfg.dns.enabled);
        assert_eq!(cfg.global.dedup_secs, 30);
        assert_eq!(cfg.global.max_scan_size_mb, 100);
        assert_eq!(cfg.global.quarantine_dir, "~/.tav/quarantine");
    }

    #[test]
    fn inline_policy_deserializes() {
        let yaml = r#"
filesystem:
  enabled: true
  policy: [quarantine, alert]
  watch: [/tmp]
  block: [badfile.*]
"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            cfg.filesystem.policy,
            Some(PolicyRef::Inline(vec![ActionName::Quarantine, ActionName::Alert]))
        );
    }

    #[test]
    fn named_policy_resolves() {
        let yaml = r#"
policies:
  strict: [quarantine, alert]
filesystem:
  policy: strict
"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.filesystem.policy, Some(PolicyRef::Named("strict".into())));
        let resolved = cfg.resolve_policy(cfg.filesystem.policy.as_ref(), &[ActionName::Alert]);
        assert_eq!(resolved, vec![ActionName::Quarantine, ActionName::Alert]);
    }

    #[test]
    fn unknown_named_policy_falls_back_to_default() {
        let yaml = r#"filesystem: { policy: nonexistent }"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        let fallback = vec![ActionName::Alert];
        let resolved = cfg.resolve_policy(cfg.filesystem.policy.as_ref(), &fallback);
        assert_eq!(resolved, fallback);
    }

    #[test]
    fn severity_enum_in_script_pattern() {
        let yaml = r#"
filesystem:
  scripts:
    enabled: true
    patterns:
      - name: test_rule
        regex: 'foo'
        severity: critical
"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.filesystem.scripts.patterns[0].severity, Severity::Critical);
    }

    #[test]
    fn alert_on_enum_deserializes() {
        let yaml = r#"
ports:
  enabled: true
  process_rules:
    - name: nc
      alert_on: any_listen
"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.ports.process_rules[0].alert_on, AlertOn::AnyListen);
    }

    #[test]
    fn expand_path_replaces_tilde() {
        let p    = Config::expand_path("~/.tav/quarantine");
        let home = std::env::var("HOME").unwrap();
        assert_eq!(p, PathBuf::from(home).join(".tav/quarantine"));
    }
}
