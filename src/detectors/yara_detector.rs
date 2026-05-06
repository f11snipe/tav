use std::path::Path;
use anyhow::Result;
use async_trait::async_trait;
use crate::config::Severity;
use super::content::{ContentDetector, DetectorMatch};

pub struct YaraDetector {
    rules: yara::Rules,
}

impl YaraDetector {
    /// Compile all `.yar` / `.yara` files found under `dir` into a single ruleset.
    pub fn from_rules_dir(dir: &Path) -> Result<Self> {
        if !dir.exists() {
            anyhow::bail!("yara rules directory not found: {}", dir.display());
        }

        let mut compiler = yara::Compiler::new()?;
        let mut loaded = 0usize;

        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let ext = entry.path().extension().and_then(|x| x.to_str()).unwrap_or("");
            if !matches!(ext, "yar" | "yara") { continue; }
            // add_rules_file is builder-style: takes self, returns self
            compiler = compiler.add_rules_file(entry.path())
                .map_err(|e| anyhow::anyhow!("yara compile error in {}: {:?}", entry.path().display(), e))?;
            loaded += 1;
        }

        tracing::info!("yara: compiled {} rule file(s) from {}", loaded, dir.display());
        Ok(Self { rules: compiler.compile_rules()? })
    }
}

#[async_trait]
impl ContentDetector for YaraDetector {
    fn name(&self) -> &str { "yara" }

    /// Empty slice = scan all file types (no extension filter).
    fn extensions(&self) -> &[String] { &[] }

    async fn scan(&self, _path: &Path, content: &str) -> Vec<DetectorMatch> {
        let hits = match self.rules.scan_mem(content.as_bytes(), 30) {
            Ok(h)  => h,
            Err(e) => {
                tracing::debug!("yara: scan_mem error: {:?}", e);
                return Vec::new();
            }
        };

        hits.iter().map(|rule| {
            let severity = rule.metadatas.iter()
                .find(|m| m.identifier == "severity")
                .and_then(|m| match &m.value {
                    yara::MetadataValue::String(s) => Some(*s),
                    _ => None,
                })
                .and_then(parse_severity)
                .unwrap_or(Severity::Medium);

            DetectorMatch {
                rule_name:    rule.identifier.to_string(),
                matched_text: String::new(),
                severity,
            }
        }).collect()
    }
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high"     => Some(Severity::High),
        "medium"   => Some(Severity::Medium),
        "low"      => Some(Severity::Low),
        "info"     => Some(Severity::Info),
        _          => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_detector(rules_str: &str) -> YaraDetector {
        let compiler = yara::Compiler::new().unwrap()
            .add_rules_str(rules_str).unwrap();
        YaraDetector { rules: compiler.compile_rules().unwrap() }
    }

    #[tokio::test]
    async fn detects_matching_rule() {
        let d = make_detector(r#"
            rule malware_sig {
                meta:
                    severity = "high"
                strings:
                    $a = "MALWARE_TOKEN"
                condition:
                    $a
            }
        "#);
        let hits = d.scan(Path::new("sample.bin"), "payload MALWARE_TOKEN found").await;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_name, "malware_sig");
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[tokio::test]
    async fn no_match_on_clean_content() {
        let d = make_detector(r#"
            rule malware_sig {
                strings: $a = "MALWARE_TOKEN"
                condition: $a
            }
        "#);
        let hits = d.scan(Path::new("clean.txt"), "this is perfectly clean").await;
        assert!(hits.is_empty());
    }

    #[tokio::test]
    async fn severity_defaults_to_medium_when_absent() {
        let d = make_detector(r#"
            rule no_severity {
                strings: $a = "BADSTUFF"
                condition: $a
            }
        "#);
        let hits = d.scan(Path::new("x.bin"), "BADSTUFF embedded").await;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
    }
}
