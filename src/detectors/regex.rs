use anyhow::{Context, Result};
use regex::Regex;

/// A compiled set of regex patterns built once at config load.
/// Replaces the per-call `Regex::new()` in the old `compare_regex()`.
#[derive(Clone)]
pub struct RuleSet {
    patterns: Vec<(String, Regex)>,
}

impl RuleSet {
    /// Build from raw pattern strings. Fails fast on the first invalid pattern.
    pub fn compile(patterns: &[String]) -> Result<Self> {
        let compiled = patterns
            .iter()
            .map(|p| {
                let re = Regex::new(&format!("(?mi){}", p))
                    .with_context(|| format!("invalid regex pattern: {:?}", p))?;
                Ok((p.clone(), re))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { patterns: compiled })
    }

    /// Returns the first matching pattern string, or None.
    pub fn first_match<'a>(&'a self, subject: &str) -> Option<&'a str> {
        self.patterns
            .iter()
            .find(|(_, re)| re.is_match(subject))
            .map(|(pat, _)| pat.as_str())
    }

    /// Returns all matching pattern strings.
    pub fn all_matches<'a>(&'a self, subject: &str) -> Vec<&'a str> {
        self.patterns
            .iter()
            .filter(|(_, re)| re.is_match(subject))
            .map(|(pat, _)| pat.as_str())
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_case_insensitive() {
        let rules = RuleSet::compile(&["badfile.*".to_string()]).unwrap();
        assert!(rules.first_match("BADFILE123").is_some());
        assert!(rules.first_match("/tmp/BadFile.exe").is_some());
        assert!(rules.first_match("clean.txt").is_none());
    }

    #[test]
    fn invalid_pattern_fails_fast() {
        let result = RuleSet::compile(&["[invalid".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn all_matches_returns_multiple() {
        let rules = RuleSet::compile(&[
            "bad".to_string(),
            "evil".to_string(),
        ]).unwrap();
        let hits = rules.all_matches("badevilfile");
        assert_eq!(hits.len(), 2);
    }
}
