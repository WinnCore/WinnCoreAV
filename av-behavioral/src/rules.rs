use av_ebpf_common::{EventType, ProcessExecEvent};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub tactic: String,
    pub technique: String,
    #[serde(default)]
    pub sub_technique: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Medium
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub technique: String,
    #[serde(default)]
    pub tactic: String,
    #[serde(default)]
    pub severity: Severity,
    pub description: String,
    #[serde(default)]
    pub mitre: Option<MitreMapping>,
    pub condition: RuleCondition,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub cmdline_contains_any: Vec<String>,
    #[serde(default)]
    pub cmdline_contains_all: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuleEngineError {
    #[error("invalid regex in rule {rule_id} ({pattern}): {source}")]
    InvalidRegex {
        rule_id: String,
        pattern: String,
        source: regex::Error,
    },
}

struct CompiledRule {
    rule: Arc<Rule>,
    any_patterns: Vec<Regex>,
    all_patterns: Vec<Regex>,
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule: Arc<Rule>,
    pub event_type: EventType,
    pub pid: u32,
    pub ppid: u32,
    pub timestamp_ns: u64,
    pub comm: Option<String>,
    pub cmdline: Option<String>,
    pub matched_fields: HashMap<String, String>,
    pub matched_any: Vec<String>,
    pub matched_all: Vec<String>,
}

pub struct RuleEngine {
    compiled: Vec<CompiledRule>,
    regex_cache: HashMap<String, Regex>,
}

impl RuleEngine {
    pub fn new() -> Self {
        RuleEngine {
            compiled: Vec::new(),
            regex_cache: HashMap::new(),
        }
    }

    /// Load rules; malformed patterns are skipped individually without failing the engine.
    pub fn load_rules(&mut self, rules: Vec<Rule>) {
        self.compiled.clear();

        for rule in rules.into_iter().filter(|r| r.enabled) {
            let any = self.compile_patterns(&rule.id, &rule.condition.cmdline_contains_any);
            let all = self.compile_patterns(&rule.id, &rule.condition.cmdline_contains_all);

            self.compiled.push(CompiledRule {
                rule: Arc::new(rule),
                any_patterns: any,
                all_patterns: all,
            });
        }
    }

    fn compile_patterns(&mut self, rule_id: &str, patterns: &[String]) -> Vec<Regex> {
        let mut compiled = Vec::with_capacity(patterns.len());

        for pat in patterns {
            if let Some(cached) = self.regex_cache.get(pat) {
                compiled.push(cached.clone());
                continue;
            }

            let pattern = format!("(?i){}", pat);
            match Regex::new(&pattern) {
                Ok(re) => {
                    self.regex_cache.insert(pat.clone(), re.clone());
                    compiled.push(re);
                }
                Err(first_err) => {
                    let escaped = format!("(?i){}", regex::escape(pat));
                    match Regex::new(&escaped) {
                        Ok(fallback) => {
                            self.regex_cache.insert(pat.clone(), fallback.clone());
                            compiled.push(fallback);
                            warn!(
                                rule_id = %rule_id,
                                pattern = %pat,
                                error = %first_err,
                                "Failed to compile pattern; using escaped fallback"
                            );
                        }
                        Err(second_err) => {
                            warn!(
                                rule_id = %rule_id,
                                pattern = %pat,
                                error = %second_err,
                                "Skipping pattern; failed to compile even after escaping"
                            );
                        }
                    }
                }
            }
        }

        compiled
    }

    pub fn evaluate_process(&self, event: &ProcessExecEvent) -> Vec<RuleMatch> {
        let cmdline = event.args_str();
        let mut out = Vec::new();

        for compiled in &self.compiled {
            // Only process rules intended for process command lines.
            if compiled.rule.condition.kind.to_lowercase() != "process" {
                continue;
            }

            let mut matched_any = Vec::new();
            let mut matched_all = Vec::new();

            if !compiled.any_patterns.is_empty() {
                if compiled.any_patterns.iter().any(|re| re.is_match(cmdline)) {
                    matched_any = compiled
                        .any_patterns
                        .iter()
                        .filter(|re| re.is_match(cmdline))
                        .map(|re| re.as_str().to_string())
                        .collect();
                } else {
                    continue;
                }
            }

            if !compiled.all_patterns.is_empty() {
                if compiled.all_patterns.iter().all(|re| re.is_match(cmdline)) {
                    matched_all = compiled
                        .all_patterns
                        .iter()
                        .map(|re| re.as_str().to_string())
                        .collect();
                } else {
                    continue;
                }
            }

            let mut matched_fields = HashMap::new();
            matched_fields.insert("cmdline".to_string(), cmdline.to_string());
            matched_fields.insert("comm".to_string(), event.comm_str().to_string());

            out.push(RuleMatch {
                rule: compiled.rule.clone(),
                event_type: EventType::ProcessExec,
                pid: event.pid,
                ppid: event.ppid,
                timestamp_ns: event.timestamp_ns,
                comm: Some(event.comm_str().to_string()),
                cmdline: Some(cmdline.to_string()),
                matched_fields,
                matched_any,
                matched_all,
            });
        }

        out
    }
}
