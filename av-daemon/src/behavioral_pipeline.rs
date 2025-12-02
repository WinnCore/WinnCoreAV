use crate::heuristics::HeuristicAnalyzer;
use crate::response::ResponseEngine;
use av_behavioral::rules::{Rule, RuleEngine, RuleMatch, Severity};
use av_ebpf_common::ProcessExecEvent;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

const DEFAULT_ALERT_LOG: &str = "/var/log/winncore/alerts.json";

#[derive(Debug, Clone, Serialize)]
pub struct BehavioralAlert {
    pub rule_id: String,
    pub name: String,
    pub severity: String,
    pub technique: String,
    pub tactic: String,
    pub pid: u32,
    pub ppid: u32,
    pub cmdline: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub matched: Vec<String>,
    pub source: String,
}

#[derive(Debug)]
pub enum BehavioralEvent {
    ProcessExec(ProcessExecEvent),
}

pub struct BehavioralRuntime {
    pub event_tx: mpsc::Sender<BehavioralEvent>,
    pub alert_rx: mpsc::Receiver<BehavioralAlert>,
}

#[derive(Debug, Clone)]
pub struct BehavioralConfig {
    pub external_rules_dir: Option<PathBuf>,
    pub alert_log_path: PathBuf,
}

impl Default for BehavioralConfig {
    fn default() -> Self {
        Self {
            external_rules_dir: Some(PathBuf::from("/etc/winncore/rules")),
            alert_log_path: PathBuf::from(DEFAULT_ALERT_LOG),
        }
    }
}

pub struct BehavioralPipeline {
    engine: RuleEngine,
    heuristics: HeuristicAnalyzer,
    response: ResponseEngine,
    config: BehavioralConfig,
}

impl BehavioralPipeline {
    pub async fn new(config: BehavioralConfig) -> anyhow::Result<Self> {
        let mut engine = RuleEngine::new();
        let rules = load_rules(&config).await?;
        engine.load_rules(rules);

        Ok(BehavioralPipeline {
            engine,
            heuristics: HeuristicAnalyzer::new(),
            response: ResponseEngine::new(Default::default()),
            config,
        })
    }

    pub async fn reload_rules(&mut self) -> anyhow::Result<()> {
        let rules = load_rules(&self.config).await?;
        self.engine.load_rules(rules);
        Ok(())
    }

    pub async fn handle_event(
        &mut self,
        event: BehavioralEvent,
        alert_tx: &mpsc::Sender<BehavioralAlert>,
    ) {
        if let BehavioralEvent::ProcessExec(proc_evt) = event {
            self.handle_process_exec(proc_evt, alert_tx).await;
        }
    }

    async fn handle_process_exec(
        &mut self,
        event: ProcessExecEvent,
        alert_tx: &mpsc::Sender<BehavioralAlert>,
    ) {
        let cmdline = event.args_str().to_string();

        let heur = self.heuristics.analyze(event.ppid, &cmdline);
        if heur.is_suspicious() {
            let severity = if heur.is_critical() { "high" } else { "medium" };
            let alert = BehavioralAlert {
                rule_id: "heuristics".to_string(),
                name: "Heuristic anomaly".to_string(),
                severity: severity.to_string(),
                technique: "T1027".to_string(),
                tactic: "Defense Evasion".to_string(),
                pid: event.pid,
                ppid: event.ppid,
                cmdline: cmdline.clone(),
                description: format!(
                    "Heuristic indicators: entropy={}, rapid_spawn={}, patterns={:?}",
                    heur.high_entropy, heur.rapid_spawn, heur.suspicious_patterns
                ),
                timestamp: Utc::now(),
                matched: Vec::new(),
                source: "heuristic".to_string(),
            };
            if let Err(e) = alert_tx.send(alert).await {
                warn!(error = %e, "Failed to send heuristic alert");
            }
        }

        let matches = self.engine.evaluate_process(&event);
        for m in matches {
            self.emit_rule_alert(&event, &cmdline, m, alert_tx).await;
        }
    }

    async fn emit_rule_alert(
        &self,
        event: &ProcessExecEvent,
        cmdline: &str,
        rule_match: RuleMatch,
        alert_tx: &mpsc::Sender<BehavioralAlert>,
    ) {
        let rule = rule_match.rule;
        let severity_str = severity_to_str(&rule.severity).to_string();
        let alert = BehavioralAlert {
            rule_id: rule.id.clone(),
            name: rule.name.clone(),
            severity: severity_str.clone(),
            technique: rule.technique.clone(),
            tactic: rule.tactic.clone(),
            pid: event.pid,
            ppid: event.ppid,
            cmdline: cmdline.to_string(),
            description: rule.description.clone(),
            timestamp: Utc::now(),
            matched: [rule_match.matched_any, rule_match.matched_all].concat(),
            source: "rule".to_string(),
        };

        if let Err(e) = alert_tx.send(alert.clone()).await {
            warn!(error = %e, "Failed to enqueue alert");
        }

        if let Err(e) = persist_alert_line(&self.config.alert_log_path, &alert).await {
            error!(error = %e, "Failed to persist alert log");
        }

        self.response
            .respond(severity_to_str(&rule.severity), event.pid, None);
    }
}

pub async fn start_behavioral_pipeline(
    config: BehavioralConfig,
) -> anyhow::Result<BehavioralRuntime> {
    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let (alert_tx, alert_rx) = mpsc::channel(1024);

    let mut pipeline = BehavioralPipeline::new(config).await?;

    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            pipeline.handle_event(event, &alert_tx).await;
        }
    });

    Ok(BehavioralRuntime { event_tx, alert_rx })
}

async fn load_rules(config: &BehavioralConfig) -> anyhow::Result<Vec<Rule>> {
    let mut map: HashMap<String, Rule> = HashMap::new();

    // Embedded rules
    let embedded_json = include_str!("../../av-behavioral/rules/linux_behavioral.json");
    match serde_json::from_str::<serde_json::Value>(embedded_json) {
        Ok(parsed) => {
            if let Some(arr) = parsed.get("rules").and_then(|v| v.as_array()) {
                for val in arr {
                    match serde_json::from_value::<Rule>(val.clone()) {
                        Ok(rule) => {
                            map.insert(rule.id.clone(), rule);
                        }
                        Err(e) => warn!(error = %e, "Failed to parse embedded rule"),
                    }
                }
            }
        }
        Err(e) => warn!(error = %e, "Failed to parse embedded rules blob"),
    }

    // External overrides
    if let Some(dir) = &config.external_rules_dir {
        if dir.exists() {
            match fs::read_dir(dir).await {
                Ok(mut entries) => {
                    while let Ok(Some(entry)) = entries.next_entry().await {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) != Some("json") {
                            continue;
                        }
                        match load_rules_from_file(&path).await {
                            Ok(file_rules) => {
                                for rule in file_rules {
                                    map.insert(rule.id.clone(), rule);
                                }
                            }
                            Err(e) => warn!(file = %path.display(), error = %e, "Skipping malformed rule file"),
                        }
                    }
                }
                Err(e) => warn!(dir = %dir.display(), error = %e, "Cannot read external rules dir"),
            }
        }
    }

    Ok(map.into_values().collect())
}

async fn load_rules_from_file(path: &Path) -> anyhow::Result<Vec<Rule>> {
    let content = fs::read_to_string(path).await?;
    let parsed: serde_json::Value = serde_json::from_str(&content)?;
    let mut rules = Vec::new();

    if let Some(arr) = parsed.get("rules").and_then(|v| v.as_array()) {
        for val in arr {
            if let Ok(rule) = serde_json::from_value::<Rule>(val.clone()) {
                rules.push(rule);
            } else {
                warn!(file = %path.display(), "Skipping malformed rule entry");
            }
        }
    }

    Ok(rules)
}

fn severity_to_str(sev: &Severity) -> &'static str {
    match sev {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

async fn persist_alert_line(path: &Path, alert: &BehavioralAlert) -> Result<(), std::io::Error> {
    let json_line = match serde_json::to_string(alert) {
        Ok(line) => line,
        Err(_) => return Ok(()), // drop if serialization fails; never panic
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }

    let existing = fs::read(path).await.unwrap_or_default();
    let mut buffer = existing;
    buffer.extend_from_slice(json_line.as_bytes());
    buffer.push(b'\n');

    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, buffer).await?;
    fs::rename(&tmp_path, path).await?;

    info!(file = %path.display(), "Alert log updated atomically");
    Ok(())
}

pub fn log_alert(alert: &BehavioralAlert) {
    match serde_json::to_string(alert) {
        Ok(json) => info!("ALERT: {}", json),
        Err(e) => warn!(error = %e, "Failed to serialize alert for logging"),
    }
}
