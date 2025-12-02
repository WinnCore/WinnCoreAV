use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use crate::alerts::AlertSeverity;
use crate::rules::{RuleMatch, Severity};

/// A single event that contributed to an attack chain.
#[derive(Debug, Clone)]
pub struct CorrelatedEvent {
    pub rule_match: RuleMatch,
    /// Brief note on why this event was correlated.
    pub rationale: String,
}

/// Represents a sequence of related events that together indicate malicious behavior.
#[derive(Debug, Clone)]
pub struct AttackChain {
    pub id: String,
    pub narrative: String,
    pub severity: AlertSeverity,
    pub events: Vec<CorrelatedEvent>,
    pub primary_pid: u32,
    pub tactics: Vec<String>,
}

/// Correlates individual rule matches into higher-fidelity attack chains.
pub struct CorrelationEngine {
    window_ns: u64,
    min_events: usize,
    max_events_per_pid: usize,
    recent: HashMap<u32, VecDeque<RuleMatch>>,
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self {
            // Five minute sliding window by default
            window_ns: Duration::from_secs(300).as_nanos() as u64,
            min_events: 2,
            max_events_per_pid: 32,
            recent: HashMap::new(),
        }
    }
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a custom time window for correlation.
    pub fn with_window(mut self, window: Duration) -> Self {
        self.window_ns = window.as_nanos() as u64;
        self
    }

    /// Ingest a single rule match. Returns an attack chain when enough related events accumulate.
    pub fn ingest_match(&mut self, rule_match: RuleMatch) -> Option<AttackChain> {
        let pid = rule_match.pid;
        let now = rule_match.timestamp_ns;

        let queue = self.recent.entry(pid).or_insert_with(VecDeque::new);

        // Trim old events that fall outside the correlation window
        let cutoff = now.saturating_sub(self.window_ns);
        while let Some(front) = queue.front() {
            if front.timestamp_ns < cutoff {
                queue.pop_front();
            } else {
                break;
            }
        }

        if queue.len() >= self.max_events_per_pid {
            queue.pop_front();
        }

        queue.push_back(rule_match.clone());

        // Require at least two distinct rules before emitting an attack chain
        let distinct_rules: HashSet<_> = queue.iter().map(|m| m.rule.id.clone()).collect();
        if queue.len() < self.min_events || distinct_rules.len() < 2 {
            return None;
        }

        let chain = Self::build_chain(pid, queue);
        queue.clear(); // Avoid repeatedly emitting the same chain
        Some(chain)
    }

    /// Ingest a batch of matches and return any chains produced.
    pub fn correlate_batch<I>(&mut self, matches: I) -> Vec<AttackChain>
    where
        I: IntoIterator<Item = RuleMatch>,
    {
        let mut chains = Vec::new();
        for m in matches {
            if let Some(chain) = self.ingest_match(m) {
                chains.push(chain);
            }
        }
        chains
    }

    fn build_chain(pid: u32, events: &VecDeque<RuleMatch>) -> AttackChain {
        let mut tactics = Vec::new();
        let mut rule_names = Vec::new();

        for rm in events {
            if let Some(mitre) = &rm.rule.mitre {
                if !tactics.contains(&mitre.tactic) {
                    tactics.push(mitre.tactic.clone());
                }
            }
            rule_names.push(rm.rule.name.clone());
        }

        let severity = events
            .iter()
            .map(|rm| map_severity(rm.rule.severity))
            .max()
            .unwrap_or(AlertSeverity::Low);

        let narrative = if rule_names.is_empty() {
            format!("Correlated activity for pid {}", pid)
        } else {
            format!("{} observed on pid {}", rule_names.join(" -> "), pid)
        };

        let chain_id = events
            .back()
            .map(|rm| format!("chain-{}-{}", pid, rm.timestamp_ns))
            .unwrap_or_else(|| format!("chain-{}-{}", pid, events.len()));

        let correlated_events = events
            .iter()
            .map(|rm| CorrelatedEvent {
                rule_match: rm.clone(),
                rationale: format!("Matched rule {}", rm.rule.id),
            })
            .collect();

        AttackChain {
            id: chain_id,
            narrative,
            severity,
            events: correlated_events,
            primary_pid: pid,
            tactics,
        }
    }
}

fn map_severity(sev: Severity) -> AlertSeverity {
    match sev {
        Severity::Low => AlertSeverity::Low,
        Severity::Medium => AlertSeverity::Medium,
        Severity::High => AlertSeverity::High,
        Severity::Critical => AlertSeverity::Critical,
    }
}
