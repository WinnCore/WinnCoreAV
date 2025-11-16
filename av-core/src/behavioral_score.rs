//! Behavioral scoring engine - combines all detection signals
//!
//! This module aggregates scores from multiple detection layers:
//! - LOTL behavioral events (python -c, bash shells, etc.)
//! - Process tree analysis (suspicious parent-child relationships)
//! - Network behavior (C2, beaconing, malicious IPs)
//! - Fileless malware (memfd, injection, /dev/shm)
//!
//! The final score represents overall system compromise risk.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralScore {
    /// Overall behavioral threat score (0.0 - 1.0)
    pub overall_score: f32,
    /// Component scores
    pub component_scores: ComponentScores,
    /// Risk level based on overall score
    pub risk_level: RiskLevel,
    /// Human-readable assessment
    pub assessment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentScores {
    /// Score from LOTL events (0.0 - 1.0)
    pub lotl_events_score: f32,
    /// Score from process tree analysis (0.0 - 1.0)
    pub process_tree_score: f32,
    /// Score from network behavior (0.0 - 1.0)
    pub network_behavior_score: f32,
    /// Score from fileless malware detection (0.0 - 1.0)
    pub fileless_malware_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    /// No significant threats detected
    Clean,
    /// Low suspicion, monitoring recommended
    Low,
    /// Medium suspicion, investigation recommended
    Medium,
    /// High suspicion, immediate action recommended
    High,
    /// Critical threat, system likely compromised
    Critical,
}

impl RiskLevel {
    /// Convert risk level to recommended action
    pub fn to_action(&self) -> crate::RecommendedAction {
        match self {
            RiskLevel::Clean | RiskLevel::Low => crate::RecommendedAction::Allow,
            RiskLevel::Medium => crate::RecommendedAction::Monitor,
            RiskLevel::High | RiskLevel::Critical => crate::RecommendedAction::Quarantine,
        }
    }
}

/// Scoring engine that combines all behavioral signals
pub struct BehavioralScoringEngine {
    /// Weights for each component (must sum to 1.0)
    weights: ScoringWeights,
}

#[derive(Debug, Clone)]
pub struct ScoringWeights {
    pub lotl_events: f32,
    pub process_tree: f32,
    pub network_behavior: f32,
    pub fileless_malware: f32,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            // Balanced weighting across all components
            lotl_events: 0.25,
            process_tree: 0.25,
            network_behavior: 0.25,
            fileless_malware: 0.25,
        }
    }
}

impl BehavioralScoringEngine {
    pub fn new() -> Self {
        Self {
            weights: ScoringWeights::default(),
        }
    }

    /// Create engine with custom weights
    pub fn with_weights(weights: ScoringWeights) -> Self {
        // Normalize weights to sum to 1.0
        let total = weights.lotl_events
            + weights.process_tree
            + weights.network_behavior
            + weights.fileless_malware;

        let weights = if total > 0.0 {
            ScoringWeights {
                lotl_events: weights.lotl_events / total,
                process_tree: weights.process_tree / total,
                network_behavior: weights.network_behavior / total,
                fileless_malware: weights.fileless_malware / total,
            }
        } else {
            ScoringWeights::default()
        };

        Self { weights }
    }

    /// Calculate overall behavioral score from event summary
    pub fn calculate_score(&self, summary: &crate::EventSummary) -> BehavioralScore {
        // Calculate component scores
        let lotl_score = self.calculate_lotl_score(summary);
        let process_tree_score = self.calculate_process_tree_score(summary);
        let network_score = self.calculate_network_score(summary);
        let fileless_score = self.calculate_fileless_score(summary);

        let component_scores = ComponentScores {
            lotl_events_score: lotl_score,
            process_tree_score,
            network_behavior_score: network_score,
            fileless_malware_score: fileless_score,
        };

        // Calculate weighted overall score
        let overall_score = (lotl_score * self.weights.lotl_events)
            + (process_tree_score * self.weights.process_tree)
            + (network_score * self.weights.network_behavior)
            + (fileless_score * self.weights.fileless_malware);

        // Determine risk level
        let risk_level = Self::score_to_risk_level(overall_score);

        // Generate assessment
        let assessment = Self::generate_assessment(&component_scores, &risk_level);

        BehavioralScore {
            overall_score,
            component_scores,
            risk_level,
            assessment,
        }
    }

    /// Calculate score from LOTL events
    fn calculate_lotl_score(&self, summary: &crate::EventSummary) -> f32 {
        if summary.total_events == 0 {
            return 0.0;
        }

        // Get highest score from most recent event
        let max_event_score = summary
            .most_recent
            .as_ref()
            .map(|e| e.suspicion_score)
            .unwrap_or(0.0);

        // Calculate average score from event distribution
        let high_risk_ratio = summary.high_risk_events as f32 / summary.total_events as f32;
        let medium_risk_ratio = summary.medium_risk_events as f32 / summary.total_events as f32;

        let distribution_score = (high_risk_ratio * 0.9) + (medium_risk_ratio * 0.5);

        // Combine max score and distribution
        let base_score = (max_event_score * 0.7) + (distribution_score * 0.3);

        // Amplify score if many high-risk events
        let count_multiplier = if summary.high_risk_events > 5 {
            1.2
        } else if summary.high_risk_events > 2 {
            1.1
        } else {
            1.0
        };

        (base_score * count_multiplier).min(1.0)
    }

    /// Calculate score from process tree analysis
    fn calculate_process_tree_score(&self, summary: &crate::EventSummary) -> f32 {
        if summary.suspicious_relationships.is_empty() {
            return 0.0;
        }

        // Get maximum score from relationships
        let max_score = summary
            .suspicious_relationships
            .iter()
            .map(|r| r.suspicion_score)
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(0.0);

        // Calculate average score
        let avg_score: f32 = summary
            .suspicious_relationships
            .iter()
            .map(|r| r.suspicion_score)
            .sum::<f32>()
            / summary.suspicious_relationships.len() as f32;

        // Combine max and average (max has more weight)
        let base_score = (max_score * 0.7) + (avg_score * 0.3);

        // Amplify if multiple suspicious relationships
        let count_multiplier = if summary.suspicious_relationships.len() > 3 {
            1.2
        } else if summary.suspicious_relationships.len() > 1 {
            1.1
        } else {
            1.0
        };

        (base_score * count_multiplier).min(1.0)
    }

    /// Calculate score from network behavior
    fn calculate_network_score(&self, summary: &crate::EventSummary) -> f32 {
        if summary.network_events.is_empty() {
            return 0.0;
        }

        // Get maximum score from network events
        let max_score = summary
            .network_events
            .iter()
            .map(|e| e.suspicion_score)
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(0.0);

        // Check for beaconing (very suspicious)
        let has_beaconing = summary
            .network_stats
            .as_ref()
            .map(|s| s.beaconing_connections > 0)
            .unwrap_or(false);

        let beaconing_bonus = if has_beaconing { 0.15 } else { 0.0 };

        // Check for multiple network threats
        let threat_count = summary.network_events.len();
        let count_multiplier = if threat_count > 5 {
            1.3
        } else if threat_count > 2 {
            1.15
        } else {
            1.0
        };

        ((max_score + beaconing_bonus) * count_multiplier).min(1.0)
    }

    /// Calculate score from fileless malware detection
    fn calculate_fileless_score(&self, summary: &crate::EventSummary) -> f32 {
        if summary.fileless_events.is_empty() {
            return 0.0;
        }

        // Get maximum score from fileless events
        let max_score = summary
            .fileless_events
            .iter()
            .map(|e| e.suspicion_score)
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(0.0);

        // Check for injection (very serious)
        let has_injection = summary.fileless_stats.as_ref().map(|s| s.total_injection_targets > 0).unwrap_or(false);

        let injection_bonus = if has_injection { 0.2 } else { 0.0 };

        // Check for memfd (also serious)
        let has_memfd = summary
            .fileless_stats
            .as_ref()
            .map(|s| s.total_memfd_processes > 0)
            .unwrap_or(false);

        let memfd_bonus = if has_memfd { 0.1 } else { 0.0 };

        (max_score + injection_bonus + memfd_bonus).min(1.0)
    }

    /// Convert numeric score to risk level
    fn score_to_risk_level(score: f32) -> RiskLevel {
        if score >= 0.90 {
            RiskLevel::Critical
        } else if score >= 0.75 {
            RiskLevel::High
        } else if score >= 0.50 {
            RiskLevel::Medium
        } else if score >= 0.25 {
            RiskLevel::Low
        } else {
            RiskLevel::Clean
        }
    }

    /// Generate human-readable assessment
    fn generate_assessment(scores: &ComponentScores, risk: &RiskLevel) -> String {
        let mut parts = Vec::new();

        // Risk level summary
        match risk {
            RiskLevel::Critical => parts.push("CRITICAL THREAT: System likely compromised".to_string()),
            RiskLevel::High => parts.push("HIGH RISK: Multiple serious threats detected".to_string()),
            RiskLevel::Medium => parts.push("MEDIUM RISK: Suspicious activity detected".to_string()),
            RiskLevel::Low => parts.push("LOW RISK: Minor suspicious indicators".to_string()),
            RiskLevel::Clean => parts.push("CLEAN: No significant threats detected".to_string()),
        }

        // Component details
        let mut components = Vec::new();
        if scores.lotl_events_score > 0.5 {
            components.push(format!("LOTL activity ({:.0}%)", scores.lotl_events_score * 100.0));
        }
        if scores.process_tree_score > 0.5 {
            components.push(format!("suspicious processes ({:.0}%)", scores.process_tree_score * 100.0));
        }
        if scores.network_behavior_score > 0.5 {
            components.push(format!("network threats ({:.0}%)", scores.network_behavior_score * 100.0));
        }
        if scores.fileless_malware_score > 0.5 {
            components.push(format!("fileless malware ({:.0}%)", scores.fileless_malware_score * 100.0));
        }

        if !components.is_empty() {
            parts.push(format!("Detected: {}", components.join(", ")));
        }

        parts.join(". ")
    }
}

impl Default for BehavioralScoringEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_scoring() {
        assert_eq!(
            BehavioralScoringEngine::score_to_risk_level(0.95),
            RiskLevel::Critical
        );
        assert_eq!(
            BehavioralScoringEngine::score_to_risk_level(0.80),
            RiskLevel::High
        );
        assert_eq!(
            BehavioralScoringEngine::score_to_risk_level(0.60),
            RiskLevel::Medium
        );
        assert_eq!(
            BehavioralScoringEngine::score_to_risk_level(0.30),
            RiskLevel::Low
        );
        assert_eq!(
            BehavioralScoringEngine::score_to_risk_level(0.10),
            RiskLevel::Clean
        );
    }

    #[test]
    fn test_weights_normalization() {
        let weights = ScoringWeights {
            lotl_events: 2.0,
            process_tree: 2.0,
            network_behavior: 2.0,
            fileless_malware: 2.0,
        };

        let engine = BehavioralScoringEngine::with_weights(weights);

        // Should normalize to 0.25 each
        assert!((engine.weights.lotl_events - 0.25).abs() < 0.01);
        assert!((engine.weights.process_tree - 0.25).abs() < 0.01);
    }

    #[test]
    fn test_risk_level_to_action() {
        assert_eq!(
            RiskLevel::Clean.to_action(),
            crate::RecommendedAction::Allow
        );
        assert_eq!(
            RiskLevel::Low.to_action(),
            crate::RecommendedAction::Allow
        );
        assert_eq!(
            RiskLevel::Medium.to_action(),
            crate::RecommendedAction::Monitor
        );
        assert_eq!(
            RiskLevel::High.to_action(),
            crate::RecommendedAction::Quarantine
        );
        assert_eq!(
            RiskLevel::Critical.to_action(),
            crate::RecommendedAction::Quarantine
        );
    }
}
