// Heuristic-based zero-day detection
// Analyzes behavioral patterns without signatures

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Heuristic analyzer for zero-day threat detection
pub struct HeuristicAnalyzer {
    spawn_tracker: HashMap<u32, Vec<Instant>>,
    entropy_threshold: f64,
}

impl Default for HeuristicAnalyzer {
    fn default() -> Self {
        Self {
            spawn_tracker: HashMap::new(),
            entropy_threshold: 4.5,
        }
    }
}

impl HeuristicAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate Shannon entropy of a string
    /// High entropy (>4.5) suggests encoded/encrypted content
    pub fn calculate_entropy(&self, data: &str) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq: HashMap<char, usize> = HashMap::new();
        for c in data.chars() {
            *freq.entry(c).or_insert(0) += 1;
        }

        let len = data.len() as f64;
        freq.values()
            .map(|&count| {
                let p = count as f64 / len;
                if p > 0.0 {
                    -p * p.log2()
                } else {
                    0.0
                }
            })
            .sum()
    }

    /// Check if command has suspiciously high entropy
    pub fn is_high_entropy(&self, cmdline: &str) -> bool {
        // Only check sufficiently long commands
        if cmdline.len() < 100 {
            return false;
        }
        self.calculate_entropy(cmdline) > self.entropy_threshold
    }

    /// Track process spawn rates to detect fork bombs or rapid execution
    pub fn track_spawn(&mut self, ppid: u32) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(5);
        let threshold = 20;

        let spawns = self.spawn_tracker.entry(ppid).or_insert_with(Vec::new);
        spawns.push(now);

        // Remove old entries
        spawns.retain(|t| now.duration_since(*t) < window);

        spawns.len() > threshold
    }

    /// Check for suspicious command patterns
    pub fn check_suspicious_patterns(&self, cmdline: &str) -> Vec<&'static str> {
        let mut findings = Vec::new();

        // Very long command (possible payload)
        if cmdline.len() > 2000 {
            findings.push("extremely_long_command");
        }

        // Multiple pipes (complex evasion chain)
        if cmdline.matches('|').count() > 5 {
            findings.push("excessive_pipes");
        }

        // Multiple redirections
        if cmdline.matches('>').count() > 3 {
            findings.push("excessive_redirects");
        }

        // Nested command substitution
        if cmdline.matches("$(").count() > 2 || cmdline.matches('`').count() > 4 {
            findings.push("nested_substitution");
        }

        findings
    }

    /// Analyze a process for heuristic anomalies
    pub fn analyze(&mut self, ppid: u32, cmdline: &str) -> HeuristicResult {
        let mut result = HeuristicResult::default();

        if self.is_high_entropy(cmdline) {
            result.high_entropy = true;
            result.score += 30;
        }

        if self.track_spawn(ppid) {
            result.rapid_spawn = true;
            result.score += 50;
        }

        let patterns = self.check_suspicious_patterns(cmdline);
        if !patterns.is_empty() {
            result.suspicious_patterns = patterns;
            result.score += 20;
        }

        result
    }
}

#[derive(Default, Debug)]
pub struct HeuristicResult {
    pub score: u32,
    pub high_entropy: bool,
    pub rapid_spawn: bool,
    pub suspicious_patterns: Vec<&'static str>,
}

impl HeuristicResult {
    pub fn is_suspicious(&self) -> bool {
        self.score >= 30
    }

    pub fn is_critical(&self) -> bool {
        self.score >= 70
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let analyzer = HeuristicAnalyzer::new();

        // Low entropy (repeated chars)
        let low = analyzer.calculate_entropy("aaaaaaaaaa");
        assert!(low < 1.0);

        // Higher entropy (random-ish)
        let high = analyzer.calculate_entropy("aGVsbG8gd29ybGQhIHRoaXMgaXMgYSB0ZXN0");
        assert!(high > 3.0);
    }

    #[test]
    fn test_suspicious_patterns() {
        let analyzer = HeuristicAnalyzer::new();

        let cmd = "cat file | grep x | sed s/x/y/ | awk '{print}' | sort | uniq | head";
        let patterns = analyzer.check_suspicious_patterns(cmd);
        assert!(patterns.contains(&"excessive_pipes"));
    }
}
