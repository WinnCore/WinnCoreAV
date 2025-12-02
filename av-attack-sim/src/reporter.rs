//! Report generation for simulation results.

use crate::framework::SimulationResult;
use colored::*;
use std::collections::HashMap;

pub struct Reporter;

impl Reporter {
    pub fn new() -> Self {
        Self
    }

    pub fn print_results(&self, results: &[SimulationResult]) {
        println!("\n{}", "═".repeat(65).cyan());
        println!("  {}", "SIMULATION RESULTS".white().bold());
        println!("{}\n", "═".repeat(65).cyan());

        // Aggregate stats
        let total = results.len();
        let skipped = results.iter().filter(|r| r.skipped).count();
        let testable = total - skipped;

        let should_detect: Vec<_> = results
            .iter()
            .filter(|r| !r.skipped && r.should_detect)
            .collect();
        let detected = should_detect.iter().filter(|r| r.detected).count();
        let missed = should_detect.len() - detected;

        let should_not_detect: Vec<_> = results
            .iter()
            .filter(|r| !r.skipped && !r.should_detect)
            .collect();
        let false_positives = should_not_detect.iter().filter(|r| r.detected).count();

        let detection_rate = if !should_detect.is_empty() {
            (detected as f64 / should_detect.len() as f64) * 100.0
        } else {
            0.0
        };

        println!("  {}", "Overall Statistics".white().bold());
        println!("  {}", "─".repeat(40));
        println!("  Total Simulations:     {}", total);
        println!("  Skipped:               {}", skipped);
        println!("  Testable:              {}", testable);
        println!();
        println!(
            "  {}: {}/{} ({:.1}%)",
            "Detection Rate".green(),
            detected,
            should_detect.len(),
            detection_rate
        );
        println!("  {}: {}", "Missed Detections".red(), missed);
        println!("  {}: {}", "False Positives".yellow(), false_positives);

        let detection_times: Vec<u64> =
            results.iter().filter_map(|r| r.detection_time_ms).collect();
        if !detection_times.is_empty() {
            let avg = detection_times.iter().sum::<u64>() as f64 / detection_times.len() as f64;
            let mut sorted = detection_times.clone();
            sorted.sort_unstable();
            let p95_idx = (sorted.len() as f64 * 0.95) as usize;
            let p99_idx = (sorted.len() as f64 * 0.99) as usize;

            println!();
            println!("  {}", "Detection Latency".white().bold());
            println!("  {}", "─".repeat(40));
            println!("  Average:  {:.1}ms", avg);
            println!("  P95:      {}ms", sorted.get(p95_idx).unwrap_or(&0));
            println!("  P99:      {}ms", sorted.get(p99_idx).unwrap_or(&0));
            println!("  Min:      {}ms", sorted.first().unwrap_or(&0));
            println!("  Max:      {}ms", sorted.last().unwrap_or(&0));
        }

        let mut by_tactic: HashMap<String, (usize, usize)> = HashMap::new();
        for result in results.iter().filter(|r| !r.skipped && r.should_detect) {
            let entry = by_tactic.entry(result.tactic.clone()).or_insert((0, 0));
            entry.0 += 1;
            if result.detected {
                entry.1 += 1;
            }
        }

        println!();
        println!("  {}", "MITRE ATT&CK Coverage".white().bold());
        println!("  {}", "─".repeat(40));
        for (tactic, (total, detected)) in &by_tactic {
            let pct = (*detected as f64 / *total as f64) * 100.0;
            let status = if pct >= 80.0 {
                format!("{:.0}%", pct).green()
            } else if pct >= 50.0 {
                format!("{:.0}%", pct).yellow()
            } else {
                format!("{:.0}%", pct).red()
            };
            println!("  {}: {}/{} ({})", tactic, detected, total, status);
        }

        let failed: Vec<_> = results
            .iter()
            .filter(|r| !r.skipped && r.should_detect && !r.detected)
            .collect();

        if !failed.is_empty() {
            println!();
            println!("  {}", "Failed Detections".red().bold());
            println!("  {}", "─".repeat(40));
            for result in failed {
                println!(
                    "  {} {} - {}",
                    "✗".red(),
                    result.technique_id.yellow(),
                    result.name
                );
                if let Some(ref err) = result.error {
                    println!("    → {}", err.dimmed());
                }
            }
        }

        println!();
        println!("{}", "═".repeat(65).cyan());
        if detection_rate >= 95.0 && false_positives == 0 {
            println!(
                "  {} EXCELLENT - Enterprise-grade detection",
                "✓".green().bold()
            );
        } else if detection_rate >= 80.0 {
            println!("  {} GOOD - Minor improvements needed", "✓".green());
        } else if detection_rate >= 60.0 {
            println!("  {} FAIR - Significant gaps remain", "⚠".yellow());
        } else {
            println!(
                "  {} NEEDS WORK - Detection coverage insufficient",
                "✗".red()
            );
        }
        println!("{}\n", "═".repeat(65).cyan());
    }

    pub fn save_json(&self, results: &[SimulationResult], path: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(results)?;
        std::fs::write(path, json)
    }
}
