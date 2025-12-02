//! Test result reporting.

use std::collections::HashMap;

use serde::Serialize;

use crate::framework::{TestResult, TestStatus};

/// Summary report of test suite execution.
#[derive(Debug, Clone, Serialize)]
pub struct TestReport {
    pub suite_name: String,
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub errors: usize,
    pub detection_rate: f64,
    pub coverage_by_tactic: HashMap<String, TacticCoverage>,
    pub coverage_by_technique: HashMap<String, TechniqueCoverage>,
    pub failed_tests: Vec<FailedTest>,
    pub execution_time_secs: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TacticCoverage {
    pub tactic: String,
    pub total: usize,
    pub detected: usize,
    pub coverage_percent: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TechniqueCoverage {
    pub technique_id: String,
    pub tested: bool,
    pub detected: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FailedTest {
    pub test_id: String,
    pub technique_id: String,
    pub reason: String,
}

impl TestReport {
    pub fn from_results(suite_name: &str, results: &[TestResult]) -> Self {
        let total_tests = results.len();
        let passed = results
            .iter()
            .filter(|r| r.status == TestStatus::Passed)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.status == TestStatus::Failed)
            .count();
        let skipped = results
            .iter()
            .filter(|r| r.status == TestStatus::Skipped)
            .count();
        let errors = results
            .iter()
            .filter(|r| r.status == TestStatus::Error)
            .count();

        let detected_count = results.iter().filter(|r| r.detected).count();
        let testable = total_tests - skipped - errors;
        let detection_rate = if testable > 0 {
            detected_count as f64 / testable as f64 * 100.0
        } else {
            0.0
        };

        let failed_tests: Vec<FailedTest> = results
            .iter()
            .filter(|r| r.status == TestStatus::Failed)
            .map(|r| FailedTest {
                test_id: r.test_id.clone(),
                technique_id: r.technique_id.clone(),
                reason: if r.detected {
                    "Unexpected detection".to_string()
                } else {
                    "Expected detection missing".to_string()
                },
            })
            .collect();

        // Build technique coverage
        let mut coverage_by_technique = HashMap::new();
        for result in results {
            coverage_by_technique.insert(
                result.technique_id.clone(),
                TechniqueCoverage {
                    technique_id: result.technique_id.clone(),
                    tested: result.status != TestStatus::Skipped,
                    detected: result.detected,
                },
            );
        }

        let execution_time_secs = results
            .iter()
            .map(|r| r.execution_time_ms as f64 / 1000.0)
            .sum();

        Self {
            suite_name: suite_name.to_string(),
            total_tests,
            passed,
            failed,
            skipped,
            errors,
            detection_rate,
            coverage_by_tactic: HashMap::new(),
            coverage_by_technique,
            failed_tests,
            execution_time_secs,
        }
    }

    pub fn print_summary(&self) {
        println!("\n═══════════════════════════════════════════════════════════════");
        println!("  MITRE ATT&CK Test Report: {}", self.suite_name);
        println!("═══════════════════════════════════════════════════════════════\n");

        println!("Results:");
        println!("  Total Tests:     {}", self.total_tests);
        println!("  Passed:          {} ✓", self.passed);
        println!("  Failed:          {} ✗", self.failed);
        println!("  Skipped:         {}", self.skipped);
        println!("  Errors:          {}", self.errors);
        println!();
        println!("  Detection Rate:  {:.1}%", self.detection_rate);
        println!("  Execution Time:  {:.2}s", self.execution_time_secs);

        if !self.failed_tests.is_empty() {
            println!("\nFailed Tests:");
            for test in &self.failed_tests {
                println!(
                    "  - {} ({}): {}",
                    test.test_id, test.technique_id, test.reason
                );
            }
        }

        println!("\n═══════════════════════════════════════════════════════════════\n");
    }
}
