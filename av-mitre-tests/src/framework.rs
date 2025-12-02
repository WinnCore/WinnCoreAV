//! Test framework definitions.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A MITRE ATT&CK test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub id: String,
    pub name: String,
    pub description: String,
    /// MITRE ATT&CK technique ID (e.g., T1059.004)
    pub technique_id: String,
    /// Tactic (e.g., execution, persistence)
    pub tactic: String,
    /// Platform requirements
    pub platforms: Vec<String>,
    /// Commands to execute the test
    pub executor: TestExecutor,
    /// Cleanup commands
    pub cleanup: Option<Vec<String>>,
    /// Expected detection
    pub expected_detection: ExpectedDetection,
    /// Dependencies (other tests that must pass first)
    #[serde(default)]
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestExecutor {
    /// Executor type: bash, python, manual
    pub executor_type: String,
    /// Commands to run
    pub commands: Vec<String>,
    /// Expected exit code (0 for success)
    pub expected_exit_code: Option<i32>,
    /// Timeout in seconds
    pub timeout_secs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedDetection {
    /// Should this be detected?
    pub should_detect: bool,
    /// Expected alert severity
    pub severity: Option<String>,
    /// Expected rule ID that should fire
    pub rule_id: Option<String>,
    /// Expected MITRE technique in alert
    pub technique_match: bool,
}

/// Result of running a test case.
#[derive(Debug, Clone, Serialize)]
pub struct TestResult {
    pub test_id: String,
    pub technique_id: String,
    pub status: TestStatus,
    pub execution_time_ms: u64,
    pub detected: bool,
    pub detection_details: Option<DetectionDetails>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TestStatus {
    Passed,
    Failed,
    Skipped,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionDetails {
    pub alert_count: u32,
    pub rule_ids: Vec<String>,
    pub severities: Vec<String>,
    pub time_to_detect_ms: u64,
}

/// Test suite containing multiple test cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuite {
    pub name: String,
    pub version: String,
    pub tests: Vec<TestCase>,
}

impl TestSuite {
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    pub fn tests_by_tactic(&self) -> HashMap<String, Vec<&TestCase>> {
        let mut by_tactic: HashMap<String, Vec<&TestCase>> = HashMap::new();
        for test in &self.tests {
            by_tactic.entry(test.tactic.clone()).or_default().push(test);
        }
        by_tactic
    }

    pub fn tests_by_technique(&self) -> HashMap<String, Vec<&TestCase>> {
        let mut by_technique: HashMap<String, Vec<&TestCase>> = HashMap::new();
        for test in &self.tests {
            by_technique
                .entry(test.technique_id.clone())
                .or_default()
                .push(test);
        }
        by_technique
    }
}
