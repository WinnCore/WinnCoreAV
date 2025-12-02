//! Test execution engine.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tracing::{error, info, warn};

use crate::framework::{DetectionDetails, TestCase, TestResult, TestStatus};

/// Execute a single test case.
pub fn execute_test(test: &TestCase) -> TestResult {
    info!("Executing test: {} ({})", test.name, test.technique_id);

    let start = Instant::now();

    // Check platform compatibility
    if !test.platforms.contains(&"linux".to_string()) {
        return TestResult {
            test_id: test.id.clone(),
            technique_id: test.technique_id.clone(),
            status: TestStatus::Skipped,
            execution_time_ms: 0,
            detected: false,
            detection_details: None,
            error: Some("Platform not supported".to_string()),
        };
    }

    // Execute the attack commands
    let execution_result = match test.executor.executor_type.as_str() {
        "bash" | "sh" => execute_bash(&test.executor.commands, test.executor.timeout_secs),
        "command_prompt" | "cmd" => {
            execute_bash(&test.executor.commands, test.executor.timeout_secs)
        }
        _ => Err(format!("Unknown executor: {}", test.executor.executor_type)),
    };

    let execution_time_ms = start.elapsed().as_millis() as u64;

    match execution_result {
        Ok(output) => {
            if !output.is_empty() {
                info!("Test output: {}", output.trim());
            }

            // Give EDR time to detect
            std::thread::sleep(Duration::from_millis(500));

            // Check for detection (would query EDR alert API)
            let (detected, details) = check_detection(&test.technique_id);

            let status = if test.expected_detection.should_detect == detected {
                TestStatus::Passed
            } else {
                TestStatus::Failed
            };

            // Run cleanup
            if let Some(ref cleanup_cmds) = test.cleanup {
                let _ = execute_bash(cleanup_cmds, 30);
            }

            TestResult {
                test_id: test.id.clone(),
                technique_id: test.technique_id.clone(),
                status,
                execution_time_ms,
                detected,
                detection_details: details,
                error: None,
            }
        }
        Err(e) => {
            error!("Test execution failed: {}", e);
            TestResult {
                test_id: test.id.clone(),
                technique_id: test.technique_id.clone(),
                status: TestStatus::Error,
                execution_time_ms,
                detected: false,
                detection_details: None,
                error: Some(e),
            }
        }
    }
}

fn execute_bash(commands: &[String], _timeout_secs: u32) -> Result<String, String> {
    let script = commands.join("\n");

    let child = Command::new("bash")
        .arg("-c")
        .arg(&script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn bash: {}", e))?;

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for bash: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() && !stderr.is_empty() {
        warn!("Command stderr: {}", stderr);
    }

    Ok(stdout)
}

fn check_detection(_technique_id: &str) -> (bool, Option<DetectionDetails>) {
    // In real implementation, query EDR alert API
    // For now, return false (no detection)
    (false, None)
}

/// Run all tests in a suite.
pub fn run_suite(suite: &crate::framework::TestSuite) -> Vec<TestResult> {
    info!(
        "Running test suite: {} ({} tests)",
        suite.name,
        suite.tests.len()
    );

    let mut results = Vec::new();

    for test in &suite.tests {
        let result = execute_test(test);
        info!(
            "Test {} ({}): {:?}",
            test.id, test.technique_id, result.status
        );
        results.push(result);
    }

    results
}
