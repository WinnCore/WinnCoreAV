//! MITRE ATT&CK test suite.
//!
//! Provides a lightweight runner for Atomic-like tests to validate
//! detection coverage.

pub mod execution;
pub mod framework;
pub mod reporting;
pub mod tests;

pub use execution::{execute_test, run_suite};
pub use framework::{ExpectedDetection, TestCase, TestExecutor, TestResult, TestStatus, TestSuite};
pub use reporting::TestReport;
