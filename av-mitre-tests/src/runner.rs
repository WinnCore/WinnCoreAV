use std::env;
use std::fs;
use std::process::ExitCode;
use std::time::Instant;

use tracing_subscriber::EnvFilter;

use av_mitre_tests::{run_suite, TestReport, TestSuite};

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: mitre-test-runner <suite.yaml>");
        return ExitCode::from(1);
    }

    let path = &args[1];
    let yaml = match fs::read_to_string(path) {
        Ok(y) => y,
        Err(e) => {
            eprintln!("Failed to read {}: {}", path, e);
            return ExitCode::from(1);
        }
    };

    let suite = match TestSuite::from_yaml(&yaml) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to parse suite: {}", e);
            return ExitCode::from(1);
        }
    };

    let start = Instant::now();
    let results = run_suite(&suite);
    let mut report = TestReport::from_results(&suite.name, &results);
    report.execution_time_secs = start.elapsed().as_secs_f64();
    report.print_summary();

    // Return non-zero if any tests failed unexpectedly
    if report.failed > 0 || report.errors > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
