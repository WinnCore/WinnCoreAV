//! Memory pressure stress test. Intentionally allocates a large buffer to
//! simulate constrained environments and ensures scanning degrades
//! gracefully. Marked `#[ignore]` to avoid accidental OOM in CI.

use av_core::{Scanner, ScannerConfig};
use std::time::Duration;

const DEFAULT_MEMORY_MB: usize = 2048;
const DEFAULT_SAMPLE_COUNT: usize = 500;

#[test]
#[ignore = "allocates large buffers; run manually with care"]
fn stress_memory_pressure() {
    let target_mb = memory_target_mb();
    println!("🧪 starting memory pressure test target={}MB", target_mb);

    let mut hog: Vec<Vec<u8>> = Vec::new();
    for _ in 0..target_mb {
        // 1MB chunks to give allocator chances to release.
        hog.push(vec![0u8; 1024 * 1024]);
    }
    println!("💾 allocated ~{} MB; beginning scans", target_mb);

    let corpus = discover_corpus(DEFAULT_SAMPLE_COUNT);
    let scanner = Scanner::new(ScannerConfig::default()).expect("scanner");
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    let mut successes = 0usize;
    let mut failures = 0usize;
    for path in corpus {
        match rt.block_on(scanner.scan_path(&path)) {
            Ok(_) => successes += 1,
            Err(err) => {
                failures += 1;
                eprintln!("scan failed on {:?}: {err}", path);
            }
        }
    }

    drop(hog);
    // Small sleep to allow allocator to release and avoid noisy output.
    std::thread::sleep(Duration::from_millis(200));

    println!("📊 memory pressure results: ok={} fail={}", successes, failures);
    assert!(
        successes > failures * 9,
        "too many scan failures under pressure: ok={} fail={}",
        successes,
        failures
    );
}

fn memory_target_mb() -> usize {
    std::env::var("WINNCORE_MEM_STRESS_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MEMORY_MB)
}

fn discover_corpus(limit: usize) -> Vec<std::path::PathBuf> {
    std::fs::read_dir("/usr/bin")
        .unwrap_or_else(|_| panic!("failed to read /usr/bin for corpus"))
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .take(limit)
        .map(|e| e.path())
        .collect()
}
