//! Concurrent scanning stress: launches a high thread count to shake out
//! contention in the Scanner pipeline. Marked ignored by default.

use av_core::{Scanner, ScannerConfig};
#[path = "stress_common.rs"]
mod stress_common;
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

const DEFAULT_THREADS: usize = 100;
const FILES_PER_THREAD: usize = 128;

#[test]
#[ignore = "high concurrency; run manually: cargo test --release -p av-core stress_concurrent_scanning_ext -- --ignored --nocapture"]
fn stress_concurrent_scanning_ext() {
    stress_common::configure_quiet_mode();

    let threads = std::env::var("WINNCORE_CONC_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_THREADS);

    println!("🚀 launching {threads} concurrent scanner threads");

    let tmp = TempDir::new().expect("tempdir");
    let mut files = Vec::with_capacity(threads * FILES_PER_THREAD);
    for i in 0..threads * FILES_PER_THREAD {
        let path = tmp.path().join(format!("sample_{i}.bin"));
        std::fs::write(&path, vec![0u8; 4096]).expect("write");
        files.push(path);
    }

    let scanner = Arc::new(Scanner::new(ScannerConfig::default()).expect("scanner"));
    let mut handles = Vec::with_capacity(threads);
    for chunk in files.chunks(FILES_PER_THREAD) {
        let scanner = scanner.clone();
        let slice = chunk.to_vec();
        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            for path in slice {
                rt.block_on(scanner.scan_path(&path)).expect("scan");
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.join();
    }
}
