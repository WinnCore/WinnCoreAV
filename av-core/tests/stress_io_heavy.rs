//! I/O heavy stress test. Creates a large corpus of small files and scans
//! them concurrently to shake out descriptor leaks and contention. Marked
//! `#[ignore]` by default because it creates tens of thousands of files.

use av_core::{Scanner, ScannerConfig};
#[path = "stress_common.rs"]
mod stress_common;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

const DEFAULT_FILE_COUNT: usize = 50_000;
const DEFAULT_WORKERS: usize = 16;

#[test]
#[ignore = "heavy I/O; run manually: cargo test --release -p av-core stress_io_heavy -- --ignored --nocapture"]
fn stress_io_heavy() {
    stress_common::configure_quiet_mode();

    let file_count = io_file_count();
    let workers = io_workers();
    println!(
        "🚀 starting I/O stress: files={} workers={}",
        file_count, workers
    );

    let tmp = TempDir::new().expect("tempdir");
    let corpus = create_files(tmp.path(), file_count);

    let scanned = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));

    let chunk = (corpus.len() / workers).max(1);
    let mut handles = Vec::with_capacity(workers);
    for (idx, slice) in corpus.chunks(chunk).enumerate() {
        let slice = slice.to_vec();
        let scanned = scanned.clone();
        let errors = errors.clone();
        let handle = thread::spawn(move || {
            let scanner = Scanner::new(ScannerConfig::default()).expect("scanner");
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            for path in slice {
                match rt.block_on(scanner.scan_path(&path)) {
                    Ok(_) => {
                        scanned.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(err) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                        eprintln!("worker {idx} scan error on {:?}: {err}", path);
                    }
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.join();
    }

    let scanned = scanned.load(Ordering::Relaxed);
    let errors = errors.load(Ordering::Relaxed);
    println!(
        "📊 io stress results: scanned={} errors={}",
        scanned, errors
    );
    assert!(
        scanned >= (file_count as u64).saturating_sub(100),
        "not enough files scanned"
    );
    assert!(errors < 100, "too many scan errors: {errors}");
}

fn create_files(root: &std::path::Path, count: usize) -> Vec<PathBuf> {
    (0..count)
        .map(|i| {
            let path = root.join(format!("test_{i}.bin"));
            fs::write(&path, vec![0u8; 1024]).expect("write");
            path
        })
        .collect()
}

fn io_file_count() -> usize {
    std::env::var("WINNCORE_IO_FILES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_FILE_COUNT)
}

fn io_workers() -> usize {
    std::env::var("WINNCORE_IO_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_WORKERS)
}
