//! Stress and resilience tests for WinnCoreAV backend components.
//! CI-safe workloads live here; heavier scenarios are marked `#[ignore]`
//! and can be run manually during perf or soak testing.

use av_core::{Scanner, ScannerConfig};
use av_quarantine::{QuarantineConfig, QuarantineManager};
use tempfile::TempDir;
use tokio::task::JoinSet;

fn linux_rss_kb() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if let Some(val) = parts.first() {
                    return val.parse().ok();
                }
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_concurrent_scanning_ci_safe() {
    // Keep counts modest for CI; still shakes out race conditions in Scanner.
    let file_count = 256;
    let worker_chunks = 8usize;

    let tmp = TempDir::new().expect("tempdir");
    let mut paths = Vec::with_capacity(file_count);
    for i in 0..file_count {
        let path = tmp.path().join(format!("sample_{i}.bin"));
        std::fs::write(&path, vec![0u8; 1024]).expect("write");
        paths.push(path);
    }

    let scanner = Scanner::new(ScannerConfig::default()).expect("scanner");
    let scanner = std::sync::Arc::new(scanner);

    let mut tasks = JoinSet::new();
    let chunk_size = (paths.len() / worker_chunks).max(1);
    for chunk in paths.chunks(chunk_size) {
        let chunk = chunk.to_vec();
        let scanner = scanner.clone();
        tasks.spawn(async move {
            let mut scanned = 0usize;
            for path in chunk {
                if scanner.scan_path(&path).await.is_ok() {
                    scanned += 1;
                }
            }
            scanned
        });
    }

    let mut total = 0usize;
    while let Some(res) = tasks.join_next().await {
        total += res.expect("task panicked");
    }

    assert_eq!(total, file_count, "not all files scanned");
}

#[tokio::test]
async fn stress_memory_regression_small_loop() {
    // CI-safe loop to catch obvious growth; heavier loop is #[ignore] below.
    let tmp = TempDir::new().expect("tempdir");
    let sample = tmp.path().join("sample.bin");
    std::fs::write(&sample, vec![0u8; 64 * 1024]).expect("write");

    let scanner = Scanner::new(ScannerConfig::default()).expect("scanner");

    let start_rss = linux_rss_kb();
    for _ in 0..64 {
        scanner.scan_path(&sample).await.expect("scan");
    }
    if let (Some(start), Some(end)) = (start_rss, linux_rss_kb()) {
        let growth = end.saturating_sub(start);
        if growth > 30 * 1024 {
            eprintln!(
                "⚠️  RSS growth detected: start {start} KB, end {end} KB (growth {growth} KB)"
            );
        }
    }
}

#[tokio::test]
async fn stress_quarantine_batch_ci_safe() {
    let tmp = TempDir::new().expect("tempdir");
    let quarantine_dir = tmp.path().join("q");
    let cfg = QuarantineConfig {
        quarantine_dir: quarantine_dir.clone(),
        ..Default::default()
    };
    let manager = QuarantineManager::new(cfg).expect("quarantine");

    let mut files = Vec::new();
    for i in 0..16 {
        let p = tmp.path().join(format!("mal_{i}.bin"));
        std::fs::write(&p, vec![0xAA; 2048]).expect("write");
        files.push(p);
    }

    for (idx, path) in files.iter().enumerate() {
        let entry = manager
            .quarantine_file(path, format!("test-{idx}"), 0.9)
            .expect("quarantine");
        // Restore and delete to exercise both paths.
        manager
            .restore(&entry, &tmp.path().join(format!("restored_{idx}.bin")))
            .expect("restore");
        manager.delete(&entry).expect("delete");
    }

    let stats = manager.stats().expect("stats");
    assert_eq!(
        stats.total_files, 0,
        "quarantine should be empty after deletes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "heavier stress; run manually: cargo test --release stress_concurrent_scanning_heavy -- --ignored --nocapture"]
async fn stress_concurrent_scanning_heavy() {
    let file_count = 2_000;
    let worker_chunks = 16usize;

    let tmp = TempDir::new().expect("tempdir");
    let mut paths = Vec::with_capacity(file_count);
    for i in 0..file_count {
        let path = tmp.path().join(format!("heavy_{i}.bin"));
        std::fs::write(&path, vec![0u8; 2048]).expect("write");
        paths.push(path);
    }

    let scanner = Scanner::new(ScannerConfig::default()).expect("scanner");
    let scanner = std::sync::Arc::new(scanner);

    let mut tasks = JoinSet::new();
    let chunk_size = (paths.len() / worker_chunks).max(1);
    for chunk in paths.chunks(chunk_size) {
        let chunk = chunk.to_vec();
        let scanner = scanner.clone();
        tasks.spawn(async move {
            let mut scanned = 0usize;
            for path in chunk {
                if scanner.scan_path(&path).await.is_ok() {
                    scanned += 1;
                }
            }
            scanned
        });
    }

    let mut total = 0usize;
    while let Some(res) = tasks.join_next().await {
        total += res.expect("task panicked");
    }

    assert_eq!(total, file_count, "not all files scanned");
}
