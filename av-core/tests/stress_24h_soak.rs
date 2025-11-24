//! 24-Hour soak test scaffold. Marked `#[ignore]` by default.
//! Runs continuous scans over a corpus while sampling memory/CPU to
//! surface leaks or gradual degradation. Duration is configurable via
//! `WINNCORE_SOAK_SECS` (default 24h) so developers can run shorter
//! local soaks without editing code.

use av_core::{Scanner, ScannerConfig};
#[path = "stress_common.rs"]
mod stress_common;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};

const DEFAULT_DURATION_SECS: u64 = 24 * 60 * 60;
const DEFAULT_WORKERS: usize = 8;
const DEFAULT_CORPUS_TARGET: usize = 10_000;
const REPORT_INTERVAL: Duration = Duration::from_secs(300);
const MEMORY_INTERVAL: Duration = Duration::from_secs(60);

#[test]
#[ignore = "long-running soak; run with: cargo test --release -p av-core stress_24h_soak -- --ignored --nocapture"]
fn stress_24h_soak() {
    stress_common::configure_quiet_mode();

    let duration = soak_duration();
    let workers = soak_workers();
    let corpus_size = soak_corpus_target();

    println!(
        "🚀 Starting soak: duration={}s workers={} corpus={}",
        duration.as_secs(),
        workers,
        corpus_size
    );

    let running = Arc::new(AtomicBool::new(true));
    let scans = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));

    let corpus = build_corpus(corpus_size);

    // Memory/CPU monitor
    let monitor_flag = running.clone();
    let monitor = thread::spawn(move || monitor_process(monitor_flag));

    // Progress reporter
    let report_flag = running.clone();
    let report_scans = scans.clone();
    let report_errors = errors.clone();
    let start = Instant::now();
    let reporter = thread::spawn(move || {
        let mut last_scans = 0u64;
        while report_flag.load(Ordering::Relaxed) {
            thread::sleep(REPORT_INTERVAL);
            let total = report_scans.load(Ordering::Relaxed);
            let delta = total.saturating_sub(last_scans);
            last_scans = total;
            let errs = report_errors.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs().max(1);
            println!(
                "📈 elapsed={}s total_scans={} delta={} errors={} avg_sps={:.2}",
                elapsed,
                total,
                delta,
                errs,
                total as f64 / elapsed as f64
            );
        }
    });

    // Scanner workers
    let mut handles = Vec::with_capacity(workers);
    for id in 0..workers {
        let running = running.clone();
        let scans = scans.clone();
        let errors = errors.clone();
        let corpus = corpus.clone();
        let handle = thread::spawn(move || worker_loop(id, corpus, running, scans, errors));
        handles.push(handle);
    }

    // Let test run
    thread::sleep(duration);
    running.store(false, Ordering::Relaxed);
    println!("🛑 Soak duration reached; stopping workers...");

    for h in handles {
        let _ = h.join();
    }
    let _ = reporter.join();
    let _ = monitor.join();

    let total_scans = scans.load(Ordering::Relaxed);
    let total_errors = errors.load(Ordering::Relaxed);

    println!(
        "✅ Soak complete: scans={} errors={} duration={}s",
        total_scans,
        total_errors,
        duration.as_secs()
    );

    assert!(
        total_scans > 1000,
        "Soak ran but scanned too few files; check corpus or duration overrides"
    );
    assert!(
        total_errors < 100,
        "Error count too high during soak: {}",
        total_errors
    );
}

fn worker_loop(
    worker_id: usize,
    corpus: Vec<PathBuf>,
    running: Arc<AtomicBool>,
    scans: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
) {
    let scanner = Scanner::new(ScannerConfig::default()).expect("scanner");
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mut iterations = 0usize;
    while running.load(Ordering::Relaxed) {
        iterations += 1;
        for path in &corpus {
            let res = rt.block_on(scanner.scan_path(path));
            match res {
                Ok(_) => {
                    scans.fetch_add(1, Ordering::Relaxed);
                }
                Err(err) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                    eprintln!("worker {worker_id} scan error on {:?}: {err}", path);
                }
            }
            if !running.load(Ordering::Relaxed) {
                break;
            }
        }
        if iterations.is_multiple_of(50) {
            println!("worker {worker_id} iterations={iterations}");
        }
    }
}

fn monitor_process(running: Arc<AtomicBool>) {
    let pid = Pid::from_u32(std::process::id());
    let mut sys = System::new_all();
    let mut peak = 0u64;
    let mut initial = None;
    while running.load(Ordering::Relaxed) {
        sys.refresh_process(pid);
        if let Some(proc_info) = sys.process(pid) {
            let mem = proc_info.memory();
            peak = peak.max(mem);
            initial.get_or_insert(mem);
            let baseline = initial.unwrap_or(mem).max(1);
            let growth = mem as f64 / baseline as f64;
            println!(
                "💾 rss={} MB peak={} MB growth={:.2}x cpu={:.1}%",
                mem / 1024 / 1024,
                peak / 1024 / 1024,
                growth,
                proc_info.cpu_usage()
            );
            if growth > 1.5 {
                eprintln!("⚠️ memory growth >50% baseline");
            }
        }
        thread::sleep(MEMORY_INTERVAL);
    }
}

fn build_corpus(target: usize) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir("/usr/bin")
        .unwrap_or_else(|_| panic!("failed to read /usr/bin for corpus"))
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    if files.is_empty() {
        panic!("corpus discovery returned zero files");
    }
    while files.len() < target {
        let extend = files.clone();
        files.extend_from_slice(&extend);
    }
    files.truncate(target);
    files
}

fn soak_duration() -> Duration {
    match std::env::var("WINNCORE_SOAK_SECS") {
        Ok(val) => Duration::from_secs(val.parse().unwrap_or(DEFAULT_DURATION_SECS)),
        Err(_) => Duration::from_secs(DEFAULT_DURATION_SECS),
    }
}

fn soak_workers() -> usize {
    std::env::var("WINNCORE_SOAK_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_WORKERS)
}

fn soak_corpus_target() -> usize {
    std::env::var("WINNCORE_SOAK_CORPUS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_CORPUS_TARGET)
}
