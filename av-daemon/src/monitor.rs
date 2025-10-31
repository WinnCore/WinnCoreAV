//! Production monitoring with owned runtime

use anyhow::Result;
use av_core::{RecommendedAction, Scanner, ScannerConfig};
use crossbeam_channel::{bounded, Sender};
use filetime::FileTime;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tracing::{error, info, warn};

const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;
const DEBOUNCE_DURATION: Duration = Duration::from_millis(750);

#[derive(Debug, Default)]
pub struct ScanStats {
    pub files_scanned: AtomicU64,
    pub threats_detected: AtomicU64,
    pub threats_quarantined: AtomicU64,
    pub files_excluded: AtomicU64,
    pub scan_errors: AtomicU64,
    pub queue_drops: AtomicU64,
}

impl ScanStats {
    pub fn display(&self) {
        info!(
            "📊 scanned={}, threats={}, quarantined={}, excluded={}, errors={}, drops={}",
            self.files_scanned.load(Ordering::Relaxed),
            self.threats_detected.load(Ordering::Relaxed),
            self.threats_quarantined.load(Ordering::Relaxed),
            self.files_excluded.load(Ordering::Relaxed),
            self.scan_errors.load(Ordering::Relaxed),
            self.queue_drops.load(Ordering::Relaxed)
        );
    }
}

struct Excludes {
    patterns: Vec<glob::Pattern>,
}

impl Excludes {
    fn new(patterns: &[String]) -> Self {
        let mut compiled = Vec::new();
        for pattern in patterns {
            if let Ok(glob_pattern) = glob::Pattern::new(pattern) {
                compiled.push(glob_pattern);
            }
        }
        Self {
            patterns: compiled,
        }
    }

    fn is_excluded(&self, path: &Path) -> bool {
        if let Some(path_str) = path.to_str() {
            self.patterns.iter().any(|p| p.matches(path_str))
        } else {
            false
        }
    }
}

pub struct FileMonitor {
    watch_paths: Vec<PathBuf>,
    quarantine_dir: PathBuf,
    tx: Arc<Mutex<Option<Sender<PathBuf>>>>,
    stats: Arc<ScanStats>,
    stop: Arc<AtomicBool>,
    debounce: Arc<Mutex<HashMap<PathBuf, Instant>>>,
    runtime: Runtime,
    worker_handles: Arc<Mutex<Option<Vec<tokio::task::JoinHandle<()>>>>>,
    auto_quarantine: bool,
    notifications_enabled: bool,
}

impl FileMonitor {
    pub fn new(
        paths: Vec<PathBuf>,
        exclude_patterns: Vec<String>,
        auto_quarantine: bool,
    ) -> Result<Self> {
        #[cfg(target_family = "unix")]
        unsafe {
            libc::umask(0o077);
        }

        let config = ScannerConfig::default();
        let scanner = Arc::new(Scanner::new(config)?);

        // Get number of CPUs
        let num_workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .max(2);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_time()
            .enable_io()
            .worker_threads(num_workers)
            .thread_name("wcav-rt")
            .build()?;

        let excludes = Arc::new(Excludes::new(&exclude_patterns));
        let notifications_enabled = std::env::var("DISPLAY").is_ok() ||
                                   std::env::var("WAYLAND_DISPLAY").is_ok();

        // Use dirs crate for quarantine directory
        let quarantine_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("winncore-av")
            .join("quarantine");

        std::fs::create_dir_all(&quarantine_dir)?;

        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&quarantine_dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let stats = Arc::new(ScanStats::default());
        let (tx, rx) = bounded::<PathBuf>(2048);

        info!("✅ Scanner initialized ({} workers)", num_workers);

        let mut worker_handles = Vec::new();
        for worker_id in 0..num_workers {
            let rx = rx.clone();
            let scanner = scanner.clone();
            let stats = stats.clone();
            let excludes = excludes.clone();
            let qdir = quarantine_dir.clone();
            let watch_roots = paths.clone();

            let handle = runtime.spawn(async move {
                while let Ok(path) = rx.recv() {
                    if let Err(e) = Self::scan_worker(
                        &path,
                        &scanner,
                        &stats,
                        &excludes,
                        &qdir,
                        &watch_roots,
                        auto_quarantine,
                        notifications_enabled,
                    ).await {
                        error!("[worker-{}] {}", worker_id, e);
                        stats.scan_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
                info!("[worker-{}] exiting", worker_id);
            });
            worker_handles.push(handle);
        }

        info!("🔔 Notifications: {}", if notifications_enabled { "ENABLED" } else { "DISABLED" });
        info!("🔒 Auto-quarantine: {}", if auto_quarantine { "ENABLED" } else { "DISABLED" });

        Ok(Self {
            watch_paths: paths,
            quarantine_dir,
            tx: Arc::new(Mutex::new(Some(tx))),
            stats,
            stop: Arc::new(AtomicBool::new(false)),
            debounce: Arc::new(Mutex::new(HashMap::new())),
            runtime,
            worker_handles: Arc::new(Mutex::new(Some(worker_handles))),
            auto_quarantine,
            notifications_enabled,
        })
    }

    pub fn start(&self) -> Result<()> {
        info!("🚀 Starting monitoring...");

        let stop = self.stop.clone();
        let _ = ctrlc::set_handler(move || {
            info!("Shutdown signal received");
            stop.store(true, Ordering::SeqCst);
        });

        let (event_tx, event_rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = event_tx.send(event);
                }
            },
            Config::default(),
        )?;

        for path in &self.watch_paths {
            if path.exists() {
                watcher.watch(path, RecursiveMode::Recursive)?;
                info!("👁️  Watching: {}", path.display());
            }
        }

        let mut event_count = 0;

        // Spawn a debounce cleanup task
        let debounce_clone = self.debounce.clone();
        let stop_clone = self.stop.clone();
        let _cleanup_handle = self.runtime.spawn(async move {
            while !stop_clone.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if let Ok(mut cache) = debounce_clone.lock() {
                    let now = Instant::now();
                    cache.retain(|_, &mut timestamp| now.duration_since(timestamp) < DEBOUNCE_DURATION);
                }
            }
        });

        while !self.stop.load(Ordering::SeqCst) {
            match event_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(event) => {
                    event_count += 1;
                    if let Err(e) = self.handle_event(event) {
                        error!("Event error: {:?}", e);
                    }
                    if event_count % 100 == 0 {
                        self.stats.display();
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(e) => {
                    error!("Watch error: {:?}", e);
                    break;
                }
            }
        }

        info!("🛑 Shutting down workers...");

        // Close channel by taking and dropping the sender
        if let Ok(mut tx_guard) = self.tx.lock() {
            tx_guard.take();
        }

        // Await all worker handles
        if let Ok(mut handles_guard) = self.worker_handles.lock() {
            if let Some(handles) = handles_guard.take() {
                for handle in handles {
                    let _ = self.runtime.block_on(handle);
                }
            }
        }

        info!("✅ All workers stopped");
        self.stats.display();
        Ok(())
    }

    fn handle_event(&self, event: Event) -> Result<()> {
        use notify::event::{AccessKind, AccessMode, ModifyKind, RenameMode};

        let ok = matches!(
            event.kind,
            EventKind::Modify(ModifyKind::Name(RenameMode::To))
                | EventKind::Modify(ModifyKind::Data(_))
                | EventKind::Create(_)
                | EventKind::Access(AccessKind::Close(AccessMode::Write))
        );

        if !ok {
            return Ok(());
        }

        for path in &event.paths {
            self.queue_scan(path)?;
        }
        Ok(())
    }

    fn queue_scan(&self, path: &Path) -> Result<()> {
        if path.is_dir() || !path.exists() {
            return Ok(());
        }

        let real_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

        if real_path.starts_with(&self.quarantine_dir) {
            return Ok(());
        }

        let in_allowed_tree = self.watch_paths.iter().any(|root| real_path.starts_with(root));
        if !in_allowed_tree {
            warn!("⚠️  Symlink escape: {}", real_path.display());
            return Ok(());
        }

        let name = real_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') || name.ends_with('~') {
            return Ok(());
        }

        // Check debounce cache
        {
            let mut cache = self.debounce.lock().unwrap();
            let now = Instant::now();

            if let Some(&last_time) = cache.get(&real_path) {
                if now.duration_since(last_time) < DEBOUNCE_DURATION {
                    return Ok(());
                }
            }

            cache.insert(real_path.clone(), now);
        }

        // Send to queue
        if let Ok(tx_guard) = self.tx.lock() {
            if let Some(ref tx) = *tx_guard {
                if tx.try_send(real_path).is_err() {
                    self.stats.queue_drops.fetch_add(1, Ordering::Relaxed);
                    warn!("Queue full");
                }
            }
        }

        Ok(())
    }

    async fn scan_worker(
        path: &Path,
        scanner: &Scanner,
        stats: &ScanStats,
        excludes: &Excludes,
        quarantine_dir: &Path,
        _watch_roots: &[PathBuf],
        auto_quarantine: bool,
        notifications_enabled: bool,
    ) -> Result<()> {
        if excludes.is_excluded(path) {
            stats.files_excluded.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        let meta = std::fs::metadata(path)?;
        if meta.len() > MAX_FILE_SIZE {
            warn!("⚠️  Large file: {} ({}MB)", path.display(), meta.len() / 1024 / 1024);
            return Ok(());
        }

        info!("🔍 {}", path.display());
        stats.files_scanned.fetch_add(1, Ordering::Relaxed);

        let outcome = scanner.scan_path(path).await?;

        match outcome.recommended_action {
            RecommendedAction::Allow => {
                info!("✅ {}", path.display());
            }
            RecommendedAction::Monitor => {
                warn!("⚠️  {}", path.display());
                if notifications_enabled {
                    // Desktop notification would go here if notify-rust was available
                    warn!("🔔 Suspicious: {}", path.display());
                }
            }
            RecommendedAction::Quarantine => {
                error!("🚨 {}", path.display());
                stats.threats_detected.fetch_add(1, Ordering::Relaxed);

                if notifications_enabled {
                    // Desktop notification would go here if notify-rust was available
                    error!("🔔 MALWARE: {}", path.display());
                }

                if auto_quarantine {
                    Self::quarantine_with_hash(path, quarantine_dir, stats).await?;
                }
            }
        }

        Ok(())
    }

    async fn quarantine_with_hash(
        threat_path: &Path,
        quarantine_dir: &Path,
        stats: &ScanStats,
    ) -> Result<()> {
        let hash = sha256_file(threat_path)?;

        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let name = threat_path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown");
        let final_name = format!("{}_{}", timestamp, name);
        let quarantine_path = quarantine_dir.join(&final_name);

        let tmp_path = quarantine_path.with_extension("partial");
        move_preserve(threat_path, &tmp_path)?;
        std::fs::rename(&tmp_path, &quarantine_path)?;

        error!("✅ Quarantined: {}", final_name);
        stats.threats_quarantined.fetch_add(1, Ordering::Relaxed);

        let meta_path = quarantine_dir.join(format!("{}.meta.json", final_name));
        let meta = serde_json::json!({
            "original_path": threat_path.to_string_lossy(),
            "quarantine_time": chrono::Local::now().to_rfc3339(),
            "sha256": hash,
            "size": std::fs::metadata(&quarantine_path)?.len(),
        });
        let json = serde_json::to_string_pretty(&meta)?;
        let tmp_meta = meta_path.with_extension("tmp");
        std::fs::write(&tmp_meta, json)?;
        std::fs::rename(&tmp_meta, &meta_path)?;

        Ok(())
    }
}

fn move_preserve(src: &Path, dst: &Path) -> io::Result<()> {
    if std::fs::rename(src, dst).is_err() {
        let bytes = std::fs::copy(src, dst)?;
        if bytes == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "zero-byte copy"));
        }
        std::fs::remove_file(src)?;
    }

    if let Ok(meta) = std::fs::metadata(dst) {
        let at = FileTime::from_system_time(std::time::SystemTime::now());
        let mt = FileTime::from_last_modification_time(&meta);
        let _ = filetime::set_file_times(dst, at, mt);
    }

    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut file = std::fs::File::open(path)?;
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hex::encode(hasher.finalize()))
}
