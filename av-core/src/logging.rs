//! Production-grade async logging infrastructure with sampling and backpressure

use chrono::{SecondsFormat, Utc};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Result as IoResult, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing_subscriber::{
    fmt::{self, MakeWriter},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

static GLOBAL_SAMPLER: OnceCell<Arc<LogSampler>> = OnceCell::new();

/// Configuration for the logging subsystem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Minimum log level (trace, debug, info, warn, error)
    pub level: String,
    /// Enable JSON structured logging (for production)
    pub json_format: bool,
    /// Enable sampling for high-frequency log sources
    pub enable_sampling: bool,
    /// Sample rate for ML inference logs (1 = every log, 10 = 1 in 10, etc.)
    pub ml_inference_sample_rate: u64,
    /// Sample rate for file scan events
    pub file_scan_sample_rate: u64,
    /// Maximum logs per second before backpressure kicks in
    pub max_logs_per_second: u64,
    /// Channel buffer size for async logging
    pub channel_buffer_size: usize,
    /// Log file path (None for stdout only)
    pub log_file: Option<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            json_format: false,
            enable_sampling: true,
            ml_inference_sample_rate: 100, // Log 1 in 100 ML inferences
            file_scan_sample_rate: 10,     // Log 1 in 10 file scans
            max_logs_per_second: 1000,
            channel_buffer_size: 10_000,
            log_file: None,
        }
    }
}

/// Rate limiter for log sampling with atomic counters
#[derive(Debug)]
pub struct LogSampler {
    ml_counter: AtomicU64,
    ml_sample_rate: u64,
    file_scan_counter: AtomicU64,
    file_scan_sample_rate: u64,
    global_counter: AtomicU64,
    max_per_second: u64,
    window_start: std::sync::RwLock<Instant>,
    backpressure_active: AtomicBool,
    sampling_enabled: bool,
}

impl LogSampler {
    pub fn new(config: &LogConfig) -> Self {
        let ml_rate = if config.enable_sampling {
            config.ml_inference_sample_rate.max(1)
        } else {
            1
        };
        let file_rate = if config.enable_sampling {
            config.file_scan_sample_rate.max(1)
        } else {
            1
        };

        Self {
            ml_counter: AtomicU64::new(0),
            ml_sample_rate: ml_rate,
            file_scan_counter: AtomicU64::new(0),
            file_scan_sample_rate: file_rate,
            global_counter: AtomicU64::new(0),
            max_per_second: config.max_logs_per_second.max(1),
            window_start: std::sync::RwLock::new(Instant::now()),
            backpressure_active: AtomicBool::new(false),
            sampling_enabled: config.enable_sampling,
        }
    }

    /// Check if an ML inference log should be emitted (sampling)
    pub fn should_log_ml_inference(&self) -> bool {
        let count = self.ml_counter.fetch_add(1, Ordering::Relaxed);
        !self.sampling_enabled || count % self.ml_sample_rate == 0
    }

    /// Check if a file scan log should be emitted (sampling)
    pub fn should_log_file_scan(&self) -> bool {
        let count = self.file_scan_counter.fetch_add(1, Ordering::Relaxed);
        !self.sampling_enabled || count % self.file_scan_sample_rate == 0
    }

    /// Check global rate limit, returns true if log should proceed
    pub fn check_rate_limit(&self) -> bool {
        {
            let window = self.window_start.read().unwrap();
            if window.elapsed() > Duration::from_secs(1) {
                drop(window);
                let mut window = self.window_start.write().unwrap();
                if window.elapsed() > Duration::from_secs(1) {
                    *window = Instant::now();
                    self.global_counter.store(0, Ordering::Relaxed);
                    self.backpressure_active.store(false, Ordering::Relaxed);
                }
            }
        }

        let count = self.global_counter.fetch_add(1, Ordering::Relaxed);
        if count >= self.max_per_second {
            if !self.backpressure_active.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "[WARN] Log backpressure activated: {} logs/sec exceeded",
                    self.max_per_second
                );
            }
            false
        } else {
            true
        }
    }

    /// Get sampling statistics for metrics
    pub fn get_stats(&self) -> SamplerStats {
        SamplerStats {
            ml_total: self.ml_counter.load(Ordering::Relaxed),
            ml_logged: self.ml_counter.load(Ordering::Relaxed) / self.ml_sample_rate,
            file_scan_total: self.file_scan_counter.load(Ordering::Relaxed),
            file_scan_logged: self.file_scan_counter.load(Ordering::Relaxed)
                / self.file_scan_sample_rate,
            backpressure_active: self.backpressure_active.load(Ordering::Relaxed),
        }
    }
}

impl av_ml_detector::MlLogSampler for LogSampler {
    fn should_log_ml_inference(&self) -> bool {
        LogSampler::should_log_ml_inference(self)
    }

    fn check_rate_limit(&self) -> bool {
        LogSampler::check_rate_limit(self)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SamplerStats {
    pub ml_total: u64,
    pub ml_logged: u64,
    pub file_scan_total: u64,
    pub file_scan_logged: u64,
    pub backpressure_active: bool,
}

/// Async log writer that uses a channel to avoid blocking
pub struct AsyncLogWriter {
    sender: mpsc::Sender<Vec<u8>>,
}

impl AsyncLogWriter {
    pub fn new(buffer_size: usize) -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (sender, receiver) = mpsc::channel(buffer_size);
        (Self { sender }, receiver)
    }
}

impl<'a> MakeWriter<'a> for AsyncLogWriter {
    type Writer = AsyncLogWriterGuard;

    fn make_writer(&'a self) -> Self::Writer {
        AsyncLogWriterGuard {
            sender: self.sender.clone(),
            buffer: Vec::with_capacity(256),
        }
    }
}

pub struct AsyncLogWriterGuard {
    sender: mpsc::Sender<Vec<u8>>,
    buffer: Vec<u8>,
}

impl std::io::Write for AsyncLogWriterGuard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buffer.is_empty() {
            let data = std::mem::take(&mut self.buffer);
            let _ = self.sender.try_send(data);
        }
        Ok(())
    }
}

impl Drop for AsyncLogWriterGuard {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

fn spawn_log_drain(mut receiver: mpsc::Receiver<Vec<u8>>, log_file: Option<String>) {
    let fut = async move {
        if let Some(path) = log_file {
            if let Some(parent) = std::path::Path::new(&path).parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }

            match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await
            {
                Ok(mut file) => {
                    while let Some(data) = receiver.recv().await {
                        if file.write_all(&data).await.is_err() {
                            break;
                        }
                        let _ = file.flush().await;
                    }
                }
                Err(e) => {
                    eprintln!("Failed to open log file {}: {}", path, e);
                    let mut stdout = tokio::io::stdout();
                    while let Some(data) = receiver.recv().await {
                        let _ = stdout.write_all(&data).await;
                        let _ = stdout.flush().await;
                    }
                }
            }
        } else {
            let mut stdout = tokio::io::stdout();
            while let Some(data) = receiver.recv().await {
                let _ = stdout.write_all(&data).await;
                let _ = stdout.flush().await;
            }
        }
    };

    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(fut);
    } else {
        std::thread::spawn(|| {
            if let Ok(rt) = tokio::runtime::Runtime::new() {
                rt.block_on(fut);
            }
        });
    }
}

/// Initialize the logging subsystem with the given configuration
/// Returns a handle to the log sampler for use in application code
pub fn init_logging(config: &LogConfig) -> anyhow::Result<Arc<LogSampler>> {
    let sampler = Arc::new(LogSampler::new(config));
    let _ = GLOBAL_SAMPLER.set(sampler.clone());

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.level));

    let (async_writer, receiver) = AsyncLogWriter::new(config.channel_buffer_size);
    spawn_log_drain(receiver, config.log_file.clone());

    if config.json_format {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                fmt::layer()
                    .json()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_file(true)
                    .with_line_number(true)
                    .with_writer(async_writer),
            )
            .try_init()
            .map_err(|e| anyhow::anyhow!("Failed to initialize logging: {}", e))?;
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_thread_ids(false)
                    .compact()
                    .with_writer(async_writer),
            )
            .try_init()
            .map_err(|e| anyhow::anyhow!("Failed to initialize logging: {}", e))?;
    }

    Ok(sampler)
}

/// Convenience macros for sampled logging
#[macro_export]
macro_rules! log_ml_inference {
    ($sampler:expr, $($arg:tt)*) => {
        if $sampler.should_log_ml_inference() && $sampler.check_rate_limit() {
            tracing::debug!(target: "ml_inference", $($arg)*);
        }
    };
}

#[macro_export]
macro_rules! log_file_scan {
    ($sampler:expr, $($arg:tt)*) => {
        if $sampler.should_log_file_scan() && $sampler.check_rate_limit() {
            tracing::debug!(target: "file_scan", $($arg)*);
        }
    };
}

/// Access the globally registered sampler, if available.
pub fn global_sampler() -> Option<Arc<LogSampler>> {
    GLOBAL_SAMPLER.get().cloned()
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionLog<'a> {
    pub ts: String,
    pub host: String,
    pub path: &'a str,
    pub sha256: Option<String>,
    pub model_version: Option<&'a str>,
    pub model_checksum: Option<&'a str>,
    pub score: f32,
    pub action: &'a str,
    pub mitre: &'a [String],
    pub notes: &'a [String],
    pub yara_matches: &'a [String],
    pub ioc_hits: &'a [String],
    pub adversarial_hint: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arm64_protection: Option<Arm64ProtectionLog<'a>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Arm64ProtectionLog<'a> {
    pub is_aarch64_elf: bool,
    pub pac_marked: bool,
    pub bti_marked: bool,
    pub has_gnu_property_note: bool,
    pub parsing_notes: &'a [String],
}

static NON_ELF_SKIP_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn emit_detection_log(log: &DetectionLog, json: bool) {
    if json {
        if let Ok(serialized) = serde_json::to_string(log) {
            println!("{serialized}");
        }
    } else {
        println!(
            "[{}] path={} sha256={:?} score={:.3} action={} mitre={:?} notes={:?}",
            log.ts, log.path, log.sha256, log.score, log.action, log.mitre, log.notes
        );
    }
}

pub fn sha256_file(path: &Path) -> IoResult<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn iso_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Returns true if a non-ELF skip log should be emitted based on verbosity and counters.
pub fn log_non_elf_skip_should_emit(verbose: bool) -> bool {
    if verbose {
        return true;
    }
    let count = NON_ELF_SKIP_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    count == 1 || count % 500 == 0
}

pub fn non_elf_skip_count() -> usize {
    NON_ELF_SKIP_COUNT.load(Ordering::Relaxed)
}

pub fn host_id() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return h;
        }
    }
    if let Ok(contents) = std::fs::read_to_string("/etc/hostname") {
        let trimmed = contents.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "unknown".to_string()
}

/// Returns true when stress tests have requested quieter logging.
pub fn quiet_stress_mode() -> bool {
    std::env::var("WINNCORE_QUIET_STRESS").is_ok()
}

#[cfg(test)]
mod tests;
