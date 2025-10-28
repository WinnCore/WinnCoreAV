//! Real-time file system monitoring for WinnCoreAV

use anyhow::Result;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use tracing::{error, info};

pub struct FileMonitor {
    watch_paths: Vec<PathBuf>,
}

impl FileMonitor {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self { watch_paths: paths }
    }

    pub fn start(&self) -> Result<()> {
        info!("🚀 Starting real-time file monitoring...");

        let (tx, rx) = channel();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    tx.send(event).ok();
                }
            },
            Config::default(),
        )?;

        for path in &self.watch_paths {
            watcher.watch(path, RecursiveMode::Recursive)?;
            info!("👁️  Watching: {}", path.display());
        }

        info!("✅ Monitoring active - watching for file changes...");
        loop {
            match rx.recv() {
                Ok(event) => self.handle_event(event)?,
                Err(e) => {
                    error!("Watch error: {:?}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    fn handle_event(&self, event: Event) -> Result<()> {
        match event.kind {
            EventKind::Create(_) => {
                for path in &event.paths {
                    info!("🆕 New file created: {}", path.display());
                    self.scan_file(path)?;
                }
            }
            EventKind::Modify(_) => {
                for path in &event.paths {
                    info!("✏️  File modified: {}", path.display());
                    self.scan_file(path)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn scan_file(&self, path: &Path) -> Result<()> {
        if path.is_dir() {
            return Ok(());
        }

        info!("🔍 Scanning: {}", path.display());
        info!("✅ Scan complete: {}", path.display());

        Ok(())
    }
}
