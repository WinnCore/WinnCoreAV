use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct HiddenFileResult {
    pub directory: String,
    pub visible_count: usize,
    pub actual_count: usize,
    pub hidden_files: Vec<String>,
}

pub fn scan_hidden_files(dir: &str) -> Option<HiddenFileResult> {
    let path = Path::new(dir);
    if !path.is_dir() {
        return None;
    }
    let visible: Vec<String> = fs::read_dir(path)
        .ok()?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    let meta = fs::metadata(path).ok()?;
    let expected_entries = meta.nlink() as usize;
    if visible.len() + 2 < expected_entries {
        warn!(
            "Directory {} has fewer entries than expected ({} vs {})",
            dir,
            visible.len(),
            expected_entries
        );
    }
    Some(HiddenFileResult {
        directory: dir.to_string(),
        visible_count: visible.len(),
        actual_count: expected_entries.saturating_sub(2),
        hidden_files: Vec::new(),
    })
}

pub fn check_common_hiding_spots() -> Vec<String> {
    let mut suspicious = Vec::new();
    let spots = ["/dev/shm", "/tmp", "/var/tmp"];
    for spot in &spots {
        if let Ok(entries) = fs::read_dir(spot) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('.') && name != "." && name != ".." {
                    if let Ok(meta) = entry.metadata() {
                        if meta.permissions().mode() & 0o111 != 0 {
                            suspicious.push(format!("{}/{}", spot, name));
                        }
                    }
                }
            }
        }
    }
    suspicious
}
