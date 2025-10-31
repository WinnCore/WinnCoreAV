//! Configuration management for av-daemon

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub watch_paths: Vec<PathBuf>,
    pub exclude_patterns: Vec<String>,
    pub auto_quarantine: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        let mut watch_paths = vec![];
        
        // Add Downloads directory
        if let Some(downloads) = dirs::download_dir() {
            watch_paths.push(downloads);
        }
        
        // Add Desktop directory
        if let Some(desktop) = dirs::desktop_dir() {
            watch_paths.push(desktop);
        }
        
        // Add Documents directory
        if let Some(documents) = dirs::document_dir() {
            watch_paths.push(documents);
        }
        
        // Fallback to test directory if no standard dirs found
        if watch_paths.is_empty() {
            if let Some(home) = dirs::home_dir() {
                watch_paths.push(home.join("test-av-watch"));
            }
        }
        
        Self {
            watch_paths,
            exclude_patterns: vec![
                // Version control
                String::from(".git"),
                String::from(".svn"),
                String::from(".hg"),
                
                // Build artifacts
                String::from("target"),
                String::from("build"),
                String::from("dist"),
                String::from("node_modules"),
                String::from("__pycache__"),
                
                // IDE files
                String::from(".idea"),
                String::from(".vscode"),
                String::from(".vs"),
                
                // Cache directories
                String::from(".cache"),
                String::from(".npm"),
                String::from(".cargo"),
                
                // System/temp files
                String::from(".tmp"),
                String::from(".temp"),
            ],
            auto_quarantine: false, // Safe default
        }
    }
}
