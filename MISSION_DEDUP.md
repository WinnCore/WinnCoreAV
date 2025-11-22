# MISSION: Integrate Scan Deduplication into av-daemon

## CONTEXT
The av-daemon currently scans files MULTIPLE TIMES (4x) because file watchers 
trigger multiple inotify events (CREATE, MODIFY, CLOSE_WRITE, ATTRIB) for a 
single file operation. This wastes memory by loading the ML model 4 times per file.

## SOLUTION ALREADY BUILT
The deduplication module already exists at `av-daemon/src/dedup.rs` with:
- `ScanDeduplicator` struct
- `should_scan(&self, path: &str)` method that returns true only if file 
  hasn't been scanned in the last 5 seconds

## TASK
Integrate the deduplicator into av-daemon/src/main.rs:

### Step 1: Add module import (after line with "mod config;")
```rust
mod dedup;
use dedup::ScanDeduplicator;
```

### Step 2: Add field to DaemonState struct
```rust
struct DaemonState {
    scanner: Arc<Scanner>,
    response: Arc<RwLock<ResponseEngine>>,
    config: Arc<DaemonConfig>,
    stats: Arc<RwLock<Stats>>,
    dedup: Arc<ScanDeduplicator>,  // ADD THIS
}
```

### Step 3: Create dedup instance in main() function
After these lines:
```rust
let response = ResponseEngine::new(
    config.response.enabled,
    config.thresholds.kill_threshold,
);
```

Add:
```rust
// Create scan deduplicator
let dedup = ScanDeduplicator::new();
```

### Step 4: Add dedup to state creation
In the `let state = DaemonState {` block, add:
```rust
let state = DaemonState {
    scanner: Arc::new(scanner),
    response: Arc::new(RwLock::new(response)),
    config: Arc::new(config.clone()),
    stats: Arc::new(RwLock::new(Stats {
        uptime_start: std::time::Instant::now(),
        ..Default::default()
    })),
    dedup: Arc::new(dedup),  // ADD THIS
};
```

### Step 5: Add dedup check at START of scan_file function
At the very beginning of `async fn scan_file(path: PathBuf, state: DaemonState)`,
BEFORE any other code, add:
```rust
async fn scan_file(path: PathBuf, state: DaemonState) {
    // Deduplicate scans - skip if scanned recently
    let path_str = path.to_string_lossy().to_string();
    if !state.dedup.should_scan(&path_str).await {
        return; // Already scanned recently
    }

    // Rest of function continues...
```

## VERIFICATION
After making changes:
1. Build: `cargo build --release --bin av-daemon`
2. Test: Run daemon and create a malware file
3. Verify: Should see "🔍 Scanning" message only ONCE (not 4 times)
4. Verify: Should see "Loading ML model" only ONCE (not 4 times)

## SUCCESS CRITERIA
✅ Code compiles without errors
✅ Daemon runs without crashes
✅ Each file is scanned exactly ONCE
✅ ML model is loaded exactly ONCE per file
✅ Memory usage is 75% lower (no duplicate model loads)

## CURRENT STATUS
- dedup.rs: ✅ Already created
- Integration: ❌ NOT DONE (sed scripts failed)
- Testing: ❌ PENDING

Start working on this now. Make the code changes, build, test, and verify.
