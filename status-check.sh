#!/bin/bash

echo "═══════════════════════════════════════════════════════════════"
echo "WINNCORE AV - COMPLETE STATUS CHECK"
echo "═══════════════════════════════════════════════════════════════"
echo "Timestamp: $(date)"
echo ""

# ═══════════════════════════════════════════════════════════════
# 1. BUILD STATUS
# ═══════════════════════════════════════════════════════════════
echo "1️⃣  BUILD STATUS"
echo "────────────────────────────────────────────────────────────"

# Kill any running daemons first
sudo killall -9 av-daemon 2>/dev/null || true
sleep 2

# Try to build
echo "Building..."
if cargo build --release --bin av-daemon 2>&1 | tee build-status.log | tail -5; then
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo "✅ BUILD: SUCCESS"
        BUILD_OK=true
    else
        echo "❌ BUILD: FAILED"
        BUILD_OK=false
        echo "Last 20 lines of build output:"
        tail -20 build-status.log | grep -i error
    fi
else
    echo "❌ BUILD: FAILED"
    BUILD_OK=false
fi

# ═══════════════════════════════════════════════════════════════
# 2. CODE STRUCTURE
# ═══════════════════════════════════════════════════════════════
echo -e "\n2️⃣  CODE STRUCTURE"
echo "────────────────────────────────────────────────────────────"

echo "FileMonitor struct:"
METRICS_COUNT=$(awk '/pub struct FileMonitor/,/^}/' av-daemon/src/monitor.rs 2>/dev/null | grep -c "metrics: Arc<Metrics>" || echo "0")
if [ "$METRICS_COUNT" -eq 1 ]; then
    echo "   ✅ Exactly 1 metrics field (correct)"
elif [ "$METRICS_COUNT" -gt 1 ]; then
    echo "   ❌ $METRICS_COUNT metrics fields (duplicates!)"
elif [ "$METRICS_COUNT" -eq 0 ]; then
    echo "   ❌ No metrics field found"
fi

echo ""
echo "FileMonitor Self initialization:"
if sed -n '/Ok(Self {/,/})/p' av-daemon/src/monitor.rs 2>/dev/null | grep -q "metrics,"; then
    echo "   ✅ Constructor stores metrics"
else
    echo "   ❌ Constructor doesn't store metrics"
fi

echo ""
echo "Metrics usage in scan operations:"
METRICS_USAGE=$(grep -c "ctx.metrics\." av-daemon/src/monitor.rs 2>/dev/null || echo "0")
if [ "$METRICS_USAGE" -gt 0 ]; then
    echo "   ✅ Metrics used $METRICS_USAGE times in code"
else
    echo "   ❌ Metrics not used in scan operations"
fi

# ═══════════════════════════════════════════════════════════════
# 3. RUNTIME STATUS (if build succeeded)
# ═══════════════════════════════════════════════════════════════
if [ "$BUILD_OK" = true ]; then
    echo -e "\n3️⃣  RUNTIME STATUS"
    echo "────────────────────────────────────────────────────────────"
    
    echo "Starting daemon..."
    cargo run --release --bin av-daemon > daemon-status-check.log 2>&1 &
    DAEMON_PID=$!
    
    sleep 5
    
    # Check if running
    if ps -p $DAEMON_PID > /dev/null 2>&1; then
        echo "✅ DAEMON: Running (PID: $DAEMON_PID)"
        
        # Check port
        if ss -tulpn 2>/dev/null | grep -q ":9090"; then
            BIND_ADDR=$(ss -tulpn 2>/dev/null | grep ":9090" | awk '{print $5}' | head -1)
            echo "✅ PORT 9090: Listening on $BIND_ADDR"
            
            if echo "$BIND_ADDR" | grep -q "127.0.0.1"; then
                echo "✅ SECURITY: Localhost only (secure)"
            else
                echo "⚠️  SECURITY: Not localhost-only"
            fi
        else
            echo "❌ PORT 9090: Not listening"
        fi
        
        # Check metrics endpoint
        sleep 2
        if curl -s http://127.0.0.1:9090/metrics > /dev/null 2>&1; then
            echo "✅ METRICS ENDPOINT: Accessible"
            
            echo ""
            echo "Current metrics:"
            curl -s http://127.0.0.1:9090/metrics | grep winncore_ | head -10
        else
            echo "❌ METRICS ENDPOINT: Not accessible"
        fi
        
    else
        echo "❌ DAEMON: Failed to start"
        echo "Logs:"
        tail -20 daemon-status-check.log
    fi
else
    echo -e "\n3️⃣  RUNTIME STATUS"
    echo "────────────────────────────────────────────────────────────"
    echo "⏭️  Skipped (build failed)"
fi

# ═══════════════════════════════════════════════════════════════
# 4. FUNCTIONAL TEST (if running)
# ═══════════════════════════════════════════════════════════════
if [ "$BUILD_OK" = true ] && ps -p $DAEMON_PID > /dev/null 2>&1; then
    echo -e "\n4️⃣  FUNCTIONAL TEST"
    echo "────────────────────────────────────────────────────────────"
    
    echo "Creating test files..."
    for i in 1 2 3; do
        echo "Test file $i" > ~/Downloads/status-test-$i.txt
        sleep 2
    done
    
    sleep 5
    
    echo "Checking if metrics incremented..."
    FILES_SCANNED=$(curl -s http://127.0.0.1:9090/metrics | grep "winncore_files_scanned_total" | awk '{print $2}')
    
    if [ -n "$FILES_SCANNED" ]; then
        if [ "$FILES_SCANNED" -gt 0 ]; then
            echo "✅ SCANNING: Working ($FILES_SCANNED files scanned)"
        else
            echo "⚠️  SCANNING: Metrics show 0 (files not being scanned?)"
        fi
    else
        echo "❌ SCANNING: Can't read metrics"
    fi
    
    # Cleanup test files
    rm -f ~/Downloads/status-test-*.txt
else
    echo -e "\n4️⃣  FUNCTIONAL TEST"
    echo "────────────────────────────────────────────────────────────"
    echo "⏭️  Skipped (daemon not running)"
fi

# ═══════════════════════════════════════════════════════════════
# 5. GIT STATUS
# ═══════════════════════════════════════════════════════════════
echo -e "\n5️⃣  GIT STATUS"
echo "────────────────────────────────────────────────────────────"

echo "Current branch:"
git branch --show-current

echo ""
echo "Uncommitted changes:"
git status --short | head -10

echo ""
echo "Last commit:"
git log -1 --oneline

# ═══════════════════════════════════════════════════════════════
# 6. FILES & STRUCTURE
# ═══════════════════════════════════════════════════════════════
echo -e "\n6️⃣  PROJECT STRUCTURE"
echo "────────────────────────────────────────────────────────────"

echo "Key files present:"
[ -f av-daemon/src/main.rs ] && echo "   ✅ av-daemon/src/main.rs" || echo "   ❌ av-daemon/src/main.rs"
[ -f av-daemon/src/monitor.rs ] && echo "   ✅ av-daemon/src/monitor.rs" || echo "   ❌ av-daemon/src/monitor.rs"
[ -f av-daemon/src/metrics.rs ] && echo "   ✅ av-daemon/src/metrics.rs" || echo "   ❌ av-daemon/src/metrics.rs"
[ -f av-core/src/lib.rs ] && echo "   ✅ av-core/src/lib.rs" || echo "   ❌ av-core/src/lib.rs"
[ -f README.md ] && echo "   ✅ README.md" || echo "   ❌ README.md"
[ -f Cargo.toml ] && echo "   ✅ Cargo.toml" || echo "   ❌ Cargo.toml"

# ═══════════════════════════════════════════════════════════════
# 7. SUMMARY
# ═══════════════════════════════════════════════════════════════
echo -e "\n═══════════════════════════════════════════════════════════════"
echo "SUMMARY"
echo "═══════════════════════════════════════════════════════════════"

if [ "$BUILD_OK" = true ]; then
    echo "✅ Build: SUCCESS"
else
    echo "❌ Build: FAILED"
fi

if ps -p $DAEMON_PID > /dev/null 2>&1; then
    echo "✅ Daemon: RUNNING"
else
    echo "❌ Daemon: NOT RUNNING"
fi

if curl -s http://127.0.0.1:9090/metrics > /dev/null 2>&1; then
    echo "✅ Metrics: ACCESSIBLE"
else
    echo "❌ Metrics: NOT ACCESSIBLE"
fi

echo ""
echo "Next steps:"
if [ "$BUILD_OK" != true ]; then
    echo "1. Fix build errors (see build-status.log)"
elif ! ps -p $DAEMON_PID > /dev/null 2>&1; then
    echo "1. Debug daemon startup (see daemon-status-check.log)"
elif [ "$FILES_SCANNED" = "0" ] || [ -z "$FILES_SCANNED" ]; then
    echo "1. Debug why files aren't being scanned"
else
    echo "1. ✅ Everything working! Ready to:"
    echo "   - Update README"
    echo "   - Commit changes"
    echo "   - Push to GitHub"
    echo "   - Add documentation"
fi

echo "═══════════════════════════════════════════════════════════════"
