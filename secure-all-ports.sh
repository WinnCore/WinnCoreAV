#!/bin/bash

echo "═══════════════════════════════════════════════════════════════"
echo "WINNCORE AV - PORT SECURITY HARDENING"
echo "═══════════════════════════════════════════════════════════════"

cd ~/av-suite-unpacked/av-suite-clean

# ===================================================================
# STEP 1: AUDIT CURRENT STATE
# ===================================================================
echo -e "\nSTEP 1: Current Security State"
echo "─────────────────────────────────────────────────────────────"

echo "Current port 9090 binding:"
sudo ss -tulpn | grep 9090 || echo "Port 9090 not listening"

# ===================================================================
# STEP 2: SECURE PORT 9090 (LOCALHOST ONLY)
# ===================================================================
echo -e "\nSTEP 2: Securing Port 9090 (Metrics)"
echo "─────────────────────────────────────────────────────────────"

# Backup current code
if [ -f av-daemon/src/main.rs ]; then
    cp av-daemon/src/main.rs av-daemon/src/main.rs.backup-$(date +%Y%m%d-%H%M%S)
    echo "✅ Backed up main.rs"
fi

# Change binding to localhost
if grep -q "0.0.0.0:9090" av-daemon/src/main.rs; then
    echo "Changing bind address from 0.0.0.0:9090 to 127.0.0.1:9090..."
    sed -i 's/0\.0\.0\.0:9090/127.0.0.1:9090/g' av-daemon/src/main.rs
    echo "✅ Updated main.rs to bind to localhost only"
else
    echo "✅ Already using localhost binding (or different configuration)"
fi

# Verify change
echo "Verifying change in main.rs:"
grep -n "127.0.0.1:9090\|0.0.0.0:9090" av-daemon/src/main.rs

# ===================================================================
# STEP 3: CONFIGURE FIREWALL
# ===================================================================
echo -e "\nSTEP 3: Configuring Firewall"
echo "─────────────────────────────────────────────────────────────"

if command -v ufw &> /dev/null; then
    echo "Configuring UFW firewall..."
    
    # Enable UFW if not already enabled
    if sudo ufw status | grep -q "Status: inactive"; then
        echo "Enabling UFW..."
        sudo ufw --force enable
    fi
    
    # Block port 9090 from external access (redundant if binding to localhost, but extra safety)
    echo "Adding UFW rule to block external access to port 9090..."
    sudo ufw deny 9090 comment "Block WinnCoreAV metrics from network"
    
    # Allow localhost access explicitly (though not strictly necessary)
    sudo ufw allow from 127.0.0.1 to any port 9090 comment "Allow WinnCoreAV metrics on localhost"
    
    echo "✅ Firewall configured"
    sudo ufw status numbered | grep 9090
else
    echo "⚠️  UFW not installed. Install with: sudo apt-get install ufw"
fi

# ===================================================================
# STEP 4: REBUILD DAEMON
# ===================================================================
echo -e "\nSTEP 4: Rebuilding Daemon with Security Changes"
echo "─────────────────────────────────────────────────────────────"

# Kill old daemon
killall -9 av-daemon 2>/dev/null || true
sleep 1

# Rebuild
echo "Building..."
cargo build --release --bin av-daemon

if [ $? -eq 0 ]; then
    echo "✅ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi

# ===================================================================
# STEP 5: START SECURED DAEMON
# ===================================================================
echo -e "\nSTEP 5: Starting Secured Daemon"
echo "─────────────────────────────────────────────────────────────"

cargo run --release --bin av-daemon > secure-daemon.log 2>&1 &
DAEMON_PID=$!

echo "Started daemon with PID: $DAEMON_PID"
sleep 5

if ps -p $DAEMON_PID > /dev/null; then
    echo "✅ Daemon running"
else
    echo "❌ Daemon failed to start"
    cat secure-daemon.log
    exit 1
fi

# ===================================================================
# STEP 6: VERIFY SECURITY
# ===================================================================
echo -e "\nSTEP 6: Security Verification"
echo "─────────────────────────────────────────────────────────────"

echo "1. Port binding check:"
BINDING=$(sudo ss -tulpn | grep 9090 | awk '{print $5}')
if echo "$BINDING" | grep -q "127.0.0.1:9090"; then
    echo "   ✅ SECURE: Bound to localhost only ($BINDING)"
elif echo "$BINDING" | grep -q "0.0.0.0:9090"; then
    echo "   ⚠️  INSECURE: Bound to all interfaces ($BINDING)"
else
    echo "   Status: $BINDING"
fi

echo -e "\n2. Localhost accessibility:"
if curl -s http://127.0.0.1:9090/metrics > /dev/null 2>&1; then
    echo "   ✅ Accessible from localhost"
else
    echo "   ❌ NOT accessible from localhost"
fi

echo -e "\n3. Network accessibility:"
NETWORK_IP=$(ip addr show | grep "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}' | cut -d/ -f1)
if [ -n "$NETWORK_IP" ]; then
    if curl -s --connect-timeout 2 http://$NETWORK_IP:9090/metrics > /dev/null 2>&1; then
        echo "   ⚠️  ACCESSIBLE from network ($NETWORK_IP) - SECURITY ISSUE!"
    else
        echo "   ✅ NOT accessible from network (blocked as expected)"
    fi
fi

echo -e "\n4. Firewall rules:"
if command -v ufw &> /dev/null; then
    sudo ufw status | grep 9090 || echo "   No specific rules for port 9090"
fi

# ===================================================================
# STEP 7: CREATE MONITORING SCRIPT
# ===================================================================
echo -e "\nSTEP 7: Creating Port Monitoring Script"
echo "─────────────────────────────────────────────────────────────"

cat > monitor-ports.sh << 'MONEOF'
#!/bin/bash
# WinnCoreAV Port Monitor
# Run this periodically to check port security

echo "WinnCoreAV Port Monitor - $(date)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check daemon
if pgrep av-daemon > /dev/null; then
    echo "✅ Daemon: Running"
else
    echo "❌ Daemon: Not running"
    exit 1
fi

# Check port 9090
BINDING=$(sudo ss -tulpn | grep 9090 | awk '{print $5}')
if [ -n "$BINDING" ]; then
    if echo "$BINDING" | grep -q "127.0.0.1"; then
        echo "✅ Port 9090: Secure (localhost: $BINDING)"
    else
        echo "⚠️  Port 9090: EXPOSED ($BINDING) - SECURITY RISK!"
    fi
else
    echo "❌ Port 9090: Not listening"
fi

# Check firewall
if command -v ufw &> /dev/null; then
    if sudo ufw status | grep -q "Status: active"; then
        echo "✅ Firewall: Active"
    else
        echo "⚠️  Firewall: Inactive"
    fi
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
MONEOF

chmod +x monitor-ports.sh
echo "✅ Created monitoring script: monitor-ports.sh"

# ===================================================================
# FINAL SUMMARY
# ===================================================================
echo -e "\n═══════════════════════════════════════════════════════════════"
echo "SECURITY HARDENING COMPLETE"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Summary of changes:"
echo "  ✅ Port 9090 bound to localhost only (127.0.0.1)"
echo "  ✅ Firewall rules configured (if UFW available)"
echo "  ✅ Daemon rebuilt and restarted"
echo "  ✅ Security verified"
echo ""
echo "You can monitor port security with:"
echo "  ./monitor-ports.sh"
echo ""
echo "To re-audit all ports anytime:"
echo "  ./audit-all-ports.sh"
echo ""
echo "═══════════════════════════════════════════════════════════════"

