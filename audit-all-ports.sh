#!/bin/bash

echo "═══════════════════════════════════════════════════════════════"
echo "WINNCORE AV - COMPLETE PORT SECURITY AUDIT"
echo "═══════════════════════════════════════════════════════════════"
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "User: $(whoami)"
echo ""

# ===================================================================
# PART 1: DISCOVER ALL LISTENING PORTS
# ===================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "PART 1: ALL LISTENING PORTS ON THIS SYSTEM"
echo "═══════════════════════════════════════════════════════════════"

echo -e "\n--- All TCP Listening Ports ---"
sudo ss -tulpn | grep LISTEN | sort -k5

echo -e "\n--- All UDP Listening Ports ---"
sudo ss -tulpn | grep -v LISTEN | grep udp | sort -k5

echo -e "\n--- Summary by Port Number ---"
sudo ss -tulpn | grep -E "LISTEN|udp" | awk '{print $5}' | sed 's/.*://g' | sort -n | uniq -c | sort -rn

# ===================================================================
# PART 2: CHECK WINNCORE AV SPECIFIC PORTS
# ===================================================================
echo -e "\n═══════════════════════════════════════════════════════════════"
echo "PART 2: WINNCORE AV SPECIFIC PORTS"
echo "═══════════════════════════════════════════════════════════════"

# Check if av-daemon is running
if pgrep av-daemon > /dev/null; then
    echo "✅ av-daemon is running"
    
    AV_PID=$(pgrep av-daemon | head -1)
    echo "   PID: $AV_PID"
    
    echo -e "\n--- Ports used by av-daemon ---"
    sudo lsof -p $AV_PID -i -n -P 2>/dev/null || echo "   (No network connections or lsof not available)"
    
    echo -e "\n--- Specific port checks ---"
    
    # Port 9090 (Prometheus metrics)
    echo "Port 9090 (Prometheus Metrics):"
    if sudo ss -tulpn | grep -q ":9090"; then
        BIND_ADDR=$(sudo ss -tulpn | grep ":9090" | awk '{print $5}')
        echo "   Status: LISTENING on $BIND_ADDR"
        
        if echo "$BIND_ADDR" | grep -q "127.0.0.1:9090"; then
            echo "   Security: ✅ SECURE (localhost only)"
        elif echo "$BIND_ADDR" | grep -q "0.0.0.0:9090"; then
            echo "   Security: ⚠️  EXPOSED (all interfaces - INSECURE)"
        elif echo "$BIND_ADDR" | grep -q "\[::\]:9090"; then
            echo "   Security: ⚠️  EXPOSED (IPv6 all interfaces - INSECURE)"
        else
            echo "   Security: ℹ️  Bound to: $BIND_ADDR"
        fi
    else
        echo "   Status: ❌ NOT LISTENING"
    fi
    
else
    echo "❌ av-daemon is NOT running"
fi

# ===================================================================
# PART 3: FIREWALL STATUS
# ===================================================================
echo -e "\n═══════════════════════════════════════════════════════════════"
echo "PART 3: FIREWALL CONFIGURATION"
echo "═══════════════════════════════════════════════════════════════"

if command -v ufw &> /dev/null; then
    echo "--- UFW (Uncomplicated Firewall) Status ---"
    sudo ufw status verbose
    
    echo -e "\n--- UFW Rules ---"
    sudo ufw status numbered
else
    echo "ℹ️  UFW not installed"
fi

echo -e "\n--- iptables Rules (if any) ---"
sudo iptables -L -n -v --line-numbers 2>/dev/null | head -50 || echo "iptables not available or no rules"

# ===================================================================
# PART 4: NETWORK INTERFACES AND IP ADDRESSES
# ===================================================================
echo -e "\n═══════════════════════════════════════════════════════════════"
echo "PART 4: NETWORK INTERFACES AND IP ADDRESSES"
echo "═══════════════════════════════════════════════════════════════"

echo "--- IPv4 Addresses ---"
ip -4 addr show | grep inet | grep -v "127.0.0.1"

echo -e "\n--- IPv6 Addresses ---"
ip -6 addr show | grep inet6 | grep -v "::1"

echo -e "\n--- Default Gateway ---"
ip route show default

echo -e "\n--- Active Network Connections ---"
ss -s

# ===================================================================
# PART 5: SECURITY RECOMMENDATIONS
# ===================================================================
echo -e "\n═══════════════════════════════════════════════════════════════"
echo "PART 5: SECURITY ASSESSMENT & RECOMMENDATIONS"
echo "═══════════════════════════════════════════════════════════════"

echo ""
echo "Checking for common security issues..."
echo ""

# Check for 0.0.0.0 bindings
if sudo ss -tulpn | grep -E "0.0.0.0:[0-9]+" | grep -v -E "127.0.0.1|53|323|631" > /dev/null; then
    echo "⚠️  WARNING: Services listening on all interfaces (0.0.0.0):"
    sudo ss -tulpn | grep "0.0.0.0:" | grep -v -E "127.0.0.1|:53|:323|:631"
    echo "   Recommendation: Bind to 127.0.0.1 for local-only services"
fi

# Check if firewall is enabled
if command -v ufw &> /dev/null; then
    if sudo ufw status | grep -q "Status: inactive"; then
        echo "⚠️  WARNING: UFW firewall is DISABLED"
        echo "   Recommendation: Enable with 'sudo ufw enable'"
    else
        echo "✅ UFW firewall is enabled"
    fi
fi

# Check for port 9090 specifically
if sudo ss -tulpn | grep -q "0.0.0.0:9090"; then
    echo "⚠️  CRITICAL: Port 9090 exposed on all interfaces!"
    echo "   This is WinnCoreAV metrics endpoint"
    echo "   Recommendation: Change to 127.0.0.1:9090"
    echo "   Command: sed -i 's/0.0.0.0:9090/127.0.0.1:9090/g' av-daemon/src/main.rs"
fi

# ===================================================================
# PART 6: TESTING PORT ACCESSIBILITY
# ===================================================================
echo -e "\n═══════════════════════════════════════════════════════════════"
echo "PART 6: PORT ACCESSIBILITY TESTING"
echo "═══════════════════════════════════════════════════════════════"

echo -e "\nTesting port 9090 accessibility..."

# Test localhost
if curl -s --connect-timeout 2 http://127.0.0.1:9090/metrics > /dev/null 2>&1; then
    echo "✅ Port 9090: Accessible from localhost"
else
    echo "❌ Port 9090: NOT accessible from localhost"
fi

# Test network interface
NETWORK_IP=$(ip addr show | grep "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}' | cut -d/ -f1)
if [ -n "$NETWORK_IP" ]; then
    echo "   Testing from network IP: $NETWORK_IP"
    if curl -s --connect-timeout 2 http://$NETWORK_IP:9090/metrics > /dev/null 2>&1; then
        echo "⚠️  Port 9090: ACCESSIBLE from network ($NETWORK_IP) - SECURITY RISK!"
    else
        echo "✅ Port 9090: NOT accessible from network (good for security)"
    fi
fi

# ===================================================================
# PART 7: EXPORT RESULTS
# ===================================================================
echo -e "\n═══════════════════════════════════════════════════════════════"
echo "SAVING DETAILED RESULTS"
echo "═══════════════════════════════════════════════════════════════"

# Save to file
REPORT_FILE="port-audit-$(date +%Y%m%d-%H%M%S).txt"
echo "Saving detailed report to: $REPORT_FILE"

# Re-run everything to file
{
    echo "WinnCoreAV Port Security Audit Report"
    echo "Generated: $(date)"
    echo "========================================"
    echo ""
    
    echo "ALL LISTENING PORTS:"
    sudo ss -tulpn | grep LISTEN
    
    echo ""
    echo "WINNCORE AV PROCESSES:"
    ps aux | grep av-daemon | grep -v grep
    
    echo ""
    echo "FIREWALL STATUS:"
    sudo ufw status verbose 2>/dev/null || echo "UFW not available"
    
} > "$REPORT_FILE"

echo "✅ Report saved to: $REPORT_FILE"

# ===================================================================
# FINAL SUMMARY
# ===================================================================
echo -e "\n═══════════════════════════════════════════════════════════════"
echo "AUDIT COMPLETE"
echo "═══════════════════════════════════════════════════════════════"

