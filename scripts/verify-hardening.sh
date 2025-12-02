#!/bin/bash
# Verifies compiled binaries have expected hardening features.
# Usage: ./scripts/verify-hardening.sh target/release/av-daemon

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

BINARY="${1:-target/release/av-daemon}"
FAILED=0

log_pass() { echo -e "${GREEN}✓${NC} $1"; }
log_fail() { echo -e "${RED}✗${NC} $1"; FAILED=1; }
log_warn() { echo -e "${YELLOW}!${NC} $1"; }

echo "═══════════════════════════════════════════════════════════════"
echo "  Binary Hardening Verification: $(basename "$BINARY")"
echo "═══════════════════════════════════════════════════════════════"
echo ""

if [[ ! -f "$BINARY" ]]; then
    echo "Binary not found: $BINARY"
    exit 2
fi

for tool in readelf file objdump; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool"
        exit 2
    fi
done

echo "Binary: $BINARY"
if command -v stat >/dev/null 2>&1; then
    SIZE=$(stat -c%s "$BINARY" 2>/dev/null || stat -f%z "$BINARY")
    echo "Size: $SIZE bytes"
fi
echo "Type: $(file -b "$BINARY")"
echo ""

# PIE / ET_DYN check (more reliable than file(1) parsing)
PIE_TYPE=$(readelf -h "$BINARY" 2>/dev/null | awk '/Type:/{print $2}')
if [[ "$PIE_TYPE" == "DYN" ]]; then
    log_pass "PIE enabled (Type: DYN, ASLR effective)"
else
    log_fail "PIE disabled - binary not ET_DYN"
fi

RELRO=$(readelf -l "$BINARY" 2>/dev/null | grep -c "GNU_RELRO" || true)
BIND_NOW=$(readelf -d "$BINARY" 2>/dev/null | grep -c "BIND_NOW" || true)
if [[ "$RELRO" -gt 0 && "$BIND_NOW" -gt 0 ]]; then
    log_pass "Full RELRO (GOT read-only)"
elif [[ "$RELRO" -gt 0 ]]; then
    log_warn "Partial RELRO (GOT still writable after init)"
else
    log_fail "No RELRO - GOT overwrite possible"
fi

if objdump -d "$BINARY" 2>/dev/null | grep -q "__stack_chk_fail"; then
    log_pass "Stack canaries present"
else
    log_warn "Stack canary symbol not found (may still be present)"
fi

STACK_EXEC=$(readelf -l "$BINARY" 2>/dev/null | grep "GNU_STACK" | grep -c "RWE" || true)
if [[ "$STACK_EXEC" -eq 0 ]]; then
    log_pass "NX enabled (non-executable stack)"
else
    log_fail "Executable stack detected"
fi

SYM_COUNT=$(readelf -s "$BINARY" 2>/dev/null | grep -c "FUNC\|OBJECT" || true)
if [[ "$SYM_COUNT" -lt 100 ]]; then
    log_pass "Symbols stripped ($SYM_COUNT remaining)"
else
    log_warn "Many symbols present ($SYM_COUNT) - consider stripping"
fi

if [[ "$(uname -m)" == "aarch64" ]]; then
    PAC=$(objdump -d "$BINARY" 2>/dev/null | grep -cE "paci|auti|pac[id]" || true)
    BTI=$(objdump -d "$BINARY" 2>/dev/null | grep -c "bti" || true)
    if [[ "$PAC" -gt 100 ]]; then
        log_pass "PAC instructions present ($PAC)"
    elif [[ "$PAC" -gt 0 ]]; then
        log_warn "PAC instructions sparse ($PAC)"
    else
        log_warn "No PAC instructions detected"
    fi
    if [[ "$BTI" -gt 100 ]]; then
        log_pass "BTI landing pads present ($BTI)"
    elif [[ "$BTI" -gt 0 ]]; then
        log_warn "BTI instructions sparse ($BTI)"
    else
        log_warn "No BTI instructions detected"
    fi
fi

FORTIFY=$(objdump -t "$BINARY" 2>/dev/null | grep -c "__.*_chk" || true)
if [[ "$FORTIFY" -gt 0 ]]; then
    log_pass "FORTIFY_SOURCE active ($FORTIFY fortified functions)"
else
    log_warn "No fortified functions found"
fi

RPATH=$(readelf -d "$BINARY" 2>/dev/null | grep -cE "RPATH|RUNPATH" || true)
if [[ "$RPATH" -eq 0 ]]; then
    log_pass "No RPATH/RUNPATH set"
else
    log_warn "RPATH/RUNPATH present - potential injection surface"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
if [[ "$FAILED" -eq 0 ]]; then
    echo -e "  ${GREEN}All critical checks passed${NC}"
    exit 0
else
    echo -e "  ${RED}One or more checks failed${NC}"
    exit 1
fi
