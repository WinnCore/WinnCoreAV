#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Repository hygiene scanner for WinnCoreAV
# Exits non-zero on policy violations

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

VIOLATIONS=0

echo "🔍 WinnCoreAV Repository Scan"
echo "=============================="
echo ""

# 1. Secrets scan with gitleaks
echo "[1/5] Scanning for secrets (gitleaks)..."
if command -v gitleaks &> /dev/null; then
    if gitleaks detect --source . --no-git --verbose 2>&1 | tee /tmp/gitleaks.log; then
        echo -e "${GREEN}✅ No secrets detected${NC}"
    else
        echo -e "${RED}❌ Secrets found. Review /tmp/gitleaks.log${NC}"
        echo "   Remediation: Use 'git filter-repo' to purge history or rotate credentials"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
else
    echo -e "${YELLOW}⚠️  gitleaks not installed. Install: 'brew install gitleaks' or download from GitHub${NC}"
fi
echo ""

# 2. GPL license banners
echo "[2/5] Scanning for GPL license headers..."
if command -v rg &> /dev/null; then
    if rg --type rust --type yaml --type toml --type md --type sh \
        -i 'GNU GENERAL PUBLIC LICENSE|GNU Lesser General Public|GNU AFFERO GENERAL PUBLIC LICENSE' \
        --stats 2>&1 | grep -q "0 matches"; then
        echo -e "${GREEN}✅ No GPL headers found${NC}"
    else
        echo -e "${RED}❌ GPL license text detected${NC}"
        rg --type rust --type yaml --type toml --type md --type sh \
           -i 'GNU GENERAL PUBLIC LICENSE|GNU Lesser General Public|GNU AFFERO GENERAL PUBLIC LICENSE' \
           --no-heading --line-number
        echo "   Remediation: Remove GPL code or relicense with author permission"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
else
    echo -e "${YELLOW}⚠️  ripgrep not installed. Install: 'cargo install ripgrep'${NC}"
fi
echo ""

# 3. Raw EICAR pattern (broken regex to avoid false trigger)
echo "[3/5] Scanning for raw EICAR patterns..."
if command -v rg &> /dev/null; then
    if rg --type rust --type yaml --type sh --type md \
        'X5O.*P%.*@AP.*\[4.*PZX' \
        --stats 2>&1 | grep -q "0 matches"; then
        echo -e "${GREEN}✅ No raw EICAR patterns found${NC}"
    else
        echo -e "${RED}❌ Raw EICAR-like pattern detected${NC}"
        rg --type rust --type yaml --type sh --type md 'X5O.*P%.*@AP.*\[4.*PZX' --no-heading
        echo "   Remediation: Use base64-encoded EICAR (see tools/generate_eicar.sh)"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi
echo ""

# 4. Binary blobs in tracked files
echo "[4/5] Scanning for unexpected binary files..."
BINARIES=$(git ls-files 2>/dev/null | while read -r file; do
    if [ -f "$file" ] && file "$file" | grep -qv "text\|empty\|JSON\|YAML"; then
        echo "$file"
    fi
done)

if [ -z "$BINARIES" ]; then
    echo -e "${GREEN}✅ No unexpected binaries in tracked files${NC}"
else
    echo -e "${RED}❌ Binary files detected:${NC}"
    echo "$BINARIES" | sed 's/^/   /'
    echo "   Remediation: Remove with 'git rm' or add to .gitignore"
    VIOLATIONS=$((VIOLATIONS + 1))
fi
echo ""

# 5. License file presence
echo "[5/5] Checking required files..."
REQUIRED_FILES=("LICENSE" "SECURITY.md" "COMPLIANCE.md" "NOTICE")
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✅ $file present${NC}"
    else
        echo -e "${RED}❌ $file missing${NC}"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
done
echo ""

# Summary
echo "=============================="
if [ $VIOLATIONS -eq 0 ]; then
    echo -e "${GREEN}✅ All checks passed (0 violations)${NC}"
    exit 0
else
    echo -e "${RED}❌ Found $VIOLATIONS violation(s)${NC}"
    echo ""
    echo "Run 'cargo deny check' for dependency audits"
    echo "See SECURITY.md and COMPLIANCE.md for policies"
    exit 1
fi
