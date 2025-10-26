#!/bin/bash
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 GITHUB READINESS TEST FOR WINNCORE AV-SUITE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

PASS=0
FAIL=0

# Test 1: Build
echo "📦 TEST 1: Clean Build"
if cargo build --all-features 2>&1 | grep -q "Finished"; then
    echo "   ✅ PASS"
    ((PASS++))
else
    echo "   ❌ FAIL"
    ((FAIL++))
fi

# Test 2: No CharmedWOA
echo "🏷️  TEST 2: Branding Check"
if grep -r "CharmedWOA" --include="*.rs" --include="*.toml" . 2>/dev/null | grep -q .; then
    echo "   ❌ FAIL: CharmedWOA found"
    ((FAIL++))
else
    echo "   ✅ PASS"
    ((PASS++))
fi

# Test 3: License
echo "⚖️  TEST 3: License"
if [ -f "LICENSE" ]; then
    echo "   ✅ PASS"
    ((PASS++))
else
    echo "   ❌ FAIL"
    ((FAIL++))
fi

# Test 4: README
echo "📖 TEST 4: README"
if [ -f "README.md" ]; then
    echo "   ✅ PASS"
    ((PASS++))
else
    echo "   ❌ FAIL"
    ((FAIL++))
fi

# Test 5: .gitignore
echo "🚫 TEST 5: .gitignore"
if [ -f ".gitignore" ]; then
    echo "   ✅ PASS"
    ((PASS++))
else
    echo "   ❌ FAIL"
    ((FAIL++))
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 RESULTS: $PASS passed, $FAIL failed"
if [ $FAIL -eq 0 ]; then
    echo "🎉 READY FOR GITHUB!"
else
    echo "⚠️  Fix $FAIL issues"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
