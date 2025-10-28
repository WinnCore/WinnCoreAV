#!/bin/bash
set -e

echo "======================================"
echo "   ARM64 Build Environment Check"
echo "======================================"
echo

echo "1. Architecture:"
uname -m
echo

echo "2. Environment Variables:"
echo "   YARA_NO_PKG_CONFIG=$YARA_NO_PKG_CONFIG"
echo "   PKG_CONFIG_ALLOW_CROSS=$PKG_CONFIG_ALLOW_CROSS"
echo

echo "3. System libyara check:"
if dpkg -l | grep -i libyara >/dev/null 2>&1; then
    echo "   ❌ WARNING: System libyara detected (should not be installed)"
    dpkg -l | grep -i libyara
else
    echo "   ✓ No system libyara (correct)"
fi
echo

echo "4. Required tools:"
for cmd in gcc g++ autoconf automake libtool bison flex pkg-config; do
    if command -v $cmd >/dev/null 2>&1; then
        echo "   ✓ $cmd: $(command -v $cmd)"
    else
        echo "   ❌ $cmd: NOT FOUND"
    fi
done
echo

echo "5. Rust toolchain:"
rustc --version
cargo --version
echo

echo "6. OpenSSL:"
if pkg-config --exists openssl; then
    echo "   ✓ OpenSSL: $(pkg-config --modversion openssl)"
else
    echo "   ❌ OpenSSL: NOT FOUND (install libssl-dev)"
fi
echo

echo "======================================"
echo "   Diagnostic Complete"
echo "======================================"
