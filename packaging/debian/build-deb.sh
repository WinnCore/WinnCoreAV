#!/bin/bash
set -euo pipefail

VERSION="${1:-0.1.0}"
ARCH="${2:-$(dpkg --print-architecture 2>/dev/null || echo 'arm64')}"
PKG_NAME="winncore-av"
PKG_DIR="${PKG_NAME}_${VERSION}_${ARCH}"

echo "Building WinnCoreAV ${VERSION} for ${ARCH}"

rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/lib/winncore"
mkdir -p "$PKG_DIR/etc/winncore/rules"
mkdir -p "$PKG_DIR/var/lib/winncore/"{quarantine,cache,state,hashes}
mkdir -p "$PKG_DIR/var/log/winncore"
mkdir -p "$PKG_DIR/lib/systemd/system"

# Copy binaries if present
for bin in av-daemon av-watchdog av-cli; do
    if [ -f "../../target/release/$bin" ]; then
        cp "../../target/release/$bin" "$PKG_DIR/usr/lib/winncore/"
    else
        echo "Warning: $bin not found in target/release/"
    fi
done

# Systemd units
cp ../systemd/*.service "$PKG_DIR/lib/systemd/system/"

# Control file
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: WinnCore <maintainer@example.com>
Description: WinnCoreAV - ARM64-native EDR Agent
 Depends on libc6; service units included.
Section: security
Priority: optional
EOF

# Postinst
cat > "$PKG_DIR/DEBIAN/postinst" << 'POSTINST'
#!/bin/sh
set -e
if ! getent passwd winncore >/dev/null 2>&1; then
    adduser --system --no-create-home --shell /usr/sbin/nologin winncore || true
fi
chown -R root:winncore /etc/winncore 2>/dev/null || true
chmod 750 /etc/winncore 2>/dev/null || true
chown -R winncore:winncore /var/lib/winncore /var/log/winncore 2>/dev/null || true
chmod 750 /var/lib/winncore /var/log/winncore 2>/dev/null || true
chmod 700 /var/lib/winncore/quarantine 2>/dev/null || true
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable winncore-daemon winncore-watchdog winncore-ebpf-loader || true
fi
POSTINST
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Prerm
cat > "$PKG_DIR/DEBIAN/prerm" << 'PRERM'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop winncore-watchdog winncore-daemon winncore-ebpf-loader || true
    systemctl disable winncore-watchdog winncore-daemon winncore-ebpf-loader || true
fi
PRERM
chmod 755 "$PKG_DIR/DEBIAN/prerm"

dpkg-deb --build "$PKG_DIR"
echo "Built: ${PKG_DIR}.deb"
