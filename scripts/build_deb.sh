#!/usr/bin/env bash
set -euo pipefail

PACKAGE_NAME=charmedwoa-av
VERSION=0.1.0
TARGET=aarch64-unknown-linux-gnu
ARTIFACTS_DIR="artifacts"

mkdir -p "$ARTIFACTS_DIR"

cargo build --release --workspace --target $TARGET

DEB_ROOT="build/$PACKAGE_NAME" 
rm -rf "$DEB_ROOT"
mkdir -p "$DEB_ROOT/DEBIAN"
mkdir -p "$DEB_ROOT/usr/lib/$PACKAGE_NAME"
mkdir -p "$DEB_ROOT/etc/$PACKAGE_NAME"
mkdir -p "$DEB_ROOT/var/lib/av/quarantine"
mkdir -p "$DEB_ROOT/var/log/$PACKAGE_NAME"
mkdir -p "$DEB_ROOT/usr/lib/systemd/system"
mkdir -p "$DEB_ROOT/usr/share/apparmor"

cat > "$DEB_ROOT/DEBIAN/control" <<CONTROL
Package: $PACKAGE_NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: arm64
Maintainer: CharmedWOA Security Team <security@charmedwoa.example>
Description: User-space antivirus for Lenovo ThinkPad X13s (ARM64)
CONTROL

cp target/$TARGET/release/av-daemon "$DEB_ROOT/usr/lib/$PACKAGE_NAME/"
cp target/$TARGET/release/av-cli "$DEB_ROOT/usr/lib/$PACKAGE_NAME/"

cp systemd/av-daemon.service "$DEB_ROOT/usr/lib/systemd/system/"
cp policies/apparmor/av-daemon.apparmor "$DEB_ROOT/usr/share/apparmor/"
cp policies/seccomp/av-daemon.json "$DEB_ROOT/etc/$PACKAGE_NAME/"
cp config/daemon.toml "$DEB_ROOT/etc/$PACKAGE_NAME/"

cat > "$DEB_ROOT/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e

AA_PROFILE=/usr/share/apparmor/av-daemon.apparmor
if [ -x /usr/sbin/aa-status ] && [ -x /usr/sbin/aa-enforce ]; then
    /usr/sbin/aa-complain "$AA_PROFILE" || true
    /usr/sbin/aa-enforce "$AA_PROFILE" || true
fi

systemctl daemon-reload || true
exit 0
POSTINST
chmod 0755 "$DEB_ROOT/DEBIAN/postinst"

dpkg-deb --build "$DEB_ROOT" "$ARTIFACTS_DIR/${PACKAGE_NAME}_${VERSION}_aarch64.deb"
