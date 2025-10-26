#!/usr/bin/env bash
set -euo pipefail

PACKAGE_NAME=charmedwoa-av
PRESERVE_QUARANTINE=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge)
      PRESERVE_QUARANTINE=false
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

echo "Stopping service..."
sudo systemctl stop av-daemon.service || true
sudo systemctl disable av-daemon.service || true

if ! $PRESERVE_QUARANTINE; then
  read -p "Purge quarantine directory? [y/N] " confirm
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    sudo rm -rf /var/lib/av/quarantine
  fi
fi

sudo aa-disable /usr/share/apparmor/av-daemon.apparmor || true
sudo dpkg -r $PACKAGE_NAME
