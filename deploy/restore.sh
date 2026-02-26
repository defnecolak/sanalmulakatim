#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: ./deploy/restore.sh ./deploy/backups/backup-YYYYMMDD-HHMMSS.tar.gz"
  exit 1
fi

ARCHIVE="$1"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$ROOT_DIR/backend/data"
OUT_DIR="$ROOT_DIR/deploy/backups"

if [ ! -f "$ARCHIVE" ]; then
  echo "Backup archive not found: $ARCHIVE"
  exit 1
fi

mkdir -p "$OUT_DIR"

# Safety backup of current state
if [ -d "$DATA_DIR" ]; then
  ts="$(date +"%Y%m%d-%H%M%S")"
  safety="$OUT_DIR/pre-restore-$ts.tar.gz"
  tar -czf "$safety" -C "$ROOT_DIR/backend" data || true
  echo "Pre-restore safety backup: $safety"
fi

# Restore
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
tar -xzf "$ARCHIVE" -C "$ROOT_DIR/backend"

echo "Restored backend/data from: $ARCHIVE"
echo "Restart the app (docker compose up -d) to apply."
