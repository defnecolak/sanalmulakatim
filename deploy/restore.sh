#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: ./deploy/restore.sh ./backups/data-YYYYMMDD-HHMMSS.tar.gz"
  exit 1
fi

ARCHIVE="$1"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -f "$ARCHIVE" ]; then
  echo "Backup archive not found: $ARCHIVE"
  exit 1
fi

tar -xzf "$ARCHIVE" -C "$ROOT_DIR/backend"
echo "Restored backend/data from: $ARCHIVE"
echo "Restart the app (docker compose up -d) to apply."
