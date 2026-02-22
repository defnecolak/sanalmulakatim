#!/usr/bin/env bash
set -euo pipefail

# Creates a timestamped backup of backend/data (SQLite + logs) to ./backups/
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$ROOT_DIR/backend/data"
OUT_DIR="$ROOT_DIR/backups"

mkdir -p "$OUT_DIR"
ts="$(date +"%Y%m%d-%H%M%S")"
out="$OUT_DIR/data-$ts.tar.gz"

if [ ! -d "$DATA_DIR" ]; then
  echo "Data dir not found: $DATA_DIR"
  exit 1
fi

tar -czf "$out" -C "$ROOT_DIR/backend" data
echo "Backup created: $out"
