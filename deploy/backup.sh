#!/usr/bin/env bash
set -euo pipefail

# Creates a timestamped backup of backend/data (SQLite + logs) to deploy/backups/
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$ROOT_DIR/backend/data"
OUT_DIR="$ROOT_DIR/deploy/backups"

mkdir -p "$OUT_DIR"
ts="$(date +"%Y%m%d-%H%M%S")"
out="$OUT_DIR/backup-$ts.tar.gz"
work="$(mktemp -d)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

if [ ! -d "$DATA_DIR" ]; then
  echo "Data dir not found: $DATA_DIR"
  exit 1
fi

mkdir -p "$work/data"

# Copy non-db artifacts (best-effort)
cp -a "$DATA_DIR"/*.log "$work/data/" 2>/dev/null || true
cp -a "$DATA_DIR"/*.json "$work/data/" 2>/dev/null || true
cp -a "$DATA_DIR"/*.txt "$work/data/" 2>/dev/null || true

# Snapshot SQLite DBs consistently when sqlite3 is available
if command -v sqlite3 >/dev/null 2>&1; then
  for db in "$DATA_DIR"/*.db; do
    [ -e "$db" ] || continue
    base="$(basename "$db")"
    echo "Snapshotting DB: $base"
    sqlite3 "$db" ".backup '$work/data/$base'"
  done
else
  echo "sqlite3 not found; falling back to file copy for *.db"
  cp -a "$DATA_DIR"/*.db "$work/data/" 2>/dev/null || true
fi

tar -czf "$out" -C "$work" data

# Write checksum
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$out" > "$out.sha256"
fi

echo "Backup created: $out"
