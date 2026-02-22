#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <backup-tar.gz>"
  exit 1
fi

ARCHIVE="$1"
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

tar -xzf "$ARCHIVE" -C "$WORK"

# Find sqlite db files in extracted tree
DBS=$(find "$WORK" -type f -name "*.db" || true)

if [[ -z "${DBS}" ]]; then
  echo "No .db files found in backup."
  exit 2
fi

# Verify SQLite integrity
for db in $DBS; do
  echo "Checking integrity: $db"
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$db" "PRAGMA quick_check;" | grep -qi "ok" || (echo "Integrity check failed: $db" && exit 3)
  else
    echo "sqlite3 not found. Skipping integrity check."
    exit 4
  fi
done

echo "Backup integrity OK."
