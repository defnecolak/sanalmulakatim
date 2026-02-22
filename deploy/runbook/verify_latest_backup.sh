#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LATEST="$(ls -1t "$ROOT/backups"/backup-*.tar.gz 2>/dev/null | head -n 1 || true)"
if [[ -z "$LATEST" ]]; then
  echo "No backup found to verify."
  exit 2
fi
echo "Verifying latest backup: $LATEST"
"$ROOT/verify_backup.sh" "$LATEST"
