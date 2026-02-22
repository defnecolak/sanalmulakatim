#!/usr/bin/env bash
set -euo pipefail

RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
BACKUP_DIR="$(cd "$(dirname "$0")" && pwd)/backups"

mkdir -p "$BACKUP_DIR"

# Delete backups older than RETENTION_DAYS
find "$BACKUP_DIR" -type f -name "backup-*.tar.gz" -mtime +"$RETENTION_DAYS" -print -delete || true
find "$BACKUP_DIR" -type f -name "pre-restore-*.tar.gz" -mtime +"$RETENTION_DAYS" -print -delete || true
find "$BACKUP_DIR" -type f -name "diag-*.tar.gz" -mtime +"$RETENTION_DAYS" -print -delete || true

echo "Retention applied. Kept last ${RETENTION_DAYS} days in $BACKUP_DIR"
