#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
OUTDIR="$ROOT/backups"
mkdir -p "$OUTDIR"

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "Collecting diagnostics into $WORK ..."

# Compose status
docker compose --env-file "$ROOT/.env" -f "$ROOT/docker-compose.prod.yml" ps > "$WORK/compose_ps.txt" 2>&1 || true
docker compose --env-file "$ROOT/.env" -f "$ROOT/docker-compose.prod.yml" logs --tail=500 > "$WORK/compose_logs_tail.txt" 2>&1 || true

# Health
if [[ -n "${DOMAIN:-}" ]]; then
  curl -fsS "https://${DOMAIN}/api/healthz" > "$WORK/healthz.json" 2>&1 || true
else
  curl -fsS "http://localhost/api/healthz" > "$WORK/healthz.json" 2>&1 || true
fi

# Logs
mkdir -p "$WORK/logs"
cp -f "$ROOT/../backend/data/app.log" "$WORK/logs/app.log" 2>/dev/null || true
cp -f "$ROOT/logs/access.log" "$WORK/logs/caddy_access.log" 2>/dev/null || true

# Security summary (optional)
if [[ -n "${ADMIN_STATUS_KEY:-}" && -n "${DOMAIN:-}" ]]; then
  curl -fsS -H "x-admin-key: ${ADMIN_STATUS_KEY}" "https://${DOMAIN}/api/admin/security/summary?minutes=60" > "$WORK/security_summary.json" 2>&1 || true
fi

ARCHIVE="$OUTDIR/diag-${TS}.tar.gz"
tar -czf "$ARCHIVE" -C "$WORK" .
echo "Diagnostics bundle created: $ARCHIVE"
