#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:5555}"

echo "[smoke] BASE_URL=$BASE_URL"

check () {
  local path="$1"
  local want="$2"
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$path")
  if [[ "$code" != "$want" ]]; then
    echo "[FAIL] $path -> $code (expected $want)" >&2
    exit 1
  fi
  echo "[OK]   $path -> $code"
}

check "/" "200"
check "/privacy" "200"
check "/refund" "200"
check "/api/healthz" "200"

echo "[smoke] basic checks passed"
