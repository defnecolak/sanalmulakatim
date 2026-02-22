#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "Running post-deploy smoke..."
bash "$ROOT/smoke_public.sh"
echo "OK"
