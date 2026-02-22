#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BG="$ROOT/bluegreen"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 blue|green"
  exit 1
fi

COLOR="$1"
case "$COLOR" in
  blue)
    cp -f "$BG/Caddyfile.blue" "$BG/Caddyfile.active"
    ;;
  green)
    cp -f "$BG/Caddyfile.green" "$BG/Caddyfile.active"
    ;;
  *)
    echo "Invalid color: $COLOR (expected blue|green)"
    exit 2
    ;;
esac

echo "Reloading Caddy..."
docker compose --env-file "$ROOT/.env" -f "$BG/docker-compose.bluegreen.yml" exec -T caddy caddy reload --config /etc/caddy/Caddyfile || {
  echo "Caddy reload failed. Try: docker compose ... restart caddy"
  exit 3
}

echo "Switched active upstream to: $COLOR"
