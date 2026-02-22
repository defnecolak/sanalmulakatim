#!/usr/bin/env bash
set -euo pipefail

# Immutable-ish blue/green deploy helper.
# Assumes: you have pulled/updated the code on the server, and you want to build a new image tag
# and switch traffic with minimal downtime.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BG="$ROOT/bluegreen"
ENV_FILE="$ROOT/.env"
COMPOSE="$BG/docker-compose.bluegreen.yml"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing deploy/.env at $ENV_FILE"
  exit 1
fi

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <color-to-deploy> <image-tag>"
  echo "Example: $0 green 2026-02-20-rc1"
  exit 1
fi

COLOR="$1"
TAG="$2"

case "$COLOR" in
  blue|green) ;;
  *) echo "color must be blue|green"; exit 2;;
esac

# Build image with tag
echo "Building image sanal-mulakatim:$TAG ..."
docker build -t "sanal-mulakatim:$TAG" "$ROOT/.."

# Set env override for compose (BLUE_IMAGE_TAG / GREEN_IMAGE_TAG)
export BLUE_IMAGE_TAG="${BLUE_IMAGE_TAG:-blue}"
export GREEN_IMAGE_TAG="${GREEN_IMAGE_TAG:-green}"
if [[ "$COLOR" == "blue" ]]; then
  export BLUE_IMAGE_TAG="$TAG"
else
  export GREEN_IMAGE_TAG="$TAG"
fi

# Start target color container (it may run alongside the other color briefly)
echo "Starting $COLOR ..."
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" up -d "app_${COLOR}"

# Warmup / health probe (local-only port)
PORT="5556"
[[ "$COLOR" == "green" ]] && PORT="5557"
echo "Waiting for healthz on 127.0.0.1:$PORT ..."
for i in {1..30}; do
  if curl -fsS "http://127.0.0.1:${PORT}/api/healthz" >/dev/null 2>&1; then
    echo "Healthz OK."
    break
  fi
  sleep 1
done

# Switch caddy upstream
"$BG/switch.sh" "$COLOR"

echo "Post-switch smoke (public) ..."
if command -v bash >/dev/null 2>&1 && [[ -f "$ROOT/smoke_public.sh" ]]; then
  bash "$ROOT/smoke_public.sh" || true
fi

echo "Deploy complete. Consider stopping the other color if you don't need it running:"
echo "  docker compose --env-file $ENV_FILE -f $COMPOSE stop app_blue|app_green"
