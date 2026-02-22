#!/usr/bin/env bash
set -euo pipefail

# Simple, safer UFW setup helper.
# - Does NOT reset existing rules (to avoid accidental lockout).
# - Adds a minimal allowlist for web + SSH.
# - Optionally allows Tailscale UDP.

SSH_PORT=22
SSH_ALLOW_IP=""
ENABLE_TAILSCALE=0
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage:
  sudo bash ufw_setup.sh [options]

Options:
  --ssh-port <port>         SSH port (default: 22)
  --ssh-allow-ip <ip>       Only allow SSH from this IP (optional)
  --enable-tailscale <0|1>  Allow UDP/41641 for Tailscale (default: 0)
  --dry-run <0|1>           Print commands without running (default: 0)
  -h, --help                Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-port)
      SSH_PORT="${2:-22}"; shift 2;;
    --ssh-allow-ip)
      SSH_ALLOW_IP="${2:-}"; shift 2;;
    --enable-tailscale)
      ENABLE_TAILSCALE="${2:-0}"; shift 2;;
    --dry-run)
      DRY_RUN="${2:-0}"; shift 2;;
    -h|--help)
      usage; exit 0;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2;;
  esac
done

run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "+ $*"
  else
    echo "+ $*"
    eval "$*"
  fi
}

cat <<EOF
About to apply UFW rules:
  - default deny incoming
  - allow outgoing
  - allow 80/tcp, 443/tcp
  - allow SSH port $SSH_PORT${SSH_ALLOW_IP:+ from $SSH_ALLOW_IP}
  - tailscale UDP/41641: $ENABLE_TAILSCALE

IMPORTANT:
  - Do not close your existing SSH session.
  - Open a NEW terminal and test SSH before you log out.
EOF

if [[ "$DRY_RUN" != "1" ]]; then
  read -r -p "Type YES to continue: " ans
  if [[ "$ans" != "YES" ]]; then
    echo "Aborted."; exit 1
  fi
fi

run "ufw default deny incoming"
run "ufw default allow outgoing"
run "ufw allow 80/tcp"
run "ufw allow 443/tcp"

if [[ -n "$SSH_ALLOW_IP" ]]; then
  run "ufw allow from $SSH_ALLOW_IP to any port $SSH_PORT proto tcp"
else
  run "ufw allow $SSH_PORT/tcp"
fi

if [[ "$ENABLE_TAILSCALE" == "1" ]]; then
  run "ufw allow 41641/udp"
fi

run "ufw --force enable"
run "ufw status verbose"
