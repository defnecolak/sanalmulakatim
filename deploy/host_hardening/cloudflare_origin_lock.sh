#!/usr/bin/env bash
set -euo pipefail

# Locks down UFW so ports 80/443 are only reachable from Cloudflare IP ranges.
# This prevents origin-bypass when using Cloudflare Access/WAF.
#
# ⚠️ WARNING:
# - Run this only if your domain is proxied (orange cloud) and you understand the consequences.
# - If you misconfigure Cloudflare, you can take your site offline.
# - Keep console access.

DRY_RUN=0
WITH_IPV6=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN="${2:-0}"; shift 2;;
    --with-ipv6)
      WITH_IPV6="${2:-1}"; shift 2;;
    -h|--help)
      echo "Usage: sudo bash cloudflare_origin_lock.sh [--dry-run 1] [--with-ipv6 0|1]"; exit 0;;
    *) echo "Unknown option: $1"; exit 2;;
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

echo "Fetching Cloudflare IP ranges..."
CFV4=$(curl -fsSL https://www.cloudflare.com/ips-v4)
CFV6=""
if [[ "$WITH_IPV6" == "1" ]]; then
  CFV6=$(curl -fsSL https://www.cloudflare.com/ips-v6 || true)
fi

echo "This will:
 - deny public access to 80/443
 - allow 80/443 only from Cloudflare IP ranges
"

if [[ "$DRY_RUN" != "1" ]]; then
  read -r -p "Type YES to continue: " ans
  if [[ "$ans" != "YES" ]]; then
    echo "Aborted."; exit 1
  fi
fi

# Remove broad allows if present (best-effort)
run "ufw delete allow 80/tcp || true"
run "ufw delete allow 443/tcp || true"

# Set defaults (do not change outgoing)
run "ufw default deny incoming"

# Allow Cloudflare ranges
while IFS= read -r cidr; do
  [[ -z "$cidr" ]] && continue
  run "ufw allow proto tcp from $cidr to any port 80"
  run "ufw allow proto tcp from $cidr to any port 443"
done <<< "$CFV4"

if [[ -n "$CFV6" ]]; then
  while IFS= read -r cidr; do
    [[ -z "$cidr" ]] && continue
    run "ufw allow proto tcp from $cidr to any port 80"
    run "ufw allow proto tcp from $cidr to any port 443"
  done <<< "$CFV6"
fi

run "ufw --force enable"
run "ufw status verbose"

echo "Done. Test your site via the domain (through Cloudflare)."
