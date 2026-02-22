#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "Virtualenv yok. Önce kurulum yap:"
  echo "  python3 -m venv .venv"
  echo "  ./.venv/bin/python -m pip install -r requirements.txt"
  echo "  ./.venv/bin/python -m pip install -r requirements-dev.txt"
  exit 1
fi

./.venv/bin/python -m pytest -q
