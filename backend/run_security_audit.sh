#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "[1/4] Installing dev requirements..."
python -m pip install -r requirements-dev.txt

echo "[2/4] Running unit + smoke tests..."
python -m pytest -q

echo "[3/4] Running ruff (lint)..."
python -m ruff check .

echo "[4/4] Running bandit (basic security lints)..."
python -m bandit -q -r . -x ./tests

echo "OK ✅"
