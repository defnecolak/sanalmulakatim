$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "[1/4] Installing dev requirements..."
python -m pip install -r requirements-dev.txt

Write-Host "[2/4] Running unit + smoke tests..."
python -m pytest -q

Write-Host "[3/4] Running ruff (lint)..."
python -m ruff check .

Write-Host "[4/4] Running bandit (basic security lints)..."
python -m bandit -q -r . -x .\tests

Write-Host "OK ✅"
