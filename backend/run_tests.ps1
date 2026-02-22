\
# Run unit tests (PowerShell)
cd $PSScriptRoot
if (!(Test-Path .\.venv)) {
  Write-Host "Virtualenv yok. Önce kurulum yap:"
  Write-Host "  python -m venv .venv"
  Write-Host "  .\.venv\Scripts\python.exe -m pip install -r requirements.txt"
  Write-Host "  .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt"
  exit 1
}

.\.venv\Scripts\python.exe -m pytest -q
