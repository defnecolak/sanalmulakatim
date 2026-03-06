# Run unit tests (PowerShell)
cd $PSScriptRoot
if (!(Test-Path .\.venv)) {
  Write-Host "Virtualenv yok. Önce kurulum yap:"
  Write-Host "  python -m venv .venv"
  Write-Host "  .\.venv\Scripts\python.exe -m pip install -r requirements.txt"
  Write-Host "  .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt"
  exit 1
}

$projectTmp = Join-Path $PSScriptRoot ".tmp"
$pytestTmp = Join-Path $PSScriptRoot ".pytest_tmp"
New-Item -ItemType Directory -Force $projectTmp | Out-Null
New-Item -ItemType Directory -Force $pytestTmp | Out-Null

$env:TMP = $projectTmp
$env:TEMP = $projectTmp

.\.venv\Scripts\python.exe -m pytest -q -p no:asyncio --basetemp=$pytestTmp
