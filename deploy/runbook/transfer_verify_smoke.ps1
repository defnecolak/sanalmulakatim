$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot ".."))
$appSvc = $env:APP_SERVICE
if (-not $appSvc) { $appSvc = "app" }

$baseUrl = $env:BASE_URL
if (-not $baseUrl) { $baseUrl = "http://localhost:5555" }

Write-Host "=== SQLite -> Postgres transfer (strict) ==="
& "$root/runbook/transfer_sqlite_to_postgres.ps1"

Write-Host ""
Write-Host "=== Restart app service ($appSvc) ==="
docker compose --env-file "$root/.env" -f "$root/docker-compose.prod.pg.yml" restart $appSvc

Write-Host ""
Write-Host "=== Critical-flow smoke tests ==="
$env:BASE_URL = $baseUrl
& "$root/runbook/smoke_critical_flows.ps1"

Write-Host ""
Write-Host "ALL OK"
