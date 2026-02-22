$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot ".."))
$appSvc = $env:APP_SERVICE
if (-not $appSvc) { $appSvc = "app" }

$baseUrl = $env:BASE_URL
if (-not $baseUrl) { $baseUrl = "http://localhost:5555" }

Write-Host "Running critical-flow smoke tests inside container ($appSvc) ..."
Write-Host "- base url: $baseUrl"

# This script assumes the app is running inside the same container (localhost:5555).
# If you run it from outside, set BASE_URL to the public domain.

docker compose --env-file "$root/.env" -f "$root/docker-compose.prod.pg.yml" exec -T $appSvc `
  python /app/backend/smoke_critical_flows.py --base-url $baseUrl

Write-Host "OK"
