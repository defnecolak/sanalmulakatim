$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot ".."))
$appSvc = $env:APP_SERVICE
if (-not $appSvc) { $appSvc = "app" }

$sqliteInContainer = $env:SQLITE_IN_CONTAINER
if (-not $sqliteInContainer) { $sqliteInContainer = "/app/backend/data/usage.db" }

$archiveDirInContainer = $env:SQLITE_ARCHIVE_DIR_IN_CONTAINER
if (-not $archiveDirInContainer) { $archiveDirInContainer = "/app/deploy/backups" }

Write-Host "Running SQLite -> Postgres transfer inside container ($appSvc) ..."
Write-Host "- source sqlite: $sqliteInContainer"
Write-Host "- archive dir  : $archiveDirInContainer"
Write-Host "NOTE: For best consistency, stop traffic / pause writes before running."

# Hardened defaults: strict counts + archive snapshot + set readonly

docker compose --env-file "$root/.env" -f "$root/docker-compose.prod.pg.yml" exec -T $appSvc `
  python /app/backend/db_transfer_sqlite_to_postgres.py `
    --sqlite $sqliteInContainer `
    --migrate `
    --strict-counts `
    --archive-sqlite `
    --archive-dir $archiveDirInContainer `
    --set-readonly

Write-Host "OK"
