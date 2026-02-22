param(
  [string]$BaseUrl = ""
)

Write-Host "Running post-deploy smoke..."
& "$PSScriptRoot\smoke_public.ps1" -BaseUrl $BaseUrl
Write-Host "OK"
