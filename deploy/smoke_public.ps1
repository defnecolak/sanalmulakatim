param(
  [string]$BaseUrl = "http://localhost:5555"
)

Write-Host "[smoke] BaseUrl=$BaseUrl"

function Check([string]$Path, [int]$Want) {
  try {
    $resp = Invoke-WebRequest -UseBasicParsing -Uri ("$BaseUrl$Path") -Method GET
    $code = [int]$resp.StatusCode
  } catch {
    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
      $code = [int]$_.Exception.Response.StatusCode.Value__
    } else {
      throw $_
    }
  }

  if ($code -ne $Want) {
    Write-Host "[FAIL] $Path -> $code (expected $Want)" -ForegroundColor Red
    exit 1
  }
  Write-Host "[OK]   $Path -> $code" -ForegroundColor Green
}

Check "/" 200
Check "/privacy" 200
Check "/refund" 200
Check "/api/healthz" 200

Write-Host "[smoke] basic checks passed" -ForegroundColor Green
