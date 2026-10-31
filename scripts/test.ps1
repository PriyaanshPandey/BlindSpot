# HDX Test Suite Runner (PowerShell)
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Running HDX Automated Test Suites      " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

Set-Location "$PSScriptRoot\..\backend"
Write-Host "[1/2] Running Backend Unit & Integration Tests..." -ForegroundColor Yellow
python -m pytest ../tests -v

Set-Location "$PSScriptRoot\..\frontend"
Write-Host "[2/2] Running Frontend Typecheck & Build..." -ForegroundColor Yellow
if (Get-Command npm -ErrorAction SilentlyContinue) {
    npm run build
} else {
    Write-Host "Skipping frontend build (npm not installed)." -ForegroundColor Yellow
}

Set-Location "$PSScriptRoot\.."
Write-Host "`nTest execution finished." -ForegroundColor Green

