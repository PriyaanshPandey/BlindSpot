# HDX Setup Script (PowerShell)
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Hidden Dependency X-Ray (HDX) Setup    " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 1. Check or copy .env
if (-not (Test-Path ".env")) {
    Write-Host "[1/3] Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
} else {
    Write-Host "[1/3] .env file already exists." -ForegroundColor Green
}

# 2. Python Virtual Environment & Dependencies
Write-Host "[2/3] Setting up Python backend..." -ForegroundColor Yellow
Set-Location "$PSScriptRoot\..\backend"
if (-not (Test-Path ".venv")) {
    python -m venv .venv
}
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e .
Set-Location "$PSScriptRoot\.."

# 3. Frontend Dependencies
Write-Host "[3/3] Checking Node.js frontend..." -ForegroundColor Yellow
Set-Location "$PSScriptRoot\..\frontend"
if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host "Running npm install..." -ForegroundColor Cyan
    npm install
} else {
    Write-Host "npm not found in PATH. Please install Node.js 18+ to run the frontend." -ForegroundColor Red
}
Set-Location "$PSScriptRoot\.."

Write-Host "`nSetup complete! You can now run .\scripts\start.ps1" -ForegroundColor Green

