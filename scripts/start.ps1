# HDX Start Script (PowerShell)
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Starting Hidden Dependency X-Ray (HDX) " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Start Backend in Background or New Process
$backendScript = {
    Set-Location "$using:PSScriptRoot\..\backend"
    if (Test-Path ".venv\Scripts\activate.ps1") {
        & .\.venv\Scripts\Activate.ps1
        uvicorn main:app --reload --port 8000
    } else {
        python main.py
    }
}

Write-Host "Starting Backend on http://localhost:8000..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$PSScriptRoot\..\backend'; python -m uvicorn main:app --reload --port 8000"

Write-Host "Starting Frontend on http://localhost:5173..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$PSScriptRoot\..\frontend'; npm run dev"

Write-Host "`nAll services launching in separate windows." -ForegroundColor Yellow
Write-Host "API Documentation: http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host "Web Dashboard:     http://localhost:5173" -ForegroundColor Cyan

