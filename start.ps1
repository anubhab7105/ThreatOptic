# PowerShell launcher for Email Threat & Forensics Platform
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "   Starting Email Threat & Forensics Platform      " -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

# 1. Start Backend in a separate window
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$PSScriptRoot\backend'; if (Test-Path '$PSScriptRoot\.venv\Scripts\Activate.ps1') { & '$PSScriptRoot\.venv\Scripts\Activate.ps1' }; python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

# 2. Start Frontend in a separate window
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$PSScriptRoot\frontend'; npm run dev"

Write-Host "`n---------------------------------------------------" -ForegroundColor Yellow
Write-Host " Backend:  http://127.0.0.1:8000" -ForegroundColor Green
Write-Host " Frontend: http://127.0.0.1:5173" -ForegroundColor Green
Write-Host "---------------------------------------------------" -ForegroundColor Yellow
