# PowerShell launcher for ThreatOptic - Email Threat & Forensics Platform
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "   Starting ThreatOptic - Email Threat Platform  " -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

$Root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# 1. Start Backend in a separate window
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$Root\backend'; if (Test-Path '$Root\.venv\Scripts\Activate.ps1') { & '$Root\.venv\Scripts\Activate.ps1' }; python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

# 2. Start Frontend in a separate window
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$Root\frontend'; npm run dev"

Write-Host "`n---------------------------------------------------" -ForegroundColor Yellow
Write-Host " Backend:  http://127.0.0.1:8000" -ForegroundColor Green
Write-Host " Frontend: http://127.0.0.1:5173" -ForegroundColor Green
Write-Host "---------------------------------------------------" -ForegroundColor Yellow
