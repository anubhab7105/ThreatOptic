@echo off
title ThreatOptic Launcher
echo ===================================================
echo   Starting ThreatOptic - Email Threat ^& Forensics Platform
echo ===================================================

if not exist "%~dp0.env" (
    echo [ERROR] .env file not found in the root directory!
    echo Please copy .env.example to .env and configure it before starting.
    pause
    exit /b 1
)

if not exist "%~dp0frontend\node_modules\" (
    echo [INFO] node_modules not found. Installing frontend dependencies...
    cd /d "%~dp0frontend"
    call npm install
)

echo Starting Backend API (FastAPI)...
start "ThreatOptic Backend - Port 8000" cmd /k "cd /d "%~dp0backend" && set APP_ENV=development&& (if exist ..\.venv\Scripts\activate.bat call ..\.venv\Scripts\activate.bat) && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

echo Starting Frontend UI (Vite / React)...
start "ThreatOptic Frontend - Port 5173" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo ---------------------------------------------------
echo  Backend:  http://127.0.0.1:8000
echo  Frontend: http://127.0.0.1:5173
echo ---------------------------------------------------
echo Both services have been launched in separate windows!
pause

