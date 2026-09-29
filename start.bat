@echo off
title Email Scanner SOC Launcher
echo ===================================================
echo   Starting Email Threat & Forensics Platform
echo ===================================================

echo Starting Backend API (FastAPI)...
start "SOC Backend - Port 8000" cmd /k "cd /d "%~dp0backend" && (if exist ..\.venv\Scripts\activate.bat call ..\.venv\Scripts\activate.bat) && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

echo Starting Frontend UI (Vite / React)...
start "SOC Frontend - Port 5173" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo ---------------------------------------------------
echo  Backend:  http://127.0.0.1:8000
echo  Frontend: http://127.0.0.1:5173
echo ---------------------------------------------------
echo Both services have been launched in separate windows!
pause
