@echo off
title WinSecAudit - University Cybersecurity Demonstration Launcher
echo ============================================================================
echo   WinSecAudit - Windows Security Auditing and Compliance System (v1.0.0)
echo ============================================================================
echo.
echo [1/3] Starting FastAPI Security Audit Backend on http://127.0.0.1:8000 ...
start "WinSecAudit Backend (FastAPI)" cmd /k "cd /d "%~dp0backend" && .\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000"

timeout /t 2 /nobreak >nul

echo [2/3] Starting React + TypeScript Frontend on http://127.0.0.1:5173 ...
start "WinSecAudit Frontend (Vite)" cmd /k "cd /d "%~dp0frontend" && npm.cmd run dev"

timeout /t 3 /nobreak >nul

echo [3/3] Opening WinSecAudit Dashboard in your default browser...
start http://127.0.0.1:5173

echo.
echo Both servers are now running! Close the two terminal windows when finished.
pause
