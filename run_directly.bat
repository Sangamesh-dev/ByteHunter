@echo off
title ByteHunter — Startup
color 0A

echo.
echo  ██████╗ ██╗   ██╗████████╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
echo  ██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
echo  ██████╔╝ ╚████╔╝    ██║   █████╗  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
echo  ██╔══██╗  ╚██╔╝     ██║   ██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
echo  ██████╔╝   ██║      ██║   ███████╗██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
echo  ╚═════╝    ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
echo.
echo  AI-Powered Malware Classification System
echo  ==========================================
echo.

:: ── Check Python ──────────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)

:: ── Check Node ────────────────────────────────────────────────────────────────
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js not found. Install Node.js 18+ from https://nodejs.org
    pause
    exit /b 1
)

echo [1/4] Installing backend dependencies...
cd /d "%~dp0backend"
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [ERROR] Backend pip install failed.
    pause
    exit /b 1
)
echo       Done.

echo.
echo [2/4] Installing frontend dependencies...
cd /d "%~dp0frontend"
call npm install --silent
if errorlevel 1 (
    echo [ERROR] Frontend npm install failed.
    pause
    exit /b 1
)
echo       Done.

echo.
echo [3/4] Starting backend (FastAPI on port 8000)...
cd /d "%~dp0backend"
start "ByteHunter Backend" cmd /k "color 0A && echo ByteHunter Backend && echo. && uvicorn main:app --host 0.0.0.0 --port 8000 --reload"

:: Give the backend a moment to start
timeout /t 3 /nobreak >nul

echo.
echo [4/4] Starting frontend (Vite on port 5173)...
cd /d "%~dp0frontend"
start "ByteHunter Frontend" cmd /k "color 0B && echo ByteHunter Frontend && echo. && npm run dev"

:: Wait for frontend to be ready
timeout /t 4 /nobreak >nul

echo.
echo  ==========================================
echo   ByteHunter is running!
echo.
echo   Frontend : http://localhost:5173
echo   Backend  : http://localhost:8000
echo   Health   : http://localhost:8000/api/health
echo  ==========================================
echo.
echo  Opening browser...
start http://localhost:5173

echo.
echo  Both servers are running in separate windows.
echo  Close those windows to stop ByteHunter.
echo.
pause
