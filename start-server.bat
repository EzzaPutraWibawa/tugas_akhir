@echo off
title ServerPulse Cyber-SOC Monitoring - Closed-Loop Engine
cd /d "%~dp0"

echo ==========================================================
echo    SERVERPULSE CYBER-SOC DASHBOARD - MONITORING DAN MITIGASI
echo    Closed-Loop Automation Mitigasi DDoS 3 Level
echo ==========================================================
echo.

echo [1/3] Memeriksa dependensi modul Node.js...
if not exist "node_modules" (
    echo Mengunduh paket dependencies [express, ws, cors]...
    call npm install
)

echo [2/3] Memeriksa port 3000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":3000 *LISTENING"') do (
    echo Melepaskan port 3000 dari proses lama [PID %%a]...
    taskkill /f /pid %%a >nul 2>&1
)

echo [3/3] Mengaktifkan ServerPulse Cyber-SOC Backend...
echo Dashboard UI  : http://localhost:3000
echo Default Login : admin / admin123
echo Target Netdata: http://localhost:19999
echo.

start "" "http://localhost:3000"

node server.js
pause
