<#
.SYNOPSIS
    ServerPulse Cyber-SOC Dashboard Launcher (Native PowerShell).
#>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "ServerPulse Cyber-SOC - Closed-Loop Engine"

$appDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $appDir

Clear-Host
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SERVERPULSE CYBER-SOC DASHBOARD - MONITORING & MITIGASI" -ForegroundColor Cyan
Write-Host "   Closed-Loop Automation Mitigasi DDoS 3 Level (WSL 2)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Cek Node Modules
Write-Host "[1/3] Memeriksa dependensi modul Node.js..." -ForegroundColor White
if (-not (Test-Path "$appDir\node_modules")) {
    Write-Host "   Mengunduh dependensi npm..." -ForegroundColor Yellow
    npm install
} else {
    Write-Host "   ✅ Node modules tersedia." -ForegroundColor Green
}

# 2. Cek dan Bersihkan Port 3000 jika Terpakai
Write-Host "`n[2/3] Memeriksa ketersediaan Port 3000..." -ForegroundColor White
$existing = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue | Select-Object -First 1
if ($existing) {
    Write-Host "   Melepaskan port 3000 dari proses PID: $($existing.OwningProcess)..." -ForegroundColor Yellow
    Stop-Process -Id $existing.OwningProcess -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}
Write-Host "   ✅ Port 3000 siap digunakan." -ForegroundColor Green

# 3. Jalankan Server
Write-Host "`n[3/3] Mengaktifkan ServerPulse Backend..." -ForegroundColor White
Write-Host "   • Dashboard UI  : http://localhost:3000" -ForegroundColor Green
Write-Host "   • Login Default : admin / admin123" -ForegroundColor Yellow
Write-Host "   • Target Netdata: http://localhost:19999" -ForegroundColor Green
Write-Host ""

Start-Process "http://localhost:3000"
node server.js
