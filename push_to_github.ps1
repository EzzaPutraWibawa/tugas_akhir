<#
.SYNOPSIS
    One-Click Git Push khusus untuk Website Monitoring ServerPulse ke GitHub.
#>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "Git Push - ServerPulse Monitoring App"

$appDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $appDir

Clear-Host
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " 🚀 GIT PUSH: WEBSITE MONITORING (SERVERPULSE CYBER-SOC)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Lokasi Repo   : $appDir" -ForegroundColor Yellow
Write-Host " Target GitHub : https://github.com/EzzaPutraWibawa/tugas_akhir.git" -ForegroundColor Yellow
Write-Host " Branch Aktif  : main" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Pastikan Staging Bersih
git add .
$status = git status --porcelain
if ($status) {
    git commit -m "update: pembaruan aplikasi website monitoring ServerPulse"
} else {
    Write-Host "[1/2] Status berkas: Berkas website monitoring siap di-push." -ForegroundColor Green
}

# 2. Push ke GitHub
Write-Host "`n[2/2] Mengirim berkas website monitoring ke GitHub..." -ForegroundColor White
git push -u origin main --force

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✅ BERHASIL! Website monitoring telah terunggah ke GitHub!" -ForegroundColor Green
    Write-Host "   Silakan buka: https://github.com/EzzaPutraWibawa/tugas_akhir" -ForegroundColor Cyan
} else {
    Write-Host "`n⚠️ Push belum selesai. Jika diminta login browser, silakan login akun 'EzzaPutraWibawa'." -ForegroundColor Yellow
}

Write-Host ""
pause
