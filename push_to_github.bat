@echo off
title Git Push - ServerPulse Monitoring App
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "%~dp0push_to_github.ps1"
