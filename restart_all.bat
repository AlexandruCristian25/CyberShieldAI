@echo off
title Restart CyberShield AI
color 0E

echo ==========================================
echo      Restart CyberShield AI Enterprise
echo ==========================================
echo.

echo [1/2] Stopping current services...
taskkill /F /IM python.exe >nul 2>&1
taskkill /F /IM node.exe >nul 2>&1

timeout /t 3 >nul

echo [2/2] Starting services again...
call "%~dp0start_all.bat"
