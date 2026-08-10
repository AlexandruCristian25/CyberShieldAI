@echo off
title Stop CyberShield AI
color 0C

echo ==========================================
echo      Stop CyberShield AI Enterprise
echo ==========================================
echo.

echo [STOP] Closing Python backend processes...
taskkill /F /IM python.exe >nul 2>&1

echo [STOP] Closing Node/Vite frontend processes...
taskkill /F /IM node.exe >nul 2>&1

echo.
echo CyberShield AI services stopped.
echo.
pause
