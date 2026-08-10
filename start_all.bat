@echo off
title CyberShield AI Launcher
color 0A

echo ===============================
echo   CyberShield AI Starter
echo ===============================
echo.

set "ROOT_DIR=%~dp0"
set "BACKEND_DIR=%ROOT_DIR%backend"
set "FRONTEND_DIR=%ROOT_DIR%file-scan-log-app"

echo Starting backend server...
start "CyberShield Backend Server" cmd /k cd /d "%BACKEND_DIR%" ^&^& py app.py

echo Waiting for backend...
timeout /t 5 >nul

echo Opening backend API page...
start "" "http://127.0.0.1:5000"

echo Starting frontend application...
start "CyberShield Frontend App" cmd /k cd /d "%FRONTEND_DIR%" ^&^& npm run dev

echo Waiting for frontend...
timeout /t 8 >nul

echo Opening CyberShield AI application...
start "" "http://localhost:5173"

echo.
echo ===============================
echo CyberShield AI is running.
echo Backend API: http://127.0.0.1:5000
echo Frontend App: http://localhost:5173
echo ===============================
echo.
echo Keep both CMD windows open.
echo Close them or run stop_all.bat to stop the app.
echo.
pause