@echo off
title CyberShield AI System Check
color 0B

echo ==========================================
echo      CyberShield AI System Check
echo ==========================================
echo.

set ROOT_DIR=%~dp0
set BACKEND_DIR=%ROOT_DIR%backend
set FRONTEND_DIR=%ROOT_DIR%file-scan-log-app

echo [PATH] Root:
echo %ROOT_DIR%
echo.

echo [CHECK] Python:
python --version

echo.
echo [CHECK] Node.js:
node --version

echo.
echo [CHECK] npm:
npm --version

echo.
echo [CHECK] Backend folder:
if exist "%BACKEND_DIR%" (
    echo OK - %BACKEND_DIR%
) else (
    echo MISSING - %BACKEND_DIR%
)

echo.
echo [CHECK] app.py:
if exist "%BACKEND_DIR%\app.py" (
    echo OK - backend\app.py
) else (
    echo MISSING - backend\app.py
)

echo.
echo [CHECK] Frontend folder:
if exist "%FRONTEND_DIR%" (
    echo OK - %FRONTEND_DIR%
) else (
    echo MISSING - %FRONTEND_DIR%
)

echo.
echo [CHECK] package.json:
if exist "%FRONTEND_DIR%\package.json" (
    echo OK - file-scan-log-app\package.json
) else (
    echo MISSING - file-scan-log-app\package.json
)

echo.
echo [CHECK] Python packages:
cd /d "%BACKEND_DIR%" 2>nul
python -c "import flask, flask_cors, requests, reportlab, werkzeug; print('OK - Python packages installed')" 2>nul

if errorlevel 1 (
    echo MISSING - Some Python packages are not installed.
    echo Run:
    echo python -m pip install flask flask-cors requests reportlab werkzeug
)

echo.
echo [CHECK] node_modules:
if exist "%FRONTEND_DIR%\node_modules" (
    echo OK - node_modules exists
) else (
    echo MISSING - node_modules
    echo Run:
    echo cd "%FRONTEND_DIR%"
    echo npm install
)

echo.
echo System check completed.
echo.
pause
