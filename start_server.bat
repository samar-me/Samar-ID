@echo off
title Samar OS — Home Server (Samar Cloud 100 GB)
color 0B
cls
echo =======================================================================
echo               SAMAR OS — SHAXSIY HOME SERVER (SAMAR CLOUD)
echo =======================================================================
echo.
echo Kompyuterning mahalliy IP manzillari:
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do (
    echo    -^> http:%%a:8001
)
echo    -^> http://localhost:8001
echo.
echo Server ishga tushirilmoqda (0.0.0.0:8001)...
echo.

if not exist "%~dp0.venv\Scripts\python.exe" (
    echo [OGOHLANTIRISH] Server hali o'rnatilmagan.
    echo Dastlab "setup_home_server.bat" faylini ishga tushiring!
    echo.
    pause
    exit /b
)

cd /d "%~dp0core\samar-cloud"
"%~dp0.venv\Scripts\python.exe" -m uvicorn main:app --host 0.0.0.0 --port 8001
pause
