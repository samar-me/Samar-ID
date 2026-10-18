@echo off
title Samar OS — Samar ID (Auth Server 8000)
color 09
cls
echo =======================================================================
echo               SAMAR OS — SAMAR ID AUTH SERVER (PORT 8000)
echo =======================================================================
echo.
echo Kompyuterning mahalliy IP manzillari:
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do (
    echo    -^> http:%%a:8000
)
echo    -^> http://localhost:8000
echo.
echo Samar ID ishga tushirilmoqda (0.0.0.0:8000)...
echo.

if not exist "%~dp0.venv\Scripts\python.exe" (
    echo [OGOHLANTIRISH] Server hali o'rnatilmagan.
    echo Dastlab "setup_home_server.bat" yoki "python setup.py" ni ishga tushiring!
    echo.
    pause
    exit /b
)

cd /d "%~dp0core\samar-id"
"%~dp0.venv\Scripts\python.exe" -m uvicorn main:app --host 0.0.0.0 --port 8000
pause
