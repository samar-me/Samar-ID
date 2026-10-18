@echo off
title Samar Cloud & Moments — Samar OS (5 TB)
color 0B
echo ========================================================
echo         SAMAR OS — SAMAR CLOUD & MOMENTS (5 TB)
echo    "Sovereign Cloud & Photos — Google Drive Powered"
echo ========================================================
echo.
echo Server ishga tushmoqda...
echo Brauzeringizda quyidagi manzilni oching:
echo http://localhost:8001
echo.

cd /d "%~dp0core\samar-cloud"
..\..\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8001 --reload
pause
