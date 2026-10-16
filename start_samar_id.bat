@echo off
title Samar ID Server — Samar OS
color 0B
echo ========================================================
echo         SAMAR OS — SAMAR ID AUTH SERVER
echo    "Raqamli Erkinlik va Xavfsiz Shaxsiy Ekotizim"
echo ========================================================
echo.
echo Server ishga tushmoqda...
echo Brauzeringizda quyidagi manzilni oching:
echo http://localhost:8000
echo.

cd /d "%~dp0core\samar-id"
..\..\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
pause
