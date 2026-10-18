@echo off
title Samar Home Server - O'rnatish
color 0A
cls
echo =======================================================================
echo          SAMAR OS HOME SERVER - AVTOMATIK O'RNATISH DASTURI
echo =======================================================================
echo.
echo [1/4] Virtual muhit yaratilmoqda...
if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
)
echo [OK] Virtual muhit tayyor.
echo.

echo [2/4] Kutubxonalar o'rnatilmoqda...
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip --quiet
echo Samar Cloud kutubxonalari...
pip install -r core\samar-cloud\requirements.txt --quiet
echo Samar ID kutubxonalari...
pip install -r core\samar-id\requirements.txt --quiet
echo [OK] Kutubxonalar o'rnatildi.
echo.

echo [3/4] Sozlamalar tekshirilmoqda...
if not exist "core\samar-cloud\.env" copy "core\samar-cloud\.env.example" "core\samar-cloud\.env"
if not exist "core\samar-id\.env" copy "core\samar-id\.env.example" "core\samar-id\.env"
if not exist "core\samar-cloud\uploads" mkdir "core\samar-cloud\uploads"
if not exist "core\samar-id\uploads\avatars" mkdir "core\samar-id\uploads\avatars"
echo [OK] Sozlamalar tayyor.
echo.

echo [4/4] Bajarildi!
echo =======================================================================
echo       Server tayyor!
echo       - Samar ID uchun:    "start_samar_id.bat" (Port 8000)
echo       - Samar Cloud uchun: "start_server.bat"   (Port 8001)
echo =======================================================================
echo.
pause
