@echo off
title Samar Home Server - O'rnatish va Sozlash
color 0A
cls
echo =======================================================================
echo          SAMAR OS HOME SERVER - AVTOMATIK O'RNATISH DASTURI
echo =======================================================================
echo.
echo [1/5] Python tekshirilmoqda...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [XATOLIK] Python topilmadi! Iltimos, Python 3.10+ o'rnatilganligiga
    echo           va "Add Python to PATH" belgisi qo'yilganligiga ishonch hosil qiling.
    echo.
    pause
    exit /b
)
python --version
echo [OK] Python mavjud.
echo.

echo [2/5] Virtual muhit (.venv) tekshirilmoqda...
if not exist "%~dp0.venv\Scripts\python.exe" (
    echo Virtual muhit yaratilmoqda (.venv)...
    python -m venv "%~dp0.venv"
)
echo [OK] Virtual muhit tayyor.
echo.

echo [3/5] Kutubxonalar (pip packages) o'rnatilmoqda...
call "%~dp0.venv\Scripts\activate.bat"
python -m pip install --upgrade pip --quiet
echo Samar Cloud kutubxonalari o'rnatilmoqda...
pip install -r "%~dp0core\samar-cloud\requirements.txt" --quiet
echo [OK] Kutubxonalar muvaffaqiyatli o'rnatildi.
echo.

echo [4/5] Sozlama fayllari (.env) tayyorlanmoqda...
if not exist "%~dp0core\samar-cloud\.env" (
    copy "%~dp0core\samar-cloud\.env.example" "%~dp0core\samar-cloud\.env" >nul
    echo Samar Cloud .env yaratildi.
)
if not exist "%~dp0core\samar-id\.env" (
    copy "%~dp0core\samar-id\.env.example" "%~dp0core\samar-id\.env" >nul
    echo Samar ID .env yaratildi.
)
if not exist "%~dp0core\samar-cloud\uploads" (
    mkdir "%~dp0core\samar-cloud\uploads"
)
echo [OK] Barcha sozlamalar tayyorlandi.
echo.

echo [5/5] Tayyor!
echo =======================================================================
echo       Server to'liq tayyor bo'ldi!
echo       Endi "start_server.bat" orqali Samar Cloud'ni ishga tushirishingiz mumkin.
echo =======================================================================
echo.
pause
