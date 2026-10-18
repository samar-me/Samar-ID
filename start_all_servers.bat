@echo off
title Samar OS — All-in-One Launcher
color 0F
cls
echo =======================================================================
echo          SAMAR OS — BARCHA XIZMATLARNI ISHGA TUSHIRISH
echo =======================================================================
echo.
echo 1. Samar ID (Auth Server: Port 8000) ishga tushirilmoqda...
start "Samar ID (Port 8000)" "%~dp0start_samar_id.bat"

timeout /t 2 /nobreak >nul

echo 2. Samar Cloud (Cloud Storage: Port 8001) ishga tushirilmoqda...
start "Samar Cloud (Port 8001)" "%~dp0start_server.bat"

timeout /t 3 /nobreak >nul

echo 3. Cloudflare Internet Tunneli ochilmoqda...
start "Cloudflare Tunnel" "%~dp0start_cloudflare_tunnel.bat"

echo.
echo =======================================================================
echo Barcha xizmatlar alohida oynalarda ishga tushirildi!
echo =======================================================================
echo.
pause
