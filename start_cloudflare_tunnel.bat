@echo off
title Cloudflare Public Tunnel — Samar Home Server
color 0E
cls
echo =======================================================================
echo          SAMAR HOME SERVER — INTERNETGA CHIQARISH (TUNNEL)
echo =======================================================================
echo.
echo Tunnel ulanmoqda (HTTP/2 protokoli orqali)...
echo.
cloudflared tunnel --protocol http2 --edge-ip-version 4 --url http://localhost:8001
pause
