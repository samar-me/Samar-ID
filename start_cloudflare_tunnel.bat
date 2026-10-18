@echo off
title Cloudflare Public Tunnel — Samar Home Server
color 0E
cls
echo =======================================================================
echo          SAMAR HOME SERVER — INTERNETGA CHIQARISH (TUNNEL)
echo =======================================================================
echo.
echo Bu dastur sizning serveringizni routerda port ochmasdan butun dunyoga
echo bepul va xavfsiz HTTPS orqali ochib beradi.
echo.
echo Quyida "https://....trycloudflare.com" ko'rinishidagi havola paydo bo'ladi.
echo O'sha havolani do'stlaringizga yoki o'zingizning telefoningizga yuborib
echo Samar Cloud'ga kirsangiz bo'ladi!
echo.
echo =======================================================================
echo.
cloudflared tunnel --url http://localhost:8001
pause
