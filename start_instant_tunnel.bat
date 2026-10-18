@echo off
title Instant Public Tunnel — Samar Home Server
color 0B
cls
echo =======================================================================
echo          TEZKOR INTERNET TUNNELI (SSH 443 — BLOKLANMAYDIGAN)
echo =======================================================================
echo.
echo Tunnel ulanmoqda...
echo.
echo Agar "Are you sure you want to continue connecting (yes/no/[fingerprint])?"
echo deb so'rasa, klaviaturadan "yes" deb Enter bosing!
echo.
echo =======================================================================
echo.
ssh -o StrictHostKeyChecking=accept-new -p 443 -R0:localhost:8001 a.pinggy.io
pause
