@echo off
title Instant Public Tunnel — Samar Home Server
color 0B
cls
echo =======================================================================
echo          TEZKOR INTERNET TUNNELI (PAROLSIZ — 100%% BEPUL)
echo =======================================================================
echo.
echo Server butun dunyoga ulanmoqda...
echo Agar birinchi marta (yes/no) deb so'rasa, "yes" deb Enter bosing!
echo.
echo =======================================================================
echo.
ssh -o StrictHostKeyChecking=accept-new -R 80:localhost:8001 nokey@localhost.run
pause
