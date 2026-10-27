@echo off
title Campus Network Auto Login - Setup
cd /d "%~dp0"
python srun_core.py setpass
echo.
python install.py --status
echo.
pause
