@echo off
title ARP Spoofing Detector - Admin Mode
color 0A

:: Check if running as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ========================================
    echo ARP Spoofing Detector - Admin Required
    echo ========================================
    echo.
    echo This tool requires administrator privileges.
    echo Requesting elevation...
    echo.
    
    :: Create a temporary VBS script for UAC prompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c cd /d ""%~dp0"" && python ""arp_spoof_detector.py"" && pause", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /b
)

:: If already admin, run directly
echo ========================================
echo ARP Spoofing Detector
echo Running with Administrator privileges...
echo ========================================
echo.

python "arp_spoof_detector.py"

echo.
echo ========================================
echo ARP Detector has finished.
echo Press any key to exit...
pause >nul
