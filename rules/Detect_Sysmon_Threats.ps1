$sysmonLog = "Microsoft-Windows-Sysmon/Operational"

Write-Host "=== Reflective DLL Injection events ===" -ForegroundColor Yellow
Get-WinEvent -LogName $sysmonLog -FilterHashtable @{Id=7} -MaxEvents 100 |
    Where-Object { $_.Properties[0].Value -like "*.dll" -and $_.Properties[1].Value -eq "false" } |
    Format-Table TimeCreated, Id, @{Name="ImageLoaded";Expression={$_.Properties[0].Value}} -AutoSize

Write-Host "`n=== Suspicious Process Access (VirtualAlloc etc) ===" -ForegroundColor Yellow
Get-WinEvent -LogName $sysmonLog -FilterHashtable @{Id=10} -MaxEvents 100 |
    Where-Object { $_.Properties[4].Value -match "VirtualAlloc|WriteProcessMemory|CreateRemoteThread" } |
    Format-Table TimeCreated, Id, @{Name="CallTrace";Expression={$_.Properties[4].Value}} -AutoSize

Write-Host "`n=== PrintNightmare Exploit Attempts ===" -ForegroundColor Yellow
Get-WinEvent -LogName $sysmonLog -FilterHashtable @{Id=1} -MaxEvents 100 |
    Where-Object { $_.Properties[0].Value -like "*rundll32.exe" -and ($_.Properties[1].Value -match "spoolsv|RpcAddPrinterDriverEx") } |
    Format-Table TimeCreated, Id, @{Name="CommandLine";Expression={$_.Properties[1].Value}} -AutoSize

Write-Host "`n=== HiveNightmare Suspicious File Access ===" -ForegroundColor Yellow
Get-WinEvent -LogName $sysmonLog -FilterHashtable @{Id=11} -MaxEvents 100 |
    Where-Object { $_.Properties[0].Value -match "SAM|SYSTEM|SECURITY" } |
    Format-Table TimeCreated, Id, @{Name="TargetFilename";Expression={$_.Properties[0].Value}} -AutoSize

Write-Host "`n=== SpoolFool Exploit Attempts ===" -ForegroundColor Yellow
Get-WinEvent -LogName $sysmonLog -FilterHashtable @{Id=1} -MaxEvents 100 |
    Where-Object { ($_.Properties[0].Value -match "cmd.exe|powershell.exe") -and ($_.Properties[1].Value -match "icacls|takeown") -and ($_.Properties[1].Value -match "\\spool\\drivers") } |
    Format-Table TimeCreated, Id, @{Name="CommandLine";Expression={$_.Properties[1].Value}} -AutoSize
