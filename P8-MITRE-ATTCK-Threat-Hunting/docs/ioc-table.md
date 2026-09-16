# 📋 Indicators of Compromise (IOC) & Tradecraft Signatures

[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v15-red.svg)](https://attack.mitre.org/)
[![Project](https://img.shields.io/badge/Project-P8%20Threat%20Hunting-orange.svg)](../README.md)

This document catalogs the forensic indicators, living-off-the-land binaries (LOLBins), suspicious command-line parameters, persistence artifacts, and network signatures targeted by the **Project P8** threat hunting library.

---

## 1. Living-Off-The-Land Binaries (LOLBins) & Dual-Use Tools

| Binary Name | Legitimate System Path | Malicious Use Case | High-Risk Arguments / Signatures | MITRE ATT&CK |
|---|---|---|---|---|
| `certutil.exe` | `C:\Windows\System32\certutil.exe` | Remote payload download / Base64 decode | `-urlcache`, `-split`, `-f http://...`, `-decode` | `T1105` |
| `bitsadmin.exe` | `C:\Windows\System32\bitsadmin.exe` | Ingress tool transfer / BITS staging | `/transfer`, `/addfile`, `/setnotifycmdline` | `T1105` |
| `mshta.exe` | `C:\Windows\System32\mshta.exe` | Remote scriptlet execution (VBS/JS) | `http://...`, `vbscript:Execute(...)`, `javascript:...` | `T1218.005` |
| `regsvr32.exe` | `C:\Windows\System32\regsvr32.exe` | Squiblydoo remote SCT execution | `/s`, `/u`, `/i:http://... scrobj.dll` | `T1218.010` |
| `rundll32.exe` | `C:\Windows\System32\rundll32.exe` | In-memory execution of DLLs/scripts | `javascript:...`, `shell32.dll`, `Control_RunDLL` | `T1218.011` |
| `fodhelper.exe` | `C:\Windows\System32\fodhelper.exe` | UAC elevation bypass | Registry hijack: `HKCU\Software\Classes\ms-settings` | `T1548.002` |
| `psexesvc.exe` | Staged in `C:\Windows\` | PsExec lateral execution daemon | Remote SMB service instantiation | `T1021.002` |
| `wmic.exe` | `C:\Windows\System32\wbem\wmic.exe`| Lateral execution / process spawning | `process call create "cmd.exe ..."` | `T1047` |

---

## 2. Persistence Locations & Registry Keys

| Platform | Persistence Mechanism | Exact Registry / File Location | Monitored Event |
|---|---|---|---|
| **Windows** | User Run Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Sysmon EventID 12, 13 |
| **Windows** | Machine Run Key | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | Sysmon EventID 12, 13 |
| **Windows** | RunOnce Key | `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce` | Sysmon EventID 12, 13 |
| **Windows** | Winlogon Shell/Userinit | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` | Sysmon EventID 13 |
| **Windows** | Scheduled Task | `C:\Windows\System32\Tasks\` / `schtasks /create` | Sysmon EventID 1, EID 11 |
| **Windows** | Windows Service | `HKLM\System\CurrentControlSet\Services\` / `sc create` | Windows EventCode 7045 |
| **Linux** | User Crontab | `/var/spool/cron/crontabs/<user>` | `index=linux_security` |
| **Linux** | System Cron Directories| `/etc/cron.d/`, `/etc/cron.hourly/`, `/etc/crontab` | `index=linux_security` |

---

## 3. High-Risk Command-Line Signatures

| Pattern Category | Sample Command Line String | Threat Significance |
|---|---|---|
| **PowerShell Obfuscation** | `powershell.exe -w hidden -ep bypass -enc SQBFAFgA...` | Hides window, bypasses policy, executes Base64 payload. |
| **Download Cradle** | `powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString('http://...')"` | In-memory dropper avoiding disk writes. |
| **Local Group Escalation** | `net localgroup administrators attacker_user /add` | Direct elevation to administrative access. |
| **Discovery Burst** | `cmd.exe /c whoami & net user & ipconfig /all & systeminfo` | Rapid automated reconnaissance following initial compromise. |
| **Linux Sudo Abuse** | `sudo /bin/bash` or `sudo vim -c ':!/bin/bash'` | GTFOBins privilege escalation bypass. |

---

## 4. Network & C2 Signatures

| Indicator Type | Signature / Pattern | Context |
|---|---|---|
| **Dynamic DNS Domains** | `*.ngrok.io`, `*.duckdns.org`, `*.no-ip.biz`, `*.dynu.net` | Reverse tunneling and dynamic adversary C2 nodes. |
| **Suspicious TLDs** | `.top`, `.xyz`, `.buzz`, `.online`, `.work`, `.icu`, `.kim`, `.cc` | Low-reputation, high-abuse registrar top-level domains. |
| **Adversary Tool Ports** | TCP `4444` (Metasploit), TCP `1337` / `31337` (Backdoors) | Default egress connections to command-and-control listeners. |
| **Admin Shares** | `\\<target_ip>\ADMIN$`, `\\<target_ip>\C$` | Staging ground for remote executable propagation. |
