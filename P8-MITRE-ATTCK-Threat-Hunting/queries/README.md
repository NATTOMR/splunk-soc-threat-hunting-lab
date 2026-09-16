# 🔍 SPL Threat Hunting Query Library

[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v15-red.svg)](https://attack.mitre.org/)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%2010.4.3-blue.svg)](https://www.splunk.com/)
[![Project](https://img.shields.io/badge/Project-P8%20Threat%20Hunting-orange.svg)](../README.md)

This directory contains the production-grade SPL query library for **Project P8 — MITRE ATT&CK Threat Hunting with Splunk**. Each query implements an empirical, hypothesis-driven hunt designed to uncover covert adversary activity across the endpoint and network telemetry streams collected within the lab.

---

## Query Index & MITRE ATT&CK Matrix

| Query File | Hunt Domain | MITRE ATT&CK Techniques | Target Telemetry | Output Summary |
|---|---|---|---|---|
| [`01-hypothesis-authentication-hunting.spl`](01-hypothesis-authentication-hunting.spl) | **Authentication** | `T1078.002`, `T1078.003`, `T1110.001`, `T1550.002` | `index=windows` (4624, 4625, 4672) | Logon Type 9 (NewCredentials/PtH), Type 3 privileged SMB, and privilege elevation anomalies. |
| [`02-hypothesis-process-hunting.spl`](02-hypothesis-process-hunting.spl) | **Process & LOLBins** | `T1036.005`, `T1218.005`, `T1218.010`, `T1218.011`, `T1105` | `index=sysmon` (EventID 1) | Living-off-the-land binaries (`certutil`, `bitsadmin`, `mshta`, `regsvr32`, `rundll32`) and path masquerading. |
| [`03-hypothesis-powershell-hunting.spl`](03-hypothesis-powershell-hunting.spl) | **PowerShell & Obfuscation** | `T1059.001`, `T1027`, `T1105` | `index=sysmon` (EventID 1) | Multi-flag obfuscation (`-enc`, `-w hidden`, `-ep bypass`, `DownloadString`, `IEX`) scored by risk. |
| [`04-hypothesis-persistence-hunting.spl`](04-hypothesis-persistence-hunting.spl) | **Persistence Mechanisms** | `T1547.001`, `T1053.005`, `T1543.003`, `T1053.003` | `index=sysmon` (1, 12, 13), `index=windows` (7045), `index=linux_security` | Windows Run keys, `schtasks`, rogue service creation (`sc.exe` / 7045), and Linux crontab tampering. |
| [`05-hypothesis-privilege-escalation.spl`](05-hypothesis-privilege-escalation.spl) | **Privilege Escalation** | `T1098`, `T1548.002`, `T1548.003`, `T1134` | `index=windows` (4728, 4732, 4672), `index=sysmon` (1), `index=linux_security` | Group escalation (`Domain Admins`), UAC bypass binaries (`fodhelper`), and Linux GTFOBins / sudo shell abuse. |
| [`06-hypothesis-command-execution.spl`](06-hypothesis-command-execution.spl) | **Command Execution** | `T1059.003`, `T1059.004`, `T1047`, `T1204.002` | `index=sysmon` (EventID 1) | Anomalous parent-child spawning (Office, Spooler, Web Daemons spawning `cmd.exe`/`powershell.exe`). |
| [`07-hypothesis-lateral-movement.spl`](07-hypothesis-lateral-movement.spl) | **Lateral Movement** | `T1021.001`, `T1021.002`, `T1021.006`, `T1570` | `index=sysmon` (1, 3), `index=windows` (4624, 5140, 5145) | PsExec (`PSEXESVC.exe`), admin share staging (`ADMIN$`, `C$`), remote RDP sessions, and WinRM pivots. |
| [`08-hypothesis-ioc-investigation.spl`](08-hypothesis-ioc-investigation.spl) | **IOC & C2 Triage** | `T1071.001`, `T1071.004`, `T1105`, `T1027` | `index=sysmon` (1, 3, 11, 22) | High-entropy / dynamic DNS lookups, temp folder staging, non-standard egress ports, and SHA256 hashes. |

---

## Telemetry & Syntax Prerequisites

### 1. Sysmon XML Extraction Pattern
Because the lab's Universal Forwarder ingests Windows Event Logs and Sysmon channels with `renderXml = true`, Sysmon `EventID` is encapsulated in XML tags:
```spl
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
```
Direct queries using `EventCode=1` against `index=sysmon` will yield zero results. All queries in this library encapsulate regex extraction compatible with this pipeline.

### 2. Time-Window Baselines
All queries are written with default earliest boundaries (`earliest=-7d` or configurable via dashboard global time pickers). For deep forensic back-hunts, adjust `earliest` to `-30d` or `-90d`.

### 3. Tuning & False Positive Mitigation
- **SCCM / Admin Tooling:** In enterprise production, administration suites (e.g. MECM, PDQ Deploy, Tanium) may legitimately invoke `bitsadmin` or remote services. Baseline legitimate service accounts in query 02 and 07.
- **Developer Workstations:** Developers regularly invoke Base64 encoded scripts or execute Node/Python CLI commands. Use whitelist lookups (`inputlookup authorized_admin_scripts.csv`) to filter approved internal orchestration.
