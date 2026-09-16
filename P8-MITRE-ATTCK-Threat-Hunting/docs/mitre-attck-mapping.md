# 🗺️ MITRE ATT&CK Enterprise Matrix Mapping

[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v15-red.svg)](https://attack.mitre.org/)
[![Project](https://img.shields.io/badge/Project-P8%20Threat%20Hunting-orange.svg)](../README.md)
[![SIEM Coverage](https://img.shields.io/badge/SIEM%20Coverage-8%20Tactics%20Mapped-success.svg)](#attck-technique-coverage-matrix)

This document provides a comprehensive mapping of all hunting queries, telemetry data sources, and adversary detection rules developed in **Project P8 — MITRE ATT&CK Threat Hunting with Splunk** to the MITRE ATT&CK Enterprise Matrix (v15).

---

## ATT&CK Technique Coverage Matrix

| ATT&CK Tactic | Technique Name | Technique ID | Sub-technique | Target Telemetry Source | SPL Query Reference | Detection Logic Summary |
|---|---|---|---|---|---|---|
| **Initial Access / Lateral** | Valid Accounts | `T1078` | `.002` (Domain), `.003` (Local) | `index=windows` (4624, 4672) | [`01-hypothesis-authentication-hunting.spl`](../queries/01-hypothesis-authentication-hunting.spl) | Identifies administrative accounts logging on over network SMB shares or assigned special token rights. |
| **Credential Access** | Brute Force | `T1110` | `.001` (Password Guessing) | `index=windows` (4625) | [`01-hypothesis-authentication-hunting.spl`](../queries/01-hypothesis-authentication-hunting.spl) | Correlates failure bursts against target accounts. |
| **Lateral Movement** | Use Alternate Auth Material | `T1550` | `.002` (Pass the Hash) | `index=windows` (4624) | [`01-hypothesis-authentication-hunting.spl`](../queries/01-hypothesis-authentication-hunting.spl) | Flags Logon Type 9 (NewCredentials) originating from local caller processes. |
| **Defense Evasion** | Masquerading | `T1036` | `.005` (Match Legitimate Name/Location) | `index=sysmon` (EventID 1) | [`02-hypothesis-process-hunting.spl`](../queries/02-hypothesis-process-hunting.spl) | Catches critical system processes (`svchost.exe`, `lsass.exe`, `explorer.exe`) outside approved system directories. |
| **Defense Evasion** | System Binary Proxy Execution | `T1218` | `.005` (Mshta), `.010` (Regsvr32), `.011` (Rundll32) | `index=sysmon` (EventID 1) | [`02-hypothesis-process-hunting.spl`](../queries/02-hypothesis-process-hunting.spl) | Detects LOLBin command-line invocations containing URLs, scriptlets (`scrobj.dll`), or obfuscated arguments. |
| **Command & Control** | Ingress Tool Transfer | `T1105` | — | `index=sysmon` (EventID 1) | [`02-hypothesis-process-hunting.spl`](../queries/02-hypothesis-process-hunting.spl) | Identifies `certutil.exe -urlcache` and `bitsadmin /transfer` downloading remote binaries. |
| **Execution** | Command & Scripting Interpreter | `T1059` | `.001` (PowerShell) | `index=sysmon` (EventID 1) | [`03-hypothesis-powershell-hunting.spl`](../queries/03-hypothesis-powershell-hunting.spl) | Evaluates multi-parameter risk scores (`-enc`, `-ep bypass`, `-w hidden`, `DownloadString`, `IEX`). |
| **Defense Evasion** | Obfuscated Files or Info | `T1027` | — | `index=sysmon` (EventID 1) | [`03-hypothesis-powershell-hunting.spl`](../queries/03-hypothesis-powershell-hunting.spl) | Flags Base64 encoded payload strings. |
| **Persistence** | Boot or Logon Autostart | `T1547` | `.001` (Registry Run Keys) | `index=sysmon` (EventID 12, 13) | [`04-hypothesis-persistence-hunting.spl`](../queries/04-hypothesis-persistence-hunting.spl) | Detects registry value writes under `HKLM\...\Run` or `HKCU\...\Run`. |
| **Persistence / Execution**| Scheduled Task/Job | `T1053` | `.005` (Scheduled Task), `.003` (Cron) | `index=sysmon` (1), `index=linux_security` | [`04-hypothesis-persistence-hunting.spl`](../queries/04-hypothesis-persistence-hunting.spl) | Hunts for `schtasks.exe /create` commands and Linux crontab file modifications. |
| **Persistence / PrivEsc** | Create or Modify System Process | `T1543` | `.003` (Windows Service) | `index=windows` (7045), `index=sysmon` (1) | [`04-hypothesis-persistence-hunting.spl`](../queries/04-hypothesis-persistence-hunting.spl) | Detects new service installations (`sc.exe create` or System Event 7045). |
| **Privilege Escalation** | Account Manipulation | `T1098` | — | `index=windows` (4728, 4732), `index=sysmon` (1) | [`05-hypothesis-privilege-escalation.spl`](../queries/05-hypothesis-privilege-escalation.spl) | Catches accounts added to `Administrators` or `Domain Admins`. |
| **Privilege Escalation** | Abuse Elevation Control | `T1548` | `.002` (Bypass UAC), `.003` (Sudo Abuse) | `index=sysmon` (1), `index=linux_security` | [`05-hypothesis-privilege-escalation.spl`](../queries/05-hypothesis-privilege-escalation.spl) | Identifies LOLBin UAC bypasses (`fodhelper.exe`) and Linux sudo shell spawns (`/bin/bash` via sudo). |
| **Execution** | Command & Scripting Interpreter | `T1059` | `.003` (Windows Shell), `.004` (Unix Shell) | `index=sysmon` (EventID 1) | [`06-hypothesis-command-execution.spl`](../queries/06-hypothesis-command-execution.spl) | Uncovers unusual parent processes (Office suite, print spooler, web daemons) spawning shells. |
| **Lateral Movement** | Remote Services | `T1021` | `.001` (RDP), `.002` (SMB/Admin Shares), `.006` (WinRM) | `index=sysmon` (1, 3), `index=windows` (4624, 5140) | [`07-hypothesis-lateral-movement.spl`](../queries/07-hypothesis-lateral-movement.spl) | Traverses PsExec execution (`PSEXESVC.exe`), admin share file transfer (`ADMIN$`, `C$`), and RDP sessions. |
| **Command & Control** | Application Layer Protocol | `T1071` | `.001` (Web), `.004` (DNS) | `index=sysmon` (EventID 3, 22) | [`08-hypothesis-ioc-investigation.spl`](../queries/08-hypothesis-ioc-investigation.spl) | Triages dynamic DNS domain queries (`ngrok.io`, `duckdns.org`), high-entropy FQDNs, and non-standard egress ports. |

---

## Telemetry Source Mapping

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SPLUNK SIEM TELEMETRY LAYER                        │
├──────────────────────┬──────────────────────┬───────────────────────────────┤
│ index=sysmon         │ index=windows        │ index=linux_security          │
├──────────────────────┼──────────────────────┼───────────────────────────────┤
│ EventID 1:  Process  │ EventCode 4624: Logon│ auth.log: sudo invocations    │
│ EventID 3:  Network  │ EventCode 4625: Fail │ syslog: cron reloads          │
│ EventID 11: FileCreate│ EventCode 4672: Priv │ audit.log: privilege escalation│
│ EventID 12: RegAdd   │ EventCode 4728: Group│                               │
│ EventID 13: RegSet   │ EventCode 7045: Svc  │                               │
│ EventID 22: DNS Query│ EventCode 5140: Share│                               │
└──────────────────────┴──────────────────────┴───────────────────────────────┘
```
