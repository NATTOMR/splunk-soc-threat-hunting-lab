# 🏹 P8 — MITRE ATT&CK Threat Hunting with Splunk

[![Status](https://img.shields.io/badge/Status-Completed%20%26%20Validated-success.svg)](#15-project-status)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%2010.4.3-blue.svg)](https://www.splunk.com/)
[![Telemetry](https://img.shields.io/badge/Telemetry-Sysmon%20XML%20%2B%20WinEvent%20%2B%20Linux-orange.svg)](#4-scope--architecture)
[![Dashboard](https://img.shields.io/badge/Dashboard-ATT%26CK%20Threat%20Hunting-success.svg)](dashboards/README.md)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v15-red.svg)](https://attack.mitre.org/)
[![GitHub Issue](https://img.shields.io/badge/GitHub%20Issue-%239-brightgreen.svg)](https://github.com/NATTOMR/splunk-soc-threat-hunting-lab/issues/9)
[![Report](https://img.shields.io/badge/Report-PDF%20Compiled-red.svg)](reports/P8-MITRE-ATTCK-Threat-Hunting-Report.pdf)

![P8 Threat Hunting Architecture & Workflow](screenshots/p8-workflow-architecture.png)

> **Author:** Natto Chakma  
> **Master Repository Component:** This project constitutes **Project P8** in the [Splunk SOC & Threat Hunting Lab](../README.md).  
> **Project Identity:** P8 — MITRE ATT&CK Threat Hunting with Splunk  
> **Core Purpose:** Develop and operationalize an empirical, hypothesis-driven threat hunting program in Splunk Enterprise mapped to the MITRE ATT&CK Enterprise Matrix (v15). Evaluates 8 threat hypotheses across multi-source endpoint, host, and network telemetry to uncover stealthy Living-Off-The-Land Binaries (LOLBins), obfuscated PowerShell memory cradles, persistence mechanisms, privilege escalations, lateral movement, and dynamic DNS C2 beaconing.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Objective](#2-objective)
3. [Security Problem & Threat Model](#3-security-problem--threat-model)
4. [Scope & Architecture](#4-scope--architecture)
5. [The 8-Stage Threat Hunting Methodology](#5-the-8-stage-threat-hunting-methodology)
6. [MITRE ATT&CK Matrix Mapping](#6-mitre-attck-matrix-mapping)
7. [Adversary Emulation Telemetry Campaign](#7-adversary-emulation-telemetry-campaign)
8. [SPL Threat Hunting Query Library](#8-spl-threat-hunting-query-library)
9. [SOC Threat Hunting Dashboard](#9-soc-threat-hunting-dashboard)
10. [SOC Investigation Playbooks](#10-soc-investigation-playbooks)
11. [Evidence & Forensic Findings](#11-evidence--forensic-findings)
12. [Results & Metrics Scorecard](#12-results--metrics-scorecard)
13. [Limitations](#13-limitations)
14. [Future Improvements](#14-future-improvements)
15. [Project Status](#15-project-status)
16. [Master Repository Navigation](#16-master-repository-navigation)

---

## 1. Project Overview

Conventional Security Operations Centers often rely exclusively on reactive alerting triggered by static indicators of compromise (IOCs) or fixed threshold rules. However, sophisticated cyber threat actors routinely circumvent perimeter defenses and antivirus engines by abusing native administrative binaries (Living-Off-The-Land / LOLBins), encoding scripts in volatile memory, establishing persistence via native registry autostart keys, and operating within legitimate user privileges.

**Project P8** bridges this operational gap by designing and executing an empirical, hypothesis-driven threat hunting methodology in **Splunk Enterprise 10.4.3**. Operating under the assumption of breach, this project systematically scrutinizes kernel-level Sysmon XML telemetry, Windows Security Event channels, and Linux audit trails to uncover hidden adversary behaviors mapped directly to the **MITRE ATT&CK framework**.

---

## 2. Objective

- Develop a standardized **8-stage hypothesis-driven threat hunting lifecycle** aligned with the TaHiTI and Splunk PEAK methodologies.
- Ingest and normalize multi-source telemetry across **Windows Sysmon XML** (`index=sysmon`), **Windows Security/System Logs** (`index=windows`), and **Linux Audit Streams** (`index=linux_security`).
- Engineer **8 specialized SPL hunting queries** targeting Authentication manipulation, LOLBins, Obfuscated PowerShell, Persistence mechanisms, Privilege escalation, Parent-Child process anomalies, Lateral movement, and C2/DNS beacons.
- Design and operationalize a dark-mode **MITRE ATT&CK Threat Hunting & Detection Operations SOC Dashboard** in Splunk.
- Construct controlled adversary emulation scripts for Windows ([`scripts/simulate_threats.ps1`](scripts/simulate_threats.ps1)) and Linux ([`scripts/simulate_threats.sh`](scripts/simulate_threats.sh)) to safely generate authentic validation telemetry.
- Provide comprehensive **SOC analyst investigation playbooks** ([`docs/investigation-playbooks.md`](docs/investigation-playbooks.md)) and an **IOC registry** ([`docs/ioc-table.md`](docs/ioc-table.md)).
- Publish formal engagement documentation in Markdown, HTML, and high-resolution compiled PDF format ([`reports/P8-MITRE-ATTCK-Threat-Hunting-Report.pdf`](reports/P8-MITRE-ATTCK-Threat-Hunting-Report.pdf)).

---

## 3. Security Problem & Threat Model

Threat hunting requires identifying behaviors that blend seamlessly into standard administrative activity:
1. **Living-Off-The-Land Defense Evasion:** Binaries like `certutil.exe` and `bitsadmin.exe` are cryptographically signed Microsoft executables commonly whitelisted by application control policies, yet frequently abused for ingress payload delivery.
2. **In-Memory Script Execution:** PowerShell commands utilizing Base64 encoding (`-enc`) and hidden window styles (`-w hidden`) avoid disk writes, evading traditional endpoint file scanners.
3. **Legitimate Authentication Abuse:** Attackers leveraging stolen credentials across administrative SMB shares (Logon Type 3) or Pass-the-Hash (Logon Type 9) generate normal logon success event codes that elude basic brute-force detection thresholds.

---

## 4. Scope & Architecture

### Laboratory Topology

| Role | Hostname | IP Address | Operating System | Active Telemetry Services |
|---|---|---|---|---|
| **Central SIEM** | `wazuh-server` | `192.168.100.7` | Ubuntu 24.04 LTS | Splunk Enterprise 10.4.3 (TCP 9997, Web 18000) |
| **Monitored Endpoint** | `WinServer2022` / Win 11 | `192.168.100.8` | Windows Server 2022 | Sysmon v15.15 (`renderXml=true`), Universal Forwarder 10.4.3 |
| **Linux Host** | `ubuntu-p3` | `192.168.100.9` | Ubuntu 24.04.5 LTS | Forwarder streaming `/var/log/auth.log`, `syslog` |
| **Adversary Node** | `kali` | `192.168.100.6` | Kali Linux 2024.x | Emulation orchestration, network scanning, payload hosting |

### Hunting Data Flow

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                            ADVERSARY ACTIVITY                               │
│       Kali Linux (192.168.100.6) & Controlled Endpoint Emulation            │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
      ┌───────────────────────────┐         ┌───────────────────────────┐
      │   Windows 11 / 2022 Host  │         │   Ubuntu Server Host      │
      │       (192.168.100.8)     │         │       (192.168.100.9)     │
      │ ├── Sysmon v15.15 (Kernel)│         │ ├── /var/log/auth.log     │
      │ ├── Windows Event Logs    │         │ ├── /var/log/syslog       │
      │ └── Universal Forwarder   │         │ └── Universal Forwarder   │
      └─────────────┬─────────────┘         └─────────────┬─────────────┘
                    │                                     │
                    │ TCP 9997 (renderXml = true)         │ TCP 9997
                    └──────────────────┬──────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 CENTRAL SIEM: Splunk Enterprise (192.168.100.7)             │
│  ├── index=sysmon         (Sysmon XML EventIDs 1, 3, 11, 12, 13, 22)        │
│  ├── index=windows        (Security EventCodes 4624, 4625, 4672, 7045)      │
│  └── index=linux_security (Sudo escalations, SSH authentications, Cron)     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    P8 THREAT HUNTING OPERATIONS LAYER                       │
│  ├── 8 Hypothesis-Driven Production SPL Queries (queries/)                  │
│  ├── MITRE ATT&CK Hunting Dashboard XML (dashboards/)                       │
│  ├── Formal Threat Hunting Engagement Report (reports/)                     │
│  └── SOC Analyst Investigation Playbooks (docs/)                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. The 8-Stage Threat Hunting Methodology

This project implements the formalized **8-Stage Threat Hunting Pipeline** detailed in [`docs/hunting-methodology.md`](docs/hunting-methodology.md):

```text
Threat Hypothesis
       │
       ▼
MITRE ATT&CK Technique
       │
       ▼
Telemetry Identification
       │
       ▼
SPL Hunt Execution
       │
       ▼
Event Correlation
       │
       ▼
Forensic Investigation
       │
       ▼
Evidence Documentation
       │
       ▼
Conclusion & Hardening
```

---

## 6. MITRE ATT&CK Matrix Mapping

Complete mapping documented in [`docs/mitre-attck-mapping.md`](docs/mitre-attck-mapping.md):

| Tactic | Technique | ID | Target Telemetry | SPL Hunt Reference |
|---|---|---|---|---|
| **Initial Access / Lateral** | Valid Accounts | `T1078` | `index=windows` (4624, 4672) | [`01-hypothesis-authentication-hunting.spl`](queries/01-hypothesis-authentication-hunting.spl) |
| **Defense Evasion** | Living-Off-The-Land (LOLBins) | `T1218` | `index=sysmon` (EventID 1) | [`02-hypothesis-process-hunting.spl`](queries/02-hypothesis-process-hunting.spl) |
| **Defense Evasion** | Process Masquerading | `T1036.005` | `index=sysmon` (EventID 1) | [`02-hypothesis-process-hunting.spl`](queries/02-hypothesis-process-hunting.spl) |
| **Execution** | PowerShell Obfuscation | `T1059.001` | `index=sysmon` (EventID 1) | [`03-hypothesis-powershell-hunting.spl`](queries/03-hypothesis-powershell-hunting.spl) |
| **Persistence** | Registry Run Keys | `T1547.001` | `index=sysmon` (12, 13) | [`04-hypothesis-persistence-hunting.spl`](queries/04-hypothesis-persistence-hunting.spl) |
| **Persistence** | Scheduled Task / Service | `T1053` / `T1543` | `index=sysmon` (1), `index=windows` (7045) | [`04-hypothesis-persistence-hunting.spl`](queries/04-hypothesis-persistence-hunting.spl) |
| **Privilege Escalation** | Sudo Abuse / Group Addition | `T1548.003` / `T1098` | `index=linux_security`, `index=windows` (4728) | [`05-hypothesis-privilege-escalation.spl`](queries/05-hypothesis-privilege-escalation.spl) |
| **Execution** | Anomalous Parent-Child Spawns | `T1059` / `T1204.002` | `index=sysmon` (EventID 1) | [`06-hypothesis-command-execution.spl`](queries/06-hypothesis-command-execution.spl) |
| **Lateral Movement** | Remote SMB / PsExec / RDP | `T1021.002`, `T1021.001` | `index=sysmon` (1, 3), `index=windows` (4624) | [`07-hypothesis-lateral-movement.spl`](queries/07-hypothesis-lateral-movement.spl) |
| **Command & Control** | Dynamic DNS / C2 Egress | `T1071.004` | `index=sysmon` (EventID 22, 3) | [`08-hypothesis-ioc-investigation.spl`](queries/08-hypothesis-ioc-investigation.spl) |

---

## 7. Adversary Emulation Telemetry Campaign

To test and validate each hunting hypothesis empirically, controlled emulation scripts were authored:

### Windows Emulation Harness ([`scripts/simulate_threats.ps1`](scripts/simulate_threats.ps1))
```powershell
# Run controlled, safe threat emulation across Windows 11 endpoint
.\simulate_threats.ps1

# To clean up all test artifacts:
.\simulate_threats.ps1 -CleanupOnly
```
*Generates safe telemetry for Obfuscated PowerShell (`-enc`), `certutil.exe -urlcache` parameter parsing, Registry Run key writes, Scheduled task creation, and Dynamic DNS querying.*

### Linux Emulation Harness ([`scripts/simulate_threats.sh`](scripts/simulate_threats.sh))
```bash
# Run controlled Linux emulation on ubuntu-p3
chmod +x simulate_threats.sh && ./simulate_threats.sh
```
*Generates sudo verification telemetry and crontab reload events streaming into `index=linux_security`.*

---

## 8. SPL Threat Hunting Query Library

Full library index located in [`queries/README.md`](queries/README.md):

```spl
# Example: Obfuscated PowerShell Threat Hunting (T1059.001 / T1027)
index=sysmon earliest=-7d
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| search Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
| eval cmd_lower=lower(CommandLine)
| eval has_enc=if(match(cmd_lower, "(?i)\s+-(e|en|enc|encodedcommand)\s+"), 30, 0)
| eval has_bypass=if(match(cmd_lower, "(?i)\s+-(ep|executionpolicy)\s+bypass"), 20, 0)
| eval has_hidden=if(match(cmd_lower, "(?i)\s+-(w|windowstyle)\s+hidden"), 20, 0)
| eval has_cradle=if(match(cmd_lower, "(?i)(downloadstring|net\.webclient|invoke-webrequest|iwr)"), 25, 0)
| eval threat_score=has_enc+has_bypass+has_hidden+has_cradle
| where threat_score>=40
| table _time, threat_score, CommandLine, Image
```

---

## 9. SOC Threat Hunting Dashboard

The dark-mode dashboard is defined in [`dashboards/mitre-attck-threat-hunting-dashboard.xml`](dashboards/mitre-attck-threat-hunting-dashboard.xml). It features:
- **KPI Row:** Total Detections, Active ATT&CK Tactics Covered, PowerShell Bypasses, LOLBin Invocations.
- **Tactic Visualization:** MITRE Tactic distribution breakdown pie chart and temporal execution area chart.
- **Triage Tables:** Dedicated operational tables for Process Masquerading, Obfuscated PowerShell, Parent-Child anomalies, Persistence, and Lateral Movement.

![Splunk SOC Threat Hunting & Detection Operations Dashboard](screenshots/p8-00-soc-threat-hunting-dashboard.png)

*Figure — Live Splunk SOC Threat Hunting Dashboard displaying 49 hunting anomalies, 4 unique MITRE ATT&CK tactics, 2 obfuscated PowerShell invocations, and 30 Living-off-the-Land binary detections.*

---

## 10. SOC Investigation Playbooks

Step-by-step triage playbooks are maintained in [`docs/investigation-playbooks.md`](docs/investigation-playbooks.md), covering:
1. Abnormal Authentication & Pass-The-Hash Triage
2. LOLBin Execution & Process Masquerading Scoping
3. Obfuscated PowerShell & Memory Injection Analysis
4. Persistence Artifact Eradication
5. Local Privilege Escalation & Sudo Abuse Containment
6. Malicious Parent-Child Process Spawning Triage
7. Lateral Movement (PsExec/SMB/RDP) Isolation
8. C2 Beaconing & Dynamic DNS Sinkholing

---

## 11. Evidence & Forensic Findings

The threat hunting hypotheses were empirically verified against live kernel telemetry streamed from Windows Server 2022 into Splunk Enterprise:

### Exhibit A — Obfuscated PowerShell Hunt (T1059.001 / T1027)
- **Hunting Query:** [`queries/03-hypothesis-powershell-hunting.spl`](queries/03-hypothesis-powershell-hunting.spl)
- **Calculated Threat Score:** **`70`** (`has_enc: 30`, `has_bypass: 20`, `has_hidden: 20`)
- **Captured Command Line:**
  ```text
  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ep bypass -w hidden -nop -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFAAOAA...
  ```
- **Triage Result:** Flagged as a high-confidence, critical-tier stealth execution attempting in-memory script staging.

![Figure 2 — Obfuscated PowerShell Threat Hunting (Score 70)](screenshots/p8-01-powershell-hunt-score-70.png)

### Exhibit B — Dynamic DNS C2 Beaconing Hunt (T1071.004)
- **Hunting Query:** [`queries/08-hypothesis-ioc-investigation.spl`](queries/08-hypothesis-ioc-investigation.spl)
- **Sysmon Event Channel:** `index=sysmon EventID=22` (DNS Query)
- **Queried Domain:** `beacon-p8-test.duckdns.org`
- **Requesting Process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **User Context:** `WIN-SERVER\Administrator`
- **Triage Result:** Surfaced outbound resolution requests destined for public dynamic DNS tunneling services.

![Figure 3 — Dynamic DNS C2 Beaconing Hunt](screenshots/p8-02-dynamic-dns-c2-beacon.png)

### Exhibit C — Scheduled Task & Registry Autostart Persistence (T1053.005 / T1547.001)
- **Hunting Query:** [`queries/04-hypothesis-persistence-hunting.spl`](queries/04-hypothesis-persistence-hunting.spl)
- **Scheduled Task Artifact:** `EventID=1` capturing `schtasks.exe /create /tn P8_ThreatHunt_Task /tr "cmd.exe /c echo threat_hunt" /sc daily /st 12:00 /f`
- **Registry Run Key Artifact:** `EventID=13` capturing autostart modification at `HKU\...\Software\Microsoft\Windows\CurrentVersion\Run\P8_ThreatHunt_Persistence`
- **Triage Result:** Successfully identified multiple concurrent persistence hooks designed to survive host restarts.

![Figure 4 — Scheduled Task and Registry Run Key Persistence](screenshots/p8-03-persistence-registry-and-tasks.png)

### Exhibit D — Living-off-the-Land (LOLBin) Ingress (T1105 / T1218)
- **Hunting Query:** [`queries/02-hypothesis-process-hunting.spl`](queries/02-hypothesis-process-hunting.spl)
- **Invocations:** `bitsadmin.exe /create myDownloadJob` and `certutil.exe -urlcache -split`
- **Triage Result:** Telemetry captured administrative utilities leveraged outside normal baselines for ingress file staging.

---

## 12. Results & Metrics Scorecard

| Metric | Target | Actual Result | Status |
|---|---|---|---|
| **Hypotheses Formulated & Tested** | 8 | 8 | 🟢 Complete |
| **MITRE ATT&CK Tactics Covered** | $\ge 6$ | 8 Tactics | 🟢 Exceeded |
| **Telemetry Events Analyzed** | > 10,000 | 14,820 Events | 🟢 Complete |
| **Durable Alerts Engineered** | $\ge 3$ | 4 Alerts | 🟢 Complete |
| **Formal Engagement Report** | MD, HTML, PDF | 3 Formats Generated | 🟢 Complete |

---

## 13. Limitations

- Emulation was performed in an isolated VirtualBox NAT lab network; true command-and-control egress was intentionally contained without internet exposure.
- Sysmon telemetry requires regex extraction of `<EventID>` due to `renderXml = true` forwarding.

---

## 14. Future Improvements

- Integrate automated **Atomic Red Team** test suites via PowerShell execution.
- Implement automated Sigma rule translation to SPL.
- Integrate threat intelligence feeds (VirusTotal API / AbuseIPDB) via Splunk lookup tables.

---

## 15. Project Status

| Milestone | Status | Details |
|---|---|---|
| **Threat Hunting Methodology Defined** | 🟢 Complete | 8-stage lifecycle aligned with TaHiTI and PEAK |
| **SPL Hunting Query Library** | 🟢 Complete | 8 production queries across ATT&CK tactics |
| **SOC Dashboard XML** | 🟢 Complete | Dark-mode interactive XML validated |
| **Adversary Emulation Harnesses** | 🟢 Complete | PowerShell & Bash test scripts verified |
| **Formal Engagement Report** | 🟢 Complete | [PDF Report](reports/P8-MITRE-ATTCK-Threat-Hunting-Report.pdf) compiled |

---

## 16. Master Repository Navigation

- ⬅️ **Previous Project:** [P7 — Phishing Email Investigation with Splunk](../P7-Phishing-Email-Investigation/README.md)
- 🏠 **Master Repository Overview:** [Splunk SOC & Threat Hunting Lab](../README.md)
- ➡️ **Next Project:** [P9 — Splunk SOC Dashboard](../README.md#project-roadmap)
