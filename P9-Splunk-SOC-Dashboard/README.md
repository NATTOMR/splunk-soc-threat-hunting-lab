# 🛡️ P9 — Splunk SOC Dashboard

[![Dashboard](https://img.shields.io/badge/Dashboard-Production%20XML%20Validated-success.svg)](dashboards/README.md)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%2010.4.3-blue.svg)](https://www.splunk.com/)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v15-red.svg)](https://attack.mitre.org/)
[![Scope](https://img.shields.io/badge/Telemetry-Unified%20P1--P8%20Data-orange.svg)](#4-data-sources--telemetry-matrix)
[![Design Spec](https://img.shields.io/badge/Design%20Spec-Analytical%20Rationale-blue.svg)](docs/dashboard-design.md)

> **Author:** Natto Chakma  
> **Master Repository Component:** This project constitutes **Project P9** in the [Splunk SOC & Threat Hunting Lab](../README.md).  
> **Project Identity:** P9 — Splunk SOC Dashboard  
> **Core Purpose:** Build and operationalize an enterprise-grade Splunk SOC Operations Dashboard that unifies multi-source telemetry, threat detections, alert triage, and investigation workflows developed throughout projects P1 through P8 into a cohesive, single-pane-of-glass interface.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Objective](#2-objective)
3. [Lab Architecture & Environment Roles](#3-lab-architecture--environment-roles)
4. [Data Sources & Telemetry Matrix](#4-data-sources--telemetry-matrix)
5. [Dashboard Architecture & Design](#5-dashboard-architecture--design)
6. [Reusable SPL Query Library](#6-reusable-spl-query-library)
7. [Panel Descriptions & Analytical Insights](#7-panel-descriptions--analytical-insights)
8. [Threat Detection & Alert Triage Visibility](#8-threat-detection--alert-triage-visibility)
9. [MITRE ATT&CK Framework Integration](#9-mitre-attck-framework-integration)
10. [SOC Investigation Workflow](#10-soc-investigation-workflow)
11. [Installation & Deployment Guide](#11-installation--deployment-guide)
12. [Limitations](#12-limitations)
13. [Future Improvements](#13-future-improvements)
14. [Master Repository Navigation](#14-master-repository-navigation)

---

## 1. Project Overview

Throughout projects P1 through P8, the **Splunk SOC & Threat Hunting Lab** engineered targeted telemetry pipelines and detection rules spanning multiple operational domains:
- **Windows Security & Kernel Sysmon Monitoring** (P2, P8)
- **Linux Server Audit & Sudo Logging** (P3)
- **Authentication & SSH Brute-Force Detection** (P4)
- **Network Reconnaissance & Port Scan Analysis** (P5)
- **Web Application Attack Detection** (P6)
- **Phishing Gateway & Weaponized Email Triage** (P7)
- **Hypothesis-Driven Threat Hunting across MITRE ATT&CK** (P8)

While each previous project developed localized dashboards and queries for specific attack surfaces, modern enterprise Security Operations Centers (SOCs) require a **centralized operational command center**. 

**Project P9** delivers the **Splunk SOC Operations Dashboard**—a single-pane-of-glass monitoring console that synthesizes all telemetry channels, normalizes disparate event schemas, visualizes high-level risk metrics, and provides a unified chronological investigation stream for Tier 1, Tier 2, and Tier 3 analysts.

---

## 2. Objective

- Construct a centralized, dark-mode **Splunk SOC Dashboard** ([`dashboards/splunk_soc_dashboard.xml`](dashboards/splunk_soc_dashboard.xml)) integrating telemetry across all prior lab phases.
- Implement **8 distinct operational sections**: SOC Overview, Authentication, Endpoint Security, Network Security, Web Security, Threat Detection, Alert Summary, and Investigation Timeline.
- Author a modular library of **14 production-grade SPL queries** ([`queries/`](queries/)) optimized for performance and grounded in authentic lab field schemas.
- Provide comprehensive engineering rationale in [`docs/dashboard-design.md`](docs/dashboard-design.md) detailing why each panel exists and how analysts interpret the data.
- Incorporate MITRE ATT&CK technique mapping across all surfaced detections without fabricating data or requiring unsupported telemetry channels.

---

## 3. Lab Architecture & Environment Roles

The dashboard consumes live and forwarded telemetry across the isolated lab network:

| Machine Name | Role in Lab | IP Address | Operating System | Forwarded Telemetry / Services |
|---|---|---|---|---|
| **Ubuntu Server** | **Central SIEM / Search Head** | `192.168.100.7` | Ubuntu 24.04 LTS | Splunk Enterprise 10.4.3 (TCP 9997 Receiver, Port 18000 Web UI) |
| **Windows 11 / Server** | **Monitored Endpoint Target** | `192.168.100.8` | Windows Server 2022 / Win 11 | Sysmon v15.15 (`renderXml=true`), WinEventLog (`Security`, `System`), Universal Forwarder |
| **Ubuntu Server (`ubuntu-p3`)** | **Monitored Linux Endpoint** | `192.168.100.9` | Ubuntu 24.04.5 LTS | Apache2 Web Server, Postfix MTA, `/var/log/auth.log`, `/var/log/syslog`, Universal Forwarder |
| **Kali Linux** | **Attacker / Security Testing Machine**| `192.168.100.6` | Kali Linux 2024.x | Hydra (P4), Nmap/Scapy (P5), Nikto/SQLmap (P6), Swaks (P7), Adversary Emulation (P8) |

### End-to-End Data Pipeline

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ATTACK & TELEMETRY GENERATION                  │
│       Kali Linux (192.168.100.6)  ──►  Controlled Scans, Exploits, Logons  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
      ┌───────────────────────────┐         ┌───────────────────────────┐
      │   Windows 11 / Server     │         │   Ubuntu Endpoint (p3)    │
      │       (192.168.100.8)     │         │       (192.168.100.9)     │
      │ ├── Sysmon v15.15         │         │ ├── /var/log/auth.log     │
      │ ├── Windows Security Logs │         │ ├── /var/log/apache2/     │
      │ └── Universal Forwarder   │         │ └── Universal Forwarder   │
      └─────────────┬─────────────┘         └─────────────┬─────────────┘
                    │                                     │
                    │ TCP 9997 (XML Rendered)             │ TCP 9997 (Syslog/Access)
                    └──────────────────┬──────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CENTRAL SIEM: Splunk Enterprise (192.168.100.7)          │
│  ├── index=windows        (EventCodes 4624, 4625, 4672, 4728, 7045)         │
│  ├── index=sysmon         (Sysmon XML EventIDs 1, 3, 11, 12, 13, 22)        │
│  ├── index=linux_security (SSH Logons, Sudo Invocations, Cron Modifications)│
│  ├── index=web            (Apache2 W3C access_combined HTTP traffic)        │
│  └── index=email          (Postfix MTA Gateway syslog traffic)              │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    P9: SPLUNK SOC OPERATIONS DASHBOARD                      │
│   [Section 1: Overview]    [Section 2: Auth]       [Section 3: Endpoint]    │
│   [Section 4: Network]     [Section 5: Web]        [Section 6: Detections]  │
│   [Section 7: Alerts]      [Section 8: Investigation Timeline]              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Data Sources & Telemetry Matrix

| Telemetry Source | Splunk Index | Sourcetype | Target Event Codes / Artifacts | Lab Project Origin |
|---|---|---|---|---|
| **Windows Security Log** | `index=windows` | `XmlWinEventLog:Security` | `EventCode=4624` (Success Logon), `4625` (Fail Logon), `4672` (Privileges), `4728`/`4732` (Group Adds) | P2, P4, P8 |
| **Windows System Log** | `index=windows` | `XmlWinEventLog:System` | `EventCode=7045` (New Windows Service Installed) | P2, P8 |
| **Sysmon Process Monitoring** | `index=sysmon` | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | `<EventID>1</EventID>` (Process Create, `Image`, `CommandLine`, `ParentImage`, `User`, `Hashes`) | P2, P8 |
| **Sysmon Network Monitoring** | `index=sysmon` | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | `<EventID>3</EventID>` (Network Connect, `SourceIp`, `DestinationIp`, `DestinationPort`) | P5, P8 |
| **Sysmon Registry Monitoring**| `index=sysmon` | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | `<EventID>12</EventID>` / `13` (Registry Run Keys, Autostart Persistence) | P8 |
| **Sysmon DNS Query Logging** | `index=sysmon` | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | `<EventID>22</EventID>` (DNS Lookups, Dynamic DNS C2 Beacons) | P7, P8 |
| **Linux SSH & Auth Logs** | `index=linux_security` | `linux_secure` | `/var/log/auth.log` (`Failed password`, `Accepted`, SSH session triage) | P3, P4 |
| **Linux Sudo & Cron Logs** | `index=linux_security` | `syslog` | `sudo:` command invocations, `NOT in sudoers`, crontab reload telemetry | P3, P8 |
| **Apache2 Web Access Logs** | `index=web` | `access_combined` | `/var/log/apache2/access.log` (`clientip`, `method`, `uri_path`, `uri_query`, `status`, `useragent`) | P6 |
| **Postfix Mail Gateway Logs**| `index=email` | `postfix:syslog` | `/var/log/mail.log` (`queue_id`, `sender`, `recipient`, `subject`, `src_ip`) | P7 |

---

## 5. Dashboard Architecture & Design

The dashboard is defined in [`dashboards/splunk_soc_dashboard.xml`](dashboards/splunk_soc_dashboard.xml) and incorporates dark-mode styling (`theme="dark"`) with a global time picker. It organizes security monitoring into 8 distinct operational tiers:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    GLOBAL TIME RANGE PICKER (earliest/latest)               │
├─────────────────────────────────────────────────────────────────────────────┤
│  SECTION 1: SOC OVERVIEW — 6 High-Level KPI Metric Cards                    │
│  [Total Events] [Auth Events] [Detections] [Network] [Web Events] [Crit/High]│
├─────────────────────────────────────────────────────────────────────────────┤
│  SECTION 2: AUTHENTICATION MONITORING                                       │
│  [Pie: Success vs Failure]               [Chart: Velocity Timeline]         │
│  [Table: Top Targeted Accounts]          [Table: Brute-Force Activity]      │
├─────────────────────────────────────────────────────────────────────────────┤
│  SECTION 3: ENDPOINT SECURITY                                               │
│  [Bar: Windows & Sysmon Event Breakdown] [Table: Process & LOLBin Activity] │
├─────────────────────────────────────────────────────────────────────────────┤
│  SECTION 4: NETWORK SECURITY                                                │
│  [Area: Network Connections Over Time]   [Table: Suspicious Ports (4444...)]│
├─────────────────────────────────────────────────────────────────────────────┤
│  SECTION 5: WEB SECURITY                                                    │
│  [Pie: OWASP Attack Categories]          [Chart: HTTP Status Trends]        │
├─────────────────────────────────────────────────────────────────────────────┤
│  SECTION 6: THREAT DETECTION                                                │
│  [Table: Master Detection Catalog & MITRE ATT&CK Technique Mapping]         │
├─────────────────────────────────────────────────────────────────────────────┤
│  SECTION 7: ALERT SUMMARY                                                   │
│  [Pie: Severity Breakdown]               [Table: Priority Action Queue]     │
├─────────────────────────────────────────────────────────────────────────────┤
│  SECTION 8: UNIFIED INVESTIGATION TIMELINE                                  │
│  [Chronological Multi-Source Correlation Stream: Time/IP/User/Severity]     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Reusable SPL Query Library

All underlying queries are modularized in the [`queries/`](queries/) directory:

| Query File | Primary Scope | Target Telemetry | Key Output Fields |
|---|---|---|---|
| [`01_soc_event_summary.spl`](queries/01_soc_event_summary.spl) | Section 1: SOC Overview | Multi-Index | `total_events`, `total_auth_events`, `total_detections`, `critical_high_severity` |
| [`02_authentication_overview.spl`](queries/02_authentication_overview.spl) | Section 2: Auth Posture | `windows`, `linux_security` | `auth_status`, `auth_result`, `count`, `percentage` |
| [`03_failed_authentication.spl`](queries/03_failed_authentication.spl) | Section 2: Failed Logons | `windows` (4625), `linux` | `TargetUser`, `Platform`, `failure_count`, `source_ips`, `failure_reasons` |
| [`04_successful_authentication.spl`](queries/04_successful_authentication.spl) | Section 2: Successful Logons| `windows` (4624), `linux` | `TargetUser`, `is_privileged`, `logon_types`, `source_ips`, `success_count` |
| [`05_bruteforce_activity.spl`](queries/05_bruteforce_activity.spl) | Section 2: Brute-Force | `windows` (4625), `linux` | `_time`, `SourceIP`, `failure_burst_count`, `distinct_users_targeted`, `attack_pattern` |
| [`06_top_source_ips.spl`](queries/06_top_source_ips.spl) | Top Source IP Analysis | Multi-Index | `SourceIP`, `total_events`, `distinct_domains_active`, `classification` |
| [`07_top_targeted_accounts.spl`](queries/07_top_targeted_accounts.spl) | Section 2: Targeted Identities| `windows`, `linux`, `email` | `TargetAccount`, `failed_attempts`, `successful_logons`, `account_risk` |
| [`08_windows_security_events.spl`](queries/08_windows_security_events.spl) | Section 3: Windows Endpoint | `windows`, `sysmon` | `EventSummary`, `SecurityTier`, `event_count`, `sample_commands` |
| [`09_linux_security_events.spl`](queries/09_linux_security_events.spl) | Section 3: Linux Endpoint | `linux_security` | `LinuxEventType`, `UserContext`, `event_count`, `sample_activities` |
| [`10_network_threats.spl`](queries/10_network_threats.spl) | Section 4: Network Threats | `sysmon` (EventID 3) | `SourceIp`, `DestinationIp`, `threat_classification`, `targeted_ports`, `connection_count` |
| [`11_web_attacks.spl`](queries/11_web_attacks.spl) | Section 5: Web Attacks | `web` (access_combined) | `attack_category`, `clientip`, `http_methods`, `http_statuses`, `sample_paths` |
| [`12_detection_summary.spl`](queries/12_detection_summary.spl) | Section 6: Detection Catalog | Multi-Index | `detection_id`, `detection_name`, `severity`, `mitre_techniques`, `detection_count` |
| [`13_alert_severity.spl`](queries/13_alert_severity.spl) | Section 7: Alert Severity | Multi-Index | `alert_severity`, `count`, `percentage` |
| [`14_investigation_timeline.spl`](queries/14_investigation_timeline.spl) | Section 8: Investigation | Multi-Index | `_time`, `Severity`, `EventTriage`, `MITRE_Technique`, `SourceIP`, `TargetAccount`, `ActivityDetail` |

---

## 7. Panel Descriptions & Analytical Insights

For deep architectural rationale and engineering justification, see [`docs/dashboard-design.md`](docs/dashboard-design.md).

### Highlights of Operational Value:
- **Authentication Triage:** Distinguishes brute-force password guessing (`T1110.001`) from horizontal password spraying (`T1110.003`) by calculating the ratio of targeted accounts to failure volume in 5-minute rolling windows.
- **Endpoint Threat Surfacing:** Automatically extracts Sysmon XML `<CommandLine>` fields and applies threat scoring to flag Base64-obfuscated PowerShell (`T1059.001`) and Living-off-the-Land Ingress binaries (`certutil.exe -urlcache`, `bitsadmin.exe`).
- **Network Reconnaissance Tracking:** Isolates vertical port scans and flags non-standard egress to high-risk backdoor ports (e.g. TCP `4444`, `1337`).
- **Web Application Inspection:** Inspects Apache URI query strings for OWASP Top 10 exploits (`UNION SELECT`, `<script>`, `../`) without requiring third-party WAF plugins.

---

## 8. Threat Detection & Alert Triage Visibility

The dashboard features an integrated master detection catalog synthesizing detections from across P1 through P8:

| Rule ID | Detection Name | Target Telemetry | Assigned Severity | Primary ATT&CK Technique |
|---|---|---|---|---|
| **DET-P4-01** | Windows Authentication Brute-Force | `index=windows` (4625) | Medium / High | `T1110` Brute Force |
| **DET-P4-02** | Linux SSH Password Spraying | `index=linux_security` | Medium / High | `T1110.003` Password Spraying |
| **DET-P5-01** | Uncommon / Backdoor Port Egress | `index=sysmon` (EventID 3) | High / Critical | `T1571` Non-Standard Port |
| **DET-P6-01** | SQL Injection (SQLi) Exploitation | `index=web` (access_combined) | Critical | `T1190` Exploit Public-Facing App |
| **DET-P6-02** | Cross-Site Scripting (XSS) Injection | `index=web` (access_combined) | High | `T1190` Exploit Public-Facing App |
| **DET-P6-03** | Directory / Path Traversal | `index=web` (access_combined) | High | `T1083` File and Directory Discovery |
| **DET-P6-04** | Automated Security Scanner Probe | `index=web` (access_combined) | Medium | `T1595.002` Vulnerability Scanning |
| **DET-P7-01** | Weaponized Email Attachment / Phish | `index=email` (postfix) | High / Critical | `T1566.001` Spearphishing Attachment |
| **DET-P8-01** | Obfuscated PowerShell Dropper | `index=sysmon` (EventID 1) | Critical | `T1059.001` PowerShell |
| **DET-P8-02** | Living-off-the-Land Ingress Transfer| `index=sysmon` (EventID 1) | High | `T1105` Ingress Tool Transfer |
| **DET-P8-03** | Endpoint Autostart Persistence | `index=sysmon` (1, 12, 13) | High | `T1547.001` Registry Run Keys |
| **DET-P8-04** | Dynamic DNS / C2 Beaconing Query | `index=sysmon` (EventID 22) | Medium / High | `T1071.004` DNS |
| **DET-P8-05** | Pass-The-Hash / NewCredentials | `index=windows` (4624 Type 9) | Critical | `T1550.002` Pass the Hash |
| **DET-P8-06** | Administrative Group Manipulation | `index=windows` (4728, 4732) | Critical | `T1098` Account Manipulation |

---

## 9. MITRE ATT&CK Framework Integration

The dashboard seamlessly maps security events to the MITRE ATT&CK Enterprise Matrix (v15):

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                       MITRE ATT&CK ENTERPRISE MATRIX                        │
├─────────────────┬─────────────────┬───────────────────┬─────────────────────┤
│ INITIAL ACCESS  │ EXECUTION       │ PERSISTENCE       │ PRIVILEGE ESCALATION│
├─────────────────┼─────────────────┼───────────────────┼─────────────────────┤
│ T1190 (Web Expl)│ T1059.001 (Psh) │ T1547.001 (RunKey)│ T1098 (Group Mod)   │
│ T1566 (Phishing)│ T1059.003 (Cmd) │ T1053.005 (Tasks) │ T1548.003 (Sudo)    │
│ T1078 (Valid Acc)│                │ T1543.003 (Serv)  │ T1550.002 (PtH)     │
├─────────────────┼─────────────────┼───────────────────┼─────────────────────┤
│ DEFENSE EVASION │ DISCOVERY       │ LATERAL MOVEMENT  │ COMMAND & CONTROL   │
├─────────────────┼─────────────────┼───────────────────┼─────────────────────┤
│ T1027 (Obfusc)  │ T1046 (PortScan)│ T1021.002 (SMB)   │ T1071.004 (DNS C2)  │
│ T1218 (LOLBins) │ T1082 (SysInfo) │ T1021.001 (RDP)   │ T1571 (Uncommon Port│
│ T1105 (Ingress) │ T1087 (Account) │ T1021.006 (WinRM) │ T1572 (Tunnels)     │
└─────────────────┴─────────────────┴───────────────────┴─────────────────────┘
```

---

## 10. SOC Investigation Workflow

When an analyst spots an anomaly on the dashboard, the following standardized workflow is executed:

```text
1. Alert / Metric Spike in Section 1 (e.g. Critical/High Incidents counter increments)
   │
   ▼
2. Domain Triage in Sections 2–5 (Identify targeted domain: Auth, Endpoint, Net, or Web)
   │
   ▼
3. Rule Inspection in Section 6 & 7 (Confirm Rule ID, Severity, and MITRE Technique)
   │
   ▼
4. Root Cause Analysis in Section 8 (Pivot into Investigation Timeline for chronology)
   │
   ▼
5. Containment & Remediation (Isolate endpoint, block IP on firewall, revoke credentials)
```

---

## 11. Installation & Deployment Guide

1. Open your browser and access **Splunk Web**:
   👉 `http://192.168.100.7:18000` (or host-forwarded `http://127.0.0.1:18000`)
2. Navigate to **Search & Reporting** $\rightarrow$ Click **Dashboards** in the top navigation bar.
3. Click the green button **"Create New Dashboard"**:
   - **Dashboard Title:** `P9 — Splunk SOC Operations Dashboard`
   - **Permissions:** Shared in App
4. In the top right corner of the dashboard editor, switch to **Source** (XML) mode.
5. Copy the complete XML from [`dashboards/splunk_soc_dashboard.xml`](dashboards/splunk_soc_dashboard.xml) and paste it into the editor.
6. Click **Save**. The dashboard will immediately begin rendering telemetry across all 8 sections!

---

## 12. Limitations

- **Sysmon XML Extraction:** Because Windows event logs are forwarded with `renderXml = true`, queries against `index=sysmon` must extract `<EventID>` using regex rather than relying on unindexed `EventCode` fields.
- **Single-Node Forwarding:** In this lab architecture, log transport relies on direct Universal Forwarder connections to `192.168.100.7:9997` without intermediate Splunk Heavy Forwarders or load balancers.
- **Isolated NAT Networking:** External adversary C2 beaconing and phishing domains are simulated in private subnets without live WAN routing.

---

## 13. Future Improvements

- Implement drilldown event tokens allowing analysts to click any row in Section 8 to automatically filter the entire dashboard by that specific `SourceIP` or `TargetAccount`.
- Integrate Splunk Enterprise Security (ES) Incident Review and Notable Event frameworks.
- Implement automated alert actions invoking Webhook / SOAR playbooks.
- Add Wazuh HIDS telemetry ingestion under `index=wazuh` as planned for **Project P10**.

---

## 14. Master Repository Navigation

- ⬅️ **Previous Project:** [P8 — MITRE ATT&CK Threat Hunting with Splunk](../P8-MITRE-ATTCK-Threat-Hunting/README.md)
- 🏠 **Master Repository Overview:** [Splunk SOC & Threat Hunting Lab](../README.md)
- ➡️ **Next Project:** [P10 — Wazuh + Splunk SIEM Integration](../P10-Wazuh-Splunk-SIEM-Integration/README.md)
