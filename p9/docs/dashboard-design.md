# 🏛️ P9 SOC Dashboard Architecture & Analytical Design Rationale

[![Document Type](https://img.shields.io/badge/Document-Engineering%20Architecture-blue.svg)](#operational-philosophy)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v15-red.svg)](https://attack.mitre.org/)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%2010.4.3-orange.svg)](https://www.splunk.com/)

This document provides the analytical and engineering design specification for the **Splunk SOC Operations Dashboard** developed in **Project P9**. It details the operational purpose of each dashboard section, explains why specific metrics and visualizations were chosen, and maps each panel directly to its underlying SPL query in the [`queries/`](../queries/) library.

---

## 1. Operational Philosophy & Tiered SOC Triage

Modern Security Operations Centers operate under immense alert volume. Without structured visual hierarchy, analysts suffer from cognitive fatigue and alert blindness. The P9 Dashboard is designed around the **Pyramid of Triage**:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ LEVEL 1: SITUATIONAL AWARENESS (Section 1: High-Level KPIs)                │
│ -> Immediate operational status: Is the environment currently under attack? │
├─────────────────────────────────────────────────────────────────────────────┤
│ LEVEL 2: DOMAIN-SPECIFIC TRIAGE (Sections 2–5: Auth, Endpoint, Net, Web)   │
│ -> Where is the attack originating, and what attack surface is targeted?   │
├─────────────────────────────────────────────────────────────────────────────┤
│ LEVEL 3: THREAT DETECTION & POSTURE (Sections 6–7: Rules & Severity)       │
│ -> Which engineered detection rules triggered, and what is the severity?    │
├─────────────────────────────────────────────────────────────────────────────┤
│ LEVEL 4: FORENSIC RECONSTRUCTION (Section 8: Investigation Timeline)        │
│ -> What is the exact chronological sequence of events for root-cause RCA?  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Detailed Section Rationale & SPL Query Mapping

### SECTION 1 — SOC Overview
- **Why It Exists:** Tier 1 analysts and SOC managers require instantaneous situational awareness upon shift handover. These single-value KPI cards quantify global ingestion health, isolate the volume of flagged security threats, and highlight high/critical incidents demanding immediate containment.
- **Powering SPL Query:** [`queries/01_soc_event_summary.spl`](../queries/01_soc_event_summary.spl)
- **Key Metrics:**
  - *Total Security Events:* Aggregated event throughput across all indices.
  - *Authentication Events:* Combined Windows and Linux logons.
  - *Threat Detections:* Active rule hits across all attack surfaces.
  - *Network Events:* Sysmon EventID 3 connection telemetry.
  - *Web Requests & Attacks:* Apache2 HTTP transactions.
  - *Critical/High Incidents:* Urgent escalations requiring triage.

---

### SECTION 2 — Authentication Monitoring
- **Why It Exists:** Identity is the primary perimeter in modern enterprise networks. Brute-force attacks, credential stuffing, and compromised domain credentials (T1110, T1078) represent the initial beachhead in the cyber kill chain. This section enables analysts to differentiate routine operational login failures from distributed horizontal password sprays or targeted credential brute-forcing.
- **Powering SPL Queries:**
  - *Failed vs Successful Logons:* [`queries/02_authentication_overview.spl`](../queries/02_authentication_overview.spl)
  - *Logon Failure Triage:* [`queries/03_failed_authentication.spl`](../queries/03_failed_authentication.spl)
  - *Successful Logon Auditing:* [`queries/04_successful_authentication.spl`](../queries/04_successful_authentication.spl)
  - *Brute-Force & Password Spray Detection:* [`queries/05_bruteforce_activity.spl`](../queries/05_bruteforce_activity.spl)
  - *Top Targeted User Accounts:* [`queries/07_top_targeted_accounts.spl`](../queries/07_top_targeted_accounts.spl)
- **Analytical Insight:** By binning authentication failures into 5-minute windows and calculating `dc(TargetUser)`, analysts can instantly separate targeted single-account brute-force (high failure count, 1 user) from horizontal password sprays ($\ge 3$ distinct users targeted from a single IP).

---

### SECTION 3 — Endpoint Security
- **Why It Exists:** Once initial access occurs, adversaries interact directly with the operating system to achieve code execution, establish persistence, and bypass controls. This section isolates high-risk process creations (Sysmon EventID 1), Living-off-the-Land Binaries (LOLBins like `certutil.exe` and `bitsadmin.exe`), obfuscated PowerShell wrappers, and Linux administrative sudo violations.
- **Powering SPL Queries:**
  - *Windows Security & Sysmon Telemetry:* [`queries/08_windows_security_events.spl`](../queries/08_windows_security_events.spl)
  - *Linux Security Events & Sudo Triage:* [`queries/09_linux_security_events.spl`](../queries/09_linux_security_events.spl)
  - *Suspicious Process & LOLBin Hunts:* Cross-references [`queries/08_windows_security_events.spl`](../queries/08_windows_security_events.spl) and P8 hunting rules.
- **Analytical Insight:** Evaluates process parent-child relationships, command-line arguments, and privilege escalations (EventCodes 4672, 4728, 4732) to catch defense evasion and lateral movement staging before damage occurs.

---

### SECTION 4 — Network Security
- **Why It Exists:** Attackers rely on network communication for reconnaissance, command-and-control (C2) beaconing, and lateral movement. This section monitors connection velocity and alerts on traffic traversing uncommon, administrative, or known backdoor ports.
- **Powering SPL Query:** [`queries/10_network_threats.spl`](../queries/10_network_threats.spl)
- **Key Indicators:**
  - *Port Reconnaissance:* Flags single IP addresses contacting $\ge 10$ distinct ports within short time windows (vertical port scan).
  - *Backdoor & C2 Ports:* Highlights TCP 4444 (Metasploit default), 1337/31337 (backdoor listeners), and 5985/5986 (WinRM lateral pivots).

---

### SECTION 5 — Web Security
- **Why It Exists:** Public-facing web applications are continuously probed by external adversaries and automated vulnerability scanners. This section parses Apache2 W3C Combined access logs (`index=web`) to classify application-layer attacks and detect abnormal error spikes.
- **Powering SPL Query:** [`queries/11_web_attacks.spl`](../queries/11_web_attacks.spl)
- **Attack Classifications:**
  - *SQL Injection (SQLi):* Regex inspection of URI query strings for `UNION SELECT`, `information_schema`, and comment delimiters (`--`).
  - *Cross-Site Scripting (XSS):* Flags `<script>`, JavaScript wrappers, and event handlers (`onload=`, `onerror=`).
  - *Directory Traversal:* Flags `../` sequences and attempts to read `/etc/passwd` or `win.ini`.
  - *Automated Scanners:* Matches user-agent signatures for Nikto, SQLmap, Nmap, and DirBuster.
  - *HTTP Status Trends:* Visualizes 4xx client errors (directory fuzzing) and 5xx server errors (application crashes/exploits).

---

### SECTION 6 — Threat Detection
- **Why It Exists:** Bridges the gap between raw telemetry events and structured threat intelligence. This section compiles all detection rules engineered throughout the lab into a standardized detection catalog, explicitly mapping each trigger to its MITRE ATT&CK technique ID.
- **Powering SPL Query:** [`queries/12_detection_summary.spl`](../queries/12_detection_summary.spl)
- **Mitre Mapping Highlights:**
  - Initial Access & Execution: `T1190`, `T1059.001`
  - Persistence & Privilege Escalation: `T1547.001`, `T1053.005`, `T1548.003`, `T1098`
  - Defense Evasion & LOLBins: `T1105`, `T1218`
  - Discovery & C2: `T1046`, `T1082`, `T1071.004`

---

### SECTION 7 — Alert Summary
- **Why It Exists:** Security analysts must prioritize incident handling based on risk severity. This section groups all active detections into standardized severity tiers (Critical, High, Medium, Low) to facilitate queue management and identify high-priority investigation candidates.
- **Powering SPL Query:** [`queries/13_alert_severity.spl`](../queries/13_alert_severity.spl)
- **Triage Priority:**
  - *CRITICAL:* Active SQL Injection, Obfuscated PowerShell memory droppers, Pass-the-Hash, or Administrative group tampering.
  - *HIGH:* LOLBin ingress downloads, Scheduled Task/Run Key persistence, Cross-Site Scripting, or Backdoor port connections.
  - *MEDIUM:* Brute-force failure bursts, Dynamic DNS queries, Sudo security violations, or Automated web scanners.
  - *LOW / INFO:* Baseline successful authentications and benign web transactions.

---

### SECTION 8 — Investigation Timeline
- **Why It Exists:** When an incident is confirmed, the SOC analyst must establish an exact chronology of the adversary's actions (Root Cause Analysis). Rather than querying multiple indices separately, this section provides a unified, cross-layer event stream chronologically linking timestamps, source IPs, target identities, event classifications, severity ratings, and raw execution details.
- **Powering SPL Query:** [`queries/14_investigation_timeline.spl`](../queries/14_investigation_timeline.spl)
- **Forensic Pivot Fields:**
  `_time`, `Severity`, `EventTriage`, `MITRE_Technique`, `SourceIP`, `TargetAccount`, `host`, `ActivityDetail`.
