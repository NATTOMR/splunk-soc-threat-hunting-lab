# 🏹 Structured Threat Hunting Methodology Framework

[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v15-red.svg)](https://attack.mitre.org/)
[![Model](https://img.shields.io/badge/Model-TaHiTI%20%26%20PEAK%20Aligned-blue.svg)](#industry-framework-alignment)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise-orange.svg)](https://www.splunk.com/)

This document defines the formal, hypothesis-driven threat hunting methodology implemented in **Project P8 — MITRE ATT&CK Threat Hunting with Splunk**. It operationalizes a structured 8-stage workflow to proactively identify, isolate, and remediate stealthy adversary tradecraft that evades conventional threshold-based alerts.

---

## 1. The 8-Stage Threat Hunting Lifecycle

Threat hunting in this project transitions security operations from reactive alerting to proactive hypothesis testing. The 8-stage pipeline is depicted below:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. Threat Hypothesis                                                        │
│    Formulate testable question based on threat intelligence or tradecraft   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. MITRE ATT&CK Technique                                                  │
│    Map hypothesis to precise ATT&CK tactic, technique, and sub-technique ID │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. Telemetry Identification                                                 │
│    Identify required log channels (Sysmon XML, Windows Events, Linux Syslog)│
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. SPL Hunt Execution                                                       │
│    Execute targeted Search Processing Language queries in Splunk            │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. Event Correlation                                                        │
│    Pivot across ProcessId, User, SourceIP, and Timestamp to link activities │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 6. Forensic Investigation                                                   │
│    Analyze parent-child relationships, hashes, network egress, and context  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 7. Evidence Documentation                                                   │
│    Extract raw log exhibits, execution artifacts, command lines, and paths  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 8. Conclusion & Detection Engineering                                       │
│    Assess true/false positives, convert findings to durable alert rules     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Industry Framework Alignment

### TaHiTI (Targeted Hunting Integrating Threat Intelligence)
This project incorporates the Dutch National Cyber Security Centre's **TaHiTI** model:
1. **Trigger & Input:** Intelligence indicators, MITRE matrix gaps, or novel red team techniques.
2. **Scoping & Hypothesis:** Clearly defining boundaries (e.g., "Windows 11 endpoint within last 7 days").
3. **Execution:** Querying data models and pivoting through raw XML events.
4. **Output & Maturation:** Converting hunting findings into durable, permanent detection rules.

### PEAK (Prepare, Execute, and Act with Knowledge)
Aligned with the Splunk PEAK threat hunting framework:
- **Prepare:** Telemetry audit, inputs.conf verification, and index mapping.
- **Execute:** Hypothesis testing, statistical anomaly hunting, and LOLBin stacking.
- **Act:** Incident ticketing, IOC blacklisting, and detection rule creation.

---

## 3. Threat Hunting Maturity Model (HMM)

| Level | Maturity Status | Implementation in Lab |
|---|---|---|
| **HMM 0** | Initial / Reactive | Pure alert response; no structured hunting. |
| **HMM 1** | Minimal | Basic routine searches based on public IOC indicators. |
| **HMM 2** | Procedural | Documented hunting playbooks based on established methodologies. |
| **HMM 3** | Innovative | Custom hypothesis generation mapped to MITRE ATT&CK techniques with custom SPL. |
| **HMM 4** | Leading | Fully automated data collection, continuous emulation validation, feedback into engineering. |

> **Project P8 operates at HMM 3/4**, delivering repeatable, hypothesis-driven SPL playbooks validated through controlled adversary emulation scripts.

---

## 4. The 8 Core Hunting Hypotheses

### Hypothesis 1: Authentication Manipulation (T1078, T1110, T1550)
*Adversaries leverage compromised administrative accounts or utilize Pass-the-Hash / NewCredentials (Logon Type 9) and privileged SMB network sessions (Logon Type 3) to move stealthily across systems without generating high-volume failed password alerts.*

### Hypothesis 2: Living-Off-The-Land & Process Masquerading (T1218, T1036)
*Adversaries bypass application whitelisting and endpoint controls by executing native, signed Windows binaries (`certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `rundll32.exe`) to download payloads and execute arbitrary scriptlets, or masquerade process paths outside `System32`.*

### Hypothesis 3: Obfuscated PowerShell Execution (T1059.001, T1027)
*Attackers utilize multi-flag obfuscation (`-enc`, `-w hidden`, `-ep bypass`), direct memory reflection (`IEX`), and web download cradles (`System.Net.WebClient`) to evade command-line string matching.*

### Hypothesis 4: Persistence via Registry, Tasks & Services (T1547.001, T1053, T1543)
*Footholds are maintained across system reboots through modification of autostart run keys, programmatic scheduled task creation, rogue service installation, or Linux crontab tampering.*

### Hypothesis 5: Privilege Escalation & Token Abuse (T1098, T1548)
*Adversaries elevate from low-privileged users to local administrator or root by modifying local security groups, exploiting UAC bypass mechanisms (`fodhelper.exe`), or abusing misconfigured Linux sudo permissions.*

### Hypothesis 6: Abnormal Parent-Child Command Execution (T1059.003, T1204.002)
*Exploited client applications (Microsoft Office, Adobe Acrobat, Print Spooler, Apache/Nginx web daemons) directly spawn command interpreters (`cmd.exe`, `powershell.exe`) indicative of shellcode execution or webshell interaction.*

### Hypothesis 7: Lateral Movement & Pivot Activity (T1021, T1570)
*Adversaries pivot across internal network segments by staging executables onto administrative SMB shares (`ADMIN$`, `C$`), spawning remote execution services (`PSEXESVC.exe`), or opening interactive RDP sessions.*

### Hypothesis 8: C2 Beaconing & Volatile IOC Triage (T1071, T1105)
*Active implants maintain communication with remote adversary infrastructure via high-entropy DNS queries, dynamic DNS tunnels, or staging payload artifacts in volatile directories (`C:\Windows\Temp`).*
