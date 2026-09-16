# 📊 P8 — MITRE ATT&CK Threat Hunting Dashboard

[![Dashboard Status](https://img.shields.io/badge/Dashboard-Production%20XML%20Validated-success.svg)](#installation)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v15-red.svg)](https://attack.mitre.org/)
[![Theme](https://img.shields.io/badge/Theme-Dark%20Mode-black.svg)](#dashboard-architecture)

This directory contains the operational, dark-mode Splunk SOC dashboard for **Project P8 — MITRE ATT&CK Threat Hunting with Splunk**. It aggregates multi-source telemetry from Windows Sysmon, Windows Security Event Logs, and Linux audit streams to provide centralized tactical visibility across all MITRE ATT&CK phases.

---

## Dashboard Architecture

The dashboard is defined in [`mitre-attck-threat-hunting-dashboard.xml`](mitre-attck-threat-hunting-dashboard.xml) and is organized into 5 functional analytical tiers:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                       GLOBAL TIME PICKER (earliest/latest)                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  ROW 1: KEY PERFORMANCE INDICATOR (KPI) METRIC CARDS                        │
│  [Total Detections]  [Active ATT&CK Tactics]  [PowerShell Bypasses] [LOLBins]│
├─────────────────────────────────────────────────────────────────────────────┤
│  ROW 2: TACTICAL AGGREGATION & TRENDS                                       │
│  [Pie Chart: Activity by MITRE Tactic]   [Area Chart: Execution Timeline]   │
├─────────────────────────────────────────────────────────────────────────────┤
│  ROW 3: PROCESS MASQUERADING & LIVING-OFF-THE-LAND (LOLBIN) TRIAGE          │
│  [Table: Certutil, Bitsadmin, Mshta, Regsvr32, Rundll32, Svchost anomalies] │
├─────────────────────────────────────────────────────────────────────────────┤
│  ROW 4: SCRIPTING OBFUSCATION & PARENT-CHILD EXECUTION ANOMALIES            │
│  [Table: PowerShell Scored Risk Matrix]  [Table: Office/Spooler Spawns]    │
├─────────────────────────────────────────────────────────────────────────────┤
│  ROW 5: PERSISTENCE & LATERAL MOVEMENT TRIAGE                               │
│  [Table: Run Keys / Tasks / Services]    [Table: PsExec / Admin Shares / RDP]│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Panel Breakdown & Query Logic

| Panel Title | Visualization | Target Telemetry | Primary ATT&CK Tactic |
|---|---|---|---|
| **Total Hunting Detections** | Single value (KPI) | `index=sysmon`, `index=windows`, `index=linux_security` | Cross-Tactic Aggregation |
| **Active ATT&CK Tactics** | Single value (KPI) | Multi-index classification | Tactic Coverage Metric |
| **Obfuscated PowerShell Invocations** | Single value (KPI) | `index=sysmon` (EventID 1) | `TA0002: Execution` / `T1059.001` |
| **Living-Off-The-Land (LOLBin) Attacks** | Single value (KPI) | `index=sysmon` (EventID 1) | `TA0005: Defense Evasion` / `T1218` |
| **Adversary Activity by MITRE ATT&CK Tactic** | Pie Chart | Cross-index rule classifier | Matrix Tactic Breakdown |
| **Adversary Execution Timeline over Time** | Stacked Area Chart | `index=sysmon` (EventID 1) | Temporal Execution Spikes |
| **Living-Off-The-Land Binaries & Process Masquerading** | Event Table | `index=sysmon` (EventID 1) | `T1218` / `T1036.005` |
| **Obfuscated PowerShell Threat Matrix** | Event Table | `index=sysmon` (EventID 1) | `T1059.001` / `T1027` |
| **Anomalous Parent-Child Spawns** | Event Table | `index=sysmon` (EventID 1) | `T1059` / `T1204.002` |
| **Persistence Mechanisms Hunt** | Event Table | `index=sysmon` (1, 12, 13), `index=windows` (7045), `index=linux_security` | `T1547.001` / `T1053` / `T1543` |
| **Lateral Movement & Remote Access Triage** | Event Table | `index=windows` (4624, 5140), `index=sysmon` | `T1021` / `T1570` |

---

## Installation

1. In Splunk Enterprise Web UI (`http://192.168.100.7:18000` or `http://127.0.0.1:18000`), navigate to **Search & Reporting**.
2. Click **Dashboards** $\rightarrow$ **Create New Dashboard**.
3. Dashboard Title: `P8 — MITRE ATT&CK Threat Hunting & Detection Operations`.
4. Switch editor mode to **Source** (XML).
5. Paste the entire contents of [`mitre-attck-threat-hunting-dashboard.xml`](mitre-attck-threat-hunting-dashboard.xml).
6. Click **Save** and verify all panels populate against the lab telemetry.
