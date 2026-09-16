# 📊 P9 — Splunk SOC Operations Dashboard

[![Dashboard Status](https://img.shields.io/badge/Dashboard-Production%20XML%20Validated-success.svg)](#installation--deployment)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%2010.4.3-blue.svg)](https://www.splunk.com/)
[![Theme](https://img.shields.io/badge/Theme-Dark%20Mode-black.svg)](#dashboard-architecture)

This directory contains the master **Splunk SOC Operations Dashboard** XML definition ([`splunk_soc_dashboard.xml`](splunk_soc_dashboard.xml)). It synthesizes telemetry, detections, and forensic artifacts from across all prior lab phases (**P1 through P8**) into a centralized, single-pane-of-glass operational view.

---

## Dashboard Architecture

The dashboard is structured into 8 analytical sections:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    GLOBAL TIME RANGE PICKER (earliest/latest)               │
├─────────────────────────────────────────────────────────────────────────────┤
│  SECTION 1: SOC OVERVIEW — 6 KPI METRIC CARDS                               │
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

## Installation & Deployment

1. Log in to **Splunk Web** on your SIEM host:
   👉 `http://192.168.100.7:18000` or `http://127.0.0.1:18000`
2. Navigate to **Search & Reporting** $\rightarrow$ Click **Dashboards** in the top navigation bar.
3. Click the green button **"Create New Dashboard"**:
   - **Dashboard Title:** `P9 — Splunk SOC Operations Dashboard`
   - **Permissions:** Shared in App
4. In the top right corner of the dashboard editor, switch to **Source** (XML) mode.
5. Paste the entire contents of [`splunk_soc_dashboard.xml`](splunk_soc_dashboard.xml).
6. Click **Save** and verify that all panels populate against your lab telemetry.

---

## Panel Mapping & Data Sources

| Section | Panel Title | Visualization | Target Telemetry | Primary Focus |
|---|---|---|---|---|
| **1** | Total Security Events | Single Value | All Indices | Overall telemetry throughput |
| **1** | Authentication Events | Single Value | `windows`, `linux_security` | Global logon volume |
| **1** | Threat Detection Events | Single Value | Multi-Index | Active rule triggers |
| **1** | Network Connection Events | Single Value | `sysmon` (EventID 3) | Egress/Ingress traffic |
| **1** | Web Request & Attack Volume | Single Value | `web` (Apache2) | HTTP transactions |
| **1** | Critical / High Severity | Single Value | Multi-Index | Severe incident count |
| **2** | Success vs Failure Ratio | Pie Chart | `windows`, `linux_security` | Authentication health |
| **2** | Authentication Timeline | Stacked Column | `windows`, `linux_security` | Login velocity spikes |
| **2** | Top Targeted Accounts | Table | `windows`, `linux_security` | Credential attack targets |
| **2** | Brute-Force & Password Spray | Table | `windows` (4625), `linux` | Velocity bursts ($\ge 5$) |
| **3** | Windows Event Breakdown | Bar Chart | `windows`, `sysmon` | Windows security telemetry |
| **3** | Suspicious Process & LOLBins | Table | `sysmon` (EventID 1) | Execution & evasion tools |
| **4** | Connections Over Time | Area Chart | `sysmon` (EventID 3) | Network session trends |
| **4** | Uncommon / Backdoor Ports | Table | `sysmon` (EventID 3) | Egress on 4444, 1337, etc. |
| **5** | Web Attack Categories | Pie Chart | `web` (access_combined) | SQLi, XSS, Path Traversal |
| **5** | HTTP Status Trends | Stacked Column | `web` (access_combined) | 4xx client / 5xx server errors |
| **6** | Active Detections & MITRE | Table | Multi-Index | Catalog of triggered rules |
| **7** | Alert Severity Distribution | Pie Chart | Multi-Index | Risk posture classification |
| **8** | Investigation Timeline | Event Table | Multi-Index | Chronological audit stream |
