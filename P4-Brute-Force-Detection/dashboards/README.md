# SOC Dashboards — Brute-Force Detection & Investigation

> **Project:** P4 — Brute-Force Detection & Investigation  
> **Status:** Dashboard Architecture Planned (XML Implementation Scheduled Post-Telemetry Validation)  
> **Rule:** No fabricated dashboard XML or synthetic data will be committed. Real dashboard panels will be constructed and exported directly from Splunk Web during project execution.

---

## Overview

This directory houses the dashboard XML definitions, panel configurations, and visualization specifications for the **"Brute-Force Detection & Investigation"** SOC operational dashboard.

---

## Planned Dashboard Panels

| Panel ID | Panel Title | Visualization Type | Query Purpose |
|:---:|---|---|---|
| **PANEL-01** | Total Failed Authentications (24h) | Single Value Card with Sparkline | High-level baseline indicator of authentication health |
| **PANEL-02** | Authentication Failure Velocity | Timechart (Line/Area, `span=15m`) | Identifies sudden spikes and attack bursts |
| **PANEL-03** | Top Offending Source IPs | Horizontal Bar Chart | Isolates primary attack origins |
| **PANEL-04** | Top Targeted User Accounts | Column Chart | Identifies accounts under credential pressure |
| **PANEL-05** | Attack Classification Breakdown | Pie / Donut Chart | Proportion of Password Spray vs Targeted Brute-Force |
| **PANEL-06** | Potential Account Compromise Feed | Table View with Alert Highlights | Live correlation of failure sequences ending in success |

---

## Implementation Roadmap

- [ ] Verify telemetry sources and field extractions in **P4.1**.
- [ ] Build and test individual search panels in Splunk Search & Reporting in **P4.2**.
- [ ] Implement correlation queries and threshold visual formatting in **P4.3**.
- [ ] Export final dashboard Simple XML to `dashboards/brute-force-dashboard.xml` in **P4.5**.
