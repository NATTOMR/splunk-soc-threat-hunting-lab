# Splunk Detections & Alert Rules — Network Threat Monitoring

> **Project:** P5 — Network Threat Detection with Splunk  
> **Status:** Candidate Rules Defined (Alert Tuning & Deployment in P5.2 & P5.3)  
> **Rule:** No alert triggers or scheduled searches will be committed to Splunk production until telemetry is verified in P5.1.

---

## Overview

This directory contains detection engineering specifications, scheduled alert rules, and correlation logic designed for identifying unauthorized network reconnaissance, connection velocity spikes, and suspicious protocol/port communications.

---

## Candidate Detection Rules

| Detection Rule ID | Rule Name | Target Telemetry | Trigger Condition | Severity | MITRE ATT&CK | Status |
|---|---|---|---|:---:|:---:|:---:|
| **DET-P5-01** | High-Velocity Vertical Port Scan | `index=sysmon` (EventCode=3) / Firewall | $\ge 10$ distinct ports probed from single IP within 2m | High | T1046, T1595.002 | Candidate |
| **DET-P5-02** | Horizontal Subnet Reconnaissance | `index=sysmon` (EventCode=3) / Firewall | $\ge 5$ distinct hosts probed on same port in 5m | High | T1046, T1018 | Candidate |
| **DET-P5-03** | High-Volume Connection Velocity Spike | `index=sysmon` (EventCode=3) / Firewall | $> 50$ connections from single IP within 1m | Medium | T1498 | Candidate |
| **DET-P5-04** | Uncommon / Backdoor Port Connection | `index=sysmon` (EventCode=3) | Outbound/Inbound traffic to non-standard ports (e.g., 4444, 1337) | High | T1571, T1071 | Candidate |
| **DET-P5-05** | Network Reconnaissance to Exploitation | `index=sysmon` + `index=windows`/`linux` | Port scan followed by unusual process or auth event within 15m | Critical | T1046 $\to$ T1190 | Candidate |

---

## Alert Lifecycle Workflow

1. **Step 1: Baseline Verification (P5.1):** Observe ambient connection rates and standard service ports in lab.
2. **Step 2: Simulation & Query Testing (P5.2):** Execute controlled port scans (Nmap/custom) and measure detection metrics.
3. **Step 3: Alert Tuning & Threshold Calibration (P5.2/P5.3):** Configure cardinality filters, time bins, and suppressions to avoid flooding.
4. **Step 4: SOC Dashboard & Production Alert Integration (P5.4/P5.5):** Integrate rules into the SOC dashboard and incident response playbooks.
