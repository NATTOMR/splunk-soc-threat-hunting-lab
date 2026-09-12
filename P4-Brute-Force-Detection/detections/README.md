# Splunk Detections & Alert Rules — Brute-Force Monitoring

> **Project:** P4 — Brute-Force Detection & Investigation  
> **Status:** Candidate Rules Defined (Alert Tuning & Deployment Pending in P4.2 & P4.3)  
> **Rule:** No alert triggers or scheduled searches will be committed to Splunk production until telemetry is verified in P4.1.

---

## Overview

This directory contains the detection engineering specifications and saved search definitions designed for automated alerting against brute-force authentication activity.

---

## Candidate Detection Rules

| Detection Rule ID | Rule Name | Target Telemetry | Trigger Condition | Severity | MITRE ATT&CK | Status |
|---|---|---|---|:---:|:---:|:---:|
| **DET-P4-01** | High-Volume Authentication Failures | `index=windows` / `index=linux_security` | $\ge 10$ failures in 5m from single source | High | T1110 | Candidate |
| **DET-P4-02** | Horizontal Password Spray | `index=windows` (EventID 4625) | $\ge 3$ distinct accounts failed from single IP | High | T1110.003 | Candidate |
| **DET-P4-03** | Targeted Account Brute-Force | `index=windows` (EventID 4625) | $\ge 5$ failures on single account in 15m | Medium | T1110.001 | Candidate |
| **DET-P4-04** | Failed-to-Success Correlation | `index=windows` (4625 $\to$ 4624) | $\ge 3$ failures followed by success within 15m | Critical | T1078, T1110 | Candidate |

---

## Alert Configuration Lifecycle

1. **Step 1: Baseline Verification (P4.1):** Measure background failure noise during normal lab operations.
2. **Step 2: Simulation & Query Testing (P4.2):** Execute controlled brute-force attacks and measure detection fidelity.
3. **Step 3: Alert Tuning & Suppression (P4.2):** Add suppression windows (e.g., suppress alert for 15 minutes per source IP) to prevent alert storms.
4. **Step 4: Production Alert Deployment (P4.3):** Configure Splunk saved searches (`savedsearches.conf`) with trigger actions (email, webhook, or dashboard indicator).
