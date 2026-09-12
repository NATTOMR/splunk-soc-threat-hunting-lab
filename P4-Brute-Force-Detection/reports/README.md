# Investigation Reports — Brute-Force Incidents

> **Project:** P4 — Brute-Force Detection & Investigation  
> **Status:** Report Templates Defined (Live Incident Findings Scheduled for P4.5)  
> **Rule:** No fabricated findings, synthetic incidents, or unverified conclusions will be documented.

---

## Overview

This directory stores formal SOC investigation reports, threat hunt summaries, and technical incident documentation generated during brute-force detection and investigation exercises.

---

## Report Structure Standards

Formal investigation reports in this repository adhere to standard SOC analyst reporting structure:

1. **Executive Summary:** High-level summary of the detected brute-force campaign, timeline, affected systems, and business risk.
2. **Incident Details & Scope:** Targeted endpoints, affected user accounts, source IP addresses, attack velocity, and duration.
3. **Detection & Correlation Telemetry:** Exact SPL queries executed, event timelines, and telemetry artifacts (Windows Security Event Logs, Sysmon, auth.log).
4. **Outcome Analysis (Triage):** Verification of whether any authentication succeeded, and assessment of post-compromise activity (Sysmon Event ID 1 / Event ID 3).
5. **MITRE ATT&CK Alignment:** Detailed mapping of observed behaviors to adversary tactics and techniques.
6. **Remediation Actions Taken:** Host isolation, password reset, account lockout verification, and firewall blocks.
7. **Recommendations & Hardening:** Password complexity, lockout policy tuning, MFA deployment, and network segment restrictions.

---

## Scheduled Deliverables

- **Final Investigation Report:** [`reports/brute-force-investigation-report.md`](brute-force-investigation-report.md) — Completed investigation covering the SSH password spray and targeted brute-force campaign against `ubuntu-p3`.

