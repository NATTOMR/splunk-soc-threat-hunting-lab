# Investigation Reports — Network Threat Incidents

> **Project:** P5 — Network Threat Detection with Splunk  
> **Status:** Report Templates Defined (Live Incident Findings in P5.5)  
> **Rule:** No fabricated findings, synthetic incidents, or unverified conclusions will be documented.

---

## Overview

This directory stores formal SOC investigation reports, threat hunt summaries, and technical incident documentation generated during network threat detection and traffic investigation exercises.

---

## Report Structure Standards

Formal network threat reports adhere to professional SOC analyst reporting standards:

1. **Executive Summary:** High-level summary of the detected network threat, attack timeline, affected assets, and potential impact.
2. **Reconnaissance & Threat Scope:** Targeted subnets and endpoints, scanned ports, source IP attribution, scan duration, and connection velocity.
3. **Detection & Forensic Telemetry:** Exact SPL queries executed, event timelines, and network telemetry artifacts (Sysmon Event ID 3, Linux iptables/UFW, network logs).
4. **Outcome Analysis & Compromise Status:** Assessment of whether any target ports were open, connections established, or if any follow-on exploitation occurred.
5. **MITRE ATT&CK Alignment:** Detailed mapping to adversary tactics and techniques (T1595, T1046, T1018, T1571, T1498).
6. **Remediation & Containment Actions:** Firewall block rules, host network isolation, and service hardening.
7. **Recommendations & Preventive Controls:** Network segmentation, egress filtering, microsegmentation, and IDS/IPS tuning.

---

## Deliverables (Scheduled in P5.5)

- 📄 **Official Executive & Technical SOC Report (PDF):** `P5-Network-Threat-Detection-Report.pdf`
- 📝 **Markdown Incident Report:** `network-threat-investigation-report.md`
