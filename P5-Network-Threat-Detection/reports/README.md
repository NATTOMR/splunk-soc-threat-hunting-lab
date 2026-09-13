# Technical Reports & Incident Documentation — Network Threat Detection

> **Project:** P5 — Network Threat Detection with Splunk  
> **Status:** ✅ Report Completed & Verified

---

## Overview

This directory houses the formal security incident investigation reports, analyst playbooks, and threat-hunting documentation produced during Project P5.

---

## Published Reports

| Report ID | Title | Format | Status | Primary Focus |
|:---:|---|:---:|:---:|---|
| **INC-2026-P5-001** | **Network Reconnaissance & Threat Detection Report** | [**PDF**](P5-Network-Threat-Detection-Report.pdf) \| [HTML](P5-Network-Threat-Detection-Report.html) \| [Markdown](network-threat-investigation-report.md) | ✅ Complete | Triage of Kali Linux (`192.168.100.6`) vertical port scan, uncommon port traffic, and velocity bursts against Windows 11 (`192.168.100.8`). |

---

## Key Investigation Highlights

- **Adversary Activity:** Multi-port active reconnaissance targeting SSH (`22`) and RDP (`3389`), coupled with high-volume PowerShell socket bursts over TCP `8000`.
- **Telemetry Utilized:** Sysmon Event ID 3 (NetworkConnect) ingested via Splunk Universal Forwarder with XML field extraction.
- **MITRE ATT&CK Mapping:** T1595.002 (Port Scanning), T1046 (Network Service Discovery), T1571 (Non-Standard Port), T1498 (Network DoS).
- **Remediation Plan:** Host firewall scoping, AppLocker/CLM PowerShell hardening, and automated Splunk alert deployment.
