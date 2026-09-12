# Lab Evidence & Screenshots — Brute-Force Detection

> **Project:** P4 — Brute-Force Detection & Investigation  
> **Status:** Evidence Collection Scheduled (To Be Captured During P4.1–P4.5 Execution)  
> **Rule:** No fabricated, staged, or placeholder images are permitted. All visual evidence must originate from live Splunk Web and lab virtual machines.

---

## Overview

This directory preserves authentic photographic evidence and screenshots supporting the detection, investigation, and dashboarding deliverables for Project P4.

---

## Evidence Capture Standards

All screenshots added to this directory must satisfy the following criteria:
1. **Unambiguous Telemetry:** Include the complete Splunk search bar, executed SPL query, time picker, and event counts.
2. **Authentic Timestamps:** Timestamps in events and Splunk UI must align with the active lab simulation timeline.
3. **High Resolution:** Clean, uncompressed captures showing readable text and visualizations.
4. **No Sensitive Data:** Exclude production passwords, private keys, or extraneous personal identifiers (lab IP ranges `192.168.100.0/24` are permitted).

---

## Planned Evidence Inventory

| Exhibit ID | Scheduled Capture | Objective | Sub-Issue |
|---|---|---|:---:|
| `p4-01-attack-simulation.png` | Kali / attack script output | Evidence of controlled brute-force simulation | [P4.1](../../issues/16) |
| `p4-02-raw-4625-telemetry.png` | Splunk Search: EventID 4625 | Verified Windows failure event ingestion | [P4.1](../../issues/16) |
| `p4-03-high-volume-detection.png` | Splunk Search: Velocity query | Detection rule triggering on burst failures | [P4.2](../../issues/17) |
| `p4-04-source-ip-spray.png` | Splunk Search: Spray analysis | Source IP profiling distinguishing spray vs targeted | [P4.2](../../issues/17) |
| `p4-05-failed-to-success-corr.png` | Splunk Search: Correlation | Sequence of failures followed by success | [P4.3](../../issues/18) |
| `p4-06-brute-force-dashboard.png` | Splunk Web Dashboard View | Complete SOC Brute-Force Investigation Dashboard | [P4.5](../../issues/20) |
