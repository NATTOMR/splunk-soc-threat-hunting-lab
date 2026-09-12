# SPL Query Library — Network Threat Detection

> **Project:** P5 — Network Threat Detection with Splunk  
> **Status:** Candidate Templates (Telemetry Validation Scheduled in P5.1 & P5.2)

---

## Overview

This directory contains Search Processing Language (SPL) detection queries designed to detect network reconnaissance, horizontal and vertical port scanning, high-velocity connection bursts, and communication to uncommon ports.

---

## Query Inventory

| Query File | Primary Target | Detection Logic | Sub-Issue |
|---|---|---|:---:|
| [`port-scan-detection.spl`](port-scan-detection.spl) | Reconnaissance / Port Scanning | `dc(dest_port) >= 10` per source IP | [P5.2](../../issues/22) |
| [`high-volume-connections.spl`](high-volume-connections.spl) | DoS / Connection Bursts | Rate threshold velocity (`span=5m`) | [P5.2](../../issues/22) |
| [`uncommon-ports-analysis.spl`](uncommon-ports-analysis.spl) | Backdoor / Non-standard Ports | Inverted standard port filtering | [P5.2](../../issues/22) |
| [`suspicious-traffic-patterns.spl`](suspicious-traffic-patterns.spl) | Beaconing / Anomaly Profiling | Connection frequency & destination profiling | [P5.2](../../issues/22) |
| [`network-recon-correlation.spl`](network-recon-correlation.spl) | Recon-to-Exploitation Pivot | Cross-event correlation (Event ID 3 + 1) | [P5.3](../../issues/23) |
