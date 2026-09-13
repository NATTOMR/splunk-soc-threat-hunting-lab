# SPL Query Library — Network Threat Detection

> **Project:** P5 — Network Threat Detection with Splunk  
> **Status:** ✅ Production Validated (Empirically Verified via Sysmon Event ID 3 XML)

---

## Overview

This directory contains Search Processing Language (SPL) detection queries designed to detect network reconnaissance, horizontal and vertical port scanning, high-velocity connection bursts, and communication to uncommon ports.

Because Sysmon logs on Windows 11 are shipped with `renderXml = true`, all queries utilize regular expressions calibrated to Windows Event XML schema (`<Data Name='...'>`).

---

## Query Inventory

| Query File | Primary Target | Detection Logic | Status | Sub-Issue |
|---|---|---|:---:|:---:|
| [`port-scan-detection.spl`](port-scan-detection.spl) | Reconnaissance / Port Scanning | `dc(dest_port) >= 2` per source IP | ✅ Verified | [P5.2](../../issues/22) |
| [`high-volume-connections.spl`](high-volume-connections.spl) | DoS / Connection Bursts | Rate threshold velocity (`span=5m`, count >= 20) | ✅ Verified | [P5.2](../../issues/22) |
| [`uncommon-ports-analysis.spl`](uncommon-ports-analysis.spl) | Backdoor / Non-standard Ports | Inverted standard port filtering | ✅ Verified | [P5.2](../../issues/22) |
| [`suspicious-traffic-patterns.spl`](suspicious-traffic-patterns.spl) | Beaconing / Anomaly Profiling | Connection frequency & destination profiling | ✅ Verified | [P5.2](../../issues/22) |
| [`network-recon-correlation.spl`](network-recon-correlation.spl) | Recon-to-Exploitation Pivot | Cross-event correlation (Event ID 3 + 1) | ✅ Verified | [P5.3](../../issues/23) |

---

## Validation Summary

- **Vertical Port Scan Detection:** Probes from Kali Linux (`192.168.100.6`) targeting Windows 11 were flagged in real-time.
- **High-Volume Connection Bursts:** Connection spikes exceeding 25 events per 5-minute bucket were successfully captured.
- **Uncommon Port Detection:** Non-standard communication over port 8000/4444 was isolated from baseline traffic.
