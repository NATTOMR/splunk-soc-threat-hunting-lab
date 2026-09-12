# 🌐 P5 — Network Threat Detection with Splunk

[![Status](https://img.shields.io/badge/Status-In%20Progress%20(Scaffolded)-yellow.svg)](#14-project-status)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%2010.4.3-blue.svg)](https://www.splunk.com/)
[![Forwarder](https://img.shields.io/badge/Log%20Forwarder-Splunk%20UF%2010.4.3-orange.svg)](https://www.splunk.com/)
[![Dashboard](https://img.shields.io/badge/Dashboard-Network%20Threat%20Monitoring-success.svg)](dashboards/README.md)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Issue](https://img.shields.io/badge/GitHub%20Issue-%236-brightgreen.svg)](https://github.com/NATTOMR/splunk-soc-threat-hunting-lab/issues/6)
[![Project](https://img.shields.io/badge/Project-Splunk%20SOC%20Lab-purple.svg)](https://github.com/users/NATTOMR/projects/5)

> **Author:** Natto Chakma  
> **Master Repository Component:** This project constitutes **Project P5** in the [Splunk SOC & Threat Hunting Lab](../README.md).  
> **Project Identity:** P5 — Network Threat Detection with Splunk  
> **Core Purpose:** Develop, validate, and operationalize Splunk-based detections for network-layer adversary activities including port scanning, host discovery, abnormal connection velocity, uncommon/backdoor ports, and reconnaissance correlation.

---

## Table of Contents

1. [Project Title & Overview](#1-project-title--overview)
2. [Objective](#2-objective)
3. [Security Problem](#3-security-problem)
4. [Scope](#4-scope)
5. [Lab Architecture](#5-lab-architecture)
6. [Detection Scenarios](#6-detection-scenarios)
7. [Investigation Methodology](#7-investigation-methodology)
8. [SPL Query Library](#8-spl-query-library)
9. [MITRE ATT&CK Mapping](#9-mitre-attck-mapping)
10. [Evidence](#10-evidence)
11. [Results](#11-results)
12. [Limitations](#12-limitations)
13. [Future Improvements](#13-future-improvements)
14. [Project Status](#14-project-status)
15. [Relationship to P1, P2, P3, and P4](#15-relationship-to-p1-p2-p3-and-p4)
16. [Master Repository Navigation](#16-master-repository-navigation)

---

## 1. Project Title & Overview

**P5 — Network Threat Detection with Splunk**

Network reconnaissance and unauthorized communications represent the initial exploratory and command-and-control phases of modern cyber intrusions. Before launching targeted exploits, brute-force campaigns, or lateral movement, adversaries systematically probe enterprise subnets, identify open service ports, and establish backdoor communication channels.

This project delivers comprehensive detection engineering, anomaly analysis, and incident triage for network-level threats within Splunk Enterprise. Utilizing endpoint network connection telemetry (Sysmon Event ID 3), Linux network telemetry, and host firewall logs, P5 establishes robust SPL detections for vertical port scans, horizontal sweeps, connection spikes, and non-standard port communications.

---

## 2. Objective

The strategic goals of Project P5 include:
- **Network Telemetry Integration:** Validate network connection logging forwarded from Windows 11 (`index=sysmon`, Event ID 3) and Linux endpoints (`index=linux_security` or Sysmon for Linux / UFW / iptables).
- **Port Scan Detection Engineering:** Implement high-confidence SPL queries capable of identifying both high-speed automated sweeps and targeted vertical port reconnaissance.
- **Velocity & Outlier Analysis:** Detect anomalous spikes in connection attempts and packet rates indicative of scanning tools or denial-of-service attempts.
- **Uncommon & Backdoor Port Profiling:** Detect unauthorized traffic traversing non-standard ports (e.g., Meterpreter default `4444`, Netcat listeners, IRC bots).
- **SOC Threat Hunting Dashboard:** Build an interactive dark-theme dashboard for real-time visualization of network traffic and reconnaissance attempts.
- **MITRE ATT&CK Alignment:** Map all detections and triage procedures to Reconnaissance, Discovery, and Command & Control tactics.

---

## 3. Security Problem

Traditional perimeter defenses often miss stealthy internal reconnaissance and lateral movement probing conducted from already compromised endpoints. Organizations face severe challenges:
1. **Differentiating Scans from Ambient Noise:** Local networks experience benign discovery protocols (mDNS, SSDP, NetBIOS, ARP) that trigger false positives in naive network detection rules.
2. **Cardinality vs. Velocity:** Sophisticated adversaries scan slowly or vary destination ports, requiring cardinality-based detections (`dc(dest_port)`) rather than simplistic raw count thresholds.
3. **Contextual Isolation:** Network detections without host context (process image, command line) leave SOC analysts unable to determine if a connection is benign administrative software or a reverse shell.

---

## 4. Scope

| In-Scope | Out-of-Scope |
|---|---|
| Sysmon Event ID 3 (NetworkConnect) analysis | Full packet payload capture (PCAP) storage in Splunk |
| Linux network connection / firewall logging | Physical network tap hardware configuration |
| Vertical & horizontal port scan simulation & detection | Distributed Denial-of-Service (DDoS) across WAN scale |
| Non-standard port & backdoor communication detection | TLS decryption and SSL inspection engineering |
| Dark-mode Classic Simple XML SOC Dashboard | Commercial proprietary IDS/IPS hardware deployment |
| End-to-end incident investigation and PDF reporting | Automated firewall active-response scripting |

---

## 5. Lab Architecture

```
                                  [ Isolated Lab Network: 192.168.100.0/24 ]
                                                      │
         ┌────────────────────────────────────────────┼────────────────────────────────────────────┐
         │                                            │                                            │
         ▼                                            ▼                                            ▼
┌───────────────────┐                        ┌───────────────────┐                        ┌───────────────────┐
│  Ubuntu 22.04 LTS │                        │   Ubuntu Server   │                        │    Windows 11     │
│   wazuh-server    │                        │     ubuntu-p3     │                        │     win11-tgt     │
│  192.168.100.7    │                        │  192.168.100.9    │                        │  192.168.100.8    │
├───────────────────┤                        ├───────────────────┤                        ├───────────────────┤
│ • Splunk Indexer  │                        │ • Target/Monitor  │                        │ • Target Endpoint │
│ • Splunk Web 10.4 │                        │ • Splunk UF       │                        │ • Sysmon (EID 3)  │
│ • Attack Source   │                        │ • UFW / iptables  │                        │ • Splunk UF       │
└─────────┬─────────┘                        └─────────┬─────────┘                        └─────────┬─────────┘
          │                                            │                                            │
          │                                            │                                            │
          └───────────────────── Port 9997 (Splunk Forwarding) ─────────────────────────────────────┘
```

---

## 6. Detection Scenarios

Detailed attack scenarios and detection logic are documented in [docs/attack-scenarios.md](docs/attack-scenarios.md):
- **Scenario A: High-Velocity Vertical Port Scan:** Adversary probes 15+ ports on a target server in a short burst (Nmap `-sS` / `-sT`).
- **Scenario B: Horizontal Subnet Discovery:** Adversary scans a single common service port across all subnet IPs (`192.168.100.0/24`).
- **Scenario C: Suspicious / Backdoor Port Usage:** Connection initiated to uncommon listening ports (e.g., `4444`, `1337`).
- **Scenario D: Multi-Stage Reconnaissance to Exploitation:** Port scan immediately followed by brute force or process spawning.

---

## 7. Investigation Methodology

The complete SOC analyst playbook is detailed in [docs/investigation.md](docs/investigation.md):
1. **Source Triage:** Determine whether source IP is an internal workstation, server, or gateway.
2. **Scan Profiling:** Assess distinct port counts, common targeted services, and scan velocity.
3. **Endpoint Correlation:** Cross-reference connection events with Sysmon Event ID 1 (Process Creation) to identify the initiating binary.
4. **Containment:** Implement firewall drop rules and isolate compromised endpoints.

---

## 8. SPL Query Library

Production-grade SPL detection queries are available in [queries/](queries/):
- [`port-scan-detection.spl`](queries/port-scan-detection.spl): Vertical port scan detection using distinct destination port cardinality.
- [`high-volume-connections.spl`](queries/high-volume-connections.spl): Connection rate spikes over short time windows.
- [`uncommon-ports-analysis.spl`](queries/uncommon-ports-analysis.spl): Outbound/inbound traffic on non-standard service ports.
- [`suspicious-traffic-patterns.spl`](queries/suspicious-traffic-patterns.spl): Multi-destination sweeps and abnormal outbound flows.
- [`network-recon-correlation.spl`](queries/network-recon-correlation.spl): Longitudinal scan campaign correlation and duration analysis.

---

## 9. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection Implementation |
|---|---|:---:|---|
| **Reconnaissance** | Active Scanning: Scanning IP Blocks | **T1595.001** | `suspicious-traffic-patterns.spl` |
| **Reconnaissance** | Active Scanning: Port Scanning | **T1595.002** | `port-scan-detection.spl` |
| **Discovery** | Network Service Discovery | **T1046** | `port-scan-detection.spl` |
| **Discovery** | Remote System Discovery | **T1018** | `suspicious-traffic-patterns.spl` |
| **Command & Control** | Non-Standard Port | **T1571** | `uncommon-ports-analysis.spl` |
| **Command & Control** | Application Layer Protocol | **T1071** | `uncommon-ports-analysis.spl` |
| **Impact** | Network Denial of Service | **T1498** | `high-volume-connections.spl` |

---

## 10. Evidence

Authentic photographic evidence and screenshots are curated in [screenshots/README.md](screenshots/README.md):
- Pending execution in sub-issues P5.1 through P5.5.

---

## 11. Results

*(To be populated following live execution and verification in sub-issue P5.5)*

---

## 12. Limitations

- Detection thresholds calibrated for lab environment size (`192.168.100.0/24`); production environments require baseline adjustment.
- Encrypted traffic payload inspection requires dedicated SSL inspection proxies or host-level process inspection.

---

## 13. Future Improvements

- Integrate Zeek (Bro) network security monitoring logs for enriched protocol analysis.
- Implement machine learning SPL algorithms (`density_function`, `anomalies`) for dynamic baseline deviation alerting.

---

## 14. Project Status

| Phase / Sub-Issue | Focus Area | Status | Deliverables |
|---|---|:---:|---|
| **[#21](https://github.com/NATTOMR/splunk-soc-threat-hunting-lab/issues/21) P5.1** | Network Telemetry & Port Scan Simulation | 🟡 In Progress | Live scan execution, connection ingestion verification |
| **[#22](https://github.com/NATTOMR/splunk-soc-threat-hunting-lab/issues/22) P5.2** | Network Threat Detection SPL Engineering | ⚪ Pending | Tuned SPL detection rules for scans and velocity |
| **[#23](https://github.com/NATTOMR/splunk-soc-threat-hunting-lab/issues/23) P5.3** | Reconnaissance & Suspicious Traffic Correlation | ⚪ Pending | Multi-vector correlation and noise suppression logic |
| **[#24](https://github.com/NATTOMR/splunk-soc-threat-hunting-lab/issues/24) P5.4** | Network Incident Investigation & ATT&CK Mapping | ⚪ Pending | Incident triage playbook, ATT&CK matrix validation |
| **[#25](https://github.com/NATTOMR/splunk-soc-threat-hunting-lab/issues/25) P5.5** | Evidence, Dashboard, Technical Report & Validation | ⚪ Pending | SOC Dashboard XML, verified screenshots, PDF report |

---

## 15. Relationship to P1, P2, P3, and P4

- **P1 (Core Infrastructure):** Established Splunk Enterprise indexer (`wazuh-server`, `192.168.100.7`) and network forwarding on port 9997.
- **P2 (Windows Endpoint Monitoring):** Deployed Sysmon and Universal Forwarder on Windows 11 (`192.168.100.8`), enabling Sysmon Event ID 3 (NetworkConnect).
- **P3 (Linux Endpoint Monitoring):** Deployed Universal Forwarder on Ubuntu Server (`ubuntu-p3`, `192.168.100.9`), collecting system telemetry.
- **P4 (Brute-Force Detection & Investigation):** Operationalized authentication monitoring and credential defense.
- **P5 (Network Threat Detection):** Builds the network-layer defense pillar, detecting the reconnaissance and unauthorized connections that precede endpoint exploitation.

---

## 16. Master Repository Navigation

- 🏠 **[Master Lab Repository](../README.md)**
- 📁 **[P1 — Splunk Core Deployment & Indexing](../P1-Core-Deployment/README.md)**
- 📁 **[P2 — Windows Endpoint Monitoring with Sysmon](../P2-Windows-Monitoring/README.md)**
- 📁 **[P3 — Linux Endpoint Monitoring](../P3-Linux-Monitoring/README.md)**
- 📁 **[P4 — Brute-Force Detection & Investigation](../P4-Brute-Force-Detection/README.md)**
- 📁 **[P5 — Network Threat Detection with Splunk](README.md)**
