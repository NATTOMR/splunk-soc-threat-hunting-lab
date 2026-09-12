# SOC Dashboards — Network Threat Detection & Traffic Analysis

> **Project:** P5 — Network Threat Detection with Splunk  
> **Status:** Dashboard Architecture Defined (Live Deployment in P5.5)  
> **Target Dashboard Title:** `P5 — Network Threat Detection & Monitoring`  
> **Source XML:** `network-threat-dashboard.xml` (Scheduled)

---

## Overview

This directory houses the Splunk Simple XML dashboard definitions and documentation for real-time network threat monitoring, reconnaissance detection, and traffic anomaly visualization.

---

## Planned Dashboard Architecture & Visualizations

| Panel ID | Panel Title | Visualization Type | SOC Operational Objective |
|:---:|---|---|---|
| **PANEL-01** | Total Network Connections | Single Value Card | Real-time connection volume across monitored assets |
| **PANEL-02** | Scanned / Probed Ports (Distinct) | Single Value Card | Immediate indicator of active vertical port scanning |
| **PANEL-03** | Suspicious / Non-Standard Ports | Single Value Card | Alerts on unusual or backdoor port activity |
| **PANEL-04** | Port Distribution / Probed Services | Column / Bar Chart | Visualizes top destination ports being probed |
| **PANEL-05** | Top Offending Source IPs | Pie / Bar Chart | Attribution of reconnaissance sources |
| **PANEL-06** | Connection Velocity Over Time | Timechart (Area / Column) | Spikes in connection rate indicating automated scans or floods |
| **PANEL-07** | Network Reconnaissance Live Triage Stream | Table View | Real-time drilldown for SOC analysts (`_time`, `src_ip`, `dest_ip`, `dest_port`, `protocol`, `action`) |

---

## Deployment Instructions

1. Navigate to **Splunk Web** $\to$ **Search & Reporting** $\to$ **Dashboards**.
2. Click **Create New Dashboard**.
3. Choose **Classic Dashboards** (Simple XML).
4. Click **Source** and paste the XML from `network-threat-dashboard.xml`.
5. Click **Save** and verify dark theme rendering.
