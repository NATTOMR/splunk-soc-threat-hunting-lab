# SOC Dashboards — Web Attack Detection & Application Security

> **Project:** P6 — Web Attack Detection with Splunk  
> **Status:** ✅ Dashboard Architecture Established  
> **Target Dashboard Title:** `P6 — Web Attack Detection & Application Security`  
> **Source XML:** `web-attack-dashboard.xml`

---

## Overview

This directory houses the Splunk Simple XML dashboard definitions and documentation for real-time web application threat monitoring, attack signature detection, and HTTP telemetry triage.

---

## Dashboard Architecture & Visualizations

| Panel ID | Panel Title | Visualization Type | SOC Operational Objective |
|:---:|---|---|---|
| **PANEL-01** | Total HTTP Requests | Single Value Card | Real-time traffic volume across monitored web assets |
| **PANEL-02** | SQL Injection Attempts | Single Value Card (Red Block) | Immediate alert on SQLi payloads in request URIs |
| **PANEL-03** | Cross-Site Scripting (XSS) | Single Value Card (Red Block) | Alerts on script tags, event handlers, and DOM probes |
| **PANEL-04** | Path Traversal & LFI | Single Value Card (Red Block) | Identifies dot-dot-slash traversal and sensitive file access |
| **PANEL-05** | Scanner User-Agents | Single Value Card (Warning Block) | Flags automated vulnerability scanners (Nikto, sqlmap) |
| **PANEL-06** | Web Traffic & Error Velocity | Timechart (Area) | Correlates request velocity with 4xx/5xx error surges |
| **PANEL-07** | HTTP Status Code Distribution | Column Chart | Analyzes server response health (200 OK vs 404/500 errors) |
| **PANEL-08** | Top Requesting Client IPs | Pie Chart | Attribution of web attack sources and fuzzers |
| **PANEL-09** | Correlated Attack Activity Alerts | Table View | High-level adversary attribution table by attack categories |
| **PANEL-10** | Web Access Log Live Triage Stream | Table View | Drilldown stream (`_time`, `clientip`, `method`, `uri`, `status`, `useragent`) |

---

## Deployment Instructions

1. In **Splunk Web**, navigate to **Dashboards** $\to$ **Create New Dashboard**.
2. Set title to **`P6 — Web Attack Detection & Application Security`**.
3. Choose **Classic Dashboards** (Simple XML).
4. Click **Source** (`< >`), replace contents with [`web-attack-dashboard.xml`](web-attack-dashboard.xml), and click **Save**.
