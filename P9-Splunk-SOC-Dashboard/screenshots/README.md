# 📸 P9 Splunk SOC Dashboard Screenshots & Exhibits

[![Project](https://img.shields.io/badge/Project-P9%20Splunk%20SOC%20Dashboard-blue.svg)](../README.md)
[![Status](https://img.shields.io/badge/Dashboard-Ready%20for%20Exhibits-success.svg)](#dashboard-exhibits)

This directory stores visual exhibits, dashboard panel screenshots, and investigation workflows for **Project P9 — Splunk SOC Dashboard**.

---

## Dashboard Exhibits

| Figure | Section Name | Description | Target Telemetry |
|---|---|---|---|
| `p9-01-soc-overview.png` | **Section 1: SOC Overview** | High-level KPI metric cards displaying Total Events, Authentication Events, Detections, Network Volume, Web Requests, and Critical/High Incidents. | Multi-Index Aggregation |
| `p9-02-authentication-monitoring.png` | **Section 2: Authentication** | Success vs. Failure ratio pie chart, logon velocity timeline, top targeted accounts, and brute-force attack correlation table. | `index=windows`, `index=linux_security` |
| `p9-03-endpoint-security.png` | **Section 3: Endpoint Security** | Windows EventCode distribution bar chart and suspicious process / LOLBin execution table. | `index=windows`, `index=sysmon` |
| `p9-04-network-threats.png` | **Section 4: Network Security** | Network connection area chart and uncommon backdoor port traffic table. | `index=sysmon` (EventID 3) |
| `p9-05-web-security.png` | **Section 5: Web Security** | OWASP Top 10 attack categories pie chart and HTTP status code trend area chart. | `index=web` (access_combined) |
| `p9-06-threat-detections-alerts.png` | **Section 6 & 7: Detections & Alerts** | Active detection rules table mapped to MITRE ATT&CK and Alert Severity distribution chart. | Master Rule Catalog |
| `p9-07-investigation-timeline.png` | **Section 8: Investigation Timeline** | Full-width chronological incident triage stream correlating IP, user, activity, severity, and MITRE technique. | Cross-Layer Correlation |

---

## How to Add Screenshots
1. Deploy [`splunk_soc_dashboard.xml`](../dashboards/splunk_soc_dashboard.xml) into Splunk Web.
2. Ensure lab telemetry is ingested or execute simulation scripts (`P4`, `P5`, `P6`, `P7`, `P8`).
3. Capture panels or full-page dashboard view using your operating system screenshot utility.
4. Save images into this directory using the standardized names listed above.
