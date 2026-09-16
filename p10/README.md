# Project P10 — Wazuh + Splunk SIEM Integration

[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%2010.4.3-orange.svg)](https://www.splunk.com/)
[![XDR](https://img.shields.io/badge/XDR-Wazuh%20Manager%204.x-blue.svg)](https://wazuh.com/)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Status](https://img.shields.io/badge/Status-IMPLEMENTED%20%26%20VALIDATED-brightgreen.svg)](#-project-status)
[![Dashboard](https://img.shields.io/badge/Dashboard-Simple%20XML%20(10%20Panels)-purple.svg)](dashboards/wazuh_splunk_dashboard.xml)

---

## 1. Executive Summary

**Project P10: Wazuh + Splunk SIEM Integration** implements a centralized telemetry and detection bridge between the **Wazuh EDR/XDR** platform and **Splunk Enterprise 10.4.3**. Operating within an isolated virtual laboratory network (`LabNetwork` — `192.168.100.0/24`), this project aggregates host-level security alerts, rule firings, agent health telemetry, and MITRE ATT&CK adversarial mappings into Splunk.

By establishing a dedicated ingestion pipeline under `index=wazuh`, SOC analysts gain single-pane-of-glass operational visibility across Windows and Linux endpoints, enabling multi-index correlation with Windows Security events (`index=windows`), Sysmon kernel telemetry (`index=sysmon`), and Linux audit logs (`index=linux_security`).

---

## 2. Project Status & Lab Integration State

| Component | Target Environment | Integration State | Operational Details |
|---|---|:---:|---|
| **Wazuh Manager** | Ubuntu 24.04 (`192.168.100.7`) | **IMPLEMENTED** | Active analysis daemon emitting JSON records to `/var/ossec/logs/alerts/alerts.json`. |
| **Wazuh Windows Agent** | Windows 11 (`192.168.100.8`) | **IMPLEMENTED** | `WazuhSvc` running, streaming Security & Sysmon channels over `1514/tcp`. |
| **Splunk Ingestion Pipeline** | Ubuntu 24.04 (`192.168.100.7`) | **IMPLEMENTED** | Direct local file monitoring (`[monitor:///var/ossec/.../alerts.json]`) into `index=wazuh`. |
| **SPL Threat Hunting Suite** | Splunk Enterprise 10.4.3 | **IMPLEMENTED** | 8 Modular SPL queries (`p10/queries/01_` to `08_`) grounded in real JSON schemas. |
| **SOC Integration Dashboard** | Splunk Web (`127.0.0.1:18000`) | **IMPLEMENTED** | 10-Panel Simple XML dashboard (`dashboards/wazuh_splunk_dashboard.xml`). |
| **Investigation Scenario** | Multi-host lab | **IMPLEMENTED** | Documented Kali brute-force attack triage, correlation, and RCA workflow. |

---

## 3. Laboratory Architecture & Roles

```
  ┌─────────────────────────┐          ┌─────────────────────────┐
  │  [Windows 11 Endpoint]  │          │      [Kali Linux]       │
  │      192.168.100.8      │          │      192.168.100.6      │
  │ • Wazuh Agent (003)     │          │ • Attack Simulation     │
  │ • Sysmon64 & Forwarder  │          │ • Nmap / SMB Probing    │
  └───────────┬─────────────┘          └───────────┬─────────────┘
              │                                    │
              │ Encrypted TCP 1514                 │ Unauthorized Probes
              ▼                                    ▼
  ┌──────────────────────────────────────────────────────────────┐
  │         [Ubuntu Server] wazuh-server (192.168.100.7)         │
  │                                                              │
  │  ┌────────────────────────────────────────────────────────┐  │
  │  │                  WAZUH CORE ENGINE                     │  │
  │  │ • wazuh-manager / wazuh-analysisd                      │  │
  │  │ • Rule Evaluation, Decoder Matching & MITRE Mapping    │  │
  │  │ • Output: /var/ossec/logs/alerts/alerts.json           │  │
  │  └──────────────────────────┬─────────────────────────────┘  │
  │                             │                                │
  │                 Direct Local File Ingestion                  │
  │                             ▼                                │
  │  ┌────────────────────────────────────────────────────────┐  │
  │  │                SPLUNK ENTERPRISE 10.4.3                │  │
  │  │ • Input: [monitor:///var/ossec/logs/alerts/alerts.json]│  │
  │  │ • Parsing: sourcetype=wazuh (Native JSON Extractions)  │  │
  │  │ • Target Storage: index=wazuh                          │  │
  │  │ • SOC Dashboard: 10 Integrated Analytical Panels        │  │
  │  └────────────────────────────────────────────────────────┘  │
  └──────────────────────────────────────────────────────────────┘
```

### Machine Directory:
- **`[Ubuntu Server]` (`wazuh-server` — `192.168.100.7`):** Co-locates Wazuh Manager, Wazuh Indexer, Wazuh Dashboard, and Splunk Enterprise 10.4.3 (`18000/tcp` Web, `9997/tcp` Receiver, `8089/tcp` Mgmt).
- **`[Windows 11]` (`win11-tgt` — `192.168.100.8`):** Workstation monitored by Wazuh Agent (ID 003), Sysmon, and Universal Forwarder.
- **`[Kali Linux]` (`kali` — `192.168.100.6`):** Authorized penetration testing and reconnaissance system.
- **`[Ubuntu Server]` (`ubuntu-p3` — `192.168.100.9`):** Monitored Linux server running Universal Forwarder.

---

## 4. Integration Methodology

### 4.1 Transport Selection: Co-located File Stream
Because both Wazuh Manager and Splunk Enterprise operate on the same Ubuntu Server instance (`wazuh-server`), the architecture utilizes **Direct Local File Ingestion**:
1. `wazuh-analysisd` writes real-time JSON alert objects to `/var/ossec/logs/alerts/alerts.json`.
2. Splunk's input engine monitors the file stream with non-blocking file tracking (`crcSalt = <SOURCE>`).
3. Splunk extracts JSON attributes at index-time via `INDEXED_EXTRACTIONS = json` (`sourcetype=wazuh`).
4. Events are isolated in `index=wazuh` to preserve retention and search boundaries.

### 4.2 Linux Hardening & Security
To enable least-privilege reading without root privileges:
```bash
# [Ubuntu Server]
sudo usermod -aG ossec splunk
sudo chmod 750 /var/ossec/logs/alerts
sudo chmod 640 /var/ossec/logs/alerts/alerts.json
```

---

## 5. Directory Structure

```
p10/
├── README.md                                    # This master documentation file
├── architecture/
│   └── integration-architecture.md              # In-depth architectural & transport specification
├── configs/
│   └── configuration-examples.md                # Sanitized inputs.conf, props.conf, indexes.conf, ossec.conf
├── queries/                                     # 8 Production-grade SPL queries
│   ├── 01_wazuh_event_summary.spl               # Total alerts, active agents, rule volume KPIs
│   ├── 02_wazuh_alert_levels.spl                # Severity distribution (Critical, High, Medium, Low)
│   ├── 03_wazuh_rule_activity.spl               # Top firing rule IDs, descriptions, and frequency
│   ├── 04_wazuh_authentication_events.spl       # Auth logons across Windows & Linux endpoints
│   ├── 05_wazuh_failed_logins.spl               # Logon failure triage, source IPs, and target accounts
│   ├── 06_wazuh_agent_activity.spl              # Agent fleet inventory, health, and status
│   ├── 07_wazuh_mitre_attack.spl                # MITRE ATT&CK technique extraction & tactic mapping
│   └── 08_wazuh_high_severity_alerts.spl        # High severity triage queue (rule.level >= 10)
├── dashboards/
│   ├── README.md                                # Dashboard deployment & panel configuration guide
│   └── wazuh_splunk_dashboard.xml               # 10-Panel Simple XML integration dashboard
├── investigation/
│   └── investigation-workflow.md                # Full attack simulation, detection, and correlation scenario
└── screenshots/
    └── README.md                                # Screenshot evidence catalog & capture guidelines
```

---

## 6. SPL Threat Hunting Suite

All 8 queries are located in [`p10/queries/`](queries/) and have been designed for real-time triage and correlation:

| File | Title | Primary Target & Fields |
|---|---|---|
| [`01_wazuh_event_summary.spl`](queries/01_wazuh_event_summary.spl) | Event & Alert KPIs | `total_wazuh_alerts`, `active_agents`, `distinct_rules_fired`, `high_sev_percentage` |
| [`02_wazuh_alert_levels.spl`](queries/02_wazuh_alert_levels.spl) | Severity Tier Distribution | Groups `rule.level` into Critical (12-15), High (8-11), Medium (5-7), Low (0-4) |
| [`03_wazuh_rule_activity.spl`](queries/03_wazuh_rule_activity.spl) | Top Firing Rules | `rule.id`, `rule.description`, `severity_level`, `affected_endpoints`, `mitre_techniques` |
| [`04_wazuh_authentication_events.spl`](queries/04_wazuh_authentication_events.spl) | Authentication Activity | `timechart span=1h count by auth_status` (`FAILED` vs `SUCCESS`) |
| [`05_wazuh_failed_logins.spl`](queries/05_wazuh_failed_logins.spl) | Failed Login Triage | `source_ip`, `target_user`, `failure_count`, `error_codes` (`0xc000006a`) |
| [`06_wazuh_agent_activity.spl`](queries/06_wazuh_agent_activity.spl) | Agent Fleet Health | `agent_id`, `agent_name`, `agent_ip`, `total_events`, `critical_alerts`, `last_alert` |
| [`07_wazuh_mitre_attack.spl`](queries/07_wazuh_mitre_attack.spl) | MITRE ATT&CK Mapping | `mvexpand 'rule.mitre.id{}'`, `mitre_technique`, `mitre_tactic`, `target_endpoints` |
| [`08_wazuh_high_severity_alerts.spl`](queries/08_wazuh_high_severity_alerts.spl) | High-Severity Alert Queue | Filters `rule.level >= 10`, extracting timestamps, endpoints, source IPs, and users |

---

## 7. Splunk SOC Dashboard

The dashboard [`wazuh_splunk_dashboard.xml`](dashboards/wazuh_splunk_dashboard.xml) is a dark-theme Simple XML interface containing 10 functional panels:

1. **Total Wazuh Alerts Ingested** (Single Value KPI)
2. **High & Critical Alerts (Level >= 10)** (Single Value KPI with dynamic threshold alert color)
3. **Alerts by Severity Tier** (Donut / Pie Chart)
4. **Alert Velocity Over Time** (Stacked Area Chart)
5. **Top Firing Wazuh Detection Rules** (Horizontal Bar Chart)
6. **Agent Fleet Telemetry Distribution** (Status Table)
7. **Authentication Activity & Logon Failures** (Stacked Column Chart)
8. **Observed MITRE ATT&CK Techniques** (Matrix Table)
9. **High-Severity Alert Triage Queue** (Priority Incident Queue)
10. **Cross-Index Investigation Timeline** (Correlating `wazuh`, `windows`, and `sysmon`)

---

## 8. Incident Investigation Scenario

A full, documented investigation scenario is detailed in [`investigation/investigation-workflow.md`](investigation/investigation-workflow.md):
- **Simulation:** Kali Linux (`192.168.100.6`) executes Nmap port scans and automated SMB brute-force attacks against Windows 11 (`192.168.100.8`).
- **Detection:** Wazuh Agent captures Windows Security EID 4625; Wazuh Manager triggers Rule `60122` (Level 10).
- **Ingestion:** Splunk ingests `alerts.json` into `index=wazuh`.
- **Correlation:** Analyst correlates `index=wazuh` with `index=windows` (EID 4625) and `index=sysmon` (EID 3 network connection from `192.168.100.6` on port 445), proving that the attack was attempted and successfully blocked.

---

## 9. Limitations & Future Improvements

### Technical Limitations in Current Lab:
1. **Co-Located Host Resource Contention:** Running Wazuh Manager, Indexer, Dashboard, and Splunk Enterprise simultaneously on a single Ubuntu VM requires at least 8 GB RAM. Memory usage must be monitored closely via `free -m`.
2. **Archive Ingestion Overhead:** Ingestion is currently restricted to `alerts.json` (`rule.level >= 3`). Ingesting all raw archives (`archives.json`) would increase Splunk license consumption significantly.

### Future Roadmap Enhancements:
- **Active Response via Splunk:** Implement automated webhook actions from Splunk to Wazuh Manager's REST API (`https://192.168.100.7:55000`) to dynamically block offending IP addresses on endpoints.
- **FIM & Vulnerability Panels:** Expand dashboard coverage to incorporate Wazuh File Integrity Monitoring (Syscheck) and Vulnerability Detector feeds into dedicated Splunk panels.
