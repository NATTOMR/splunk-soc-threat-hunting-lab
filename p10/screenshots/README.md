# Project P10 — Screenshots & Verification Exhibits Catalog

**Project:** P10 — Wazuh + Splunk SIEM Integration  
**Directory:** `p10/screenshots/`  
**Purpose:** Photographic evidence guide and visual artifact catalog for laboratory verification.

---

## 1. Exhibits Overview

| Figure ID | File Name | Subject / Component | Description |
|:---:|---|---|---|
| **EX-01** | `p10-01-wazuh-manager-service-status.png` | Ubuntu Server CLI | Confirmed `systemctl status wazuh-manager` showing active (running) daemon on `wazuh-server`. |
| **EX-02** | `p10-02-wazuh-agent-service-windows.png` | Windows 11 PowerShell | Verified `Get-Service WazuhSvc` in running state on the Windows endpoint (`192.168.100.8`). |
| **EX-03** | `p10-03-wazuh-alerts-json-raw.png` | Wazuh Alerts File | Terminal capture of `tail -n 10 /var/ossec/logs/alerts/alerts.json` showing live JSON structures. |
| **EX-04** | `p10-04-splunk-monitor-input-wazuh.png` | Splunk Enterprise CLI | Verified active file monitor input via `/opt/splunk/bin/splunk list monitor`. |
| **EX-05** | `p10-05-splunk-search-index-wazuh.png` | Splunk Search UI | Successful execution of `index=wazuh earliest=-24h` returning extracted JSON fields. |
| **EX-06** | `p10-06-wazuh-splunk-dashboard-overview.png` | Splunk Web Dashboard | Full view of the 10-panel dark-theme integration dashboard in Splunk Web (`127.0.0.1:18000`). |
| **EX-07** | `p10-07-wazuh-mitre-attack-panel.png` | Splunk Dashboard Panel | Close-up of Panel 8 showing MITRE ATT&CK technique breakdown and tactic distribution. |
| **EX-08** | `p10-08-cross-index-investigation-timeline.png` | Splunk Dashboard Panel | Close-up of Panel 10 correlating `index=wazuh`, `index=windows`, and `index=sysmon`. |

---

## 2. Evidence Capture Guidelines

When capturing exhibits from the live laboratory environment:
1. **Resolution & Aspect Ratio:** Capture at standard 1920x1080 or clear browser window viewports.
2. **Sanitization:** Ensure no real domain credentials, administrative passwords, or production keys appear in shell prompts.
3. **Format:** Save exhibits as optimized `.png` format files directly into this directory (`p10/screenshots/`).
