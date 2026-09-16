# 📸 P8 Threat Hunting Screenshots & Evidence Exhibits

[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v15-red.svg)](https://attack.mitre.org/)
[![Project](https://img.shields.io/badge/Project-P8%20Threat%20Hunting-orange.svg)](../README.md)

This directory stores visual evidence, architecture diagrams, and dashboard exhibits captured during the **Project P8 — MITRE ATT&CK Threat Hunting with Splunk** engagement.

---

## Evidence Exhibit Catalog

| Exhibit File | Description | Target Telemetry |
|---|---|---|
| `p8-workflow-architecture.png` | Threat hunting 8-stage lifecycle and multi-source telemetry pipeline architecture. | Methodology & Flow |
| `p8-01-hunting-dashboard-overview.png` | Dark-mode Splunk Threat Hunting Dashboard overview showcasing KPI cards and ATT&CK tactic distribution. | Dashboard |
| `p8-02-powershell-obfuscation-hunt.spl.png` | Live hunt execution uncovering Base64-obfuscated PowerShell download cradle. | `index=sysmon` EID 1 |
| `p8-03-lolbin-certutil-execution.png` | Living-off-the-land `certutil.exe -urlcache` remote file staging detection. | `index=sysmon` EID 1 / 11 |
| `p8-04-persistence-registry-hunt.png` | Autostart registry key write surfaced in `HKCU\...\CurrentVersion\Run`. | `index=sysmon` EID 12/13 |
| `p8-05-lateral-movement-triage.png` | Administrative SMB and logon session correlation table. | `index=windows` EID 4624 |
