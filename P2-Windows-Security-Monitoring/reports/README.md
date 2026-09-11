# 📑 P2 Incident Investigation & Technical Reports

[![Report Status](https://img.shields.io/badge/Report%20Status-Complete%20%26%20Verified-brightgreen.svg)](#-published-reports)
[![Author](https://img.shields.io/badge/Author-Natto%20Chakma-blue.svg)](#-published-reports)
[![Date](https://img.shields.io/badge/Date-September%2011%2C%202026-orange.svg)](#-published-reports)

This directory houses the formal engineering and forensic investigation deliverables from Project P2: Windows Security Monitoring & Threat Hunting with Splunk.

---

## 📑 Published Reports

### 1. Official Executive & Technical SOC Report (PDF)

- **Deliverable:** [`P2-Windows-Security-Monitoring-Report.pdf`](P2-Windows-Security-Monitoring-Report.pdf)
- **Document ID:** `SOC-REP-P2-2026-0911`
- **Author:** **Natto Chakma**
- **Date:** **September 11, 2026**
- **Classification:** `TLP:CLEAR / Lab Deliverable`
- **Scope:**
  - Full Windows 11 endpoint monitoring architecture (`DESKTOP-US2NJE2` — `192.168.100.8`)
  - Sysmon deployment and XML event parsing (`index=sysmon`)
  - Windows Event Log ingestion (`index=windows`)
  - 8,638 Windows Security events & 8,406 Sysmon events analyzed
  - MITRE ATT&CK alignment (T1059.001, T1059.003, T1046, T1110, T1078)
  - 5 core SPL correlation searches
  - Operational analytics for the **SOC Threat Hunting Dashboard** (Exhibit EX-20)
  - Forensic investigation of controlled reconnaissance from Kali Linux (`192.168.100.6` / `KALI`) via the **Kali Attacker Activity Dashboard** (Exhibit EX-21)
  - Endpoint hardening recommendations and mitigation strategies
