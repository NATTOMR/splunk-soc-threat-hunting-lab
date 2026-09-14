# SPL Query Library — Phishing Email Investigation

> **Project:** P7 — Phishing Email Investigation with Splunk  
> **Author:** Natto Chakma  
> **Data Model / Telemetry:** `index=email`, `sourcetype=email:security` & `index=sysmon`

---

## Overview

This directory provides 7 production-grade Splunk Search Processing Language (SPL) rules designed for triage, threat detection, hunting, and post-exploitation correlation across email gateway logs and endpoint telemetry.

---

## Query Inventory

| File | Detection Focus | Key Fields | MITRE ATT&CK |
|---|---|---|:---:|
| [`01-suspicious-senders.spl`](01-suspicious-senders.spl) | Lookalike/homoglyph domains, free webmail impersonation, executive spoofing | `sender`, `sender_domain`, `recipient` | T1566, T1036 |
| [`02-authentication-failures.spl`](02-authentication-failures.spl) | SPF, DKIM, and DMARC alignment failures | `spf`, `dkim`, `dmarc`, `src_ip` | T1566.002, T1586 |
| [`03-suspicious-subjects.spl`](03-suspicious-subjects.spl) | High-urgency keywords, wire transfer, overdue invoices, password expirations | `subject`, `risk_score` | T1566, T1204 |
| [`04-malicious-attachments.spl`](04-malicious-attachments.spl) | Weaponized Office macros (`.xlsm`), ISO droppers, dual-extension `.pdf.exe`, scripts | `attachment_name`, `attachment_hash` | T1566.001, T1204.002 |
| [`05-malicious-urls.spl`](05-malicious-urls.spl) | Credential harvesters, IP-literal links, URL shorteners | `url`, `action`, `risk_score` | T1566.002, T1204.001 |
| [`06-recipient-targeting.spl`](06-recipient-targeting.spl) | Whaling (C-suite/VIP) and mass-blast phishing campaigns | `recipient`, `sender`, `subject` | T1566, T1566.002 |
| [`07-endpoint-correlation.spl`](07-endpoint-correlation.spl) | Cross-correlation between email delivery and Sysmon DNS queries / process launches | `url`, `QueryName`, `ParentImage` | T1204, T1059 |

---

## Usage Instructions

1. Ensure email logs are indexed under `index=email` with `sourcetype="email:security"`.
2. Execute individual queries in Splunk Search Head (`http://192.168.100.7:8000`).
3. These queries are integrated into the [SOC Phishing Investigation Dashboard](../dashboards/phishing-investigation-dashboard.xml).
