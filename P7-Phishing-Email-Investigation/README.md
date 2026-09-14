# 📧 P7 — Phishing Email Investigation with Splunk

[![Status](https://img.shields.io/badge/Status-Completed%20%26%20Validated-success.svg)](#14-project-status)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%2010.4.3-blue.svg)](https://www.splunk.com/)
[![Log Ingestion](https://img.shields.io/badge/Telemetry-Email%20Security%20Gateway-orange.svg)](#5-lab-architecture)
[![Dashboard](https://img.shields.io/badge/Dashboard-Phishing%20SOC%20Operations-success.svg)](dashboards/README.md)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![GitHub Issue](https://img.shields.io/badge/GitHub%20Issue-%238-brightgreen.svg)](https://github.com/NATTOMR/splunk-soc-threat-hunting-lab/issues/8)
[![Report](https://img.shields.io/badge/Report-PDF%20Compiled-red.svg)](reports/P7-Phishing-Email-Investigation-Report.pdf)

> **Author:** Natto Chakma  
> **Master Repository Component:** This project constitutes **Project P7** in the [Splunk SOC & Threat Hunting Lab](../README.md).  
> **Project Identity:** P7 — Phishing Email Investigation with Splunk  
> **Core Purpose:** Build an end-to-end phishing incident triage and threat hunting workflow in Splunk to analyze email security telemetry, identify suspicious lures, extract IOCs, correlate with endpoint telemetry, and orchestrate containment.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Objective](#2-objective)
3. [Security Problem](#3-security-problem)
4. [Scope](#4-scope)
5. [Lab Architecture & Workflow](#5-lab-architecture--workflow)
6. [Detection Scenarios](#6-detection-scenarios)
7. [Investigation Methodology](#7-investigation-methodology)
8. [SPL Query Library](#8-spl-query-library)
9. [MITRE ATT&CK Mapping](#9-mitre-attck-mapping)
10. [Evidence](#10-evidence)
11. [Results](#11-results)
12. [Limitations](#12-limitations)
13. [Future Improvements](#13-future-improvements)
14. [Project Status](#14-project-status)
15. [Master Repository Navigation](#15-master-repository-navigation)

---

## 1. Project Overview

Phishing remains the predominant initial access vector utilized by cyber adversaries to breach corporate networks. Threat actors deploy sophisticated techniques—including lookalike typosquatting domains, SPF/DKIM/DMARC alignment evasion, Mark-of-the-Web (MOTW) container droppers, and executive impersonation (Whaling)—to deceive employees and harvest credentials or establish foothold malware.

This project delivers a complete detection engineering, triage workflow, and incident investigation system for email-borne threats in Splunk Enterprise. Ingesting email gateway telemetry into `index=email sourcetype="email:security"`, P7 establishes a resilient SPL detection suite, cross-correlates indicators against Windows Sysmon endpoint telemetry, provides an operational dark-mode SOC Phishing Dashboard, and presents an executive investigation report.

---

## 2. Objective

- Ingest and parse email security gateway message traces into Splunk (`index=email sourcetype="email:security"`).
- Engineer high-confidence SPL detection rules for lookalike domains, authentication failures, weaponized attachments, phishing URLs, and executive impersonation.
- Implement the structured 7-step SOC Phishing Investigation Playbook (Email Event ➔ Sender/Recipient ➔ URL/Domain/IP ➔ Attachment ➔ IOC Extraction ➔ Endpoint Correlation ➔ Containment).
- Operationalize a dark-mode **P7 — Phishing Email Investigation & Security Operations** SOC dashboard.
- Map all detections to the MITRE ATT&CK Enterprise Matrix (T1566.001, T1566.002, T1204.001, T1204.002, T1036, T1553).
- Compile a formal incident investigation report in Markdown, HTML, and high-resolution PDF formats.

---

## 3. Security Problem

Email security gateways process high volumes of inbound messaging. Differentiating benign corporate correspondence from sophisticated spearphishing requires multi-layered inspection:
1. **Header & Alignment Validation:** Attackers frequently forge display names while using freemail providers, or exploit lax DMARC configurations to bypass simple sender checks.
2. **Obfuscated Payloads:** Modern malware droppers evade traditional antivirus by encapsulating binaries inside disk images (`.iso`) to bypass Windows Mark-of-the-Web (MOTW) or utilizing dual extensions (`.pdf.exe`).
3. **Cross-Layer Telemetry Disconnect:** A gateway block is only half the battle; SOC analysts must rapidly determine whether a recipient clicked a phishing link before quarantine occurred by querying endpoint DNS logs (`index=sysmon EventCode=22`).

---

## 4. Scope

| In-Scope | Out-of-Scope |
|---|---|
| Email security gateway telemetry ingestion (`index=email`) | Live mail exchange server deployment (Microsoft Exchange / Postfix cluster) |
| Sender display name and homoglyph domain detection | Automated sandboxing detonator VM farm (e.g. Cuckoo Sandbox) |
| SPF, DKIM, and DMARC alignment failure analysis | Email body NLP sentiment classification |
| Suspicious attachment detection (`.xlsm`, `.iso`, `.pdf.exe`, `.vbs`) | Live active directory password sync scripting |
| Malicious URL, IP-literal, and shortener extraction | End-user phishing awareness training campaign management |
| Whaling / Executive impersonation detection | Production tenant email tenant admin rights |
| Cross-telemetry correlation with Sysmon EID 1 & EID 22 | Anti-spam Bayesian scoring engine tuning |
| Splunk Classic Simple XML dark-mode SOC dashboard | Automated webhook SOAR orchestration |
| Formal Incident Investigation PDF Report | External passive DNS historical infrastructure mapping |

---

## 5. Lab Architecture & Workflow

### Architectural Data Flow

```
                      [ Email Threat Pipeline ]
                                  │
      ┌───────────────────────────┴───────────────────────────┐
      ▼                                                       ▼
[ Inbound Phishing Relays ]                             [ Benign Senders ]
(185.220.101.45 / 194.26.29.112)                        (Slack / GitHub / AWS)
      │                                                       │
      └───────────────────────────┬───────────────────────────┘
                                  │ SMTP Traffic
                                  ▼
                    ┌───────────────────────────┐
                    │  Email Security Gateway   │
                    │  (Telemetry Generation)   │
                    └─────────────┬─────────────┘
                                  │ /var/log/email_gateway/mail.log
                                  ▼
                    ┌───────────────────────────┐
                    │ Splunk Universal Forwarder│
                    └─────────────┬─────────────┘
                                  │ TCP 9997 Forwarding
                                  ▼
                    ┌───────────────────────────┐
                    │     Splunk Enterprise     │
                    │     (192.168.100.7)       │
                    ├───────────────────────────┤
                    │ • index=email             │
                    │ • index=sysmon            │
                    │ • SOC Phishing Dashboard  │
                    └───────────────────────────┘
```

### Investigation Workflow (from GitHub Issue #8)

```
Email Event Received
         │
         ▼
Sender / Recipient Analysis (Lookalike Domains, VIP Whaling, Multi-Recipient Blast)
         │
         ▼
URL / Domain / IP Analysis (Direct IP Links, Harvesters, Shorteners, Defanging)
         │
         ▼
Attachment Analysis (Dual-Extension, Macros, MOTW ISO Droppers, SHA-256 Hashes)
         │
         ▼
IOC Extraction (Defanged Domains, Sender IPs, C2 URLs, File Hashes)
         │
         ▼
Correlation (Cross-referencing with Endpoint Sysmon EID 1 Process / EID 22 DNS)
         │
         ▼
Timeline Reconstruction (Campaign Delivery, User Interaction, Containment)
         │
         ▼
SOC Investigation & Playbook Execution
         │
         ▼
MITRE ATT&CK Mapping (T1566.001, T1566.002, T1204.001, T1204.002, T1036)
```

---

## 6. Detection Scenarios

- **Scenario 1: Credential Harvester Link:** Adversary uses lookalike domain `micros0ft-support.com` delivering a password expiration notice linking to `http://login-micros0ft-verify.com/auth/login.php`.
- **Scenario 2: Dual-Extension Executable:** Delivery failure notification carrying `Shipping_Manifest.pdf.exe` intended to trick users via hidden Windows extensions.
- **Scenario 3: MOTW Bypass via ISO Dropper:** Lure masquerading as a DocuSign contract delivering `DocuSign_Contract_Review.iso` to evade Mark-of-the-Web protections.
- **Scenario 4: Macro-Enabled Remittance Invoice:** Invoicing lure carrying `INVOICE_OCT2026.xlsm` containing obfuscated VBA stagers.
- **Scenario 5: Executive Impersonation / Whaling:** Spoofed CEO identity via external Gmail address requesting urgent confidential acquisition wire transfer from the corporate CFO.
- **Scenario 6: Mass-Blast HR Phishing:** Coordinated HR policy acknowledgment phish targeting multiple users concurrently from rogue IP `91.240.118.22`.

---

## 7. Investigation Methodology

The end-to-end investigation methodology is formally detailed in the [SOC Investigation Playbook](docs/investigation-playbook.md):
1. **Header & Authentication Triage:** Inspect `spf`, `dkim`, and `dmarc` tags to identify spoofing and alignment breakdowns.
2. **Sender Profiling:** Identify homoglyph domains, disposable email relays, and executive masquerading.
3. **Hyperlink Inspection:** Extract embedded destinations, flag direct IP-literal URLs, and expand shorteners.
4. **Attachment Examination:** Extract cryptographic SHA-256 hashes and classify dangerous container/macro formats.
5. **IOC Extraction:** Defang indicators for safe storage and log in the [IOC Catalog](docs/ioc-table.md).
6. **Cross-Layer Telemetry Correlation:** Query `index=sysmon` for DNS resolutions (EventCode 22) or suspicious process launches (EventCode 1) on endpoints matching the targeted users.
7. **Playbook Containment:** Purge inbox messages, block sender IPs/domains at edge firewall, and revoke user sessions.

---

## 8. SPL Query Library

Production detection rules available in [queries/](queries/):
- [`01-suspicious-senders.spl`](queries/01-suspicious-senders.spl): Lookalike domains, free webmail executive spoofing, and rogue TLDs.
- [`02-authentication-failures.spl`](queries/02-authentication-failures.spl): SPF, DKIM, and DMARC alignment failures.
- [`03-suspicious-subjects.spl`](queries/03-suspicious-subjects.spl): High-urgency keywords, wire transfers, and overdue invoices.
- [`04-malicious-attachments.spl`](queries/04-malicious-attachments.spl): Weaponized Office macros, ISO droppers, and dual-extension files.
- [`05-malicious-urls.spl`](queries/05-malicious-urls.spl): Credential harvesters, IP-literal destinations, and URL shorteners.
- [`06-recipient-targeting.spl`](queries/06-recipient-targeting.spl): Whaling detection and mass-blast campaign grouping.
- [`07-endpoint-correlation.spl`](queries/07-endpoint-correlation.spl): Cross-index correlation between email lures and Sysmon EID 1 / EID 22 logs.

---

## 9. MITRE ATT&CK Mapping

| Tactic | Technique Name | ATT&CK ID | Telemetry Indicator | Detection Rule |
|---|---|:---:|---|---|
| **Initial Access** | Spearphishing Attachment | **T1566.001** | `.xlsm`, `.iso`, `.pdf.exe`, `.vbs` | `04-malicious-attachments.spl` |
| **Initial Access** | Spearphishing Link | **T1566.002** | Credential-harvesting landing pages | `05-malicious-urls.spl` |
| **Execution** | User Execution: Malicious Link | **T1204.001** | Endpoint DNS query to phishing URL | `07-endpoint-correlation.spl` |
| **Execution** | User Execution: Malicious File | **T1204.002** | Process creation from Office application | `07-endpoint-correlation.spl` |
| **Defense Evasion** | Masquerading: Match Legitimate Name | **T1036.005** | Homoglyph typosquat domains | `01-suspicious-senders.spl` |
| **Defense Evasion** | Mark-of-the-Web (MOTW) Bypass | **T1553.005** | ISO container image encapsulating payload | `04-malicious-attachments.spl` |

---

## 10. Evidence

Authentic visual evidence from Splunk Enterprise and forensic investigation workflows:

| Exhibit ID | File Reference | Description | Status |
|:---:|---|---|:---:|
| **EX-P7-01** | [`p7-01-phishing-investigation-dashboard.png`](screenshots/p7-01-phishing-investigation-dashboard.png) | Operational SOC Phishing Investigation Dashboard displaying live KPIs, attack distributions, SPF/DKIM/DMARC breakdown, and prioritized triage queue. | 🟢 Verified |
| **EX-P7-02** | [`p7-02-email-triage-investigation.png`](screenshots/p7-02-email-triage-investigation.png) | Splunk Search Head executing targeted SPL triage query across `index=email` gateway telemetry. | 🟢 Verified |

### Operational SOC Phishing Dashboard (Exhibit EX-P7-01)
![P7 Phishing Dashboard](screenshots/p7-01-phishing-investigation-dashboard.png)

---

## 11. Results

- **Log Ingestion & Normalization:** Ingested 100% of sample email security telemetry into `index=email` under `sourcetype="email:security"`.
- **Threat Isolation:** Accurately classified all 8 malicious campaign vectors across weaponized files, credential harvesters, BEC, and spoofing.
- **Cross-Layer Telemetry Hunting:** Validated correlation workflow with Sysmon endpoint events to verify link interaction and process creation.
- **Executive Reporting:** Compiled 3-page standalone technical incident report ([`P7-Phishing-Email-Investigation-Report.pdf`](reports/P7-Phishing-Email-Investigation-Report.pdf)).

---

## 12. Limitations

- Gateway telemetry alone cannot confirm whether an end-user submitted credentials on a landing page; full confirmation requires proxy/firewall egress inspection or identity provider logs (e.g. Azure AD Sign-in logs).
- Encrypted or password-protected archives require perimeter decryption or sandboxing.

---

## 13. Future Improvements

- Integrate VirusTotal and urlscan.io API lookups directly into Splunk search pipelines via automated custom search commands.
- Implement automated SOAR playbooks (Phantom / Splunk SOAR) to execute tenant-wide message deletion and Active Directory password resets upon high-confidence alerts.

---

## 14. Project Status

| Phase / Sub-Issue | Focus Area | Status | Deliverables |
|---|---|:---:|---|
| **P7.1** | Email Gateway Telemetry Ingestion | 🟢 Completed | Standardized email CIM schema, inputs.conf, and sample dataset |
| **P7.2** | SPL Detection Engineering | 🟢 Completed | 7 validated production SPL queries covering senders, attachments, and URLs |
| **P7.3** | SOC Phishing Investigation Dashboard | 🟢 Completed | Dark-mode Simple XML dashboard with 10 operational panels |
| **P7.4** | Investigation Playbook & ATT&CK Mapping | 🟢 Completed | 7-step SOC response playbook, defanged IOC catalog, and MITRE matrix |
| **P7.5** | Technical Investigation Report & PDF | 🟢 Completed | Formal incident report (MD, HTML, and compiled PDF) |

---

## 15. Master Repository Navigation

- 🏠 **[Master Lab Repository](../README.md)**
- 📁 **[P1 — Splunk Core Deployment & Indexing](../P1-Core-Deployment/README.md)**
- 📁 **[P2 — Windows Endpoint Monitoring with Sysmon](../P2-Windows-Monitoring/README.md)**
- 📁 **[P3 — Linux Endpoint Monitoring](../P3-Linux-Monitoring/README.md)**
- 📁 **[P4 — Brute-Force Detection & Investigation](../P4-Brute-Force-Detection/README.md)**
- 📁 **[P5 — Network Threat Detection with Splunk](../P5-Network-Threat-Detection/README.md)**
- 📁 **[P6 — Web Attack Detection with Splunk](../P6-Web-Attack-Detection/README.md)**
- 📁 **[P7 — Phishing Email Investigation with Splunk](README.md)**
