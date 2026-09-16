# SOC Incident Investigation Report: Phishing Threat Detection & Analysis

> **Incident ID:** INC-2026-P7-001  
> **Investigation Title:** Multi-Vector Phishing Campaign: Credential Harvesting, Weaponized Attachments, and Whaling Impersonation  
> **Investigating Analyst:** Natto Chakma  
> **Date:** September 14, 2026  
> **Target Environment:** Enterprise Messaging Infrastructure & User Endpoints  
> **Primary Monitored Index:** `index=email` (`sourcetype="email:security"`) & `index=sysmon`  
> **Severity:** **HIGH**  
> **Incident Status:** Contained / Documented  

---

## 1. Executive Summary

During continuous Security Operations Center (SOC) threat hunting and perimeter log monitoring, security analysts detected an orchestrated, multi-vector email threat campaign targeting corporate users. The attack sequence leveraged diverse social engineering lures, domain typosquatting, SPF/DKIM/DMARC alignment bypass attempts, weaponized file containers, and credential harvesting landing pages.

Centralized email security telemetry ingested into **Splunk Enterprise** (`index=email`) identified 15 total message events, within which **8 distinct malicious phishing operations** were triaged, isolated, and categorized:

1. **Credential Harvesting Lures (T1566.002):** Attackers utilized lookalike domain `micros0ft-support.com` to deliver fake Microsoft 365 password expiration notices directing targets to external harvester `hxxp://login-micros0ft-verify[.]com`.
2. **Weaponized Attachment Distribution (T1566.001):** Multiple dangerous payload formats were distributed:
   - Macro-enabled Excel workbook (`INVOICE_OCT2026.xlsm`)
   - Dual-extension PE binary masquerading as PDF (`Shipping_Manifest.pdf.exe`)
   - ISO disk image container (`DocuSign_Contract_Review.iso`) designed to bypass Windows Mark-of-the-Web (MOTW)
   - VBScript downloader (`Direct_Deposit_Receipt.vbs`) linked via a shortened URL (`bit.ly/3xPayrollVerify`)
3. **Executive Impersonation / Whaling (T1566 / T1036):** Threat actors spoofed CEO credentials via external freemail (`ceo.corporate.exec77@gmail.com`) targeting the corporate CFO with an urgent wire transfer authorization request.
4. **Mass-Blast Phishing Campaign (T1566.002):** An HR policy lure originating from `91.240.118.22` was dispatched concurrently to multiple employees (`alice.smith`, `bob.miller`, `charlie.davis`) to maximize victim conversion probability.
5. **Cross-Layer Telemetry Correlation:** Cross-referencing gateway telemetry with Windows endpoint Sysmon logs (`index=sysmon`) validated DNS resolution events (Sysmon EventCode 22) and verified that no malicious child processes (Sysmon EventCode 1) achieved successful execution.

All malicious emails were triaged according to the standard SOC Phishing Playbook, with indicators defanged and pushed to perimeter blocklists.

---

## 2. Incident Scope & Telemetry Architecture

| Parameter | Forensic Detail |
|---|---|
| **Primary Ingestion Channel** | Postfix MTA Gateway syslog (`/var/log/mail.log`) |
| **Splunk Ingestion Pipeline** | Splunk Universal Forwarder ➔ Splunk Enterprise (`192.168.100.7:9997`) |
| **Monitored Indices** | `index=email` (`sourcetype="postfix:syslog"`), `index=sysmon` |
| **Total Ingested Messages** | 31 Gateway Transactions (401 Syslog Events) |
| **High-Risk Phishing Detections** | 17 flagged threats |
| **Malicious Attachments** | 12 Weaponized Executables / Archives (`.exe`, `.xlsm`, `.iso`) |
| **Phishing URLs** | 3 Extracted Credential Harvesters & Token Stealers |
| **Domain Spoofing / Whaling** | 12 Senders Masquerading as C-Suite or Trusted Vendors |
| **Adversary Relays / IPs** | `192.168.100.6` (Kali Linux wire transmission across TCP 25) |
| **Victim Impact** | 0 confirmed credential compromises, 0 malware executions |

---

## 3. Telemetry Evidence & Detection Queries

The SOC detection engineering team deployed targeted SPL queries to correlate Postfix transactions by `queue_id` and extract sender, recipient, subject, attachment, and URL parameters:

```spl
# Unified Phishing Triage Pipeline (Postfix Syslog)
index=email sourcetype="postfix:syslog"
| rex "postfix/\w+\[\d+\]: (?<queue_id>[A-F0-9]{8,12}):"
| rex "header Subject: (?<subject>.*?) from \w+\["
| rex "header From: (?<sender>.*?) from \w+\["
| rex "header To: (?<recipient>.*?) from \w+\["
| rex "from \w+\[(?<src_ip>\d+\.\d+\.\d+\.\d+)\]"
| rex "(?:body|header)[^:\n]*:.*?(?<url>https?://[^\s>\"\'\)]+)"
| rex "(?<attachment_name>[\w\.\-]+\.(?:exe|xlsm|iso|pdf|vbs))"
| stats 
    values(src_ip) as src_ip
    values(sender) as sender
    values(recipient) as recipient
    values(subject) as subject
    values(attachment_name) as attachment_name
    values(url) as url
    by queue_id
| where isnotnull(sender)
| eval sender=trim(sender, "<> \"'"), recipient=trim(recipient, "<> \"'")
| eval Threat_Type=case(
    isnotnull(attachment_name) AND match(attachment_name, "(?i)\.(exe|xlsm|iso|vbs)"), "Weaponized Attachment (T1566.001)",
    isnotnull(url) AND match(url, "(?i)(login|portal|auth|update|194\.)"), "Credential Harvester (T1566.002)",
    match(sender, "(?i)(ceo|cfo|executive)"), "Executive Impersonation / Whaling (T1566)",
    match(subject, "(?i)(action required|mandatory policy)"), "Internal HR Mass Spray (T1566.002)",
    match(sender, "(?i)(spoofed|quick-invoices|docusign|payroll)"), "Domain Spoofing / Brand Masquerade",
    true(), "Benign Activity"
  )
| eval Risk_Score=case(
    match(Threat_Type, "Weaponized"), 98,
    match(Threat_Type, "Credential"), 94,
    match(Threat_Type, "Executive"), 92,
    match(Threat_Type, "Domain Spoofing"), 88,
    match(Threat_Type, "Internal HR"), 82,
    true(), 0
  )
| search Threat_Type!="Benign Activity"
| table queue_id, src_ip, sender, recipient, subject, Threat_Type, attachment_name, url, Risk_Score
| rename queue_id as "Queue ID", src_ip as "Sender IP", sender as "Sender Address",
         recipient as "Target Recipient", subject as "Email Subject",
         Threat_Type as "Threat Classification", attachment_name as "Attachment",
         url as "Extracted URL", Risk_Score as "Risk Score"
| sort - "Risk Score"
```

### Forensic Event Stream Sample

```text
2026-09-14 11:42:01  payroll@payroll-notice.cc           kevin.hart@company.com    Direct_Deposit_Receipt.vbs      quarantined  Risk: 99
2026-09-14 09:30:15  courier@dhl-express-tracking...     john.doe@company.com      Shipping_Manifest.pdf.exe       blocked      Risk: 98
2026-09-14 11:05:40  documents@docusign-docs.online      legal@company.com         DocuSign_Contract_Review.iso    quarantined  Risk: 96
2026-09-14 08:45:03  admin@micros0ft-support.com         sarah.connor@company.com  login-micros0ft-verify.com      quarantined  Risk: 95
2026-09-14 09:55:50  sharepoint-noreply@onedrive-...     elizabeth.vane@comp...    194.26.29.112:8080/sharepoint   quarantined  Risk: 92
2026-09-14 09:02:18  orders@quick-invoices-secure.org    finance@company.com       INVOICE_OCT2026.xlsm            quarantined  Risk: 90
2026-09-14 10:48:09  humanresources@hr-internal...       alice.smith@company.com   hr-internal-portal.net/update   delivered    Risk: 88
2026-09-14 10:15:33  ceo.corporate.exec77@gmail.com      cfo@company.com           Urgent Wire Transfer (Whaling)  delivered    Risk: 85
```

---

## 4. Operational Dashboard Verification

All incoming email telemetry and prioritized alerts were monitored through the operational **P7 — Phishing Email Investigation & Security Operations** SOC dashboard:

![P7 Phishing Dashboard](../screenshots/p7-01-phishing-investigation-dashboard.png)

### Key Metrics Triaged at Incident Close:
- **Total Ingested Messages:** `15`
- **Flagged Phishing Incidents:** `8`
- **Weaponized Files Detected:** `4`
- **Malicious & Harvesting URLs:** `4`
- **SPF/DKIM/DMARC Failures:** `7`
- **Malicious Messages Quarantined or Blocked at Perimeter:** `75%` (6 of 8)
- **Delivered Messages Remediated via Automated Mailbox Purge:** `100%` (2 of 2)

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique Name | ID | Forensic Application |
|---|---|:---:|---|
| **Initial Access** | Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Obfuscated VBA macros (`.xlsm`), ISO container dropper, and `.pdf.exe` |
| **Initial Access** | Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Credential harvesting landing pages and IP-literal SharePoint spoof |
| **Execution** | User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Monitored link interaction using endpoint Sysmon EID 22 DNS logs |
| **Execution** | User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Proactive rule alerting on office processes spawning command interpreters |
| **Defense Evasion** | Masquerading: Match Legitimate Name | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Lookalike homoglyphs (`micros0ft`) and spoofed executive display names |
| **Defense Evasion** | Mark-of-the-Web (MOTW) Bypass | [T1553.005](https://attack.mitre.org/techniques/T1553/005/) | Packing executable inside ISO container image |

---

## 6. Containment, Eradication & Post-Incident Actions

1. **Enterprise Mailbox Remediation:**
   - Executed administrative search-and-purge commands across mail servers to remove delivered messages matching subjects `Action Required: Mandatory Q3 Security...` and `URGENT CONFIDENTIAL: Wire Transfer...`.
2. **Perimeter Firewall & Proxy Blocking:**
   - Added `185.220.101.45`, `194.26.29.112`, `91.240.118.22`, and `45.142.166.7` to perimeter edge drop lists.
   - Pushed all extracted phishing domains and URLs to secure web gateway (SWG) categorization blocklists.
3. **Identity & Credential Hardening:**
   - Initiated mandatory password reset and active session token revocation for `sarah.connor`, `alice.smith`, `bob.miller`, and `charlie.davis`.
   - Verified that FIDO2/WebAuthn phishing-resistant multi-factor authentication (MFA) was active on all impacted user accounts.
4. **Endpoint Validation:**
   - Queried Sysmon telemetry on all targeted endpoints; confirmed zero outbound connections to adversary C2 endpoints and zero abnormal process creations.
5. **Security Awareness Enhancement:**
   - Dispatched organization-wide alert highlighting the specific executive wire transfer lure and fraudulent HR policy lure observed in this campaign.
