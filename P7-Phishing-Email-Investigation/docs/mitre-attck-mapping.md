# MITRE ATT&CK Mapping: Phishing Email Threat Vectors

> **Project:** P7 — Phishing Email Investigation with Splunk  
> **Author:** Natto Chakma  
> **Framework:** MITRE ATT&CK Enterprise Matrix v14

---

## 1. Tactical Alignment Matrix

The table below maps the telemetry fields, detection rules, and simulated attack vectors to the MITRE ATT&CK framework:

| Tactic | Technique Name | ATT&CK ID | Telemetry Indicator / Evidence | SPL Detection Rule |
|---|---|:---:|---|---|
| **Initial Access** | Spearphishing Attachment | **T1566.001** | Malicious files (`.xlsm`, `.pdf.exe`, `.iso`, `.vbs`) | [`04-malicious-attachments.spl`](../queries/04-malicious-attachments.spl) |
| **Initial Access** | Spearphishing Link | **T1566.002** | Credential-harvesting URLs and IP-literal links | [`05-malicious-urls.spl`](../queries/05-malicious-urls.spl) |
| **Execution** | User Execution: Malicious Link | **T1204.001** | User clicks link leading to Sysmon EventCode 22 DNS query | [`07-endpoint-correlation.spl`](../queries/07-endpoint-correlation.spl) |
| **Execution** | User Execution: Malicious File | **T1204.002** | User opens attachment resulting in child process launch (EID 1) | [`07-endpoint-correlation.spl`](../queries/07-endpoint-correlation.spl) |
| **Defense Evasion** | Masquerading: Match Legitimate Name | **T1036.005** | Homoglyph/typosquat domains (`micros0ft-support.com`) | [`01-suspicious-senders.spl`](../queries/01-suspicious-senders.spl) |
| **Defense Evasion** | Mark-of-the-Web (MOTW) Bypass | **T1553.005** | ISO container dropper (`DocuSign_Contract_Review.iso`) | [`04-malicious-attachments.spl`](../queries/04-malicious-attachments.spl) |
| **Resource Development** | Compromise Accounts: Email Accounts | **T1586.002** | Free webmail impersonation (`ceo...77@gmail.com`) | [`01-suspicious-senders.spl`](../queries/01-suspicious-senders.spl) |
| **Initial Access** | Business Email Compromise (BEC) | **T1566** | Executive impersonation wire transfer lure to CFO | [`03-suspicious-subjects.spl`](../queries/03-suspicious-subjects.spl), [`06-recipient-targeting.spl`](../queries/06-recipient-targeting.spl) |

---

## 2. Attack Lifecycle & Kill Chain Mapping

```mermaid
flowchart TD
    subgraph Stage1["1. Resource Development & Delivery"]
        A["Adversary Infrastructure<br>(185.220.101.45 / 194.26.29.112)"] -->|SMTP Handshake| B["Email Security Gateway<br>(index=email)"]
    end

    subgraph Stage2["2. Evasion & Triage"]
        B -->|SPF/DKIM/DMARC Failure| C{"Security Gateway Action"}
        C -->|Risk Score >= 75| D["Quarantined / Blocked"]
        C -->|Low Risk or BEC Webmail| E["Delivered to Inbox"]
    end

    subgraph Stage3["3. User Execution & Impact"]
        E -->|Click Link (T1204.001)| F["Credential Harvester Landing Page"]
        E -->|Open Attachment (T1204.002)| G["Macro Execution / Child Process (EID 1)"]
    end

    subgraph Stage4["4. SOC Detection & Hunting"]
        D & E --> H["Splunk SOC Phishing Dashboard"]
        F & G --> I["Cross-Correlation Hunting (EID 22 / EID 3)"]
    end
```
