# Wazuh + Splunk SIEM Integration Architecture

**Project:** P10 — Wazuh + Splunk SIEM Integration  
**Document:** Integration Architecture & Data Pipeline Specification  
**Target Environment:** Splunk Enterprise 10.4.3 & Wazuh Manager 4.x / 5.x  
**Classification:** Defensive Cybersecurity Lab Reference  

---

## 1. Executive Architecture Overview

In modern enterprise Security Operations Centers (SOCs), organizations frequently deploy specialized host-based endpoint detection and response (EDR/XDR) platforms alongside centralized SIEM solutions. 

This project integrates **Wazuh** (open-source XDR/SIEM) with **Splunk Enterprise** (central SIEM, correlation engine, and operational dashboard), establishing a unified defensive telemetry pipeline. Wazuh excels at endpoint security monitoring, rootkit detection, file integrity monitoring (FIM), vulnerability assessment, and host-level compliance auditing, while Splunk provides cross-domain correlation, advanced threat hunting, and operational visualization.

```
       ┌────────────────────────────────────────────────────────┐
       │               MONITORED LAB ENDPOINTS                  │
       └────────────────────────────────────────────────────────┘
            │                                        │
     [Windows 11 Endpoint]                      [Kali Linux]
       192.168.100.8                            192.168.100.6
  Wazuh Agent (WazuhSvc)                   Authorized Testing Host
  Sysmon64 + WinEventLog                     Port Scans & Probes
            │                                        │
            │ TCP 1514 (Encrypted Events)            │
            ▼                                        ▼
       ┌────────────────────────────────────────────────────────┐
       │     [Ubuntu Server] wazuh-server (192.168.100.7)        │
       │                                                        │
       │  ┌──────────────────────────────────────────────────┐  │
       │  │                  WAZUH STACK                     │  │
       │  │  • Wazuh Manager (wazuh-analysisd)               │  │
       │  │  • Rule Engine (Decoders & MITRE Mapping)        │  │
       │  │  • Alert Stream: /var/ossec/logs/alerts/alerts.json│  │
       │  └──────────────────────────────────────────────────┘  │
       │                           │                            │
       │             Direct Local File Ingestion                │
       │                           ▼                            │
       │  ┌──────────────────────────────────────────────────┐  │
       │  │             SPLUNK ENTERPRISE 10.4.3             │  │
       │  │  • Input: [monitor:///var/ossec/.../alerts.json] │  │
       │  │  • Parsing: sourcetype=wazuh (Native JSON)       │  │
       │  │  • Storage: index=wazuh (Dedicated Index)       │  │
       │  │  • Search & Correlation Head (TCP 18000 Web)     │  │
       │  │  • Unified SOC Dashboards & 8 Modular Queries    │  │
       │  └──────────────────────────────────────────────────┘  │
       └────────────────────────────────────────────────────────┘
```

---

## 2. Lab Host Identification & Machine Roles

The integration strictly preserves the existing VirtualBox NAT Network (`LabNetwork` — `192.168.100.0/24`) infrastructure:

| Machine Name | Operating System | IP Address | Active Services & Components | Integration Role |
|---|---|---|---|---|
| **`wazuh-server`** | Ubuntu Server 24.04 LTS | `192.168.100.7` | • `wazuh-manager`<br>• `wazuh-indexer`<br>• `wazuh-dashboard`<br>• `splunkd` (Splunk Enterprise 10.4.3)<br>• Ports: `1514/tcp`, `1515/tcp`, `8000/18000/tcp`, `9997/tcp`, `8089/tcp` | **Central SIEM & XDR Core:** Co-locates Wazuh Manager and Splunk Enterprise. Hosts the raw alert files and serves as the central correlation indexer. |
| **Windows 11 Endpoint** | Windows 11 64-bit / Server | `192.168.100.8` | • `WazuhSvc` (Wazuh Agent 4.x, Agent ID 003)<br>• `Sysmon64`<br>• `SplunkForwarder` (Universal Forwarder 10.4.3) | **Monitored Endpoint:** Streams Windows Security event logs and Sysmon telemetry to Wazuh Manager over encrypted port 1514. |
| **Kali Linux** | Kali Linux Rolling | `192.168.100.6` | • Security testing utilities (`nmap`, Hydra, curl) | **Attack Simulation Source:** Executes controlled network reconnaissance and authentication probes to generate trigger alerts. |
| **`ubuntu-p3`** | Ubuntu Server 24.04.5 LTS | `192.168.100.9` | • Splunk Universal Forwarder<br>• OpenSSH Server | **Linux Monitored Endpoint:** Generates Linux authentication, syslog, and audit telemetry. |

---

## 3. Data Pipeline & Transport Mechanism

### 3.1 Selection of Transport Mechanism: Co-located File Stream
In this lab architecture, both the **Wazuh Manager** daemon (`wazuh-analysisd`) and the **Splunk Enterprise** daemon (`splunkd`) are co-located on the same physical VM (`wazuh-server` at `192.168.100.7`). 

Consequently, the **Direct Local File Ingestion** method is used:
1. **Event Generation:** Wazuh Manager continuously evaluates decoded events against its rule library. Whenever an event matches a rule with `level >= 3` (or configured alert threshold), `wazuh-analysisd` appends a single-line JSON object to `/var/ossec/logs/alerts/alerts.json`.
2. **Splunk File Monitor:** Splunk's input engine uses a non-blocking `tail` monitor on `/var/ossec/logs/alerts/alerts.json`.
3. **JSON Extraction:** By utilizing `INDEXED_EXTRACTIONS = json` (or `KV_MODE = json`), Splunk parses every JSON attribute at index time without requiring custom regular expression parsing.
4. **Index Isolation:** Events are written into `index=wazuh`, ensuring strict RBAC boundaries, dedicated search performance, and separate retention tiers from Windows (`index=windows`, `index=sysmon`) and Linux (`index=linux_security`).

### 3.2 Alternative Architectural Patterns Evaluated

| Pattern | Description | Pros | Cons / Trade-offs in Current Lab |
|---|---|---|---|
| **A. Co-located Local Monitor** *(Active in Lab)* | Splunk Enterprise directly monitors `/var/ossec/logs/alerts/alerts.json` on `wazuh-server`. | Zero network overhead, zero latency, resilient to network drops, simple deployment. | Requires proper Linux filesystem permissions between user `splunk` and group `ossec`. |
| **B. Universal Forwarder over TCP 9997** | Splunk Universal Forwarder installed on a standalone Wazuh server forwarding to remote Splunk Indexer. | Ideal for distributed architectures with dedicated Wazuh clusters. | Adds redundant forwarder overhead when Splunk Enterprise is already local on the VM. |
| **C. Wazuh Syslog Output (`<syslog_output>`)** | Wazuh Manager forwards alerts via RFC 3164/5424 syslog over UDP/TCP 514 to Splunk receiver. | Minimal configuration in `ossec.conf`. | Drops complex nested JSON structures, truncates long payload messages, and UDP can lose packets. |
| **D. Splunk HEC (HTTP Event Collector)** | Wazuh custom integration script (`integrator` daemon) posts alerts via REST API. | Highly scalable across cloud environments. | Requires custom Python webhook scripts and continuous HEC token management. |

---

## 4. Wazuh Alert JSON Telemetry Schema

Wazuh alerts emitted to `alerts.json` adhere to a strictly structured schema. Below are the key fields ingested into Splunk:

```json
{
  "timestamp": "2026-09-17T01:15:22.418+0000",
  "rule": {
    "level": 10,
    "description": "Windows logon failure - unknown user name or bad password.",
    "id": "60122",
    "mitre": {
      "id": ["T1110.001", "T1110"],
      "tactic": ["Credential Access"],
      "technique": ["Password Guessing"]
    },
    "frequency": 1,
    "firedtimes": 5,
    "mail": false,
    "groups": ["windows", "windows_security", "authentication_failed"],
    "gdpr": ["IV_35.7.d"],
    "pci_dss": ["10.2.4", "10.2.5"],
    "tsc": ["CC6.1", "CC6.8"]
  },
  "agent": {
    "id": "003",
    "name": "win11-tgt",
    "ip": "192.168.100.8"
  },
  "manager": {
    "name": "wazuh-server"
  },
  "id": "1694913322.849201",
  "decoder": {
    "name": "windows_eventchannel"
  },
  "data": {
    "win": {
      "system": {
        "providerName": "Microsoft-Windows-Security-Auditing",
        "eventID": "4625",
        "channel": "Security",
        "computer": "win11-tgt.lab.local",
        "severityValue": "AUDIT_FAILURE"
      },
      "eventdata": {
        "targetUserName": "administrator",
        "workstationName": "KALI",
        "ipAddress": "192.168.100.6",
        "ipPort": "54210",
        "subStatus": "0xc000006a",
        "status": "0xc000006d",
        "logonType": "3"
      }
    }
  },
  "location": "EventChannel"
}
```

### Ingested Splunk Field Mappings:

| Wazuh JSON Path | Splunk Extracted Field | Data Type | Analytical Usage |
|---|---|---|---|
| `rule.level` | `rule.level` | Integer (0–15) | Alert severity classification and prioritization |
| `rule.id` | `rule.id` | String | Specific detection rule identification |
| `rule.description` | `rule.description` | String | Human-readable alert summary |
| `rule.mitre.id{}` | `rule.mitre.id` | Multivalue String | MITRE ATT&CK technique IDs (e.g. `T1110.001`) |
| `rule.mitre.tactic{}`| `rule.mitre.tactic` | Multivalue String | ATT&CK matrix tactics (e.g. `Credential Access`) |
| `rule.groups{}` | `rule.groups` | Multivalue String | Functional grouping (`authentication_failed`, `sysmon`) |
| `agent.id` | `agent.id` | String | Wazuh agent numeric identifier (`000`, `003`) |
| `agent.name` | `agent.name` | String | Monitored host name (`win11-tgt`, `wazuh-server`) |
| `agent.ip` | `agent.ip` | IP Address | Agent network address (`192.168.100.8`) |
| `data.win.eventdata.ipAddress` | `data.win.eventdata.ipAddress` | IP Address | Attacking source IP (`192.168.100.6`) |
| `data.win.eventdata.targetUserName` | `data.win.eventdata.targetUserName` | String | Targeted user account (`administrator`) |
| `data.srcip` | `data.srcip` | IP Address | Network source IP (Linux / Network logs) |
| `data.dstip` | `data.dstip` | IP Address | Network destination IP |
| `full_log` | `full_log` | String | Raw log snippet decoded by Wazuh analysisd |

---

## 5. Security & Access Control Boundaries

1. **Least-Privilege File Permissions:**
   The Splunk service runs under the dedicated non-root account `splunk`. To enable Splunk to read `/var/ossec/logs/alerts/alerts.json` without exposing root privileges:
   - Group ownership of `/var/ossec/logs/alerts` is assigned to `ossec`.
   - The user `splunk` is added as a member of the secondary group `ossec`.
   - Read permissions are granted via `chmod 640 /var/ossec/logs/alerts/alerts.json`.
2. **Encrypted Ingestion:**
   Agent-to-Manager traffic over port `1514/tcp` is encrypted using AES-256 via Wazuh's proprietary TLS session protocol.
3. **Network Isolation:**
   All communication is confined within VirtualBox NAT Network `192.168.100.0/24`. No telemetry or credentials traverse external or public networks.
