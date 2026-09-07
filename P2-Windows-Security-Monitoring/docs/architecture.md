# 🏗️ P2 Architecture: Windows 11 to Splunk Pipeline

> **Document Status:** ⚪ **PLANNED / PENDING VERIFICATION**  
> **Component:** Telemetry & Networking Architecture  

---

## Intended Architecture Overview

This document will detail the technical specifications, network flow, and port configurations connecting the Windows 11 endpoint to Splunk Enterprise.

```
Windows 11 Endpoint
        │
        │ Event Telemetry (Security, System, PowerShell, Sysmon)
        ▼
Splunk Universal Forwarder
        │
        │ Encrypted Stream (TCP 9997)
        ▼
Splunk Enterprise (Receiver / Indexer / Search Head)
        │
        ├── SPL Analysis
        ├── Alerts
        └── Dashboard
                │
                ▼
        SOC Analyst Investigation
```

## Planned Technical Specifications

- **Endpoint Node:** Windows 11 Professional / Enterprise (x64)
- **Agent Service:** Splunk Universal Forwarder (`splunkforwarder` service running as LocalSystem or dedicated service account)
- **Transport Protocol:** TCP port `9997` (splunktcp)
- **Target Index:** `index=windows`
- **Network Segmentation:** VirtualBox Host-Only / NAT Network

*Detailed network validation results and verified packet flow will be documented once the receiver and agent are operational.*
