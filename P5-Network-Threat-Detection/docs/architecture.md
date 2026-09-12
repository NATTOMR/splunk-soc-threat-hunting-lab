# P5 Architecture — Network Security Telemetry Pipeline

> **Project:** P5 — Network Threat Detection with Splunk  
> **Status:** Architecture Defined (Ingestion Verification Scheduled in P5.1)

---

## 1. Network Telemetry Architecture

Project P5 instruments endpoint and perimeter network sensors across the virtual lab to capture and analyze connection attempts, port probes, and traffic anomalies.

```mermaid
flowchart TD
    subgraph Sensors["Network Telemetry Providers"]
        direction TB
        W11["Windows 11 Endpoint\n(192.168.100.8)\nSysmon Event ID 3 (NetworkConnect)"]
        LNX["Ubuntu Linux Endpoint\n(192.168.100.9)\nUFW Firewall & iptables logs"]
    end

    subgraph Forwarding["Log Transport (Splunk UF 10.4.3)"]
        UF_W["Windows Forwarder\nTCP 9997 (index=sysmon)"]
        UF_L["Linux Forwarder\nTCP 9997 (index=linux_security)"]
    end

    subgraph SIEM["Splunk Enterprise Server (192.168.100.7)"]
        direction TB
        REC["TCP 9997 Receiver Port"]
        
        subgraph Engine["Detection & Analytics Engine"]
            D1["Port Scan Detector (dc(dest_port))"]
            D2["Connection Burst Analyzer"]
            D3["Uncommon Port Filter"]
            D4["Recon-to-Process Correlator"]
        end

        subgraph Visuals["SOC Operations Console"]
            DASH["Network Threat SOC Dashboard"]
            ALERT["Splunk Alert Notifications"]
        end
    end

    W11 --> UF_W
    LNX --> UF_L
    UF_W --> REC
    UF_L --> REC
    REC --> Engine
    Engine --> Visuals
```

---

## 2. Key Data Sources & Schemas

### Windows Sysmon Event ID 3 (NetworkConnect)
- **Index:** `sysmon`
- **Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Fields:** `SourceIp`, `DestinationIp`, `DestinationPort`, `Protocol`, `Image` (Process), `User`

### Linux Firewall Logs (UFW / iptables)
- **Index:** `linux_security`
- **Sourcetype:** `syslog` / `ufw`
- **Fields:** `SRC`, `DST`, `DPT` (Destination Port), `PROTO`
