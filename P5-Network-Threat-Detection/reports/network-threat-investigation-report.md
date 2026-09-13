# SOC Incident Investigation Report: Network Reconnaissance & Threat Detection

> **Incident ID:** INC-2026-P5-001  
> **Investigation Title:** Internal Network Reconnaissance, Multi-Port Scanning, and Outbound C2 Probing  
> **Investigating Analyst:** Natto Chakma  
> **Date:** September 14, 2026  
> **Target Asset:** Windows 11 Enterprise (`192.168.100.8`)  
> **Originating Attacker IP:** Kali Linux (`192.168.100.6`)  
> **Secondary Internal Source:** Host / Gateway (`192.168.100.1`)  
> **Severity:** **HIGH**  
> **Incident Status:** Contained / Documented  

---

## 1. Executive Summary

During real-time threat monitoring within the Splunk SOC laboratory, security alerts were triggered for network reconnaissance and anomalous connection velocity against the Windows 11 endpoint (`192.168.100.8`). Telemetry ingested via the **Splunk Universal Forwarder** from **Sysmon Event ID 3 (NetworkConnect)** identified a multi-stage attack lifecycle:

1. **Active Reconnaissance & Port Scanning (T1046 / T1595.002):** The Kali Linux attacker (`192.168.100.6`) executed a vertical port scan against Windows 11, repeatedly probing listening services on TCP ports `22` (`sshd.exe`) and `3389` (`svchost.exe` / Remote Desktop).
2. **Suspicious / Non-Standard Port Communication (T1571):** Telemetry flagged **26 connection attempts** to uncommon and non-standard high ports, notably destination port `8000` initiated by `powershell.exe`, simulating command-and-control (C2) beaconing and data staging.
3. **High-Volume Connection Burst (T1498):** A rapid velocity spike exceeding **50 connections per 5-minute bucket** was observed, driving total endpoint connection volume to **116 events**.

All activities were captured, extracted, and correlated in real time on the operational **P5 — Network Threat Detection & Monitoring** SOC dashboard.

---

## 2. Incident Scope & Telemetry

| Parameter | Observed Evidence |
|---|---|
| **Monitored Victim Endpoint** | Windows 11 (`192.168.100.8`) |
| **Telemetry Source** | `Microsoft-Windows-Sysmon/Operational` (Event ID 3) |
| **Splunk Index** | `index=sysmon` |
| **Primary Attacker Host** | `192.168.100.6` (Kali Linux) |
| **Gateway / Management Host** | `192.168.100.1` |
| **Total Ingested Connections** | **116** events |
| **Distinct Probed Ports** | **6** (`22`, `80`, `443`, `3389`, `8000`, `47001`) |
| **Suspicious / Non-Standard Hits** | **26** events (Dest Port `8000` via `powershell.exe`) |
| **Peak Connection Velocity** | ~50 connections / 5m interval |
| **Targeted Executables** | `sshd.exe`, `svchost.exe`, `powershell.exe` |

---

## 3. Telemetry Evidence & Field Extraction

Because Sysmon logs on Windows 11 are collected with `renderXml = true`, raw XML payloads were parsed using calibrated regular expressions matching the Windows Event XML schema:

```spl
index=sysmon earliest=-24h
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=3
| rex field=_raw "<Data Name=['\"]SourceIp['\"]>(?<src_ip>[^<]+)</Data>"
| rex field=_raw "<Data Name=['\"]DestinationIp['\"]>(?<dest_ip>[^<]+)</Data>"
| rex field=_raw "<Data Name=['\"]DestinationPort['\"]>(?<dest_port>\d+)</Data>"
| rex field=_raw "<Data Name=['\"]Image['\"]>(?<process_image>[^<]+)</Data>"
| table _time, src_ip, dest_ip, dest_port, process_image
| sort - _time
```

### Forensic Event Stream Sample
```text
2026-09-14 01:18:31.317  192.168.100.8  192.168.100.7  8000  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
2026-09-14 01:18:31.314  192.168.100.8  192.168.100.7  8000  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
2026-09-14 01:18:31.304  192.168.100.8  192.168.100.7  8000  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
2026-09-14 01:00:00.275  192.168.100.6  192.168.100.8  3389  C:\Windows\System32\svchost.exe
2026-09-14 00:59:58.522  192.168.100.6  192.168.100.8  22    C:\Windows\System32\OpenSSH\sshd.exe
2026-09-14 00:56:25.881  192.168.100.6  192.168.100.8  22    C:\Windows\System32\OpenSSH\sshd.exe
```

---

## 4. Operational Dashboard Verification

The detected activity was visualized on the **"P5 — Network Threat Detection & Monitoring"** SOC dashboard:

![P5 Dashboard](../screenshots/p5-01-network-threat-monitoring-dashboard.png)

### Dashboard Metrics at Triage:
- **Total Network Connections:** `116` (Sysmon Event ID 3)
- **Scanned / Probed Ports (Distinct):** `6` (Triggered High-Severity Red Alert)
- **Suspicious / Non-Standard Ports:** `26` (Triggered Red Alert)
- **Port Scan Alert Table:** Identified `192.168.100.6` with 41 total probes targeting ports `22` and `3389`.
- **Top Probed Ports:** Port `22` (approx. 50), Port `8000` (approx. 28), Port `3389` (approx. 28).

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Application |
|---|---|:---:|---|
| **Reconnaissance** | Active Scanning: Port Scanning | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Systematic SYN/TCP probes against ports 22 and 3389 |
| **Discovery** | Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Attacker enumeration of listening services on Windows 11 endpoint |
| **Command and Control** | Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | Outbound high-volume burst over TCP 8000 originating from `powershell.exe` |
| **Execution** | Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Automated socket connections initiated through PowerShell |
| **Impact** | Network Denial of Service | [T1498](https://attack.mitre.org/techniques/T1498/) | Velocity flood spike testing endpoint connection rate limits |

---

## 6. Analyst Recommendations & Remediation

1. **Host-Based Firewall Hardening (Windows Defender Firewall):**
   * Restrict inbound SSH (`22`) and RDP (`3389`) strictly to authorized management IP (`192.168.100.1`):
     ```powershell
     Set-NetFirewallRule -DisplayGroup "Remote Desktop" -RemoteAddress 192.168.100.1
     Set-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -RemoteAddress 192.168.100.1
     ```
2. **Restrict PowerShell Outbound Socket Connections:**
   * Implement AppLocker or Software Restriction Policies to prevent unauthorized script-based outbound socket calls.
   * Enable PowerShell Constrained Language Mode (CLM) for standard user sessions.
3. **Deploy Splunk Real-Time Correlation Alerts:**
   * Operationalize [`port-scan-detection.spl`](../queries/port-scan-detection.spl) as an automated alert with a 5-minute cron schedule:
     ```spl
     index=sysmon earliest=-10m
     | rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
     | search EventID=3
     | rex field=_raw "<Data Name=['\"]SourceIp['\"]>(?<src_ip>[^<]+)</Data>"
     | rex field=_raw "<Data Name=['\"]DestinationIp['\"]>(?<dest_ip>[^<]+)</Data>"
     | rex field=_raw "<Data Name=['\"]DestinationPort['\"]>(?<dest_port>\d+)</Data>"
     | stats dc(dest_port) as scanned_ports by src_ip, dest_ip
     | where scanned_ports >= 2
     ```
4. **Attacker Host Isolation:**
   * Add active-response or static drop rules on internal routing devices to quarantine `192.168.100.6` following reconnaissance alerts.
