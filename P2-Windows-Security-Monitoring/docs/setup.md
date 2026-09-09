# Splunk SOC Lab Setup Guide (P2)

This document provides a simple, direct reference for the working Splunk SOC laboratory setup.

---

## 1. Lab Architecture & Network Parameters

The lab consists of two virtual machines connected over an isolated VirtualBox NAT Network (`192.168.100.0/24`):

```text
Windows 11 Endpoint (192.168.100.8)
  │
  ├── Sysmon (Driver & Service)
  │     └── Generates deep process, file, and network telemetry
  │
  ├── Windows Event Logs
  │     └── Security, System, Application, and Sysmon/Operational channels
  │
  └── Splunk Universal Forwarder 10.4.3
        ├── Service: SplunkForwarder (runs under NT SERVICE\SplunkForwarder)
        ├── Group: Event Log Readers
        └── Configuration:
              ├── inputs.conf  -> Ingests event channels with renderXml = true
              └── outputs.conf -> Routes telemetry over TCP 9997
                    │
                    │ Ingestion Stream (TCP 9997)
                    ▼
Ubuntu 24.04 Server (192.168.100.7)
  │
  └── Splunk Enterprise 10.4.3
        ├── Receiving Port : TCP 9997 (splunktcp)
        ├── Web UI Port    : TCP 8000 (accessible on host via port 18000)
        ├── Indexes        :
        │     ├── index=windows (Security, System, and Application logs)
        │     └── index=sysmon  (Sysmon operational telemetry)
        └── Analytics      : SPL search, detection engineering, dashboards
```

### Key Configuration Parameters:
- **Windows IP:** `192.168.100.8` (Windows 11 Endpoint)
- **Ubuntu IP:** `192.168.100.7` (Ubuntu Splunk Enterprise Server)
- **Forwarding / Receiving Port:** `TCP 9997`
- **Splunk Web Interface:** `http://192.168.100.7:8000` (or `http://127.0.0.1:18000` via VirtualBox port forwarding)
- **Endpoint Agent:** Splunk Universal Forwarder 10.4.3 (Windows Service: `SplunkForwarder`, Account: `NT SERVICE\SplunkForwarder`)
- **Telemetry Sources:**
  - **Sysmon:** `Microsoft-Windows-Sysmon/Operational`
  - **Windows OS Logs:** `Security`, `System`, `Application`
- **Target Splunk Indexes:**
  - `windows` — Windows OS event channels
  - `sysmon` — Sysmon operational telemetry

---

## 2. Basic Startup Procedure

Follow this sequence to start the lab:

1. **Start Ubuntu Splunk Enterprise VM (`192.168.100.7`):**
   - Power on the VM.
   - Check if Splunk Enterprise is running:
     ```bash
     sudo -u splunk /opt/splunk/bin/splunk status
     ```
   - If stopped, start it:
     ```bash
     sudo -u splunk /opt/splunk/bin/splunk start
     ```
   - Verify that TCP port 9997 is listening:
     ```bash
     ss -lntp | grep 9997
     ```

2. **Start Windows 11 VM (`192.168.100.8`):**
   - Power on the VM.
   - Open PowerShell as Administrator and verify/start the services:
     ```powershell
     Get-Service -Name SplunkForwarder, Sysmon*
     Start-Service SplunkForwarder -ErrorAction SilentlyContinue
     ```

3. **Open Splunk Web:**
   - On the host browser, navigate to:
     ```text
     http://127.0.0.1:18000
     ```
     (or `http://192.168.100.7:8000` from within the lab network)

---

## 3. Basic Verification Procedure

### Method A: Automated Verification Script
On the Windows 11 endpoint, run the read-only verification script from PowerShell:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\verify-splunk.ps1
```
This script checks:
- `SplunkForwarder` service status
- `Sysmon` service status
- `Event Log Readers` group membership
- `inputs.conf` channel definitions
- `outputs.conf` receiver target
- TCP connectivity to `192.168.100.7:9997`

### Method B: Splunk Web Searches
Log into Splunk Web (`http://127.0.0.1:18000`), open **Search & Reporting**, and run these basic validation queries:

1. **Verify Sysmon events are arriving:**
   ```spl
   index=sysmon earliest=-15m
   ```

2. **Verify Windows OS security and system events:**
   ```spl
   index=windows earliest=-15m
   ```

3. **Verify Sysmon process creation tracking (EventCode 1):**
   ```spl
   index=sysmon EventCode=1 earliest=-15m
   ```
