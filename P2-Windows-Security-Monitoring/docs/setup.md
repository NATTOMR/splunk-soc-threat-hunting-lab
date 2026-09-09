# 🛠️ Splunk SOC Lab Setup & Operations Guide

Complete step-by-step architectural reference, deployment guide, operational runbook, verification procedures, and troubleshooting catalog for **Project P2: Windows Security Monitoring**.

---

## 1. End-to-End Architecture & Data Flow

The telemetry ingestion pipeline routes host-level activity from the Windows 11 endpoint directly into the central Splunk Enterprise indexer:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        WINDOWS 11 WORKSTATION                         │
│                           (192.168.100.8)                              │
│                                                                        │
│   [System Activity]                                                    │
│         │                                                              │
│         ▼                                                              │
│   ┌───────────┐      ┌──────────────────────────────────────────────┐  │
│   │  Sysmon   │ ───► │ Windows Event Channels                       │  │
│   │ (Driver)  │      │ - Security                                   │  │
│   └───────────┘      │ - System                                     │  │
│                      │ - Application                                │  │
│                      │ - Microsoft-Windows-Sysmon/Operational       │  │
│                      └──────────────────────┬───────────────────────┘  │
│                                             │                          │
│                                             ▼                          │
│                      ┌──────────────────────────────────────────────┐  │
│                      │ Splunk Universal Forwarder 10.4.3            │  │
│                      │ - Service: NT SERVICE\SplunkForwarder        │  │
│                      │ - Group: Event Log Readers                   │  │
│                      │ - inputs.conf (renderXml = true)             │  │
│                      │ - outputs.conf                               │  │
│                      └──────────────────────┬───────────────────────┘  │
└─────────────────────────────────────────────┼──────────────────────────┘
                                              │
                                              │ Encrypted/Raw Telemetry Stream
                                              │ TCP Port 9997 (splunktcp)
                                              ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      UBUNTU SPLUNK ENTERPRISE                          │
│                           (192.168.100.7)                              │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │ Splunk Ingestion Receiver: TCP 9997                            │   │
│   └─────────────────────────────┬──────────────────────────────────┘   │
│                                 │                                      │
│                                 ▼                                      │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │ Splunk Indexing Pipeline (indexes.conf)                        │   │
│   │  ├── index=windows (Security, System, Application)             │   │
│   │  └── index=sysmon  (Sysmon Operational Events)                 │   │
│   └─────────────────────────────┬──────────────────────────────────┘   │
│                                 │                                      │
│                                 ▼                                      │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │ Splunk Analytics & Detection Layer (Splunk Web: 18000 / 8000)   │   │
│   │  ├── SPL Threat Hunting Searches                               │   │
│   │  ├── Detection Rules & Alerts                                  │   │
│   │  └── Windows SOC Operations Dashboard                          │   │
│   └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

### Architecture Breakdown:
1. **Sysmon (System Monitor):** Kernel driver and background service monitoring deep endpoint behavior (process execution, network connections, file integrity, process injection).
2. **Windows Event Logs:** Sysmon and OS security events are recorded in local Windows event logs (`Security`, `System`, `Application`, `Microsoft-Windows-Sysmon/Operational`).
3. **Splunk Universal Forwarder:** Runs as a dedicated service account (`NT SERVICE\SplunkForwarder`), member of `Event Log Readers`. Reads event log channels using `renderXml = true` for high-fidelity parsing.
4. **TCP 9997 Ingestion Transport:** Forwarder establishes a persistent TCP stream to `192.168.100.7:9997`.
5. **Splunk Enterprise Receiver:** Ingests the TCP stream through `splunktcp://9997` configured in Splunk Enterprise.
6. **Dedicated Indexes:** Ingested streams are separated into `index=windows` and `index=sysmon` to optimize search performance and retention policies.
7. **Searches & Detections:** SOC analysts run SPL queries, trigger high-fidelity alerts, and visualize endpoint telemetry on dashboards.

---

## 2. Lab Quick-Start Runbook

Follow these sequential steps every time you power on the lab environment:

### Step 1: Start Ubuntu Splunk Enterprise VM
1. Power on the Ubuntu 24.04 VM (`192.168.100.7`).
2. Log in and verify that Splunk Enterprise is active:
   ```bash
   sudo -u splunk /opt/splunk/bin/splunk status
   ```
   If stopped, start it:
   ```bash
   sudo -u splunk /opt/splunk/bin/splunk start
   ```

### Step 2: Verify Receiver 9997 is Listening
Confirm that the Splunk receiver port `9997` is actively listening and bound to `splunkd`:
```bash
ss -lntp | grep 9997
```
*Expected output: `LISTEN 0 128 0.0.0.0:9997 ... users:(("splunkd",pid=...,fd=...))`*

### Step 3: Start Windows SplunkForwarder
1. Power on the Windows 11 VM (`192.168.100.8`).
2. Open PowerShell as Administrator and verify/start the forwarder service:
   ```powershell
   Get-Service SplunkForwarder
   Start-Service SplunkForwarder -ErrorAction SilentlyContinue
   ```

### Step 4: Verify Forwarding & Pipeline Health
Run the automated verification script on Windows 11:
```powershell
cd "E:\SOC projects\splunk-soc-threat-hunting-lab\P2-Windows-Security-Monitoring\scripts"
powershell.exe -ExecutionPolicy Bypass -File .\verify-splunk.ps1
```
*Ensure all 6 checks (`SplunkForwarder`, `Sysmon`, `Event Log Readers`, `inputs.conf`, `outputs.conf`, `TCP 9997`) report `[PASS]`.*

### Step 5: Open Splunk Web
Access the Splunk Enterprise Web UI from your host machine browser:
```text
http://127.0.0.1:18000
```
*(Or directly from within the lab subnet at `http://192.168.100.7:8000`)*

### Step 6: Run First Verification Search
Navigate to **Apps > Search & Reporting** and execute:
```spl
index=sysmon earliest=-15m
```
*Verify that live Sysmon events are actively appearing in real time.*

---

## 3. Verification Searches

Once the forwarder is active, execute these core verification searches to confirm full telemetry coverage:

### Search 1: Verify Sysmon Telemetry Ingestion
Confirms that the Universal Forwarder is streaming Sysmon operational events and Splunk is routing them to `index=sysmon`.
```spl
index=sysmon earliest=-15m
```
*Expected Result: Events from source `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` displaying fields such as `EventCode`, `Image`, `ProcessId`, and `UtcTime`.*

### Search 2: Verify Core Windows Security & System Logs
Confirms that standard Windows event channels (`Security`, `System`, `Application`) are arriving in `index=windows`.
```spl
index=windows earliest=-15m
```
*Expected Result: Security logs (e.g., EventCode 4624, 4672, 4688) and System events (EventCode 7045).*

### Search 3: Verify Sysmon Process Creation (EventCode = 1)
Validates that command-line tracking, hashes, parent-child process relationships, and executable paths are captured for threat detection.
```spl
index=sysmon EventCode=1 earliest=-15m
```
*Expected Result: Detailed process creation records displaying `CommandLine`, `ParentCommandLine`, `CurrentDirectory`, `Hashes` (SHA256/MD5), and `User`.*

---

## 4. Troubleshooting Catalog

Use this diagnostic matrix if events do not appear as expected:

### 1. Forwarder Service Not Running
- **Symptom:** `verify-splunk.ps1` reports `[FAIL]` or `[WARN]` on SplunkForwarder service.
- **Root Causes:**
  - Service disabled or stopped.
  - Insufficient account permissions to start service.
- **Remediation:**
  1. Check Windows service manager:
     ```powershell
     Get-Service SplunkForwarder | Select-Object -Property Status, StartType
     ```
  2. Start service and set to Automatic:
     ```powershell
     Set-Service -Name SplunkForwarder -StartupType Automatic
     Start-Service -Name SplunkForwarder
     ```
  3. Review forwarder internal logs:
     `C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log`

### 2. TCP 9997 Unavailable
- **Symptom:** `verify-splunk.ps1` reports `[FAIL] Unable to connect to 192.168.100.7:9997`.
- **Root Causes:**
  - Ubuntu host UFW firewall blocking port 9997.
  - NAT Network adapter misconfigured in VirtualBox.
- **Remediation:**
  1. Test network reachability from Windows:
     ```powershell
     Test-NetConnection -ComputerName 192.168.100.7 -Port 9997
     ```
  2. On Ubuntu, verify UFW firewall allows port 9997 from the lab subnet:
     ```bash
     sudo ufw status verbose
     sudo ufw allow from 192.168.100.0/24 to any port 9997 proto tcp
     ```

### 3. Splunk Enterprise Receiver Not Listening
- **Symptom:** TCP connection refused even with firewall disabled.
- **Root Causes:**
  - Splunk receiver listening port was not enabled on Splunk Enterprise.
- **Remediation:**
  1. Check listening sockets on Ubuntu:
     ```bash
     ss -lntp | grep 9997
     ```
  2. Enable listening port via Splunk CLI:
     ```bash
     sudo -u splunk /opt/splunk/bin/splunk enable listen 9997 -auth <ADMIN_USERNAME>:<ADMIN_PASSWORD>
     ```
  3. Confirm `/opt/splunk/etc/system/local/inputs.conf` contains:
     ```ini
     [splunktcp://9997]
     disabled = 0
     ```

### 4. Sysmon Events Not Arriving
- **Symptom:** `index=windows` receives events, but `index=sysmon` is empty.
- **Root Causes:**
  - `Sysmon` / `Sysmon64` driver is stopped or uninstalled.
  - `inputs.conf` lacks the `[WinEventLog://Microsoft-Windows-Sysmon/Operational]` stanza.
  - Channel name typo or `disabled = 1`.
- **Remediation:**
  1. Verify Sysmon service:
     ```powershell
     Get-Service -Name Sysmon*
     ```
  2. Verify Sysmon event generation locally:
     ```powershell
     Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
     ```
  3. Ensure `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf` has:
     ```ini
     [WinEventLog://Microsoft-Windows-Sysmon/Operational]
     disabled = 0
     index = sysmon
     renderXml = true
     ```
  4. Run `.\configure-forwarder.ps1 -ForceRestart` to apply corrections.

### 5. Event Log Readers Permission Errors
- **Symptom:** `splunkd.log` shows `Access is denied` or `EvtSubscribe failed` when attempting to read Security or Sysmon channels.
- **Root Causes:**
  - Splunk forwarder runs under a non-SYSTEM service account (`NT SERVICE\SplunkForwarder`) that lacks permissions to read Windows event channels.
- **Remediation:**
  1. Add the service account to the built-in `Event Log Readers` security group:
     ```cmd
     net localgroup "Event Log Readers" "NT SERVICE\SplunkForwarder" /add
     ```
  2. Restart the forwarder service:
     ```powershell
     Restart-Service SplunkForwarder
     ```

### 6. outputs.conf Misconfiguration
- **Symptom:** Events are read locally but never forwarded (`splunkd.log` shows `TcpOutputProc - Connection to ... failed`).
- **Root Causes:**
  - Incorrect server IP, missing port, or wrong `defaultGroup` name.
- **Remediation:**
  1. Inspect `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`.
  2. Ensure it strictly defines:
     ```ini
     [tcpout]
     defaultGroup = splunk-enterprise

     [tcpout:splunk-enterprise]
     server = 192.168.100.7:9997
     ```
  3. Run `.\configure-forwarder.ps1 -ForceRestart`.

### 7. Incorrect Index Designation
- **Symptom:** Events arrive in `main` or default index instead of `windows` or `sysmon`.
- **Root Causes:**
  - Target index not created on Splunk Enterprise or missing `index = <name>` directive in `inputs.conf`.
- **Remediation:**
  1. On Ubuntu Splunk Enterprise, verify indexes exist:
     ```bash
     sudo -u splunk /opt/splunk/bin/splunk list index
     ```
  2. Create missing index if needed:
     ```bash
     sudo -u splunk /opt/splunk/bin/splunk add index sysmon
     sudo -u splunk /opt/splunk/bin/splunk add index windows
     ```
  3. Check Windows `inputs.conf` and confirm `index = windows` and `index = sysmon` are explicitly set under each stanza.

---

## 5. Security & Maintenance Best Practices

- **Zero Hardcoded Secrets:** Never commit plain-text credentials, tokens, or private certificates into version control. Use placeholders and environment parameters.
- **Least Privilege:** Always run SplunkForwarder under `NT SERVICE\SplunkForwarder` with `Event Log Readers` membership rather than a full local administrator.
- **Idempotent Automation:** Always deploy configuration changes through `configure-forwarder.ps1` to prevent accidental overwrites or duplicate stanzas.
- **Regular Verification:** Run `verify-splunk.ps1` after any VM reboot or network reconfiguration to confirm end-to-end telemetry flow.
