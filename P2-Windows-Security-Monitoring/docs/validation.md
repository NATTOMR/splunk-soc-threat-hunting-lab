# Validation & Testing Guide

> **Project:** Splunk SOC Threat Hunting Lab — P2: Windows Security Monitoring  
> **Purpose:** Document all validation commands that confirm the end-to-end data pipeline is operational.

---

## Validation Checklist

| Check | Component | Expected Result | Status |
|---|---|---|:---:|
| SplunkForwarder service running | Windows endpoint | `Running` | ✅ Verified |
| Sysmon service running | Windows endpoint | `Running` | ✅ Verified |
| Sysmon events in event log | Windows endpoint | 5+ events returned | ✅ Verified |
| Forwarder active forward | Windows endpoint | `192.168.100.7:9997` | ✅ Verified |
| TCP 9997 listening on server | Splunk Enterprise | Socket in `LISTEN` state | ✅ Verified |
| `sysmon` index exists | Splunk Enterprise | Listed in index list | ✅ Verified |
| `windows` index exists | Splunk Enterprise | Listed in index list | ✅ Verified |
| Sysmon events appear in Splunk | Splunk SPL | Count > 0 | ✅ Verified |

---

## Windows Endpoint Validation

Run the following commands on the **Windows 11 endpoint** (`192.168.100.8`) in an elevated PowerShell session.

### 1. Verify SplunkForwarder Service

```powershell
Get-Service SplunkForwarder
```

**Expected output:**

```
Status   Name               DisplayName
------   ----               -----------
Running  SplunkForwarder    SplunkForwarder
```

If `Status` is `Stopped`, start the service:

```powershell
Start-Service SplunkForwarder
```

---

### 2. Verify Sysmon Service

```powershell
Get-Service Sysmon*
```

**Expected output:**

```
Status   Name               DisplayName
------   ----               -----------
Running  Sysmon64           Sysmon64
```

If Sysmon is not running:

```powershell
Start-Service Sysmon64
```

---

### 3. Verify Sysmon Event Log

Confirm that Sysmon is actively writing events to the Windows Event Log:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

**Expected output:** 5 most recent Sysmon events displayed with TimeCreated, Id, and Message columns.

If this returns an error (`errorCode=5 / Access Denied`), the SplunkForwarder service account may lack `Event Log Readers` permission — see [troubleshooting.md](troubleshooting.md#issue-2--errorcode5-on-sysmon-subscription).

---

### 4. Verify Universal Forwarder Active Forward

From the Splunk Universal Forwarder installation directory:

```powershell
cd "C:\Program Files\SplunkUniversalForwarder\bin"
.\splunk.exe list forward-server
```

**Expected output:**

```
Active forwards:
        192.168.100.7:9997
```

If the forward shows `Configured but inactive`:
- Verify Splunk Enterprise is running on `192.168.100.7`
- Verify TCP 9997 is reachable from the endpoint
- Restart the forwarder: `Restart-Service SplunkForwarder`

---

## Splunk Enterprise Server Validation

Run the following commands on the **Ubuntu Splunk Enterprise server** (`192.168.100.7`).

### 5. Verify TCP 9997 is Listening

```bash
sudo ss -lntp | grep ':9997'
```

**Expected output:**

```
LISTEN  0  128  0.0.0.0:9997  0.0.0.0:*  users:(("splunkd",pid=...,fd=...))
```

This confirms Splunk Enterprise is actively listening on all interfaces for incoming forwarder connections.

---

### 6. Verify Splunk Indexes Exist

```bash
sudo -u splunk /opt/splunk/bin/splunk list index
```

**Expected output (partial):**

```
...
sysmon
windows
...
```

Confirm both the `sysmon` and `windows` indexes are listed. If either is missing, the index definitions need to be applied from [`config/indexes.conf`](../config/indexes.conf).

---

## Splunk SPL Validation

Run the following queries from **Splunk Web** (`http://127.0.0.1:18000`) to confirm data is actively flowing into both indexes.

### 7. Verify sysmon Index Contains Data

```spl
index=sysmon earliest=-7d | head 10
```

**Expected result:** 10 events returned from the `sysmon` index.

If no results are returned:
1. Expand the time range: `earliest=-30d`
2. Verify the forwarder active forward (Step 4)
3. Check `_internal` logs for ingestion errors

### 8. Verify windows Index Contains Data

```spl
index=windows earliest=-7d | head 10
```

**Expected result:** 10 events returned from the `windows` index.

### 9. Verify Sysmon EventID Extraction

```spl
index=sysmon earliest=-24h
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| stats count by EventID
| sort EventID
```

**Expected result:** A table of EventID values (1, 3, 5, 22, etc.) with counts confirming rex extraction is functioning correctly.

---

## Automated Verification Script

The [`verify-splunk.ps1`](../scripts/verify-splunk.ps1) script automates the Windows-side validation checks:

```powershell
# Run from an elevated PowerShell session
.\scripts\verify-splunk.ps1
```

This script verifies:
- SplunkForwarder service status
- Sysmon service status
- Sysmon event log accessibility
- inputs.conf and outputs.conf configuration
- Active forward server connection

---

*Last verified: 2026-09-10 | Environment: Windows 11 (192.168.100.8) → Splunk Enterprise 10.4.3 (192.168.100.7)*
