# Troubleshooting Guide

> **Project:** Splunk SOC Threat Hunting Lab — P2: Windows Security Monitoring  
> **Purpose:** Document real issues encountered during lab setup and their verified solutions.

---

## Issue 1 — `EventCode=1` Returns Zero Results in sysmon Index

**Symptom:**

```spl
index=sysmon EventCode=1 | stats count
```

Returns 0 results even though Sysmon events are confirmed to be flowing.

**Cause:**

The Universal Forwarder is configured with `renderXml = true` in `inputs.conf`. This causes Sysmon events to be stored as raw XML strings in the `_raw` field. The `EventCode` field is **not** automatically extracted from this XML format by Splunk's default field extraction for the `WinEventLog` sourcetype.

The EventID is embedded inside the raw XML as:

```xml
<EventID>1</EventID>
```

Splunk does not expose this as `EventCode` for the sysmon index when using XML rendering.

**Solution:**

Use `rex` to extract the EventID from the raw XML before filtering:

```spl
index=sysmon earliest=-24h
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
```

Apply this pattern to all Sysmon event type queries. Do not rely on `EventCode` in the `sysmon` index.

---

## Issue 2 — `errorCode=5` on Sysmon Subscription

**Symptom:**

The Splunk Universal Forwarder fails to subscribe to the `Microsoft-Windows-Sysmon/Operational` event channel. Splunk internal logs show:

```
errorCode=5
```

Or the forwarder service shows `Access Denied` when reading the Sysmon log.

**Cause:**

The `SplunkForwarder` Windows service runs as `NT SERVICE\SplunkForwarder` by default. This built-in service account does not have permission to read the `Microsoft-Windows-Sysmon/Operational` event log channel.

**Solution:**

Add the `NT SERVICE\SplunkForwarder` account to the local `Event Log Readers` security group. Run the following command from an **elevated (Administrator) Command Prompt**:

```cmd
net localgroup "Event Log Readers" "NT SERVICE\SplunkForwarder" /add
```

Then restart the SplunkForwarder service to apply the new group membership:

```powershell
Restart-Service SplunkForwarder
```

Verify the account is now a member:

```powershell
net localgroup "Event Log Readers"
```

After restarting, Sysmon events should begin appearing in `index=sysmon` within 1–2 minutes.

---

## Issue 3 — Forwarder Shows "Configured but Inactive Forwards"

**Symptom:**

Running `splunk list forward-server` on the Windows endpoint shows:

```
Configured but not active forwards:
        192.168.100.7:9997
```

Instead of the expected:

```
Active forwards:
        192.168.100.7:9997
```

**Cause:**

The Splunk Enterprise receiver on `192.168.100.7:9997` was not reachable or not listening at the time the forwarder attempted to connect. Possible reasons:
- Splunk Enterprise service was stopped or not yet started
- UFW firewall on the Ubuntu server was blocking TCP 9997
- The VM was not reachable on the network

**Resolution:**

1. Verify Splunk Enterprise is running on the Ubuntu server:

```bash
sudo systemctl status splunk
# or
sudo -u splunk /opt/splunk/bin/splunk status
```

2. Confirm TCP 9997 is listening:

```bash
sudo ss -lntp | grep ':9997'
```

3. Confirm UFW allows TCP 9997 from the Windows endpoint subnet:

```bash
sudo ufw status
```

Expected rule: `9997/tcp` allowed from `192.168.100.0/24` or `ALLOW 9997`.

4. If the service is running and the port is open, restart the forwarder to re-establish the connection:

```powershell
Restart-Service SplunkForwarder
```

5. Re-check the forward status:

```powershell
cd "C:\Program Files\SplunkUniversalForwarder\bin"
.\splunk.exe list forward-server
```

---

## Issue 4 — Dashboard Search Returns No Data

**Symptom:**

A dashboard panel query such as:

```spl
index=sysmon
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| stats count
```

Returns 0 results or a "No results found" message in the Splunk dashboard.

**Resolution:**

**Step 1:** Confirm the `sysmon` index contains any events at all by using a broad time range:

```spl
index=sysmon earliest=-7d | head 5
```

If this returns results, the issue is with the time window selected in the dashboard. Check the dashboard time picker and adjust to match the available data range.

**Step 2:** If `earliest=-7d` also returns nothing, verify the forwarder is actively sending data:

```powershell
# On Windows endpoint
.\splunk.exe list forward-server
Get-Service SplunkForwarder
```

**Step 3:** If the dashboard panel itself appears broken, test the underlying SPL directly in the **Search & Reporting** app before referencing it from the dashboard.

**Step 4:** Dashboard panels use the global time range picker. If the time range is set to "Last 15 minutes" and no events arrived in that window, panels will appear empty. Set the time picker to a wider range such as **Last 24 hours** or **Last 7 days** to confirm data availability.

---

## Quick Reference: Common Commands

| Problem | Command |
|---|---|
| Check forwarder service | `Get-Service SplunkForwarder` |
| Check Sysmon service | `Get-Service Sysmon*` |
| Restart forwarder | `Restart-Service SplunkForwarder` |
| Check active forwards | `.\splunk.exe list forward-server` |
| Confirm 9997 listening (Ubuntu) | `sudo ss -lntp \| grep ':9997'` |
| Check UFW rules (Ubuntu) | `sudo ufw status` |
| Verify Splunk indexes | `sudo -u splunk /opt/splunk/bin/splunk list index` |
| Verify Sysmon event log (Windows) | `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5` |

---

*Last updated: 2026-09-10 | Environment: Windows 11 (192.168.100.8) → Splunk Enterprise 10.4.3 (192.168.100.7)*
