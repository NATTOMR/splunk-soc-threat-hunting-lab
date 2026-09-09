# SOC Threat Hunting Dashboard

> **Project:** Splunk SOC Threat Hunting Lab — P2: Windows Security Monitoring  
> **Dashboard Title:** SOC Threat Hunting Dashboard  
> **Description:** SOC threat hunting dashboard for monitoring Windows Security, Sysmon, authentication activity, process creation, network activity, and suspicious behavior.

---

## Overview

The **SOC Threat Hunting Dashboard** is the primary analyst interface for this lab. It provides real-time and historical visibility into Sysmon telemetry and Windows Security event data collected from the monitored Windows 11 endpoint.

All panels use the **global time range picker**. Dashboard values change dynamically based on the selected time window. Values shown in examples below are representative snapshots from a live lab session and are not fixed figures.

### Example Snapshot (Lab Session — 2026-09-10)

| Panel | Value |
|---|---|
| Total Security Events | 8,638 |
| Sysmon Events | 8,406 |
| Sysmon Process Creation Events | 3,994 |
| Sysmon DNS Query Events | 100 |

> These values reflect a point-in-time snapshot. Actual values vary based on the selected time range and ongoing endpoint activity.

---

## Dashboard Panels

### Panel 1 — Total Security Events

| Attribute | Detail |
|---|---|
| **Panel Name** | Total Security Events |
| **Purpose** | Display the total number of Windows Security events ingested from `index=windows` in the selected time window. |
| **Visualization** | Single value |
| **Security Use Case** | Baseline monitoring of overall Windows Security event volume. A sudden spike may indicate brute-force attacks, mass account activity, or privilege escalation attempts. |

**SPL Query:**

```spl
index=windows earliest=-24h
| stats count
```

---

### Panel 2 — Sysmon Events

| Attribute | Detail |
|---|---|
| **Panel Name** | Sysmon Events |
| **Purpose** | Display the total count of all Sysmon events received in the selected time window, regardless of Event ID. |
| **Visualization** | Single value |
| **Security Use Case** | Overall Sysmon telemetry health indicator. Confirms data is flowing from the Windows endpoint. An unexpected drop to zero may indicate the forwarder stopped or Sysmon was disabled. |

**SPL Query:**

```spl
index=sysmon earliest=-24h
```

---

### Panel 3 — Sysmon Process Creation Events

| Attribute | Detail |
|---|---|
| **Panel Name** | Sysmon Process Creation Events |
| **Purpose** | Count all Sysmon Event ID 1 (Process Create) events in the time window. |
| **Visualization** | Single value |
| **Security Use Case** | Track process execution volume as a key behavioral indicator. Malware, scripts, and living-off-the-land (LOLBin) techniques all generate process creation events. |

**SPL Query:**

```spl
index=sysmon earliest=-24h
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| stats count
```

> **Note:** `rex` extraction is required because Sysmon events are ingested as raw XML (`renderXml = true`). `EventCode=1` does not work directly in the `sysmon` index.

---

### Panel 4 — Sysmon DNS Query Events

| Attribute | Detail |
|---|---|
| **Panel Name** | Sysmon DNS Query Events |
| **Purpose** | Count all Sysmon Event ID 22 (DNS Query) events. |
| **Visualization** | Single value |
| **Security Use Case** | DNS is a common exfiltration and C2 communication channel. Elevated DNS query counts from unusual processes may indicate beaconing, data exfiltration over DNS, or domain generation algorithm (DGA) activity. |

**SPL Query:**

```spl
index=sysmon earliest=-24h
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=22
| stats count
```

---

### Panel 5 — Sysmon Event ID Distribution

| Attribute | Detail |
|---|---|
| **Panel Name** | Sysmon Event ID Distribution |
| **Purpose** | Show a breakdown of all Sysmon events by Event ID, sorted numerically. |
| **Visualization** | Bar chart or table |
| **Security Use Case** | Provides a holistic view of which Sysmon event categories are active. Threat hunters use this to quickly identify whether unusual event types (e.g., Event ID 8 — CreateRemoteThread, Event ID 10 — ProcessAccess) have appeared. |

**SPL Query:**

```spl
index=sysmon earliest=-24h
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| stats count by EventID
| sort EventID
```

---

### Panel 6 — Top Process Executions

| Attribute | Detail |
|---|---|
| **Panel Name** | Top Process Executions |
| **Purpose** | List the top 15 most frequently executed process images on the monitored endpoint, with execution count. |
| **Visualization** | Bar chart |
| **Security Use Case** | Profiling normal process activity and identifying anomalies. Rarely-executed binaries in high-privilege directories, or known LOLBins (`certutil.exe`, `mshta.exe`, `wscript.exe`, `rundll32.exe`) appearing in this list warrant investigation. |

**SPL Query:**

```spl
index=sysmon earliest=-24h
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Data Name='Image'>(?<process_image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<command_line>[^<]*)</Data>"
| search process_image=*
| stats count as executions by process_image
| sort - executions
| head 15
```

---

## Time Range Behavior

All panels in the dashboard inherit the **global time range picker** configured at the top of the dashboard. Changing the global time range (e.g., from "Last 24 hours" to "Last 7 days") updates all panels simultaneously.

This means:
- Values are **not static** — they reflect the selected window
- During periods of low endpoint activity (e.g., the VM is powered off), counts will be lower
- Best practice: use **Last 24 hours** for daily monitoring or **Last 7 days** for threat hunting

---

## Accessing the Dashboard

1. Open Splunk Web: `http://127.0.0.1:18000` (host-mapped port)
2. Log in with admin credentials
3. Navigate to: **Dashboards → SOC Threat Hunting Dashboard**

---

## Screenshot References

| Figure | File | Description |
|---|---|---|
| Figure 1 | [`Screenshot 2026-09-10 031815.png`](../screenshots/Screenshot%202026-09-10%20031815.png) | SOC Threat Hunting Dashboard — full view |

---

*Last updated: 2026-09-10 | Dashboard verified on Splunk Enterprise 10.4.3*
