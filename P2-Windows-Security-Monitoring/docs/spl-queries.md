# SPL Threat Hunting Queries

> **Project:** Splunk SOC Threat Hunting Lab — P2: Windows Security Monitoring  
> **Index Coverage:** `index=sysmon` | `index=windows`  
> **Note:** Sysmon events are ingested as raw XML with `renderXml = true`. EventID values are embedded as `<EventID>...</EventID>` inside `_raw` and must be extracted using `rex` before filtering.

---

## Table of Contents

1. [Query 1 — Sysmon Events (All)](#query-1--sysmon-events-all)
2. [Query 2 — Sysmon Process Creation (Event ID 1)](#query-2--sysmon-process-creation-event-id-1)
3. [Query 3 — Sysmon DNS Queries (Event ID 22)](#query-3--sysmon-dns-queries-event-id-22)
4. [Query 4 — Event ID Distribution](#query-4--event-id-distribution)
5. [Query 5 — Top Process Executions](#query-5--top-process-executions)
6. [Query 6 — Process Creation Timeline](#query-6--process-creation-timeline)
7. [Query 7 — PowerShell Activity](#query-7--powershell-activity)

---

## Why rex Is Required for Sysmon EventID

The Universal Forwarder is configured with `renderXml = true`, which stores Sysmon events in XML format. Splunk does not automatically extract `EventCode` from this XML structure. To filter by EventID, extract it first:

```spl
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
```

Do **not** use `EventCode=1` directly against the `sysmon` index — it will return zero results because `EventCode` is not automatically parsed from this XML format.

---

## Query 1 — Sysmon Events (All)

**Purpose:** Baseline count of all Sysmon events within a time window. Used to confirm data is flowing from the Windows endpoint and to assess overall event volume.

**Security Use Case:** Data pipeline health check; confirms the Universal Forwarder is actively forwarding Sysmon telemetry.

```spl
index=sysmon earliest=-24h
```

**Panel:** Sysmon Events (Single Value)  
**Visualization:** Single value / count

---

## Query 2 — Sysmon Process Creation (Event ID 1)

**Purpose:** Count all process creation events recorded by Sysmon in the past 24 hours. Event ID 1 is triggered each time a new process is spawned on the monitored endpoint.

**Security Use Case:** Baseline process activity; detect abnormal process creation spikes that may indicate malware execution, lateral movement, or persistence mechanisms.

```spl
index=sysmon earliest=-24h
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| stats count
```

**Panel:** Sysmon Process Creation Events (Single Value)  
**Visualization:** Single value / count

---

## Query 3 — Sysmon DNS Queries (Event ID 22)

**Purpose:** Count all DNS lookup events recorded by Sysmon. Event ID 22 is generated whenever a process performs a DNS query.

**Security Use Case:** Detect command-and-control (C2) beaconing, domain generation algorithm (DGA) activity, exfiltration over DNS, or suspicious domain lookups by unusual processes.

```spl
index=sysmon earliest=-24h
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=22
| stats count
```

**Panel:** Sysmon DNS Query Events (Single Value)  
**Visualization:** Single value / count

---

## Query 4 — Event ID Distribution

**Purpose:** Show a breakdown of all Sysmon Event IDs observed in the past 24 hours, sorted by Event ID number. Provides a quick overview of which Sysmon event categories are active.

**Security Use Case:** Identify unexpected or newly active event categories; a sudden appearance of Event ID 8 (CreateRemoteThread) or Event ID 10 (Process Access) may indicate injection or credential dumping.

```spl
index=sysmon earliest=-24h
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| stats count by EventID
| sort EventID
```

**Panel:** Sysmon Event ID Distribution  
**Visualization:** Bar chart / table

### Currently Observed Event IDs

| Event ID | Description | Threat Relevance |
|:---:|---|---|
| 1 | Process Create | Execution tracking |
| 2 | File Creation Time Changed | Anti-forensic indicator |
| 3 | Network Connection | C2 / lateral movement detection |
| 4 | Sysmon Service State Changed | Tampering detection |
| 5 | Process Terminated | Execution lifecycle |
| 8 | CreateRemoteThread | Process injection indicator |
| 11 | FileCreate | Dropper / malware persistence |
| 12 | Registry Object Added/Deleted | Persistence via registry |
| 13 | Registry Value Set | Persistence / configuration tampering |
| 22 | DNS Query | C2 beaconing / DGA detection |
| 255 | Sysmon Error | Operational monitoring |

> **Note:** This table reflects Event IDs observed in current lab data. Not all IDs are continuously generated; occurrence depends on endpoint activity.

---

## Query 5 — Top Process Executions

**Purpose:** Identify the top 15 most frequently executed processes on the monitored endpoint. Extracts the process image path and command line from Sysmon Event ID 1 XML data.

**Security Use Case:** Detect unusual or low-frequency processes running in the environment; identify LOLBin abuse (`certutil.exe`, `mshta.exe`, `rundll32.exe`, `wscript.exe`); profile normal baseline process activity.

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

**Panel:** Top Process Executions  
**Visualization:** Bar chart

---

## Query 6 — Process Creation Timeline

**Purpose:** Time-chart process creation events in 1-hour buckets over the past 24 hours. Shows when process activity peaked or deviated from normal patterns.

**Security Use Case:** Detect off-hours execution patterns suggesting automated malware, lateral movement, or scheduled task abuse. Correlate activity spikes with known events or incidents.

```spl
index=sysmon earliest=-24h
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| timechart span=1h count
```

**Panel:** Process Creation Timeline  
**Visualization:** Line chart / column chart

---

## Query 7 — PowerShell Activity

**Purpose:** Enumerate all PowerShell process executions and their associated command-line arguments recorded by Sysmon Event ID 1.

**Security Use Case:** Detect encoded PowerShell commands (`-EncodedCommand`), download-cradle patterns (`IEX`, `Invoke-Expression`, `DownloadString`), AMSI bypass attempts, and unusual PowerShell execution contexts.

```spl
index=sysmon earliest=-24h
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| search Image="*powershell.exe"
| stats count by Image CommandLine
| sort -count
```

**Panel:** PowerShell Activity  
**Visualization:** Table

---

## Extending These Queries

| Technique | Suggested EventID | Extension |
|---|:---:|---|
| LSASS access (credential dumping) | 10 | `search EventID=10` + extract `TargetImage` |
| Remote thread injection | 8 | `search EventID=8` + extract `TargetImage` |
| Network beaconing | 3 | `search EventID=3` + extract `DestinationIp`, `DestinationPort` |
| Suspicious DNS domains | 22 | `search EventID=22` + extract `QueryName` |
| File drops in temp directories | 11 | `search EventID=11` + extract `TargetFilename` |

---

*Last verified: 2026-09-10 | Environment: Windows 11 → Splunk UF 10.4.3 → Splunk Enterprise 10.4.3*
