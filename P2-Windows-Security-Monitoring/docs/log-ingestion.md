# 📥 Windows Log Ingestion & Channel Mapping

> **Document Status:** ⚪ **PLANNED / PENDING VERIFICATION**  
> **Component:** Event Channel Selection & Data Model Ingestion  

---

## Planned Event Channels

This guide will define the Windows Event Log channels collected via `inputs.conf` and mapped to `index=windows`.

### Monitored Event Channels:
- `WinEventLog:Security` — User authentication, account modifications, privilege escalation, object auditing.
- `WinEventLog:System` — System startup, service installations (Event ID 7045), unexpected shutdowns.
- `WinEventLog:Application` — Application crashes, software install events.
- `WinEventLog:Microsoft-Windows-PowerShell/Operational` — Script block execution (Event ID 4104).
- `WinEventLog:Microsoft-Windows-Sysmon/Operational` — (Optional Extension) Deep process execution, network connections, file creation time manipulations.

### Target Field Extractions:
- `EventCode`, `Logon_Type`, `TargetUserName`, `WorkstationName`, `IpAddress`
- `ProcessName`, `CommandLine`, `ParentProcessName`, `NewProcessName`
- `ScriptBlockText`

*Field validation tests and sourcetype extractions will be documented once live logs are received.*
