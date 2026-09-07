# 🎯 Windows Threat Detection Engineering Strategy

> **Document Status:** ⚪ **PLANNED / PENDING VERIFICATION**  
> **Component:** Detection Logic & MITRE ATT&CK Mapping  

---

## Detection Engineering Methodology

This document outlines the planned detection rules, alert thresholds, and MITRE ATT&CK mappings to be engineered using live Windows telemetry.

### Planned Detection Use Cases:

| Rule Name | Target Event IDs | MITRE ATT&CK Tactic & Technique | Target Severity |
|---|---|---|:---:|
| **Excessive Failed Logons (Brute-Force)** | 4625 | Credential Access: Brute Force (`T1110`) | High |
| **User Account Creation in Local Admins** | 4720, 4732 | Persistence: Account Manipulation (`T1098`) | High |
| **Special Privilege Logon Anomaly** | 4672 | Privilege Escalation (`T1078`) | Medium |
| **Suspicious Process Execution (LOLBins)** | 4688 | Defense Evasion: Execution (`T1218`) | High |
| **Encoded PowerShell Command-Line** | 4688 / 4104 | Execution: Command and Scripting Interpreter (`T1059.001`) | High |
| **Persistence via Scheduled Task Creation** | 4698 | Persistence: Scheduled Task/Job (`T1053.005`) | Medium |

*Detection queries will be authored in `queries/` and validated against simulated benign and adversary activity.*
