# 🔍 Windows Security Incident Investigation Playbook

> **Document Status:** ⚪ **PLANNED / PENDING VERIFICATION**  
> **Component:** SOC Triage & Root Cause Analysis  

---

## Planned Investigation Playbooks

This guide will outline the step-by-step SOC Tier 1/Tier 2 investigative workflows for triaging alerts generated from the Windows 11 endpoint.

### Triage Workflows to Document:
1. **Investigating Logon Failures (Event 4625):**
   - Extract `TargetUserName`, `WorkstationName`, `IpAddress`, `Status`, `SubStatus`.
   - Distinguish network logons (Type 3) vs interactive (Type 2) vs RDP (Type 10).
   - Correlate with subsequent Event 4624 (account compromise triage).

2. **Investigating Process Anomalies (Event 4688):**
   - Trace parent process hierarchy (`ParentProcessName` → `NewProcessName`).
   - Analyze command-line arguments for obfuscation, URLs, download flags, or encoded strings.
   - Inspect user context executing the binary (`SubjectUserName`).

3. **Investigating Account Escalation (Events 4720 & 4732):**
   - Determine who created the account (`SubjectUserName`) and when.
   - Trace subsequent actions performed by the newly created account.

*Case studies and simulated incident timelines will be recorded upon testing.*
