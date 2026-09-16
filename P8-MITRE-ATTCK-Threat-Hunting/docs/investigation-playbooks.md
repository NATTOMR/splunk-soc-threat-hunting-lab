# 🛡️ SOC Threat Hunting & Investigation Playbooks

[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v15-red.svg)](https://attack.mitre.org/)
[![Playbook Type](https://img.shields.io/badge/Type-Tier%202%2F3%20SOC%20Playbook-blue.svg)](#playbook-directory)
[![Project](https://img.shields.io/badge/Project-P8%20Threat%20Hunting-orange.svg)](../README.md)

This document provides standardized, step-by-step investigation playbooks for SOC analysts and threat hunters responding to anomalies surfaced by the **Project P8** threat hunting library.

---

## Playbook Directory

1. [Playbook 1: Abnormal Authentication & Pass-The-Hash](#playbook-1-abnormal-authentication--pass-the-hash)
2. [Playbook 2: LOLBin Execution & Process Masquerading](#playbook-2-lolbin-execution--process-masquerading)
3. [Playbook 3: Obfuscated PowerShell & Memory Cradles](#playbook-3-obfuscated-powershell--memory-cradles)
4. [Playbook 4: Persistence Artifacts (Registry/Tasks/Services/Cron)](#playbook-4-persistence-artifacts-registrytasksservicescron)
5. [Playbook 5: Local Privilege Escalation & Sudo Abuse](#playbook-5-local-privilege-escalation--sudo-abuse)
6. [Playbook 6: Malicious Parent-Child Process Spawning](#playbook-6-malicious-parent-child-process-spawning)
7. [Playbook 7: Lateral Movement (PsExec/SMB/RDP)](#playbook-7-lateral-movement-psexecsmbrdp)
8. [Playbook 8: C2 Beaconing & Dynamic DNS Triage](#playbook-8-c2-beaconing--dynamic-dns-triage)

---

## Playbook 1: Abnormal Authentication & Pass-The-Hash

### Triage Trigger
Query [`01-hypothesis-authentication-hunting.spl`](../queries/01-hypothesis-authentication-hunting.spl) flags `Logon_Type="9"` (NewCredentials) or privileged accounts logging on via `Logon_Type="3"` (Network SMB) from untrusted IPs.

### Step-by-Step Investigation Workflow
1. **Identify Calling Process:** For Logon Type 9, query Sysmon EventID 1 around the same second (`_time`) on the source host to determine which binary initiated the `LogonUser()` call:
   ```spl
   index=sysmon earliest=-10m latest=+10m host="<HOST>"
   | rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
   | search EventID=1
   ```
2. **Determine Target Scope:** Filter `index=windows EventCode=4624 TargetUserName="<ACCOUNT>"` across all domain hosts to evaluate lateral reach.
3. **Containment & Response:**
   - Immediately revoke active Kerberos TGTs and reset compromised user credentials.
   - Terminate suspicious user processes on the source endpoint.
   - Enforce Protected Users security group or Restricted Admin mode for RDP.

---

## Playbook 2: LOLBin Execution & Process Masquerading

### Triage Trigger
Query [`02-hypothesis-process-hunting.spl`](../queries/02-hypothesis-process-hunting.spl) flags `certutil.exe` downloading files, `mshta.exe` executing web scriptlets, or `svchost.exe` running outside `C:\Windows\System32`.

### Step-by-Step Investigation Workflow
1. **Decode Command Arguments:** Extract URL, download path, or script payload embedded in the LOLBin invocation:
   - For `certutil -urlcache -split -f <URL> <DEST>`, note destination file and remote IP.
2. **Correlate Sysmon File Creation (EventID 11):**
   ```spl
   index=sysmon earliest=-1h latest=+1h host="<HOST>"
   | rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
   | search EventID=11
   | rex field=_raw "<Data Name='TargetFilename'>(?<TargetFilename>[^<]+)</Data>"
   | search TargetFilename="*<DEST_FILENAME>*"
   ```
3. **Correlate Outbound Network Traffic (EventID 3):** Identify destination IP, port, and byte counts.
4. **Containment:**
   - Quarantine downloaded file on disk.
   - Block malicious remote IP/URL on corporate firewall and proxy.

---

## Playbook 3: Obfuscated PowerShell & Memory Cradles

### Triage Trigger
Query [`03-hypothesis-powershell-hunting.spl`](../queries/03-hypothesis-powershell-hunting.spl) returns a threat score $\ge 40$ involving `-enc`, `-ep bypass`, and `DownloadString`.

### Step-by-Step Investigation Workflow
1. **Decode Base64 Command:** Extract the encoded string and decode UTF-16LE Base64 in CyberChef or PowerShell:
   ```powershell
   [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("<BASE64_STRING>"))
   ```
2. **Review Script Block Telemetry:** Search for EID 4104 (PowerShell ScriptBlock Logging) in `index=windows`:
   ```spl
   index=windows EventCode=4104 host="<HOST>"
   | stats values(ScriptBlockText) by _time
   ```
3. **Identify Parent Process:** Check if PowerShell was spawned by `cmd.exe`, `word.exe`, or an unfamiliar executable.
4. **Containment:** Kill running process tree, isolate endpoint from the network.

---

## Playbook 4: Persistence Artifacts (Registry/Tasks/Services/Cron)

### Triage Trigger
Query [`04-hypothesis-persistence-hunting.spl`](../queries/04-hypothesis-persistence-hunting.spl) flags modifications to `Run` registry keys, `schtasks /create`, or System Event 7045.

### Step-by-Step Investigation Workflow
1. **Inspect Artifact Binary:** Retrieve the executable or script referenced in the autostart value:
   - Calculate SHA256 hash.
   - Inspect digital signature status (`Get-AuthenticodeSignature`).
2. **Identify Creating User Context:** Trace the parent process that performed the registry write (Sysmon EID 13) or service creation.
3. **Remediation:**
   - Stop and delete rogue service (`sc stop <SVC>; sc delete <SVC>`).
   - Remove persistence registry entry (`reg delete <KEY> /v <VALUE> /f`).
   - Delete rogue scheduled tasks or Linux cron entries.

---

## Playbook 5: Local Privilege Escalation & Sudo Abuse

### Triage Trigger
Query [`05-hypothesis-privilege-escalation.spl`](../queries/05-hypothesis-privilege-escalation.spl) detects unauthorized members added to `Administrators` or GTFOBins commands via sudo on Linux.

### Step-by-Step Investigation Workflow
1. **Verify Authorization:** Contact the system administrator to determine if the group addition or sudo execution was authorized change activity.
2. **Review Caller Timeline:** Check what commands the user executed immediately prior to privilege escalation.
3. **Containment:**
   - Remove unauthorized account from privileged group (`net localgroup administrators <USER> /delete`).
   - Terminate active privileged shell sessions.
   - Lock compromised user account.

---

## Playbook 6: Malicious Parent-Child Process Spawning

### Triage Trigger
Query [`06-hypothesis-command-execution.spl`](../queries/06-hypothesis-command-execution.spl) detects client applications (Word, Excel, Acrobat, Web Daemons) spawning `cmd.exe` or `powershell.exe`.

### Step-by-Step Investigation Workflow
1. **Identify Weaponized Lure File:** Look up the command line of the parent office application to discover the exact path of the document opened (`.docm`, `.xlsm`, `.pdf`).
2. **Check for Child Droppers:** Trace all sub-processes launched under `cmd.exe` (e.g. `whoami`, `curl`, `certutil`).
3. **Quarantine:** Delete malicious document lure and terminate process tree.

---

## Playbook 7: Lateral Movement (PsExec/SMB/RDP)

### Triage Trigger
Query [`07-hypothesis-lateral-movement.spl`](../queries/07-hypothesis-lateral-movement.spl) detects `psexesvc.exe` execution or abnormal files staged across `ADMIN$` or `C$`.

### Step-by-Step Investigation Workflow
1. **Identify Source Workstation:** Check source IP address in Windows Event 4624 / 5140 to locate the patient-zero machine initiating lateral movement.
2. **Review Command Line Invocations:** Inspect what commands were executed remotely through the PsExec session.
3. **Containment:**
   - Block SMB (TCP 445) and RDP (TCP 3389) between lateral subnets.
   - Isolate patient-zero and all downstream compromised machines simultaneously to prevent reinfection.

---

## Playbook 8: C2 Beaconing & Dynamic DNS Triage

### Triage Trigger
Query [`08-hypothesis-ioc-investigation.spl`](../queries/08-hypothesis-ioc-investigation.spl) surfaces queries to dynamic DNS providers (`ngrok.io`, `duckdns.org`), high-entropy domains, or egress to TCP 4444.

### Step-by-Step Investigation Workflow
1. **Correlate DNS to Process:** Use Sysmon EventID 22 to map the queried domain to the specific originating process ID and executable name.
2. **Inspect Network Connection Frequency:** Search Sysmon EventID 3 to calculate beacon intervals, jitter, and total data transferred.
3. **Containment:**
   - Sinkhole or block the C2 domain at firewall/DNS resolver.
   - Collect memory dump of the infected process for malware analysis.
