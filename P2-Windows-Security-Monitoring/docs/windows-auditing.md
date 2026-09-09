# 🛡️ Windows Advanced Audit Policy Configuration Guide

Complete operational guide for establishing, automating, and verifying the Windows Advanced Audit Policy baseline on the Windows 11 endpoint (`192.168.100.8`) for **Project P2: Windows Security Monitoring**.

---

## 1. Audit Policy Architecture & MITRE ATT&CK Mapping

Windows auditing generates the foundational OS security events forwarded by Splunk Universal Forwarder into `index=windows`. The baseline is designed to provide high-fidelity detection coverage aligned with standard ATT&CK Tactics:

| Audit Subcategory | Target Setting | Generated Event IDs | ATT&CK Tactic / Detection Objective |
|---|---|---|---|
| **Credential Validation** | Success & Failure | `4776` | **Credential Access / Initial Access:** Detects NTLM authentication attempts, brute-force attacks, and password spraying. |
| **Logon** | Success & Failure | `4624`, `4625` | **Initial Access / Lateral Movement:** Identifies interactive (Type 2), network (Type 3), and RDP (Type 10) sessions or repeated authentication failures. |
| **Logoff** | Success | `4634`, `4647` | **Defense Evasion / Forensics:** Reconstructs user session durations and timeline analysis. |
| **Special Logon** | Success | `4672` | **Privilege Escalation:** Detects when administrative accounts or privileges (`SeDebugPrivilege`, `SeTcbPrivilege`) are assigned to a new logon session. |
| **User Account Management** | Success & Failure | `4720`, `4722`, `4724`, `4726` | **Persistence:** Detects creation of rogue user accounts, password resets, and account enablement/deletion. |
| **Security Group Management** | Success & Failure | `4728`, `4732`, `4756` | **Privilege Escalation / Persistence:** Flags when users are added to local or domain privileged security groups (e.g. `Administrators`). |
| **Process Creation** | Success | `4688` | **Execution:** Captures every process spawn event. Essential for identifying LOLBins (`certutil`, `powershell`, `mshta`, `cmd`). |
| **Audit Policy Change** | Success & Failure | `4719` | **Defense Evasion:** Identifies attempts by adversaries or malware to tamper with or disable audit policies. |
| **Sensitive Privilege Use** | Success & Failure | `4673`, `4674` | **Privilege Escalation / Defense Evasion:** Captures privileged token adjustments and sensitive API calls. |

---

## 2. Command-Line Argument Logging (Event 4688)

By default, Event ID 4688 records process execution but omits command-line arguments. To enable forensic visibility into adversary arguments:

### GPO / Registry Setting:
- **Registry Key:** `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`
- **Value Name:** `ProcessCreationIncludeCmdLine_Enabled`
- **Value Type:** `REG_DWORD`
- **Value Data:** `1`

Once enabled, Splunk extracts the full command line from `<Data Name='CommandLine'>` in the XML event, enabling queries such as:
```spl
index=windows EventCode=4688 CommandLine="*powershell* -enc*"
```

---

## 3. PowerShell Script Block & Module Logging

Deep PowerShell auditing exposes obfuscated, base64-encoded, or downloaded payloads before execution:

### 1. Script Block Logging (Event ID 4104):
- **Registry Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
- **Value Name:** `EnableScriptBlockLogging`
- **Value Type:** `REG_DWORD`
- **Value Data:** `1`
- **Capabilities:** Records the complete, de-obfuscated script code block executed by the PowerShell engine.

### 2. Module Logging (Event ID 4103):
- **Registry Key:** `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging`
- **Value Name:** `EnableModuleLogging` = `1`
- **Subkey:** `ModuleNames` -> Value `*` = `*`
- **Capabilities:** Tracks pipeline execution details and loaded modules.

---

## 4. Automated Deployment & Verification

A dedicated PowerShell automation script is provided in the repository to safely backup, apply, and verify the entire auditing baseline:

### Option A: Read-Only Compliance Check
Run the script with the `-VerifyOnly` switch to check compliance without making changes:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\configure-audit-policy.ps1 -VerifyOnly
```

### Option B: Automated Baseline Configuration
Run the script as Administrator to create a backup, apply all `auditpol` subcategories, and configure registry keys:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\configure-audit-policy.ps1
```

---

## 5. Manual CLI Verification Commands

You can verify active policies directly via standard Windows command-line utilities:

```cmd
:: 1. View all configured audit subcategories
auditpol /get /category:*

:: 2. Check Process Creation auditing
auditpol /get /subcategory:"Process Creation"

:: 3. Check Account Management auditing
auditpol /get /subcategory:"User Account Management"

:: 4. Verify Process Creation Command-Line registry flag
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled

:: 5. Verify PowerShell Script Block Logging registry flag
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging
```
