# 🛡️ Threat Hunting Engagement Report: MITRE ATT&CK Threat Hunt

| Engagement Reference | Engagement Period | Lead Threat Hunter | Framework | Severity Status |
|---|---|---|---|---|
| **HUNT-2026-P8-001** | September 2026 | **Natto Chakma** | MITRE ATT&CK v15 / TaHiTI | 🟡 **Anomalies Identified & Remediated** |

---

## 1. Executive Summary

During September 2026, the Security Operations Center (SOC) initiated a proactive, hypothesis-driven threat hunting engagement across the corporate lab environment. Unlike reactive alert response, this operation evaluated whether advanced adversaries had bypassed static detection controls using techniques cataloged in the **MITRE ATT&CK Enterprise Matrix**.

The hunt evaluated 8 distinct threat hypotheses across Windows endpoints (`WinServer2022` / Windows 11 — `192.168.100.8`), Linux servers (`ubuntu-p3` — `192.168.100.9`), and network security gateways. Over **14,500 telemetry events** from Windows Sysmon XML streams, Windows Security Event Logs, and Linux audit logs were analyzed.

### Key Engagement Findings
- **Obfuscated PowerShell Execution:** Multiple instances of PowerShell utilizing `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, and `-EncodedCommand` were uncovered (MITRE `T1059.001`), scoring in the Critical tier ($\ge 60$).
- **Living-Off-The-Land (LOLBin) Abuse:** Discovered `certutil.exe` invocations utilizing `-urlcache -split` flags (MITRE `T1105`) attempting to bypass perimeter URL filtering.
- **Persistence Mechanisms:** Successfully surfaced persistence hooks registered under `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run` and scheduled task creations via `schtasks.exe /create` (MITRE `T1547.001`, `T1053.005`).
- **Lateral Movement & Account Triage:** Confirmed baseline separation of administrative network logons (Logon Type 3 over SMB) and identified no active Pass-the-Hash (Type 9) propagation.

---

## 2. Environment & Telemetry Scope

| Role | Hostname | IP Address | Operating System | Monitored Telemetry Channels |
|---|---|---|---|---|
| **SIEM & Search Head** | `wazuh-server` | `192.168.100.7` | Ubuntu 24.04 LTS | Splunk Enterprise 10.4.3 |
| **Endpoint Target** | `WinServer2022` | `192.168.100.8` | Windows Server / Win 11 | `index=sysmon` (v15.15), `index=windows` |
| **Linux Host** | `ubuntu-p3` | `192.168.100.9` | Ubuntu 24.04.5 LTS | `index=linux_security` (`auth.log`, `syslog`) |
| **Adversary Node** | `kali` | `192.168.100.6` | Kali Linux 2024.x | Attack Orchestration & Telemetry Injection |

---

## 3. Hypothesis Testing Outcomes & Findings

### Hunt 1: Authentication & Privilege Escalation (T1078, T1550.002)
- **Hypothesis:** Threat actors utilize compromised credentials or NewCredentials (Logon Type 9) to conduct Pass-the-Hash.
- **Finding:** Baseline testing showed normal interactive logons (Type 2) and scheduled task logons (Type 4). No persistent Type 9 anomalies were detected in production telemetry.
- **Outcome:** **Negative (Confirmed Clean)**.

### Hunt 2: LOLBins & Process Masquerading (T1218, T1036.005, T1105)
- **Hypothesis:** Adversaries abuse native signed binaries (`certutil`, `bitsadmin`, `mshta`, `rundll32`) or disguise executables in user directories.
- **Finding:** Uncovered `certutil.exe -urlcache -split -f` execution fetching external artifacts into `%TEMP%`.
- **Outcome:** **Positive (Adversary Telemetry Confirmed)**.

### Hunt 3: PowerShell Scripting Obfuscation (T1059.001, T1027)
- **Hypothesis:** Adversaries hide malicious activity through multi-flag obfuscation (`-enc`, `-w hidden`, `-ep bypass`).
- **Finding:** Detected high-risk PowerShell invocations executing Base64 UTF-16LE encoded strings. Threat score calculated at 70/100.
- **Outcome:** **Positive (Validated)**.

### Hunt 4: Endpoint Persistence (T1547.001, T1053.005, T1543.003)
- **Hypothesis:** Adversaries implant autostart keys or scheduled tasks to maintain survival across reboots.
- **Finding:** Sysmon EventID 13 identified registry write under `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`. Scheduled task creation via CLI (`schtasks /create /tn P8_ThreatHunt_Task`) caught via Sysmon EventID 1.
- **Outcome:** **Positive (Validated)**.

### Hunt 5: Command Execution & Living Off The Land (T1059.003, T1047)
- **Hypothesis:** Discovery bursts (`whoami`, `net user`, `ipconfig`) execute immediately following initial beachhead establishment.
- **Finding:** Correlated sequential command executions spawned under `cmd.exe /c` executing reconnaissance tooling.
- **Outcome:** **Positive (Validated)**.

### Hunt 6: Command and Control (C2) & Dynamic DNS (T1071.004)
- **Hypothesis:** Malware implants beacon out to dynamic DNS domains or low-reputation TLDs.
- **Finding:** Sysmon EventID 22 revealed DNS queries attempting resolution of `*.duckdns.org` domain namespaces.
- **Outcome:** **Positive (Validated)**.

---

## 4. Threat Hunting Metrics & Coverage Scorecard

```text
+-------------------------------------------------------------------------+
|                  HUNT ENGAGEMENT METRICS SUMMARY                        |
+------------------------------------+------------------------------------+
| Metric                             | Value                              |
+------------------------------------+------------------------------------+
| Total Hypotheses Tested            | 8 Hypotheses                       |
| MITRE ATT&CK Tactics Covered       | 8 Tactics (Initial Access to C2)  |
| MITRE ATT&CK Techniques Mapped     | 18 Techniques & Sub-techniques    |
| Telemetry Events Triaged           | 14,820 Events                      |
| Validated Threat Indicators        | 6 Positive Emulations Surfaced     |
| False Positive Rate                | < 2.5% after tuning regexes        |
| Durable Alerts Engineered          | 4 Converted to Production Alerts   |
+------------------------------------+------------------------------------+
```

---

## 5. Strategic Recommendations & Lessons Learned

1. **Convert Hunting Queries into Permanent Correlation Searches:**
   - Operationalize [`02-hypothesis-process-hunting.spl`](../queries/02-hypothesis-process-hunting.spl) and [`03-hypothesis-powershell-hunting.spl`](../queries/03-hypothesis-powershell-hunting.spl) into automated real-time alerts.
2. **Harden PowerShell Execution Policy & Enforce Constrained Language Mode (CLM):**
   - Restrict interactive PowerShell execution and enable AppLocker or Windows Defender Application Control (WDAC).
3. **Audit and Restrict LOLBins via Group Policy:**
   - Block `certutil.exe` outbound network egress via Windows Firewall rules.
4. **Deploy Dynamic DNS Filtering:**
   - Enforce DNS-level sinkholing or perimeter blocking for free dynamic DNS providers (`duckdns.org`, `ngrok.io`, `no-ip.com`) on enterprise endpoints.
