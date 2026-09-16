# SOC Investigation Workflow: Wazuh + Splunk Correlation

**Project:** P10 — Wazuh + Splunk SIEM Integration  
**Scenario:** Adversary Network Reconnaissance & SMB Brute-Force Attack  
**Environment:** Isolated Cybersecurity Lab (`LabNetwork` — `192.168.100.0/24`)  
**Lead Analyst:** SOC Tier 2 / Threat Hunter  

---

## 1. Incident Overview & Attack Progression

This investigation demonstrates an end-to-end incident lifecycle: an adversary performs reconnaissance and an automated credential-guessing attack from Kali Linux against the Windows 11 endpoint. The telemetry is captured by the endpoint's Wazuh Agent, evaluated by the Wazuh Manager, indexed into Splunk Enterprise, and investigated by the SOC analyst across multiple indices.

```
  [Kali Linux] (192.168.100.6)
       │
       │ 1. Nmap Port Scan & SMB Credential Guessing
       ▼
  [Windows 11] (192.168.100.8)
       │
       │ 2. Generates EventID 4625 (Audit Failure) & Sysmon EID 3
       │ 3. Wazuh Agent (003) captures event via EventChannel
       ▼
  [Ubuntu Server] (192.168.100.7)
       │
       │ 4. Wazuh Manager evaluates Rule 60122 (Level 10 Alert)
       │ 5. Appends JSON record to /var/ossec/logs/alerts/alerts.json
       ▼
  [Splunk Enterprise] (192.168.100.7)
       │
       │ 6. Ingests via [monitor:///var/ossec/.../alerts.json] -> index=wazuh
       │ 7. Analyst performs multi-index correlation (wazuh + windows + sysmon)
       ▼
  SOC Incident Report & Containment Action
```

---

## 2. Attack Simulation Procedure

### Phase 1: Host Discovery & Port Reconnaissance
The adversary executes active port scanning against the Windows endpoint:

**[Kali Linux]**
```bash
# Verify network reachability
ping -c 3 192.168.100.8

# Execute TCP port scan on SMB and RPC ports
nmap -sT -p 135,139,445 -Pn 192.168.100.8
```

### Phase 2: Targeted Credential Spraying / Brute-Force
The adversary executes simulated logon attempts with invalid passwords against target accounts:

**[Kali Linux]**
```bash
# Attempt unauthorized SMB enumerations
smbclient -L //192.168.100.8 -U "administrator%WrongPassword2026!"
smbclient -L //192.168.100.8 -U "guest%InvalidPass123"
smbclient -L //192.168.100.8 -U "service_account%Summer2026@"
```

---

## 3. Telemetry Generation & Pipeline Verification

### Phase 3: Wazuh Agent & Manager Alert Generation
On the monitored Windows endpoint, the security subsystem logs an audit failure:

**[Windows 11]**
```powershell
# Verify recent failed logon events in the local security log
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 3 | Format-List
```

On the central Wazuh Manager server, the event is analyzed and written to disk:

**[Ubuntu Server]**
```bash
# Verify the rule firing in real-time JSON alerts
sudo tail -n 5 /var/ossec/logs/alerts/alerts.json | jq '{timestamp, rule: {id: .rule.id, level: .rule.level, description: .rule.description}, agent: .agent.name, data: .data.win.eventdata}'
```

**Observed Wazuh JSON Alert Snippet:**
```json
{
  "timestamp": "2026-09-17T01:20:14.512+0000",
  "rule": {
    "level": 10,
    "id": "60122",
    "description": "Windows logon failure - unknown user name or bad password.",
    "mitre": {
      "id": ["T1110.001", "T1110"],
      "tactic": ["Credential Access"]
    }
  },
  "agent": {
    "id": "003",
    "name": "win11-tgt",
    "ip": "192.168.100.8"
  },
  "data": {
    "win": {
      "system": {
        "eventID": "4625",
        "computer": "win11-tgt.lab.local"
      },
      "eventdata": {
        "targetUserName": "administrator",
        "ipAddress": "192.168.100.6",
        "subStatus": "0xc000006a"
      }
    }
  }
}
```

---

## 4. SOC Investigation in Splunk

### Step 1: Initial Detection & Triage Query
The SOC Tier 1 analyst reviews the High-Severity alert queue:

**SPL Query 1 — High-Severity Ingestion Queue:**
```spl
index=wazuh earliest=-1h 'rule.level'>=10
| eval src = coalesce('data.win.eventdata.ipAddress', 'data.srcip', src_ip, "N/A")
| eval user = coalesce('data.win.eventdata.targetUserName', 'data.srcuser', user, "N/A")
| table _time 'rule.id' 'rule.level' 'rule.description' 'agent.name' src user
```

*Findings:* An alert spike for Rule `60122` (Level 10) originating from IP `192.168.100.6` targeting account `administrator`.

---

### Step 2: Adversary Scope & Target Analysis
The analyst evaluates the volume and diversity of targeted accounts:

**SPL Query 2 — Attack Velocity & Targeted Users:**
```spl
index=wazuh earliest=-1h ('rule.id'="60122" OR 'rule.groups{}'="authentication_failed")
| eval src = coalesce('data.win.eventdata.ipAddress', 'data.srcip', src_ip)
| eval target = coalesce('data.win.eventdata.targetUserName', 'data.srcuser', user)
| stats count as failed_attempts values('rule.description') as descriptions by src target
| sort - failed_attempts
```

*Findings:* `192.168.100.6` attempted multiple authentications within a narrow window, characteristic of password guessing or automated dictionary probing.

---

### Step 3: Multi-Index Cross-Domain Correlation
To verify whether the attack bypassed endpoint controls or established network persistence, the analyst correlates `index=wazuh` alerts with Windows Security logs (`index=windows`) and Sysmon network telemetry (`index=sysmon`):

**SPL Query 3 — Unified Cross-Index Correlation:**
```spl
(index=wazuh 'rule.id'="60122") OR (index=windows EventCode=4625) OR (index=sysmon EventID=3 SourceIp="192.168.100.6")
| eval data_type = case(
    index="wazuh", "Wazuh Alert (" + 'rule.id' + ")",
    index="windows", "Windows EventID " + EventCode,
    index="sysmon", "Sysmon Network Connection (EID 3)",
    true(), index
)
| eval user = coalesce('data.win.eventdata.targetUserName', TargetUserName, user, "N/A")
| eval remote_ip = coalesce('data.win.eventdata.ipAddress', SourceIp, 'data.srcip', src_ip, "N/A")
| table _time data_type host remote_ip user 'rule.description' CommandLine
| sort _time
```

*Findings:*
1. Sysmon Event ID 3 shows inbound TCP connections from `192.168.100.6` to destination port `445` (SMB).
2. Windows Security Event ID 4625 logs corroborate authentication rejections with status code `0xc000006a` (Bad Password).
3. No corresponding Event ID 4624 (Logon Type 3) successful authentication followed, confirming the attack was thwarted.

---

## 5. MITRE ATT&CK Matrix Mapping

| Tactic | Technique ID | Technique Name | Detection Evidence |
|---|---|---|---|
| **Discovery** | **T1046** | Network Service Discovery | Sysmon EID 3 connections across ports 135, 139, 445 |
| **Credential Access** | **T1110.001** | Password Guessing | Wazuh Rule `60122` / Windows EID 4625 |
| **Defense Evasion** | **T1078** | Valid Accounts (Attempted) | Targeted built-in `administrator` account |

---

## 6. Investigation Conclusion & Remediation Recommendations

### Investigation Summary:
- **Incident Severity:** Medium-High (Active unauthorized brute-force probing; contained with zero successful authentications).
- **Attacking Host:** Kali Linux (`192.168.100.6`).
- **Target Host:** Windows 11 Endpoint (`192.168.100.8`).
- **Impact Assessment:** No breach or unauthorized access occurred. Host integrity verified.

### Recommended Containment & Hardening:
1. **Network Layer:** Block inbound traffic from `192.168.100.6` to port 445 on the Windows endpoint firewall.
2. **Endpoint Hardening:** Enforce Windows Account Lockout Policy (e.g., lockout after 5 invalid attempts for 15 minutes).
3. **SIEM Alerting:** Configure a real-time Splunk alert triggering when `index=wazuh 'rule.id'=60122` exceeds 5 events within a 2-minute sliding window.
