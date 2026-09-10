# P3 — Linux Security Monitoring with Splunk

[![Status](https://img.shields.io/badge/Status-In%20Progress-yellow.svg)](#project-status)
[![Platform](https://img.shields.io/badge/Endpoint-Ubuntu%2024.04%20LTS-E95420.svg)](#environment)
[![Forwarder](https://img.shields.io/badge/Universal%20Forwarder-10.4.3-orange.svg)](https://www.splunk.com/)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%2010.4.3-orange.svg)](https://www.splunk.com/)
[![Index](https://img.shields.io/badge/Index-linux__security-blue.svg)](#splunk-index)

---

## Overview

P3 extends the Splunk SOC Threat Hunting Lab to **Linux endpoint monitoring**, deploying a Splunk Universal Forwarder on an Ubuntu Server 24.04 LTS VM (`ubuntu-p3`) to forward authentication, system, and audit logs into a dedicated `linux_security` index on Splunk Enterprise.

This project demonstrates a complete Linux telemetry pipeline — from endpoint log collection through event ingestion to the first security detection use case — covering real SSH authentication events and the extraction of attacker source IPs, usernames, and failure counts.

---

## Environment

| Parameter | Value |
|---|---|
| **VM Name** | `ubuntu-p3` |
| **OS** | Ubuntu Server 24.04.5 LTS |
| **VM IP Address** | `192.168.100.6` |
| **Splunk Enterprise Server** | `192.168.100.7` |
| **Splunk Receiving Port** | `9997/tcp` |
| **Splunk Web** | `http://127.0.0.1:8000` |
| **SSH Port Forwarding** | `127.0.0.1:2223` → `192.168.100.6:22` |
| **Hypervisor** | Oracle VirtualBox |
| **Network** | VirtualBox NAT Network — `LabNetwork` (`192.168.100.0/24`) |
| **Host OS** | Windows 11 |

---

## Architecture

```
Ubuntu Server 24.04.5 LTS (ubuntu-p3 — 192.168.100.6)
        │
        │  /var/log/auth.log      (sourcetype: linux_secure)
        │  /var/log/syslog        (sourcetype: syslog)
        │  /var/log/audit/audit.log (sourcetype: linux:audit)
        ▼
Splunk Universal Forwarder (10.4.3)
        │
        │  TCP 9997
        ▼
Splunk Enterprise (192.168.100.7)
        │
        └──► index=linux_security
                │
                └──► SPL Detection: Failed SSH Authentication
```

---

## Data Collection

### Splunk Universal Forwarder Configuration

**App:** `/opt/splunkforwarder/etc/apps/linux_security/local/inputs.conf`

```ini
[monitor:///var/log/auth.log]
disabled = false
index = linux_security
sourcetype = linux_secure
host = ubuntu-p3

[monitor:///var/log/syslog]
disabled = false
index = linux_security
sourcetype = syslog
host = ubuntu-p3

[monitor:///var/log/audit/audit.log]
disabled = false
index = linux_security
sourcetype = linux:audit
host = ubuntu-p3
```

### Log Source Mapping

| Log File | Splunk Index | Sourcetype | Purpose |
|---|---|---|---|
| `/var/log/auth.log` | `linux_security` | `linux_secure` | SSH logins, sudo, PAM authentication |
| `/var/log/syslog` | `linux_security` | `syslog` | General system events |
| `/var/log/audit/audit.log` | `linux_security` | `linux:audit` | Kernel audit subsystem events |

---

## Splunk Index

| Parameter | Value |
|---|---|
| **Index Name** | `linux_security` |
| **Splunk Server** | `192.168.100.7` |
| **Status** | Created and verified — events actively indexed |

---

## Forwarder Configuration

**Forwarding target verified via:**

```bash
splunk list forward-server
```

**Result:**

```
Active forwards:
    192.168.100.7:9997
Configured but inactive forwards:
    None
```

---

## SPL Detection Use Cases

### UC-01 — Failed SSH Authentication

Identifies failed SSH login attempts, extracting source IP, targeted username, destination host, attempt count, and time window.

**Query:**

```spl
index=linux_security sourcetype=linux_secure "Failed password"
| rex "Failed password for (invalid user )?(?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count as failed_attempts earliest(_time) as first_attempt latest(_time) as last_attempt by src_ip username host
| convert ctime(first_attempt) ctime(last_attempt)
| sort - failed_attempts
```

**Extracted Fields:**

| Field | Description |
|---|---|
| `src_ip` | Attacking source IP address |
| `username` | Targeted username (including invalid users) |
| `host` | Destination host (`ubuntu-p3`) |
| `failed_attempts` | Total count of failed attempts |
| `first_attempt` | Timestamp of first observed failure |
| `last_attempt` | Timestamp of most recent failure |

**Verified:** Real `"Failed password for invalid user..."` events confirmed ingested from `ubuntu-p3`.

---

## Project Status

### ✅ Completed

| Item | Detail |
|---|---|
| Network connectivity | `ping -c 4 192.168.100.7` — 0% packet loss confirmed |
| Splunk port reachability | `nc -zv 192.168.100.7 9997` — succeeded |
| SSH access | Port forwarding `127.0.0.1:2223 → 192.168.100.6:22` configured; login verified |
| Splunk Universal Forwarder | Installed and configured on `ubuntu-p3` |
| Forwarder → Splunk connection | Active forward to `192.168.100.7:9997` verified |
| Linux log collection | `auth.log`, `syslog`, `audit.log` monitored via `inputs.conf` |
| `linux_security` index | Created on Splunk Enterprise; events confirmed |
| Event ingestion verification | Real authentication and audit events visible in Splunk |
| Failed SSH authentication detection | UC-01 SPL query implemented and returning real events |
| Source IP / username extraction | `rex` pattern extracting `src_ip` and `username` from `auth.log` |

### 🔲 Next / Not Yet Completed

| Item | Detail |
|---|---|
| Failed SSH threshold detection | Alert when ≥ 5 failures occur within 5 minutes from a single source |
| Additional Linux security detections | `sudo` escalation, account changes, audit anomalies |
| Splunk alerts | Threshold-based alert configuration |
| Security dashboard | Linux security monitoring dashboard |
| Dashboard visualization | Panels for failed SSH timeline, top offending IPs |
| Testing / evidence screenshots | Screenshot captures of live Splunk results |
| Final P3 documentation / report | Completed project write-up |

---

## Timezone Note

- Ubuntu log timestamps are stored in **UTC (+00:00)**.
- Splunk may display timestamps according to the configured user/search timezone.
- Original log timestamps must **not** be modified.
- Verify or configure Splunk timezone to **Asia/Kolkata (IST, UTC+5:30)** if timestamp display alignment is required.

---

## Network Verification

**ICMP connectivity to Splunk server:**

```bash
ping -c 4 192.168.100.7
# Result: 0% packet loss
```

**Splunk receiving port reachability:**

```bash
nc -zv 192.168.100.7 9997
# Result: Connection succeeded
```

---

## SSH Access

VirtualBox port forwarding rule:

| Parameter | Value |
|---|---|
| **Host Address** | `127.0.0.1:2223` |
| **Guest Address** | `192.168.100.6:22` |

**SSH command from Windows host:**

```powershell
ssh natto@127.0.0.1 -p 2223
```

---

## Security Considerations

- No credentials committed to this repository.
- All monitoring and testing is performed within the isolated VirtualBox NAT network (`192.168.100.0/24`).
- SSH brute-force test events generated deliberately for detection validation purposes only.

---

## Related Documentation

| Document | Path |
|---|---|
| P3 Progress Log | [`docs/P3-LINUX-SECURITY-MONITORING.md`](../docs/P3-LINUX-SECURITY-MONITORING.md) |
| Root README | [`README.md`](../README.md) |
| P2 Windows Monitoring | [`P2-Windows-Security-Monitoring/README.md`](../P2-Windows-Security-Monitoring/README.md) |
