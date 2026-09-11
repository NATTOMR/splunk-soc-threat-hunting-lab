# P3 — Linux Security Monitoring with Splunk

[![Status](https://img.shields.io/badge/Status-Completed%20%26%20Verified-brightgreen.svg)](#p3-status)
[![Platform](https://img.shields.io/badge/Endpoint-Ubuntu%2024.04%20LTS-E95420.svg)](#1-network-configuration)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%2010.4.3-orange.svg)](https://www.splunk.com/)
[![Forwarder](https://img.shields.io/badge/Universal%20Forwarder-10.4.3-orange.svg)](https://www.splunk.com/)
[![Index](https://img.shields.io/badge/Index-linux__security-blue.svg)](#5-splunk-index)

Detailed technical progress log for **Project P3: Linux Security Monitoring with Splunk**, documenting network configuration, SSH access, Splunk Universal Forwarder deployment, Linux log collection, index setup, event ingestion verification, detection engineering, and live SOC dashboard visualization.

---

## 📅 Date

**2026-09-11**

---

## 🏗️ Infrastructure Completed

### 1. Network Configuration

- **VM:** `ubuntu-p3` attached to VirtualBox NAT Network `LabNetwork`.
- **Network CIDR:** `192.168.100.0/24`
- **P3 IP Address:** `192.168.100.9`
- **Splunk Server IP:** `192.168.100.7`

**ICMP connectivity verified:**

```bash
ping -c 4 192.168.100.7
```

Result: **0% packet loss** — `ubuntu-p3` can reach the Splunk Enterprise server.

**Splunk receiving port verified:**

```bash
nc -zv 192.168.100.7 9997
```

Result: **Connection succeeded** — TCP `9997` is reachable from `ubuntu-p3`.

---

### 2. SSH Access

VirtualBox port forwarding configured to allow SSH access from the Windows 11 host to `ubuntu-p3`:

| Parameter | Value |
|---|---|
| **Host** | `127.0.0.1:2223` |
| **Guest** | `192.168.100.9:22` |

**SSH access verified from Windows host:**

```powershell
ssh natto@127.0.0.1 -p 2223
```

Result: SSH login to `ubuntu-p3` is working.

---

### 3. Splunk Universal Forwarder

- Splunk Universal Forwarder installed and configured on `ubuntu-p3`.
- Forwarding target set to `192.168.100.7:9997`.

**Verified with:**

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

The forwarder maintains an active, confirmed connection to Splunk Enterprise.

---

### 4. Log Collection

**Configuration file created:**

```
/opt/splunkforwarder/etc/apps/linux_security/local/inputs.conf
```

**Contents:**

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

**Log source summary:**

| Log File | Sourcetype | Purpose |
|---|---|---|
| `/var/log/auth.log` | `linux_secure` | SSH logins, sudo, PAM authentication events |
| `/var/log/syslog` | `syslog` | General system and kernel messages |
| `/var/log/audit/audit.log` | `linux:audit` | Kernel audit subsystem events |

- **Index:** `linux_security`
- **Host:** `ubuntu-p3`

---

### 5. Splunk Index

- `linux_security` index created on Splunk Enterprise (`192.168.100.7`).
- Events verified as actively ingested into the index.

---

### 6. Event Ingestion Verification

- Real events from `ubuntu-p3` confirmed arriving in Splunk.
- Authentication and audit events confirmed visible in `index=linux_security`.
- Real SSH failed-login activity generated on `ubuntu-p3` for detection testing.
- Events matching the pattern `"Failed password for invalid user..."` confirmed collected and indexed.

---

### 7. Security Detection Use Cases

SPL queries implemented and verified operational against real ingested telemetry:
1. Failed SSH authentication
2. Successful SSH authentication
3. SSH brute-force activity
4. Sudo privilege activity
5. Linux kernel audit events
6. Authentication activity over time
7. Source IP analysis
8. Recent security events table

---

### 8. Timezone Note

> [!NOTE]
> Ubuntu log timestamps are stored in **UTC (+00:00)**. Splunk displays timestamps aligned with the user/search timezone (**Asia/Kolkata, IST, UTC+5:30**).

---

## 🏛️ Current Architecture

```
Ubuntu Server 24.04.5 LTS (ubuntu-p3 — 192.168.100.9)
        │
        │  /var/log/auth.log        → sourcetype: linux_secure
        │  /var/log/syslog          → sourcetype: syslog
        │  /var/log/audit/audit.log → sourcetype: linux:audit
        ▼
Splunk Universal Forwarder (10.4.3)
  └── /opt/splunkforwarder/etc/apps/linux_security/local/inputs.conf
        │
        │  TCP 9997  (Active — verified)
        ▼
Splunk Enterprise (192.168.100.7)
  └── index=linux_security
        │
        ├── Detection Rules & SPL Analytics
        └── "Linux Security Monitoring" Operational Dashboard
```

---

## 📊 P3 Status

### ✅ Completed Tasks (17 / 17 Items — 100%)

1. **Network connectivity** — `ping -c 4 192.168.100.7` returned 0% packet loss.
2. **Splunk port reachability** — `nc -zv 192.168.100.7 9997` succeeded.
3. **SSH access** — VirtualBox port forwarding `127.0.0.1:2223 → 192.168.100.9:22`; login from Windows host verified.
4. **Splunk Universal Forwarder installed** — UF deployed and configured on `ubuntu-p3`.
5. **Forwarder → Splunk connection** — `192.168.100.7:9997` confirmed active.
6. **Linux log collection configured** — `auth.log`, `syslog`, and `audit.log` monitored via `inputs.conf`.
7. **`linux_security` index** — Created on Splunk Enterprise; events confirmed.
8. **Event ingestion verification** — Real authentication and audit events visible in Splunk (2,224+ events).
9. **Failed SSH authentication detection** — SPL query implemented; real events returning results (25 failures).
10. **Source IP / username extraction** — `rex` pattern successfully extracting `src_ip` and `username` from `auth.log`.
11. **Failed SSH threshold detection** — Brute-force detection implemented and verified.
12. **Privilege escalation detection** — Sudo activity monitoring implemented and verified (107 events).
13. **Linux audit telemetry parsing** — Kernel audit events aggregated and parsed (854 events).
14. **Linux Security Monitoring Dashboard** — 11-panel SOC dashboard created in Splunk Web.
15. **Dashboard visualization** — Timeline charts, single-value KPIs, and source IP distribution panels verified.
16. **Evidence capture** — Full dashboard screenshot captured (`screenshots/linux-security-monitoring-dashboard.png`).
17. **Final P3 documentation** — Complete project README, architecture guide, testing guide, and inputs configuration published.

### 📈 Completion Metrics

- **Completed items:** 17 / 17 tasks (**100%**)
- **Pending items:** 0 / 17 tasks (**0%**)

---

## 📁 Project File Structure

```
P3-Linux-Security-Monitoring/
├── README.md                                       # P3 project overview and portfolio writeup
├── configs/
│   └── inputs.conf                                 # Forwarder inputs configuration
├── docs/
│   ├── architecture.md                             # Technical architecture & pipeline documentation
│   └── testing.md                                  # Validation commands & empirical test results
└── screenshots/
    └── linux-security-monitoring-dashboard.png     # Full-resolution dashboard capture
```

