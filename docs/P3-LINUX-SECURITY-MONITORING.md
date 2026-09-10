# P3 — Linux Security Monitoring with Splunk

[![Status](https://img.shields.io/badge/Status-In%20Progress-yellow.svg)](#p3-status)
[![Platform](https://img.shields.io/badge/Endpoint-Ubuntu%2024.04%20LTS-E95420.svg)](#1-network-configuration)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%2010.4.3-orange.svg)](https://www.splunk.com/)
[![Forwarder](https://img.shields.io/badge/Universal%20Forwarder-10.4.3-orange.svg)](https://www.splunk.com/)
[![Index](https://img.shields.io/badge/Index-linux__security-blue.svg)](#5-splunk-index)

Detailed technical progress log for **Project P3: Linux Security Monitoring with Splunk**, documenting network configuration, SSH access, Splunk Universal Forwarder deployment, Linux log collection, index setup, event ingestion verification, and the first security detection use case.

---

## 📅 Date

**2026-09-11**

---

## 🏗️ Infrastructure Completed

### 1. Network Configuration

- **VM:** `ubuntu-p3` attached to VirtualBox NAT Network `LabNetwork`.
- **Network CIDR:** `192.168.100.0/24`
- **P3 IP Address:** `192.168.100.6`
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
| **Guest** | `192.168.100.6:22` |

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

### 7. First Security Detection Use Case — UC-01: Failed SSH Authentication

An SPL query was implemented to identify failed SSH authentication attempts originating from external sources.

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
| `src_ip` | Source IP address of the failed authentication attempt |
| `username` | Targeted username (valid or invalid) |
| `host` | Destination host (ubuntu-p3) |
| `failed_attempts` | Total count of failures grouped by source |
| `first_attempt` | Human-readable timestamp of first failure |
| `last_attempt` | Human-readable timestamp of most recent failure |

**Status:** Query is operational. Real events confirmed returning results.

---

### 8. Timezone Note

> [!NOTE]
> Ubuntu log timestamps are stored in **UTC (+00:00)**. Splunk may display timestamps according to the configured user/search timezone. Do **not** modify the original log timestamps. Verify or configure Splunk timezone to **Asia/Kolkata (IST, UTC+5:30)** during the next session if timestamp display alignment is required.

---

## 🏛️ Current Architecture

```
Ubuntu Server 24.04.5 LTS (ubuntu-p3 — 192.168.100.6)
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
        └──► UC-01: Failed SSH Authentication (SPL — operational)
```

---

## 📊 P3 Status

### ✅ Completed Tasks (10 Items)

1. **Network connectivity** — `ping -c 4 192.168.100.7` returned 0% packet loss.
2. **Splunk port reachability** — `nc -zv 192.168.100.7 9997` succeeded.
3. **SSH access** — VirtualBox port forwarding `127.0.0.1:2223 → 192.168.100.6:22`; login from Windows host verified.
4. **Splunk Universal Forwarder installed** — UF deployed and configured on `ubuntu-p3`.
5. **Forwarder → Splunk connection** — `192.168.100.7:9997` confirmed active.
6. **Linux log collection configured** — `auth.log`, `syslog`, and `audit.log` monitored via `inputs.conf`.
7. **`linux_security` index** — Created on Splunk Enterprise; events confirmed.
8. **Event ingestion verification** — Real authentication and audit events visible in Splunk.
9. **Failed SSH authentication detection** — UC-01 SPL query implemented; real events returning results.
10. **Source IP / username extraction** — `rex` pattern successfully extracting `src_ip` and `username` from `auth.log` events.

### 🔲 Next / Not Yet Completed Tasks (7 Items)

1. **Failed SSH threshold detection** — Detect ≥ 5 failures from a single source within 5 minutes.
2. **Additional Linux security detections** — `sudo` escalation, account changes, audit anomaly queries.
3. **Splunk alert configuration** — Threshold-based scheduled alerts.
4. **Linux security dashboard** — Dedicated Splunk dashboard for `linux_security` index.
5. **Dashboard visualization** — Failed SSH timeline, top offending IPs, event distribution panels.
6. **Testing / evidence screenshots** — Live Splunk result captures for documentation.
7. **Final P3 documentation / report** — Project completion write-up and portfolio evidence.

### 📈 Completion Metrics

- **Completed items:** 10 / 17 tasks (**58.8%**)
- **Pending items:** 7 / 17 tasks (**41.2%**)

---

## 🎯 Next Milestone

### P3.2 — Threshold Detection & Dashboard

#### Target deliverables:

1. **UC-02 — SSH Brute-Force Threshold Detection**
   - Detect ≥ 5 failed SSH attempts from a single source IP within a 5-minute window.

2. **UC-03 and beyond** — Additional Linux security detections (`sudo`, user account events, audit anomalies).

3. **Linux Security Dashboard** — Splunk dashboard with panels for:
   - Failed SSH events over time
   - Top source IPs by failure count
   - Username targeting analysis

4. **Evidence capture** — Screenshot documentation of all Splunk results and dashboard panels.

---

## 📁 Project File Structure

```
P3-Linux-Security-Monitoring/
│
├── README.md                     # P3 project overview and status
│
└── (future directories)
    ├── config/                   # Forwarder configuration files
    ├── detections/               # SPL detection queries
    ├── docs/                     # Technical documentation
    ├── dashboards/               # Dashboard definitions
    └── screenshots/              # Evidence captures
```
