# Wazuh + Splunk SIEM Integration: Configuration Reference

**Project:** P10 — Wazuh + Splunk SIEM Integration  
**Document:** Production Configuration Templates & Hardening Reference  
**Classification:** Defensive Cybersecurity Lab Reference  

---

## 1. Overview

This document provides complete, production-ready, and sanitized configuration files for integrating Wazuh with Splunk Enterprise in the threat-hunting laboratory. Every configuration block specifies its target host, absolute file path, and operational rationale.

---

## 2. Splunk Enterprise Configuration (Ubuntu Server)

### 2.1 inputs.conf
**Target Machine:** `[Ubuntu Server]` (`wazuh-server` — `192.168.100.7`)  
**File Location:** `/opt/splunk/etc/system/local/inputs.conf` (or `/opt/splunk/etc/apps/TA_wazuh/local/inputs.conf`)  
**Description:** Defines the non-blocking file monitor input for the Wazuh alerts JSON stream.

```ini
# ==============================================================================
# Wazuh Alerts Stream Monitor
# Ingests real-time JSON alert records produced by wazuh-analysisd
# ==============================================================================
[monitor:///var/ossec/logs/alerts/alerts.json]
disabled = 0
index = wazuh
sourcetype = wazuh
source = /var/ossec/logs/alerts/alerts.json
host = wazuh-server
crcSalt = <SOURCE>

# Optional: Ingest Wazuh internal daemon logs for operational health monitoring
[monitor:///var/ossec/logs/ossec.log]
disabled = 0
index = wazuh
sourcetype = wazuh:log
source = /var/ossec/logs/ossec.log
host = wazuh-server
```

---

### 2.2 props.conf
**Target Machine:** `[Ubuntu Server]` (`wazuh-server` — `192.168.100.7`)  
**File Location:** `/opt/splunk/etc/system/local/props.conf`  
**Description:** Configures index-time structured JSON extraction, ISO 8601 timestamp evaluation, and disables line truncation for large JSON payloads.

```ini
# ==============================================================================
# Wazuh Alerts Sourcetype Properties
# Native index-time JSON parsing and timestamp synchronization
# ==============================================================================
[wazuh]
INDEXED_EXTRACTIONS = json
KV_MODE = none
AUTO_KV_PARSING = false
TRUNCATE = 0
MAX_TIMESTAMP_LOOKAHEAD = 32
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%z
TZ = UTC
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)

# Field aliases for standard SOC terminology
FIELDALIAS-wazuh_src_ip = data.win.eventdata.ipAddress AS src_ip
FIELDALIAS-wazuh_user   = data.win.eventdata.targetUserName AS user
FIELDALIAS-wazuh_eid    = data.win.system.eventID AS EventCode

# ==============================================================================
# Wazuh Internal Daemon Log Sourcetype
# ==============================================================================
[wazuh:log]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = ^
TIME_FORMAT = %Y/%m/%d %H:%M:%S
TRUNCATE = 10000
```

---

### 2.3 indexes.conf
**Target Machine:** `[Ubuntu Server]` (`wazuh-server` — `192.168.100.7`)  
**File Location:** `/opt/splunk/etc/system/local/indexes.conf`  
**Description:** Establishes the dedicated `[wazuh]` index with defined database storage paths, retention policies, and sizing baselines.

```ini
# ==============================================================================
# Wazuh Security Events Index Specification
# Stores: Wazuh Manager JSON alerts, rule firings, and endpoint XDR events
# ==============================================================================
[wazuh]
homePath   = $SPLUNK_DB/wazuh/db
coldPath   = $SPLUNK_DB/wazuh/colddb
thawedPath = $SPLUNK_DB/wazuh/thaweddb
maxTotalDataSizeMB = 10240
maxDataSize = auto_high_volume
maxWarmDBCount = 300
frozenTimePeriodInSecs = 7776000
enableDataIntegrityControl = 1
```

---

## 3. Wazuh Manager Configuration (Ubuntu Server)

### 3.1 ossec.conf (Manager Alert & Logging Configuration)
**Target Machine:** `[Ubuntu Server]` (`wazuh-server` — `192.168.100.7`)  
**File Location:** `/var/ossec/etc/ossec.conf`  
**Description:** Ensures JSON alert generation is active, configures rule alert thresholds, and exposes network communication channels for agents.

```xml
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
  </global>

  <!-- Minimum rule severity level to generate alerts (Default: 3) -->
  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Agent Communication Service (Encrypted AES-256) -->
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <!-- Agent Registration / Enrollment Service -->
  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <ssl_agent_ca>/var/ossec/etc/sslmanager.cert</ssl_agent_ca>
  </auth>

  <!-- Optional: Syslog Forwarding to Splunk UDP/TCP (Alternative transport) -->
  <!--
  <syslog_output>
    <server>192.168.100.7</server>
    <port>1514</port>
    <format>json</format>
  </syslog_output>
  -->
</ossec_config>
```

---

## 4. Wazuh Agent Configuration (Windows 11 Endpoint)

### 4.1 ossec.conf (Windows Agent Channel Collection)
**Target Machine:** `[Windows 11]` (`192.168.100.8`)  
**File Location:** `C:\Program Files (x86)\ossec-agent\ossec.conf`  
**Description:** Directs the Windows agent to stream Windows Security Auditing and Sysmon operational event channels to the Wazuh Manager.

```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.100.7</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>windows, windows11</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <!-- Windows Security Event Log Ingestion -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Windows System Event Log Ingestion -->
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Sysmon Operational Channel Ingestion -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

---

## 5. Linux Permissions & Service Management

### 5.1 Ubuntu Server Deployment Commands
Execute the following commands on the Ubuntu SIEM server to grant Splunk permission to read the Wazuh alert log and create the dedicated index.

**[Ubuntu Server]**
```bash
# 1. Add the dedicated splunk service user to the ossec group
sudo usermod -aG ossec splunk

# 2. Grant group-read permissions to the Wazuh alerts directory and files
sudo chmod 750 /var/ossec/logs/alerts
sudo chmod 640 /var/ossec/logs/alerts/alerts.json
sudo chmod 640 /var/ossec/logs/alerts/alerts.log

# 3. Create the dedicated Splunk index for Wazuh telemetry
sudo -u splunk /opt/splunk/bin/splunk add index wazuh -auth admin:<SANITIZED_PASSWORD>

# 4. Apply input configuration and restart Splunkd
sudo -u splunk /opt/splunk/bin/splunk restart

# 5. Verify the file monitor input is active
sudo -u splunk /opt/splunk/bin/splunk list monitor | grep alerts.json
```

### 5.2 Windows Endpoint Verification Commands
Execute the following in administrative PowerShell on the Windows 11 workstation:

**[Windows 11]**
```powershell
# 1. Verify Wazuh Agent Service state
Get-Service -Name WazuhSvc

# 2. Verify network connectivity to Wazuh Manager port 1514
Test-NetConnection -ComputerName 192.168.100.7 -Port 1514

# 3. Restart Wazuh Agent if configuration modified
Restart-Service -Name WazuhSvc
```
