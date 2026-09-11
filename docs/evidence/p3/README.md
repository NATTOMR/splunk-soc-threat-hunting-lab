# P3 Evidence — Linux Security Monitoring Dashboard

## Evidence Directory

This directory contains evidence screenshots for **Project P3: Linux Security Monitoring with Splunk**.

---

## p3-04-linux-security-monitoring-dashboard.png

**Status:** ✅ Captured & Verified

**Source File in Repository:**
```text
P3-Linux-Security-Monitoring/screenshots/p3-04-linux-security-monitoring-dashboard.png
```

**Description:**
The screenshot captures the live **Linux Security Monitoring** operational dashboard in Splunk Enterprise, displaying all 11 panels with live telemetry ingested from `ubuntu-p3` (`192.168.100.9`):

1. **Global Time Range:** Last 24 hours
2. **Total Security Events:** 2,224 events
3. **Failed SSH Attempts:** 25 events (Alert panel - Red)
4. **Successful SSH Logins:** 4 events (Success panel - Green)
5. **Sudo Activity:** 107 events (Warning panel - Yellow)
6. **Authentication Activity Over Time:** Line chart displaying time-series peaks
7. **Top Source IPs:** Horizontal bar chart (`192.168.100.1`, `192.168.100.6`, `192.168.100.9`)
8. **Linux Audit Events:** 854 events (`auditd` kernel records)
9. **Security Events by Log Source:** Comparative chart across `syslog`, `linux:audit`, and `linux_secure`
10. **SSH Brute Force Detection:** Threshold-based source IP bar chart
11. **Recent Security Events:** Tabular log viewer streaming live security records

---

*Evidence documented: 2026-09-11*
