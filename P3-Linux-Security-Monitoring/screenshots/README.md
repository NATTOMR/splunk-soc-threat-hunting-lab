# 📸 P3 Visual Evidence & Screenshots

[![Evidence Status](https://img.shields.io/badge/Visual%20Evidence-Verified%20(4%20Exhibits)-brightgreen.svg)](#-screenshot-catalog)
[![SIEM Platform](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%2010.4.3-orange.svg)](https://www.splunk.com/)
[![Target](https://img.shields.io/badge/Endpoint-Ubuntu%2024.04%20LTS-E95420.svg)](#-linux-endpoint--universal-forwarder)

This directory serves as the repository of visual evidence and verification artifacts for **Project P3: Linux Security Monitoring with Splunk**. Every exhibit directly validates operational milestones in the laboratory environment.

---

## 📑 Screenshot Catalog

| Exhibit ID | File | Target Component | Description / Milestone Evidence |
|:---:|---|---|---|
| **EX-01** | [`p3-01-ubuntu-p3-ssh-terminal-ip-verification.png`](p3-01-ubuntu-p3-ssh-terminal-ip-verification.png) | Ubuntu P3 Endpoint | Terminal session confirming successful SSH login to `natto@ubuntu-p3` (`127.0.0.1:2223`), verifying IPv4 address `192.168.100.9` on interface `enp0s3`, system load, and kernel version. |
| **EX-02** | [`p3-02-wazuh-splunk-server-ssh-terminal-verification.png`](p3-02-wazuh-splunk-server-ssh-terminal-verification.png) | Splunk Enterprise Host | Terminal session confirming SSH login to `natto@wazuh-server` (`127.0.0.1:2222`), verifying IPv4 address `192.168.100.7` on interface `enp0s3` hosting the central Splunk SIEM. |
| **EX-03** | [`p3-03-kali-attacker-ssh-terminal-verification.png`](p3-03-kali-attacker-ssh-terminal-verification.png) | Kali Attacker Node | Terminal session confirming SSH login to `kali@kali` (`127.0.0.1:2224`), verifying attacker host availability for reconnaissance and authentication testing. |
| **EX-04** | [`p3-04-linux-security-monitoring-dashboard.png`](p3-04-linux-security-monitoring-dashboard.png) *(also available as `linux-security-monitoring-dashboard.png`)* | Splunk Web Dashboard | Full-screen view of the **Linux Security Monitoring** operational dashboard in Splunk Enterprise, displaying all 11 panels populated with live telemetry (2,224 Total Events, 25 Failed SSH Attempts, 4 Successful Logins, 107 Sudo Events, 854 Audit Events, Top Source IPs, and SSH Brute Force Detection). |

---

## 🔗 Cross-Document References

All exhibits above are integrated directly into the technical progress and architectural documentation:
- [P3 Project README](../README.md)
- [P3 Architecture Overview](../docs/architecture.md)
- [P3 Testing & Validation Guide](../docs/testing.md)
- [P3 Progress Log](../../docs/P3-LINUX-SECURITY-MONITORING.md)
