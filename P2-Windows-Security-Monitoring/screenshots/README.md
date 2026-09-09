# 📸 P2 Visual Evidence & Screenshots

[![Evidence Status](https://img.shields.io/badge/Visual%20Evidence-Verified%20(19%20Exhibits)-brightgreen.svg)](#-screenshot-catalog)
[![SIEM Platform](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%2010.4.3-orange.svg)](https://www.splunk.com/)
[![Target](https://img.shields.io/badge/Endpoint-Windows%2011-0078D6.svg)](#-windows-11-endpoint--universal-forwarder)

This directory serves as the immutable repository of photographic evidence and verification artifacts for **Project P2: Windows Security Monitoring & Splunk SOC Integration**. Every exhibit corresponds directly to verified milestones executed in the laboratory environment.

---

## 📑 Screenshot Catalog

### 🖥️ Windows 11 Endpoint & Universal Forwarder

| Exhibit ID | File | Target Component | Description / Milestone Evidence |
|:---:|---|---|---|
| **EX-01** | [`p2-01-windows11-sysmon-service-uf-download.png`](p2-01-windows11-sysmon-service-uf-download.png) | Windows 11 / Sysmon / UF | Verification of running `Sysmon64` and `VBoxService` services, along with initial forwarder MSI download via PowerShell. |
| **EX-02** | [`p2-02-virtualbox-labnetwork-windows11-vm.png`](p2-02-virtualbox-labnetwork-windows11-vm.png) | VirtualBox / LabNetwork | VirtualBox Manager displaying `Windows 11` VM attached to `NAT Network, 'LabNetwork'`. |
| **EX-03** | [`p2-03-windows11-uf-msi-download-complete.png`](p2-03-windows11-uf-msi-download-complete.png) | Windows 11 / Package Fetch | Completion of `curl.exe -L` download for `splunkforwarder-10.4.3-x64.msi` (152 MB). |
| **EX-04** | [`p2-04-windows11-uf-setup-wizard-license.png`](p2-04-windows11-uf-setup-wizard-license.png) | Universal Forwarder Setup | Forwarder setup wizard: EULA acceptance, default path (`C:\Program Files\SplunkUniversalForwarder`), and On-Premises selection. |
| **EX-05** | [`p2-05-windows11-uf-setup-admin-credentials.png`](p2-05-windows11-uf-setup-admin-credentials.png) | Forwarder Credentials | Creation of local administrator service account (`natto`) for the forwarder agent. |
| **EX-06** | [`p2-06-windows11-uf-setup-ready-to-install.png`](p2-06-windows11-uf-setup-ready-to-install.png) | Forwarder Setup Wizard | Wizard prompt confirming readiness to install with elevated UAC permissions. |
| **EX-07** | [`p2-07-windows11-uf-setup-install-progress.png`](p2-07-windows11-uf-setup-install-progress.png) | Forwarder Setup Wizard | Active MSI installation execution copying core forwarder binaries and libraries. |
| **EX-08** | [`p2-08-windows11-uf-install-directory-verify.png`](p2-08-windows11-uf-install-directory-verify.png) | Filesystem Verification | PowerShell verification of root directory tree in `C:\Program Files\SplunkUniversalForwarder`. |
| **EX-09** | [`p2-09-windows11-uf-etc-directory-structure.png`](p2-09-windows11-uf-etc-directory-structure.png) | Filesystem Verification | Directory listing of `etc/` configuration path (`apps`, `system`, `splunk-launch.conf`). |
| **EX-10** | [`p2-10-windows11-uf-local-configuration-paths.png`](p2-10-windows11-uf-local-configuration-paths.png) | Configuration Trees | Recursive discovery of `local` configuration folders across `etc/system/local` and `etc/apps/`. |

---

### 🐧 Ubuntu Server & Storage Verification

| Exhibit ID | File | Target Component | Description / Milestone Evidence |
|:---:|---|---|---|
| **EX-11** | [`p2-11-ubuntu-preinstall-disk-space-df.png`](p2-11-ubuntu-preinstall-disk-space-df.png) | Storage Baseline | `df -h` execution on `wazuh-server` verifying 27 GB available on root partition `/dev/mapper/ubuntu--vg-ubuntu--lv`. |
| **EX-12** | [`p2-12-ubuntu-storage-lvm-vgs-pvs-verify.png`](p2-12-ubuntu-storage-lvm-vgs-pvs-verify.png) | Volume Management | `lsblk`, `sudo vgs`, and `sudo pvs` verifying physical volumes and LVM storage configuration. |
| **EX-13** | [`p2-13-ubuntu-ssh-service-status.png`](p2-13-ubuntu-ssh-service-status.png) | Remote Administration | `systemctl status ssh` validating active OpenSSH listener on port 22/tcp. |
| **EX-14** | [`p2-14-ubuntu-initial-ufw-firewall-status.png`](p2-14-ubuntu-initial-ufw-firewall-status.png) | Firewall Hardening | `sudo ufw status` verifying baseline rate-limiting on SSH port 22. |

---

### ⚙️ Splunk Enterprise Installation & Management

| Exhibit ID | File | Target Component | Description / Milestone Evidence |
|:---:|---|---|---|
| **EX-15** | [`p2-15-ubuntu-create-splunk-service-user.png`](p2-15-ubuntu-create-splunk-service-user.png) | Least Privilege | Execution of `useradd -m -s /bin/bash splunk` and password provisioning on Ubuntu. |
| **EX-16** | [`p2-16-ubuntu-splunk-enterprise-deb-download.png`](p2-16-ubuntu-splunk-enterprise-deb-download.png) | Package Fetch | `wget` completion for `splunk-10.4.3-linux-amd64.deb` (1.23 GB package). |
| **EX-17** | [`p2-17-splunk-web-login-port-18000.png`](p2-17-splunk-web-login-port-18000.png) | Splunk Web UI | Browser access to Splunk Enterprise Web login screen via host port `18000` (`http://127.0.0.1:18000`). |
| **EX-18** | [`p2-18-splunk-web-admin-dashboard-home.png`](p2-18-splunk-web-admin-dashboard-home.png) | Splunk Web UI | Authenticated Splunk Administrator Home workbench confirming fully operational web interface. |

---

### 🛡️ Receiver & Firewall Port Configuration

| Exhibit ID | File | Target Component | Description / Milestone Evidence |
|:---:|---|---|---|
| **EX-19** | [`p2-19-splunk-receiver-listen-9997-ufw-rules.png`](p2-19-splunk-receiver-listen-9997-ufw-rules.png) | Ingestion Port & Firewall | Removal of accidental self-forwarder, execution of `enable listen 9997`, socket check via `ss -lntp`, and `ufw` allow rule for `9997/tcp` from `192.168.100.0/24`. |

---

## 🔗 Cross-Document References

All exhibits above are integrated directly into the technical progress and architectural documentation:
- [P2 Progress & Infrastructure Log](../../docs/P2-SPLUNK-SOC-INTEGRATION.md)
- [P2 Architecture Overview](../docs/architecture.md)
- [Windows Forwarder Deployment Guide](../docs/splunk-forwarder.md)
