# 📜 P2 Automation & Verification Scripts

This directory contains PowerShell scripts designed to automate, configure, and verify the Splunk Universal Forwarder pipeline on the Windows 11 endpoint.

---

## Script Inventory

| Script | Purpose | Elevation Required |
|---|---|:---:|
| [`verify-splunk.ps1`](verify-splunk.ps1) | Performs end-to-end health checks on `SplunkForwarder` service, Sysmon service, `Event Log Readers` membership, `inputs.conf`, `outputs.conf`, and TCP port `9997` connectivity. | No (Recommended) |
| [`configure-forwarder.ps1`](configure-forwarder.ps1) | Idempotently configures `inputs.conf` and `outputs.conf`, adds the service account to `Event Log Readers`, creates timestamped backups, and restarts the forwarder only when modified. | **Yes** (Administrator) |
| [`install-forwarder.ps1`](install-forwarder.ps1) | Automated MSI installation helper that accepts the official Splunk Universal Forwarder MSI, configures admin credentials via secure prompt, applies baseline configuration, and triggers verification. | **Yes** (Administrator) |

---

## Quick Usage

### 1. Verify Pipeline Health:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\verify-splunk.ps1
```

### 2. Safely Apply or Update Configurations:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\configure-forwarder.ps1
```

### 3. Install from Splunk Universal Forwarder MSI:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\install-forwarder.ps1 -MsiPath "C:\path\to\splunkforwarder-10.4.3-windows-x64.msi"
```
