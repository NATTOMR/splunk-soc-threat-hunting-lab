# ⚙️ P2 Production Configuration Templates

This directory contains clean, documented, and sanitized copies of the working Splunk configurations used across the Windows 11 endpoint and Ubuntu Splunk Enterprise server.

---

## Configuration Inventory

| Configuration File | Host Target | Target Path | Purpose |
|---|---|---|---|
| [`inputs.conf`](inputs.conf) | Windows 11 (`192.168.100.8`) | `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf` | Ingests Windows Security, System, Application, and Sysmon event channels using XML rendering. |
| [`outputs.conf`](outputs.conf) | Windows 11 (`192.168.100.8`) | `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf` | Directs forwarded event streams to central receiver `192.168.100.7:9997`. |
| [`indexes.conf`](indexes.conf) | Ubuntu Splunk (`192.168.100.7`) | `/opt/splunk/etc/system/local/indexes.conf` | Defines dedicated database storage containers for `windows` and `sysmon` indexes. |

---

## Deployment Instructions

### Applying Forwarder Configurations on Windows 11:
You can automatically deploy these configurations using the included PowerShell script:
```powershell
powershell.exe -ExecutionPolicy Bypass -File ..\scripts\configure-forwarder.ps1
```

### Applying Index Configurations on Ubuntu Splunk Enterprise:
Copy `indexes.conf` into `/opt/splunk/etc/system/local/indexes.conf` or create the indexes via Splunk CLI:
```bash
sudo -u splunk /opt/splunk/bin/splunk add index windows
sudo -u splunk /opt/splunk/bin/splunk add index sysmon
sudo -u splunk /opt/splunk/bin/splunk restart
```
