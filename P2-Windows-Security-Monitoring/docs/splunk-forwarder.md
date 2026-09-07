# 📦 Splunk Universal Forwarder Setup Guide (Windows)

> **Document Status:** ⚪ **PLANNED / PENDING VERIFICATION**  
> **Component:** Forwarder Agent Deployment & Service Management  

---

## Planned Deployment Workflow

This guide will document the installation and operationalization of the **Splunk Universal Forwarder** on the Windows 11 endpoint.

### Steps to Document:
1. **MSI Package Installation:** Executing the official Windows installer (`splunkforwarder-*-x64-release.msi`) via CLI or GUI wizard.
2. **Service Account Configuration:** Running the forwarder under least-privilege service account credentials.
3. **Receiver Association:** Linking the forwarder to the central Splunk Enterprise indexer:
   ```cmd
   splunk.exe set deploy-poll <indexer_ip>:8089
   splunk.exe add forward-server <indexer_ip>:9997
   ```
4. **Configuration Validation:** Verifying `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`.
5. **Service Health Checks:** Monitoring forwarder heartbeat and connection state in `splunkd.log`.

*Verified configuration commands and terminal exhibits will be added once installation commences.*
