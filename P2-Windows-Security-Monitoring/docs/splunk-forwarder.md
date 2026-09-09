# 📦 Splunk Universal Forwarder Setup Guide (Windows)

> **Document Status:** 🟡 **IN PROGRESS (Installer Executed & Scaffolding Verified)**  
> **Component:** Forwarder Agent Deployment & Service Management  
> **Target Endpoint:** Windows 11 (`192.168.100.8`)  
> **Target Receiver:** Ubuntu 24.04 (`192.168.100.7:9997`)  

---

## Deployment Workflow & Verified Exhibits

This guide documents the installation and operationalization of the **Splunk Universal Forwarder** on the Windows 11 endpoint.

### Steps & Verification Evidence:

1. **MSI Package Download:**
   - Official Windows installer fetched via `curl.exe`:
     ```powershell
     curl.exe -L "https://download.splunk.com/products/universalforwarder/releases/10.4.3/windows/splunkforwarder-10.4.3-4174a2deda5d-windows-x64.msi" -o "splunkforwarder-10.4.3.msi"
     ```
   - **Exhibit:** [`p2-03-windows11-uf-msi-download-complete.png`](../screenshots/p2-03-windows11-uf-msi-download-complete.png)

2. **Wizard Configuration & EULA:**
   - Accepted license agreement and specified On-Premises Splunk Enterprise target.
   - **Exhibit:** [`p2-04-windows11-uf-setup-wizard-license.png`](../screenshots/p2-04-windows11-uf-setup-wizard-license.png)

3. **Service Account Configuration:**
   - Configured dedicated service administrator account (`natto`).
   - **Exhibit:** [`p2-05-windows11-uf-setup-admin-credentials.png`](../screenshots/p2-05-windows11-uf-setup-admin-credentials.png)

4. **Installation Execution:**
   - Installed binaries into `C:\Program Files\SplunkUniversalForwarder`.
   - **Exhibits:**
     - [`p2-06-windows11-uf-setup-ready-to-install.png`](../screenshots/p2-06-windows11-uf-setup-ready-to-install.png)
     - [`p2-07-windows11-uf-setup-install-progress.png`](../screenshots/p2-07-windows11-uf-setup-install-progress.png)

5. **Filesystem & Directory Structure Verification:**
   - Confirmed directory layout (`bin`, `etc`, `lib`, `var`).
   - Verified configuration paths in `etc/system/local` and `etc/apps/`.
   - **Exhibits:**
     - [`p2-08-windows11-uf-install-directory-verify.png`](../screenshots/p2-08-windows11-uf-install-directory-verify.png)
     - [`p2-09-windows11-uf-etc-directory-structure.png`](../screenshots/p2-09-windows11-uf-etc-directory-structure.png)
     - [`p2-10-windows11-uf-local-configuration-paths.png`](../screenshots/p2-10-windows11-uf-local-configuration-paths.png)

6. **Next Step — Receiver Association & Output Configuration:**
   - Link forwarder to central Splunk Enterprise indexer:
     ```cmd
     splunk.exe add forward-server 192.168.100.7:9997
     ```
   - Validate `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`.
   - Configure input channels in `inputs.conf`.
