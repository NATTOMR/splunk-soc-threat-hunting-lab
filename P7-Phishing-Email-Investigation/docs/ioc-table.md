# Indicators of Compromise (IOC) Catalog — Phishing Campaign

> **Incident Reference:** INC-2026-P7-001  
> **Investigation Date:** September 14, 2026  
> **Defanged Status:** All URLs, domains, and IPs in this document are defanged for safe storage and transmission.

---

## 1. Network & Host IOCs

| Indicator Type | Defanged Value | Attribution / Threat Description | Severity |
|---|---|---|:---:|
| **IP Address** | `185.220.101[.]45` | Adversary Mail Relay / Password Harvest Server | High |
| **IP Address** | `194.26.29[.]112` | Payload Hosting & ISO Dropper Distribution | Critical |
| **IP Address** | `91.240.118[.]22` | Mass-Blast HR Phishing Origin | High |
| **IP Address** | `45.142.166[.]7` | Dual-Extension Malware Dropper Host | High |
| **Domain** | `micros0ft-support[.]com` | Homoglyph Spoofing Domain | High |
| **Domain** | `login-micros0ft-verify[.]com` | Credential Harvesting Landing Page | Critical |
| **Domain** | `onedrive-secure-docs[.]info` | SharePoint / OneDrive Cloud Phishing Lure | High |
| **Domain** | `hr-internal-portal[.]net` | HR Impersonation Domain (Mass Blast) | High |
| **Domain** | `docusign-docs[.]online` | Electronic Signature Impersonation | High |
| **Domain** | `quick-invoices-secure[.]org` | Fraudulent Invoicing Lure | Medium |

---

## 2. File & Attachment Hashes (SHA-256)

| File Name | File Size | SHA-256 Hash | Threat Classification |
|---|---|---|---|
| `Shipping_Manifest.pdf.exe` | 812 KB | `7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069` | Dual-extension PE executable |
| `DocuSign_Contract_Review.iso` | 1420 KB | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` | ISO Container (Mark-of-the-Web evasion) |
| `INVOICE_OCT2026.xlsm` | 328 KB | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Weaponized VBA macro workbook |
| `Direct_Deposit_Receipt.vbs` | 42 KB | `8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4` | VBScript downloader |

---

## 3. Malicious URLs & Query Endpoints

| Defanged URL | Lure Context | Associated Technique |
|---|---|:---:|
| `hxxp://login-micros0ft-verify[.]com/auth/login.php?user=sarah` | Microsoft 365 Password Expiry | T1566.002 |
| `hxxp://194.26.29[.]112:8080/sharepoint/token?auth=98a7` | SharePoint Document Token Lure | T1566.002 |
| `hxxp://hr-internal-portal[.]net/update` | HR Policy Mass-Blast | T1566.002 |
| `hxxp://bit[.]ly/3xPayrollVerify` | Direct Deposit / Payroll Obfuscated URL | T1566.002 |

---

## 4. Adversary Email Addresses

| Email Address | Type | Observed Subject |
|---|---|---|
| `admin@micros0ft-support[.]com` | External Homoglyph | Microsoft 365 Password Expiration Notice |
| `ceo.corporate.exec77@gmail.com` | Freemail Whaling Spoof | URGENT CONFIDENTIAL: Wire Transfer Authorization |
| `humanresources@hr-internal-portal[.]net` | Mass-Blast Impersonation | Action Required: Mandatory Q3 Security & Employee Policy |
| `documents@docusign-docs[.]online` | Lure Impersonation | DocuSign Completed: NDA Signature Verification Pending |
| `courier@dhl-express-tracking-portal[.]com` | Logistics Impersonation | Delivery Notification: Package on Hold |
