# SOC Incident Investigation Report: Web Application Threat Detection

> **Incident ID:** INC-2026-P6-001  
> **Investigation Title:** Multi-Vector Web Attack Campaign: SQL Injection, Path Traversal, and Automated Tool Scanning  
> **Investigating Analyst:** Natto Chakma  
> **Date:** September 14, 2026  
> **Target Asset:** Ubuntu Web Server (`ubuntu-p3` / `192.168.100.9`) running Apache/2.4  
> **Originating Attacker IP:** Kali Linux (`192.168.100.6`)  
> **Severity:** **HIGH**  
> **Incident Status:** Contained / Documented  

---

## 1. Executive Summary

During operational SOC threat monitoring across enterprise perimeter and web services, the Splunk SIEM platform detected an aggressive, multi-vector web application reconnaissance and exploitation campaign targeting the Apache2 web server hosted on `ubuntu-p3` (`192.168.100.9`). 

Telemetry forwarded in real time by the **Splunk Universal Forwarder** (`/var/log/apache2/access.log`, `sourcetype=access_combined`, `index=web`) confirmed an orchestrated attack sequence launched from the Kali Linux adversary endpoint (`192.168.100.6`):

1. **SQL Injection Probing (T1190):** Adversary submitted union-based and authentication-bypass SQL payloads via HTTP GET parameters (`/?id=1'+UNION+SELECT...`, `/login.php?user=admin'OR'1'='1`).
2. **Path Traversal & Local File Inclusion (T1083 / T1005):** Adversary attempted path traversal attacks seeking sensitive system files (`/download.php?file=../../../../etc/passwd`, `/view?page=..%2f..%2f..%2fetc%2fshadow`, `/include?file=../../../../windows/win.ini`).
3. **Automated Vulnerability Tool Enumeration (T1595):** Multiple automated offensive scanners were detected probing web endpoints, including `Nikto/2.1.6`, `sqlmap/1.6.12#stable`, `gobuster/3.1.0`, `DirBuster-1.0-RC1`, and `Nmap Scripting Engine`.
4. **Directory Fuzzing & 4xx Error Spikes:** Systematic brute-force probing of administrative and configuration endpoints generated an abnormal surge of HTTP 404 responses.

All activities were captured, parsed with URL decoding, categorized, and visualized on the operational **P6 — Web Attack Detection & Application Security** SOC dashboard.

---

## 2. Incident Scope & Telemetry Architecture

| Parameter | Forensic Detail |
|---|---|
| **Target Web Host** | `ubuntu-p3` (`192.168.100.9`) |
| **Web Daemon** | Apache HTTP Server 2.4.58 (Ubuntu) |
| **Monitored Telemetry Path** | `/var/log/apache2/access.log` |
| **Splunk Ingestion Pipeline** | Splunk Universal Forwarder ➔ Splunk Enterprise (`192.168.100.7:9997`) |
| **Splunk Index & Sourcetype** | `index=web` / `sourcetype=access_combined` |
| **Adversary Host** | `192.168.100.6` (Kali Linux) |
| **Total Ingested Events** | 10+ categorized exploitation events |
| **Identified Exploitation Classes** | SQL Injection, Path Traversal / LFI, Vulnerability Scanners |
| **HTTP Status Code Profile** | HTTP 200 (OK), HTTP 404 (Not Found) |

---

## 3. Telemetry Evidence & Detection Logic

Because attackers frequently percent-encode malicious payloads to evade perimeter inspection (e.g., `%27%20OR%201=1`, `%2e%2e%2f`), SPL detection rules normalize the request URI using `urldecode(uri)` before applying signature heuristics:

```spl
index=web sourcetype=access_combined
| eval clean_uri=coalesce(urldecode(uri), uri)
| eval attack_type=case(
    match(clean_uri, "(?i)(union\s+select|select\s+.*\s+from|'\s*or\s*'1'='1|information_schema|order\s+by\s+\d+|sleep\(\d+\)|benchmark\(|waitfor\s+delay|drop\s+table)"), "SQL Injection (T1190)",
    match(clean_uri, "(?i)(<script|%3Cscript|javascript:|onerror|onload|alert|document\.cookie|eval\(|<img|<svg)"), "Cross-Site Scripting (T1059.007)",
    match(clean_uri, "(?i)(\.\./|\.\.\\|\.\.%2f|\.\.%5c|/etc/passwd|/etc/shadow|boot\.ini|win\.ini)"), "Directory Traversal / LFI (T1083)",
    match(useragent, "(?i)(nikto|sqlmap|gobuster|dirbuster|nmap|masscan|wpscan|hydra)"), "Vulnerability Scanner (T1595)",
    status >= 400, "Client Error (HTTP " . status . ")",
    true(), "Benign Request"
  )
| search attack_type!="Benign Request"
| eval formatted_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table formatted_time, clientip, method, uri, status, useragent, attack_type
| rename formatted_time as "Timestamp", clientip as "Attacker IP", method as "Method", uri as "Target URI", status as "HTTP Status", useragent as "User-Agent", attack_type as "Attack Classification"
| sort - "Timestamp"
```

### Adversary Execution & Raw Web Server Responses

During the simulated engagement, the adversary executed XSS payloads directly against the web application endpoints. Apache 2.4 responded with HTTP 404 status codes as preserved in the terminal session:

```html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.58 (Ubuntu) Server at 192.168.100.9 Port 80</address>
</body></html>
```

### Forensic Event Stream Sample

```text
2026-09-14 02:13:20  192.168.100.6  GET  /user?id=1%3Cscript%3Ealert...             404  curl/8.20.0            Cross-Site Scripting (T1059.007)
2026-09-14 02:13:20  192.168.100.6  GET  /profile?bio=javascript:alert(1)           404  curl/8.20.0            Cross-Site Scripting (T1059.007)
2026-09-14 02:13:20  192.168.100.6  GET  /feedback?name=%3Csvg/onload=alert(1)%3E   404  curl/8.20.0            Cross-Site Scripting (T1059.007)
2026-09-14 02:13:20  192.168.100.6  GET  /comment.php?msg=%3Cimg%20src=x%20...      404  curl/8.20.0            Cross-Site Scripting (T1059.007)
2026-09-14 02:13:19  192.168.100.6  GET  /search.php?q=%3Cscript%3Ealert(1)...      404  curl/8.20.0            Cross-Site Scripting (T1059.007)
2026-09-14 02:00:49  192.168.100.6  GET  /                                          200  Nmap Scripting Engine  Vulnerability Scanner (T1595)
2026-09-14 02:00:48  192.168.100.6  GET  /config                                    404  DirBuster-1.0-RC1      Vulnerability Scanner (T1595)
2026-09-14 02:00:48  192.168.100.6  GET  /admin                                     404  gobuster/3.1.0         Vulnerability Scanner (T1595)
2026-09-14 02:00:48  192.168.100.6  GET  /login                                     404  sqlmap/1.6.12#stable   Vulnerability Scanner (T1595)
2026-09-14 02:00:48  192.168.100.6  GET  /test/                                     404  Nikto/2.1.6            Vulnerability Scanner (T1595)
2026-09-14 02:00:37  192.168.100.6  GET  /include?file=../../../../windows/win.ini  404  curl/8.20.0            Directory Traversal / LFI (T1083)
2026-09-14 02:00:37  192.168.100.6  GET  /view?page=..%2f..%2f..%2fetc%2fshadow     404  curl/8.20.0            Directory Traversal / LFI (T1083)
2026-09-14 02:00:36  192.168.100.6  GET  /download.php?file=../../../../etc/passwd  404  curl/8.20.0            Directory Traversal / LFI (T1083)
2026-09-14 01:58:37  192.168.100.6  GET  /login.php?user=admin'OR'1'='1             404  curl/8.20.0            SQL Injection (T1190)
2026-09-14 01:58:37  192.168.100.6  GET  /?id=1'+UNION+SELECT+1,username...         200  curl/8.20.0            SQL Injection (T1190)
```

---

## 4. Operational Dashboard Verification

All ingested web security telemetry and correlated alerts were rendered on the **"P6 — Web Attack Detection & Application Security"** SOC dashboard:

![P6 Web Threat Dashboard](../screenshots/p6-01-web-threat-dashboard.png)

### Dashboard Metrics at Triage:
- **Total Ingested Web Requests:** `15`
- **SQL Injection Attempts:** `2` (Flagged High-Severity Red Alert)
- **Cross-Site Scripting (XSS) Payloads:** `5` (Flagged High-Severity Red Alert)
- **Path Traversal & LFI Probes:** `3` (Flagged High-Severity Red Alert)
- **Scanner User-Agents:** `5` (Flagged High-Severity Yellow/Red Alert)
- **Request Velocity & Error Timeline:** Illustrated sharp surge in HTTP 404 responses during scanner, XSS, and fuzzing execution.
- **Top Client Sources:** 100% of malicious traffic mapped directly to adversary host `192.168.100.6`.

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Application & Forensic Observation |
|---|---|:---:|---|
| **Initial Access** | Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | SQL Injection attempts against parameters `id` and `user` to bypass authentication |
| **Reconnaissance** | Active Scanning: Vulnerability Scanning | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Automated scans using Nikto, sqlmap, gobuster, and Nmap Scripting Engine |
| **Discovery** | File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | Directory traversal probes querying `../../../../etc/passwd` and `win.ini` |
| **Collection** | Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Attempts to read system authentication hashes via `/etc/shadow` via URL encoded traversal |
| **Execution** | Command and Scripting Interpreter: JavaScript | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | Cross-Site Scripting probes injecting `<script>` and `onerror` event triggers |

---

## 6. Analyst Recommendations & Defense-in-Depth Remediation

1. **Deploy a Web Application Firewall (WAF):**
   * Implement **ModSecurity** with OWASP Core Rule Set (CRS) on Apache2:
     ```bash
     sudo apt install -y libapache2-mod-security2
     sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
     sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
     sudo systemctl restart apache2
     ```
2. **Enforce Parameterized SQL Queries & Prepared Statements:**
   * Require all backend database interactions to use parameterized prepared statements (e.g., PDO in PHP, SQLAlchemy in Python) to prevent SQL syntax manipulation.
3. **Path Traversal Mitigation:**
   * Disallow direct filesystem path concatenation from user input. Implement strict basename whitelisting and chroot execution environments.
4. **Block Automated Offensive Scanner User-Agents:**
   * Configure Apache access control rules or reverse-proxy policies to automatically drop requests bearing known vulnerability scanner User-Agents (`Nikto`, `sqlmap`, `gobuster`, `DirBuster`).
5. **Operationalize Splunk Real-Time Alerting:**
   * Save [`sqli-detection.spl`](../queries/sqli-detection.spl) and [`directory-traversal.spl`](../queries/directory-traversal.spl) as high-priority real-time alerts notifying the SOC on Slack or PagerDuty.
