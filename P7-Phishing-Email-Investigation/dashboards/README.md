# SOC Dashboard — Phishing Email Investigation

> **Project:** P7 — Phishing Email Investigation with Splunk  
> **Dashboard File:** [`phishing-investigation-dashboard.xml`](phishing-investigation-dashboard.xml)  
> **Theme:** Dark Mode  
> **Target Index:** `index=email` (`sourcetype="email:security"`)

---

## Overview

The **P7 — Phishing Email Investigation & Security Operations** dashboard provides real-time situational awareness and rapid forensic triage for security analysts investigating suspicious emails, business email compromise (BEC), and credential harvesting campaigns.

---

## Panel Architecture

| Row | Panel Title | Visualization | Purpose |
|:---:|---|:---:|---|
| **1** | Total Emails Ingested | Single Value KPI | Total stream volume across monitored gateway |
| **1** | Phishing Threats Flagged | Single Value KPI (Red) | Count of high-risk messages (`risk_score >= 75`) |
| **1** | Malicious Attachments | Single Value KPI (Red) | Dangerous files (`.exe`, `.iso`, `.xlsm`, `.vbs`, dual-ext) |
| **1** | Malicious / Phishing URLs | Single Value KPI (Orange/Red) | Credential harvesting links and IP-literal destinations |
| **1** | SPF / DKIM / DMARC Failures | Single Value KPI (Red) | Authentication alignment failures and spoofing attempts |
| **2** | Attack Vector Distribution | Pie Chart | Breakdown of phishing techniques across detected threats |
| **2** | Enforcement Actions | Bar Chart | Distribution of Delivered vs. Quarantined vs. Blocked |
| **2** | Authentication Breakdown | Column Chart | SPF/DKIM/DMARC alignment status ratios |
| **3** | Phishing Incident Triage Queue | Interactive Table | Sorted priority queue for analyst investigation |
| **4** | Weaponized Files & Hashes | Table | Extracted forensic metadata: file names, sizes, SHA-256 hashes |
| **4** | Extracted Malicious URLs | Table | Harvested phishing landing pages and external redirectors |

---

## Installation Guide

1. In Splunk Web (`http://192.168.100.7:8000`), navigate to **Dashboards** > **Create New Dashboard**.
2. Title the dashboard: `P7 — Phishing Email Investigation & Security Operations`.
3. Select **Classic Dashboards** > Switch to **Source** mode.
4. Paste the raw content of [`phishing-investigation-dashboard.xml`](phishing-investigation-dashboard.xml) and click **Save**.
