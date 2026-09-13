# SPL Query Library — Web Attack Detection

> **Project:** P6 — Web Attack Detection with Splunk  
> **Status:** ✅ Production Validated  
> **Target Index:** `index=web`  
> **Sourcetype:** `access_combined`

---

## Overview

This directory preserves production-grade Search Processing Language (SPL) queries designed to detect, classify, and correlate common web application attacks, malicious scanners, and reconnaissance behavior from web server access logs.

---

## Query Inventory

| Query File | Primary Threat Category | Detection Mechanism | MITRE ATT&CK |
|---|---|---|:---:|
| [`sqli-detection.spl`](sqli-detection.spl) | SQL Injection (SQLi) | Decoded URI regex matching SQL operators (`UNION SELECT`, `' OR '1'='1`) | **T1190** |
| [`xss-detection.spl`](xss-detection.spl) | Cross-Site Scripting (XSS) | URI regex matching script tags, event handlers (`<script>`, `onerror=`) | **T1059.007** |
| [`directory-traversal.spl`](directory-traversal.spl) | Path Traversal / LFI | URI matching dot-dot-slash sequence (`../`, `..%2f`) and sensitive files | **T1083** |
| [`scanner-user-agents.spl`](scanner-user-agents.spl) | Malicious Scanner Profiling | User-Agent signature matching (`Nikto`, `sqlmap`, `gobuster`) | **T1595** |
| [`web-recon-error-spikes.spl`](web-recon-error-spikes.spl) | Directory Fuzzing / 4xx Spikes | Time-windowed error rate calculation (`span=5m`, `status>=400`) | **T1083** |
