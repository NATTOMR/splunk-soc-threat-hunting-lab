# SPL Query Library — Brute-Force Detection & Investigation

> **Project:** P4 — Brute-Force Detection & Investigation  
> **Status:** Candidate Templates (Telemetry Validation Pending in P4.1 & P4.2)  
> **Rule:** No field names, index names, sourcetypes, or thresholds are assumed as final until verified against active lab data.

---

## Overview

This directory contains candidate Search Processing Language (SPL) detection templates designed for identifying, analyzing, and correlating brute-force authentication activity within Splunk Enterprise.

Because event formats differ based on endpoint platform and forwarder configuration (such as Windows XML rendering vs. Linux syslog formatting), these templates define the detection logic while explicitly marking the fields that must be validated during live implementation.

---

## Query Inventory

| File | Purpose | Detection Focus | Validation Sub-Issue |
|---|---|---|:---:|
| [`failed-authentication.spl`](failed-authentication.spl) | Base failure extraction | Parse and filter authentication failure events | [P4.1](../../issues/16) |
| [`high-volume-failures.spl`](high-volume-failures.spl) | Volume & velocity detection | Identify failure bursts exceeding rate thresholds | [P4.2](../../issues/17) |
| [`source-ip-analysis.spl`](source-ip-analysis.spl) | Source profiling & spray detection | Profile offending IPs; differentiate spray vs brute-force | [P4.2](../../issues/17) |
| [`targeted-account-analysis.spl`](targeted-account-analysis.spl) | Account vulnerability analysis | Detect repeated failed attempts against high-value accounts | [P4.2](../../issues/17) |
| [`failed-to-success-correlation.spl`](failed-to-success-correlation.spl) | Breach outcome correlation | Correlate failure bursts followed by logon success | [P4.3](../../issues/18) |

---

## Telemetry Fields Requiring Validation

Prior to executing these queries in production or lab validation, the following telemetry elements must be confirmed in sub-issue **P4.1**:

1. **Target Index:**
   - Windows Event Log: typically `index=windows`
   - Linux authentication logs: typically `index=linux_security`
2. **Sourcetype & Format:**
   - Windows Security Logs: `XmlWinEventLog:Security` (note: `renderXml = true` requires XML regex parsing if automatic field extraction is not configured)
   - Linux: `linux_secure` (`/var/log/auth.log`)
3. **Event Identifiers:**
   - Windows Failure: Event ID `4625`
   - Windows Success: Event ID `4624`
   - Linux Failure: `"Failed password"`
   - Linux Success: `"Accepted password"`
4. **Key Fields:**
   - User account: `TargetUserName` / `target_user` / `username`
   - Source IP: `IpAddress` / `src_ip`
   - Logon Type: `LogonType` (2=Interactive, 3=Network, 10=RemoteInteractive)
   - Status / SubStatus: `Status` (e.g. `0xC000006D`), `SubStatus` (e.g. `0xC000006A` for bad password)
5. **Threshold Parameters:**
   - Failure velocity threshold (e.g., `>= 10` attempts within 5 minutes)
   - Correlation max span (e.g., `maxspan=15m`)
