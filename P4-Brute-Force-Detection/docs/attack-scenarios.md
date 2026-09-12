# P4 Attack Scenarios — Brute-Force & Credential Abuse

> **Project:** P4 — Brute-Force Detection & Investigation  
> **Status:** Scenarios Defined (Controlled Lab Simulation Execution Scheduled in P4.1)

---

## Overview

Brute-force authentication attacks involve systematic attempts to gain unauthorized access by guessing credentials. Adversaries employ different variations ranging from aggressive high-velocity attempts to distributed low-and-slow password spraying designed to evade static thresholds.

This document details the six primary attack scenarios analyzed in Project P4.

---

## Scenario Catalog

### Scenario 1: High-Volume Authentication Failures (Velocity Attack)
- **Threat Vector:** Rapid automated dictionary attack or credential stuffing attempt against an endpoint service (e.g., RDP, SMB, SSH, WinRM).
- **Adversary Behavior:** Submits a large volume of login attempts in a short burst (e.g., tens or hundreds within minutes).
- **Telemetry Indicators:**
  - Sharp upward spike in EventID `4625` (Windows) or `"Failed password"` (Linux).
  - Short inter-arrival time between consecutive attempts (< 2 seconds).
  - High error rate with status code `0xC000006A` (bad password) or `0xC0000064` (user does not exist).
- **Tunable Parameters:**
  - Bucket interval: `span=5m`
  - Threshold: `>= 10` failures per interval per source host.

---

### Scenario 2: Multiple Failed Logins Against a Single Account (Targeted Guessing)
- **Threat Vector:** Targeted credential guessing against high-privilege or known sensitive accounts (e.g., `Administrator`, `root`, domain admins, executive user accounts).
- **Adversary Behavior:** Repeatedly submits different password guesses targeting one specific username.
- **Telemetry Indicators:**
  - High concentration of failures where `TargetUserName` is identical.
  - Risk of triggering domain or local account lockout policies.
  - SubStatus codes: `0xC000006A` (bad password), potentially transitioning to `0xC0000234` (account locked out).
- **Tunable Parameters:**
  - Target account: Specific account name or privileged account list.
  - Threshold: `>= 5` failures within a 15-minute window for a single account.

---

### Scenario 3: Multiple Accounts Targeted From One Source (Horizontal Password Spraying)
- **Threat Vector:** Horizontal password spray (T1110.003).
- **Adversary Behavior:** Attacker attempts one or two common passwords (e.g., `Summer2026!`, `Welcome123`) across many different accounts from a single host IP to avoid locking any single account.
- **Telemetry Indicators:**
  - Low failure count per account, but high distinct count of targeted accounts (`dc(target_user) >= 3`) from the same `src_ip`.
  - Failures occurring closely together across diverse users.
- **Tunable Parameters:**
  - Source IP aggregation: `by src_ip`
  - Unique targets threshold: `dc(target_user) >= 3` or `dc(target_user) >= 5`.

---

### Scenario 4: Repeated Authentication Attempts Within Defined Time Windows (Low & Slow)
- **Threat Vector:** Evasive brute-force attempting to fly under standard threshold-based SIEM alerts by throttling attempt rates (e.g., 1 attempt every few minutes).
- **Adversary Behavior:** Intermittent failures spaced across extended durations (e.g., several hours or days).
- **Telemetry Indicators:**
  - Sustained elevated failure rate over extended observation windows (e.g., earliest=-24h).
  - Uniform inter-arrival spacing between attempts.
- **Tunable Parameters:**
  - Observation window: 1h to 24h.
  - Evaluation metric: Cumulative failures over time window > baseline standard deviations.

---

### Scenario 5: Failed Authentication Followed by Successful Authentication (Compromise Indicator)
- **Threat Vector:** Successful brute-force / credential breach.
- **Adversary Behavior:** Attacker generates multiple failures, identifies the correct password, and successfully authenticates.
- **Telemetry Indicators:**
  - Sequence of EventID `4625` (failure) immediately followed by EventID `4624` (success) for the same `target_user` and `src_ip`.
  - In Linux: Multiple `"Failed password"` entries followed by `"Accepted password"` from the same source IP and username within a tight time delta.
  - Immediate post-logon activity (process creation, privilege escalation, file access).
- **Tunable Parameters:**
  - Failure prerequisite: `>= 3` prior failures.
  - Correlation max span: `<= 15m` between last failure and successful logon.

---

### Scenario 6: Suspicious Authentication Patterns & Contextual Anomalies
- **Threat Vector:** Rogue network logon or unexpected logon type.
- **Adversary Behavior:** Authentication originating from unexpected network segments, off-hours, or utilizing unusual logon types:
  - Logon Type 3 (Network logon - SMB/RPC)
  - Logon Type 10 (RemoteInteractive - RDP)
- **Telemetry Indicators:**
  - Anomalous `LogonType` relative to historical baseline.
  - Source workstation or IP outside authorized administrative subnets.
- **Tunable Parameters:**
  - Whitelist of authorized administrative subnets.
  - Evaluation of LogonType (focusing on Type 3 and Type 10).
