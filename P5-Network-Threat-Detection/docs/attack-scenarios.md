# P5 Attack Scenarios — Network Reconnaissance & Threat Modeling

> **Project:** P5 — Network Threat Detection with Splunk  
> **Status:** Scenarios Established (Simulation Scheduled in P5.1)

---

## Threat Scenarios

### Scenario 1: Port Scanning & Network Reconnaissance
- **Adversary Activity:** An attacker executes an `nmap` sweep (`nmap -sS -p 1-1000`) or automated port scanner to map listening services.
- **Indicators:** Single source IP connecting to a large number of distinct destination ports (`dc(dest_port) >= 10`) within a short time window.
- **MITRE ATT&CK:** T1046 (Network Service Discovery).

### Scenario 2: High-Volume Connection Bursts
- **Adversary Activity:** Aggressive probing, network fuzzing, or denial-of-service attempts.
- **Indicators:** Spike in connection count exceeding 50 attempts per 5-minute interval.

### Scenario 3: Connections to Uncommon or Suspicious Ports
- **Adversary Activity:** Malware beaconing, command-and-control communication, or reverse shells utilizing non-standard high ports (e.g. 4444, 1337, 8888).
- **Indicators:** Connections outside the baseline whitelist of approved services (80, 443, 53, 22, 3389, 445).
- **MITRE ATT&CK:** T1071 (Application Layer Protocol).

### Scenario 4: Lateral Reconnaissance & Sweep
- **Adversary Activity:** Horizontal scanning across multiple hosts on a subnet targeting a specific vulnerability (e.g. searching for open SMB 445 or RDP 3389).
- **Indicators:** Single source IP querying the same port across multiple distinct destination IPs (`dc(dest_ip) >= 5`).
