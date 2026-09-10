# P2 Completion Checklist

> **Project:** Splunk SOC Threat Hunting Lab — P2: Windows Security Monitoring  
> **Dashboard:** Kali Attacker Activity Dashboard  
> **Last updated:** 2026-09-10

---

## Lab Setup

- [x] Kali attacker configured
- [x] Windows victim reachable

---

## Attack Simulation

- [x] Host discovery completed
- [x] TCP scan completed
- [x] Service/version detection completed
- [x] RPC/SMB scan completed
- [x] SMB protocol enumeration completed
- [x] Anonymous SMB test completed

---

## Detection & Visibility

- [x] Event ID 4625 detected
- [x] Kali source IP correlated
- [x] SMB signing verified
- [x] Attacker-focused Splunk investigation completed

---

## Dashboard

- [x] Kali Attacker Activity Dashboard created
- [x] Dashboard panels validated

---

## Documentation & Evidence

- [ ] Dashboard screenshot copied into repository
- [ ] Documentation final review
- [ ] Git commit
- [ ] Git push

---

## Notes

### Dashboard Screenshot

The dashboard screenshot (`Screenshot 2026-09-10 151257.png`) exists in:

```
P2-Windows-Security-Monitoring/screenshots/
```

It must be manually copied to:

```
docs/evidence/p2/11-kali-attacker-dashboard.png
```

before marking the screenshot checklist item as complete.

### Security Scope

All P2 attack simulation tests were conducted exclusively against the controlled lab
endpoint at `192.168.100.8` within an isolated VirtualBox NAT network.

- No unauthorized systems scanned
- No malware deployed
- No brute-force attack performed
- No denial-of-service activity performed
- No destructive exploitation performed
