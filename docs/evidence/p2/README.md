# P2 Evidence — Kali Attacker Activity Dashboard

## Evidence Directory

This directory contains evidence screenshots for the P2 Kali Attacker Activity Dashboard.

---

## 11-kali-attacker-dashboard.png

**Status:** ⚠️ Screenshot must be copied manually.

**Source file (in repository):**

```
P2-Windows-Security-Monitoring/screenshots/Screenshot 2026-09-10 151257.png
```

**Target path (for evidence filing):**

```
docs/evidence/p2/11-kali-attacker-dashboard.png
```

**Action required:**

Copy the screenshot from the screenshots directory into this evidence directory and rename it:

```powershell
Copy-Item `
  "P2-Windows-Security-Monitoring\screenshots\Screenshot 2026-09-10 151257.png" `
  "docs\evidence\p2\11-kali-attacker-dashboard.png"
```

---

## Description

The screenshot (`Screenshot 2026-09-10 151257.png`) captured on 2026-09-10 shows the
**Kali Attacker Activity Dashboard** live in Splunk Enterprise, displaying all ten panels:

1. Kali Attacker Events — showing event count from `192.168.100.6`
2. Kali Failed Authentication — 4625 — single value panel
3. Kali Failed Authentication Timeline — timechart
4. Failed Logons by Host — bar chart showing `DESKTOP-US2NJE2`
5. Kali Network Logons — 4624 — single value panel
6. Kali Source IP — showing `192.168.100.6`
7. Kali Authentication Events — event table
8. Kali Workstation — showing `KALI`
9. Kali Attacker Activity — timechart
10. Kali Attacker Activity Timeline — extended timechart

The screenshot is the primary evidence that the dashboard was successfully created and
is operational in the lab Splunk instance.

---

*Evidence documented: 2026-09-10*
