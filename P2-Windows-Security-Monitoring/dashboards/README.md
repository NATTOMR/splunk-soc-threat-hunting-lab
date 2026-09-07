# 📊 Windows SOC Security Dashboard

> **Status:** ⚪ **PLANNED / AWAITING INGESTION & VISUALIZATION**  
> In accordance with lab integrity standards, no fabricated dashboard XML or placeholder charts are generated prior to live log ingestion.

---

## Planned Dashboard Layout & Panels

When telemetry streaming is established, this dashboard will be implemented in Splunk Web and documented here:

1. **Host Overview & Agent Health:** Single-value metric tracking forwarder uptime, connection status, and event velocity.
2. **Logon Status Breakdown:** Comparative pie chart / timechart of successful (4624) versus failed (4625) logons.
3. **Logon Type Distribution:** Breakdown across Interactive (Type 2), Network (Type 3), and Remote Desktop (Type 10).
4. **Top Targeted User Accounts:** Bar chart ranking accounts experiencing authentication failures.
5. **Privileged Escalation & Special Logons:** Audit log of Event ID 4672 triggers and administrator sessions.
6. **Top Executed Processes:** Column chart of unique process names (`ProcessName`) and anomalous CLI invocations.
7. **PowerShell Script-Block Activity:** Real-time log viewer of executed script blocks (Event ID 4104).

*The full Simple XML export (`dashboards/windows_soc_dashboard.xml`) and step-by-step reconstruction instructions will be committed once the dashboard is operational in Splunk.*
