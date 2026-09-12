# SOC Dashboards — Brute-Force Detection & Investigation

> **Project:** P4 — Brute-Force Detection & Investigation  
> **Status:** ✅ **Operational & Empirically Verified**  
> **Dashboard Title:** `P4 — Brute-Force Detection & Investigation`  
> **Target Endpoint:** `ubuntu-p3` (`192.168.100.9`)  
> **Attacking Source:** `wazuh-server` (`192.168.100.7`) & Lab Gateway (`192.168.100.1`)  
> **Source XML:** [`brute-force-dashboard.xml`](brute-force-dashboard.xml)

---

## Operational SOC Dashboard Exhibit

![P4 SOC Brute-Force Dashboard](../screenshots/p4-03-brute-force-dashboard.png)

---

## Verified Dashboard Panels & Empirical Metrics

The dashboard was built in Splunk Enterprise using Classic Simple XML (dark theme), capturing live authentication telemetry across four specialized visualization rows:

| Panel ID | Panel Title | Visualization Type | Empirical Metric (Lab Session) | Operational Significance |
|:---:|---|---|---|---|
| **PANEL-01** | Total Authentication Failures | Single Value Card (Red Block) | **13** Failed Attempts | High-visibility metric indicating elevated authentication stress |
| **PANEL-02** | Successful Logins | Single Value Card (Blue Block) | **1** Legitimate Login | Baseline verification for legitimate user session (`natto`) |
| **PANEL-03** | Distinct Targeted Accounts | Single Value Card (Red Block) | **8** Distinct Accounts | Confirms horizontal password spray targeting diverse usernames |
| **PANEL-04** | Attempts by Targeted Username | Horizontal Bar Chart | `admin` (4), `service` (2), `user2` (2), `backup` (1), `guest` (1), `root` (1), `test` (1), `user1` (1) | Visualizes attack distribution across privileged and non-privileged accounts |
| **PANEL-05** | Offending Source IP Addresses | Pie Chart | **100%** from `192.168.100.7` | Isolates origin of dictionary attack and password spray |
| **PANEL-06** | Authentication Timeline (Success vs. Failure) | Stacked Column Timechart | Concentrated velocity spike (`2026-09-13 00:13:00` to `00:16:15`) | Demonstrates automated burst activity compared to baseline |
| **PANEL-07** | Live Authentication Triage Stream | Table View (Sorted by `_time`) | 14 Real-time Events | Provides analyst with raw forensic details, hostnames, timestamps, and usernames |

---

## Deployment Instructions

To deploy this dashboard in any Splunk Enterprise instance:
1. Navigate to **Dashboards** $\to$ **Create New Dashboard**.
2. Select **Classic Dashboards** (Simple XML) and dark theme.
3. Open the **Source** editor and paste the contents of [`brute-force-dashboard.xml`](brute-force-dashboard.xml).
4. Click **Save**.

