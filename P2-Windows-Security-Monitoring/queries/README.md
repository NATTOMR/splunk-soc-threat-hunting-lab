# 🔍 P2 SPL Query Library

> **Status:** ⚪ **PLANNED / AWAITING INGESTION VERIFICATION**  
> In accordance with lab standards, specific SPL queries will be authored only after live Windows event telemetry has been ingested and field extractions are verified.

---

## Directory Organization

- [`authentication/`](authentication/): SPL searches analyzing successful (4624) and failed (4625) logons, logon types, and session durations.
- [`accounts/`](accounts/): SPL searches monitoring user creation (4720), deletion (4726), password resets (4724), and administrative group changes (4732).
- [`processes/`](processes/): SPL searches evaluating process creation (4688), command-line arguments, parent-child relationships, and LOLBin execution.
- [`powershell/`](powershell/): SPL searches inspecting script-block logging (4104), encoded commands, and download cradles.
- [`brute-force/`](brute-force/): SPL searches calculating authentication failure thresholds and identifying credential stuffing patterns.
