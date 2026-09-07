# 🚨 P2 Detection Engineering Rules

> **Status:** ⚪ **PLANNED / AWAITING INGESTION & TESTING**  
> This directory will house structured detection rules (SPL, trigger criteria, false-positive baselines, and response steps) mapped to the MITRE ATT&CK framework.

---

## Planned Rule Index

| Rule Name | Primary Event IDs | Tactic | Status |
|---|---|---|:---:|
| Multiple Failed Logons Followed by Success | 4625, 4624 | Credential Access | ⚪ Planned |
| Local Administrator Account Created | 4720, 4732 | Persistence | ⚪ Planned |
| Suspicious LOLBin Command-Line Execution | 4688 | Defense Evasion | ⚪ Planned |
| Obfuscated PowerShell Script-Block Execution | 4104 | Execution | ⚪ Planned |
| Service Installation with Abnormal Path | 7045 | Persistence | ⚪ Planned |

*Individual detection rule specification files (`.md` / `.spl`) will be added as rules are implemented and validated.*
