# 🛡️ Windows Advanced Audit Policy Configuration Guide

> **Document Status:** ⚪ **PLANNED / PENDING VERIFICATION**  
> **Component:** Windows Local Security Policy & Auditing Baseline  

---

## Planned Audit Baseline

To provide high-fidelity telemetry for detection engineering, the Windows 11 endpoint will be configured using Local Security Policy (`secpol.msc`) and command-line audit configuration (`auditpol.exe`).

### Target Subcategories to Enable:
1. **Account Logon:**
   - Credential Validation: Success & Failure
2. **Account Management:**
   - User Account Management: Success & Failure
   - Security Group Management: Success & Failure
3. **Detailed Tracking:**
   - Process Creation: Success
   - Include command line in process creation events (via Administrative Templates)
4. **Logon/Logoff:**
   - Logon: Success & Failure
   - Logoff: Success
   - Special Logon: Success
5. **Policy Change:**
   - Audit Policy Change: Success & Failure
6. **Privilege Use:**
   - Sensitive Privilege Use: Success & Failure
7. **System:**
   - Security State Change: Success
   - Security System Extension: Success

*The exact `auditpol /set /category` commands and backup audit policy will be documented and verified in this guide upon execution.*
