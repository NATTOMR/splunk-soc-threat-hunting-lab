<#
.SYNOPSIS
    simulate_threats.ps1 - Controlled Adversary Emulation & Threat Hunting Telemetry Generator
.DESCRIPTION
    Simulates benign, controlled telemetry corresponding to MITRE ATT&CK techniques
    targeted in Project P8: MITRE ATT&CK Threat Hunting with Splunk.
    All actions are non-destructive and include automated cleanup routines.
.NOTES
    Author: Natto Chakma
    Target: Windows 11 Monitored Endpoint (192.168.100.8)
    MITRE ATT&CK: T1059.001, T1218, T1547.001, T1053.005, T1082, T1071.004
#>

[CmdletBinding()]
param (
    [switch]$CleanupOnly = $false
)

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  P8 — MITRE ATT&CK THREAT HUNTING ADVERSARY EMULATION HARNESS   " -ForegroundColor Yellow
Write-Host "==================================================================" -ForegroundColor Cyan

# Cleanup Routine
function Invoke-Cleanup {
    Write-Host "[*] Executing cleanup of previous hunting artifacts..." -ForegroundColor Yellow
    
    # 1. Clean Registry Run Key
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    if (Get-ItemProperty -Path $regPath -Name "P8_ThreatHunt_Persistence" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $regPath -Name "P8_ThreatHunt_Persistence" -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] Removed test persistence registry key." -ForegroundColor Green
    }

    # 2. Clean Scheduled Task
    if (Get-ScheduledTask -TaskName "P8_ThreatHunt_Task" -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName "P8_ThreatHunt_Task" -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "  [+] Removed test scheduled task." -ForegroundColor Green
    }

    # 3. Clean Temp Staging File
    $tempFile = "$env:TEMP\threat_hunt_staged_payload.tmp"
    if (Test-Path $tempFile) {
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] Removed staged temp test file." -ForegroundColor Green
    }
}

if ($CleanupOnly) {
    Invoke-Cleanup
    Write-Host "[+] Cleanup complete. Exiting." -ForegroundColor Green
    exit 0
}

Invoke-Cleanup

Write-Host "`n[*] Starting Controlled Threat Emulation Sequence..." -ForegroundColor Cyan

# -------------------------------------------------------------------------
# Technique 1: T1059.001 - Obfuscated PowerShell Execution (-enc, -ep bypass)
# -------------------------------------------------------------------------
Write-Host "`n[1/6] Emulating T1059.001: Obfuscated PowerShell Execution..." -ForegroundColor White
$plainCommand = "Write-Output 'P8-Threat-Hunt-PowerShell-Validation-Success'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($plainCommand)
$encodedCommand = [System.Convert]::ToBase64String($bytes)

# Launch stealth PowerShell child process
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -EncodedCommand $encodedCommand" -Wait -NoNewWindow
Write-Host "  [+] Generated Sysmon EventID 1: powershell.exe with -enc, -ep bypass, -w hidden." -ForegroundColor Green

# -------------------------------------------------------------------------
# Technique 2: T1218 / T1105 - LOLBin Execution (CertUtil)
# -------------------------------------------------------------------------
Write-Host "`n[2/6] Emulating T1218 / T1105: LOLBin Execution (CertUtil syntax)..." -ForegroundColor White
# Safe syntax testing parameter recognition without actually downloading malware
Start-Process -FilePath "certutil.exe" -ArgumentList "-urlcache -split -f http://127.0.0.1:18000/en-US/static/img/favicon.ico $env:TEMP\threat_hunt_staged_payload.tmp" -Wait -NoNewWindow -ErrorAction SilentlyContinue
Write-Host "  [+] Generated Sysmon EventID 1: certutil.exe with -urlcache -split flags." -ForegroundColor Green

# -------------------------------------------------------------------------
# Technique 3: T1547.001 - Persistence via Registry Run Key
# -------------------------------------------------------------------------
Write-Host "`n[3/6] Emulating T1547.001: Registry Run Key Persistence Modification..." -ForegroundColor White
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $regPath -Name "P8_ThreatHunt_Persistence" -Value "C:\Windows\System32\notepad.exe" -Force
Write-Host "  [+] Generated Sysmon EventID 12/13: Registry value set under HKCU\...\Run." -ForegroundColor Green

# -------------------------------------------------------------------------
# Technique 4: T1053.005 - Persistence via Scheduled Task CLI
# -------------------------------------------------------------------------
Write-Host "`n[4/6] Emulating T1053.005: Scheduled Task Creation via schtasks..." -ForegroundColor White
Start-Process -FilePath "schtasks.exe" -ArgumentList "/create /tn `"P8_ThreatHunt_Task`" /tr `"cmd.exe /c echo threat_hunt`" /sc daily /st 12:00 /f" -Wait -NoNewWindow
Write-Host "  [+] Generated Sysmon EventID 1: schtasks.exe /create command line." -ForegroundColor Green

# -------------------------------------------------------------------------
# Technique 5: T1082 / T1087 - Post-Exploitation Discovery Recon Burst
# -------------------------------------------------------------------------
Write-Host "`n[5/6] Emulating T1082 / T1087: Rapid Reconnaissance Discovery Burst..." -ForegroundColor White
Start-Process -FilePath "cmd.exe" -ArgumentList "/c whoami & whoami /priv & net user" -Wait -NoNewWindow
Write-Host "  [+] Generated Sysmon EventID 1: Discovery command execution chain." -ForegroundColor Green

# -------------------------------------------------------------------------
# Technique 6: T1071.004 - Dynamic DNS Query Simulation
# -------------------------------------------------------------------------
Write-Host "`n[6/6] Emulating T1071.004: Suspicious TLD / Dynamic DNS Query..." -ForegroundColor White
try {
    [System.Net.Dns]::GetHostAddresses("beacon-p8-test.duckdns.org") | Out-Null
} catch {
    # Expected to fail resolution in isolated lab, but DNS Query telemetry is captured
}
Write-Host "  [+] Generated Sysmon EventID 22: DNS query lookup to dynamic DNS domain." -ForegroundColor Green

Write-Host "`n==================================================================" -ForegroundColor Cyan
Write-Host "  EMULATION COMPLETE: All threat hunting telemetry generated.     " -ForegroundColor Green
Write-Host "  To clean up artifacts, run: .\simulate_threats.ps1 -CleanupOnly" -ForegroundColor Yellow
Write-Host "==================================================================" -ForegroundColor Cyan
