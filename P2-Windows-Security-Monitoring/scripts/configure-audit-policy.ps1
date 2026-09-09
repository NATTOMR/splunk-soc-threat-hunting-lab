<#
.SYNOPSIS
    Configures and verifies Windows Advanced Audit Policy, Process Creation Command-Line Logging,
    and PowerShell Script Block Logging for Project P2.

.DESCRIPTION
    This script establishes a high-fidelity endpoint security telemetry baseline:
      1. Backs up current audit policy to a timestamped CSV before making changes.
      2. Configures auditpol subcategories:
         - Credential Validation (Success, Failure) -> Event 4776
         - User Account Management (Success, Failure) -> Events 4720, 4722, 4724, 4726
         - Security Group Management (Success, Failure) -> Events 4728, 4732, 4756
         - Process Creation (Success) -> Event 4688
         - Logon / Logoff (Success, Failure) -> Events 4624, 4625, 4634
         - Special Logon (Success) -> Event 4672
         - Audit Policy Change (Success, Failure) -> Event 4719
         - Sensitive Privilege Use (Success, Failure) -> Events 4673, 4674
      3. Enables Command-Line Logging in Process Creation events (Event 4688).
      4. Enables PowerShell Script-Block Logging (Event 4104) and Module Logging (Event 4103).
      5. Supports -VerifyOnly switch for non-intrusive compliance auditing.

.PARAMETER VerifyOnly
    Inspects current auditing and registry configuration without making any changes.

.PARAMETER BackupDir
    Directory path to store the audit policy backup. Default: current directory.

.EXAMPLE
    .\configure-audit-policy.ps1 -VerifyOnly

.EXAMPLE
    .\configure-audit-policy.ps1
#>

[CmdletBinding()]
param(
    [switch]$VerifyOnly,
    [string]$BackupDir = $PSScriptRoot
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Write-AuditStatus {
    param(
        [string]$Subcategory,
        [string]$Expected,
        [string]$Current,
        [string]$Status
    )
    $badge = if ($Status -eq "PASS") { "[PASS]" } else { "[WARN]" }
    $color = if ($Status -eq "PASS") { "Green" } else { "Yellow" }
    Write-Host "$badge " -NoNewline -ForegroundColor $color
    Write-Host "$Subcategory " -NoNewline -ForegroundColor White
    Write-Host "(Expected: $Expected | Current: $Current)" -ForegroundColor Gray
}

Write-Header "WINDOWS AUDIT POLICY & TELEMETRY CONFIGURATION"
Write-Host "Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')" -ForegroundColor Gray
Write-Host "Endpoint  : $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "Mode      : $(if ($VerifyOnly) { 'VERIFY ONLY (Read-Only)' } else { 'CONFIGURE & APPLY' })" -ForegroundColor Gray
Write-Host ""

# ------------------------------------------------------------------------------
# Subcategory Definitions
# ------------------------------------------------------------------------------
$auditItems = @(
    @{ Subcategory = "Credential Validation"; Expected = "Success and Failure" },
    @{ Subcategory = "User Account Management"; Expected = "Success and Failure" },
    @{ Subcategory = "Security Group Management"; Expected = "Success and Failure" },
    @{ Subcategory = "Process Creation"; Expected = "Success" },
    @{ Subcategory = "Logon"; Expected = "Success and Failure" },
    @{ Subcategory = "Logoff"; Expected = "Success" },
    @{ Subcategory = "Special Logon"; Expected = "Success" },
    @{ Subcategory = "Audit Policy Change"; Expected = "Success and Failure" },
    @{ Subcategory = "Sensitive Privilege Use"; Expected = "Success and Failure" }
)

# ------------------------------------------------------------------------------
# 1. Verification Logic
# ------------------------------------------------------------------------------
function Get-CurrentAuditStatus {
    $rawAudit = auditpol.exe /get /category:* /r
    $statusMap = @{}
    if ($rawAudit) {
        $lines = $rawAudit -split "`r?`n"
        foreach ($line in $lines) {
            $parts = $line -split ","
            if ($parts.Count -ge 5) {
                $subcat = $parts[2].Trim()
                $setting = $parts[4].Trim()
                if ($subcat -ne "") {
                    $statusMap[$subcat] = $setting
                }
            }
        }
    }
    return $statusMap
}

# ------------------------------------------------------------------------------
# Execution: Verify Only Mode
# ------------------------------------------------------------------------------
if ($VerifyOnly) {
    Write-Host "--> Checking Advanced Audit Policy Subcategories..." -ForegroundColor DarkCyan
    $currentStatus = Get-CurrentAuditStatus
    $passCount = 0
    $warnCount = 0

    foreach ($item in $auditItems) {
        $sub = $item.Subcategory
        $exp = $item.Expected
        $cur = if ($currentStatus.ContainsKey($sub)) { $currentStatus[$sub] } else { "Unknown" }

        # Check match
        $isMatch = $false
        if ($exp -eq "Success and Failure" -and ($cur -match "Success and Failure" -or $cur -match "Success, Failure")) {
            $isMatch = $true
        } elseif ($exp -eq "Success" -and ($cur -match "Success" -or $cur -match "Success and Failure")) {
            $isMatch = $true
        }

        if ($isMatch) {
            Write-AuditStatus $sub $exp $cur "PASS"
            $passCount++
        } else {
            Write-AuditStatus $sub $exp $cur "WARN"
            $warnCount++
        }
    }

    Write-Host "`n--> Checking Process Creation Command-Line Logging..." -ForegroundColor DarkCyan
    $cmdLinePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $cmdLineEnabled = $false
    if (Test-Path $cmdLinePath) {
        $val = (Get-ItemProperty -Path $cmdLinePath -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
        if ($val -eq 1) { $cmdLineEnabled = $true }
    }
    if ($cmdLineEnabled) {
        Write-Host "[PASS] Command-Line Logging in Process Creation (Event 4688) is ENABLED." -ForegroundColor Green
        $passCount++
    } else {
        Write-Host "[WARN] Command-Line Logging in Process Creation is NOT enabled (ProcessCreationIncludeCmdLine_Enabled != 1)." -ForegroundColor Yellow
        $warnCount++
    }

    Write-Host "`n--> Checking PowerShell Script-Block & Module Logging..." -ForegroundColor DarkCyan
    $psBlockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $psBlockEnabled = $false
    if (Test-Path $psBlockPath) {
        $val = (Get-ItemProperty -Path $psBlockPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
        if ($val -eq 1) { $psBlockEnabled = $true }
    }
    if ($psBlockEnabled) {
        Write-Host "[PASS] PowerShell Script Block Logging (Event 4104) is ENABLED." -ForegroundColor Green
        $passCount++
    } else {
        Write-Host "[WARN] PowerShell Script Block Logging is NOT enabled." -ForegroundColor Yellow
        $warnCount++
    }

    Write-Header "AUDIT VERIFICATION SUMMARY"
    Write-Host "Passed : $passCount" -ForegroundColor Green
    Write-Host "Warnings: $warnCount" -ForegroundColor Yellow
    Write-Host ""
    if ($warnCount -eq 0) {
        Write-Host "[SUCCESS] Windows endpoint conforms to the required P2 auditing baseline!" -ForegroundColor Green
    } else {
        Write-Host "[ACTION REQUIRED] Run '.\configure-audit-policy.ps1' as Administrator to apply baseline." -ForegroundColor Yellow
    }
    exit 0
}

# ------------------------------------------------------------------------------
# Execution: Configuration Mode (Requires Administrator)
# ------------------------------------------------------------------------------
if (-not (Test-IsAdministrator)) {
    Write-Warning "Administrator rights are required to modify audit policies and registry settings."
    Write-Warning "Please relaunch PowerShell as Administrator."
    exit 1
}

# 1. Backup Current Policy
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFile = Join-Path $BackupDir "auditpol_backup_${timestamp}.csv"
Write-Host "[1/4] Creating audit policy backup at: $backupFile" -ForegroundColor White
auditpol.exe /backup /file:"$backupFile" | Out-Null
Write-Host "[SUCCESS] Backup created." -ForegroundColor Green

# 2. Configure Audit Subcategories
Write-Host "`n[2/4] Applying auditpol subcategories..." -ForegroundColor White
auditpol.exe /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
auditpol.exe /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
auditpol.exe /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:disable | Out-Null
auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
auditpol.exe /set /subcategory:"Logoff" /success:enable /failure:disable | Out-Null
auditpol.exe /set /subcategory:"Special Logon" /success:enable /failure:disable | Out-Null
auditpol.exe /set /subcategory:"Audit Policy Change" /success:enable /failure:enable | Out-Null
auditpol.exe /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null
Write-Host "[SUCCESS] Audit subcategories configured." -ForegroundColor Green

# 3. Enable Process Creation Command-Line Logging
Write-Host "`n[3/4] Enabling Command-Line Logging in Process Creation (Event 4688)..." -ForegroundColor White
$auditRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $auditRegPath)) {
    New-Item -Path $auditRegPath -Force | Out-Null
}
Set-ItemProperty -Path $auditRegPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
Write-Host "[SUCCESS] ProcessCreationIncludeCmdLine_Enabled set to 1." -ForegroundColor Green

# 4. Enable PowerShell Script-Block & Module Logging
Write-Host "`n[4/4] Enabling PowerShell Script Block & Module Logging..." -ForegroundColor White
$psBlockRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psBlockRegPath)) {
    New-Item -Path $psBlockRegPath -Force | Out-Null
}
Set-ItemProperty -Path $psBlockRegPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

$psModRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $psModRegPath)) {
    New-Item -Path $psModRegPath -Force | Out-Null
}
Set-ItemProperty -Path $psModRegPath -Name "EnableModuleLogging" -Value 1 -Type DWord

$psModNamesRegPath = Join-Path $psModRegPath "ModuleNames"
if (-not (Test-Path $psModNamesRegPath)) {
    New-Item -Path $psModNamesRegPath -Force | Out-Null
}
Set-ItemProperty -Path $psModNamesRegPath -Name "*" -Value "*" -Type String

Write-Host "[SUCCESS] PowerShell Script Block Logging (4104) and Module Logging (4103) enabled." -ForegroundColor Green

Write-Host ""
Write-Host "[COMPLETED] Baseline configuration successfully applied!" -ForegroundColor Cyan
Write-Host "Run '.\configure-audit-policy.ps1 -VerifyOnly' to verify the active policy." -ForegroundColor Gray
