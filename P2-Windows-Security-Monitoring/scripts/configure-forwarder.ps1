<#
.SYNOPSIS
    Safely and idempotently applies the verified inputs.conf and outputs.conf
    configurations to Splunk Universal Forwarder on Windows 11.

.DESCRIPTION
    This automation script:
      1. Verifies elevated administrator privileges.
      2. Ensures the forwarder service account ('NT SERVICE\SplunkForwarder') is in 'Event Log Readers'.
      3. Idempotently configures inputs.conf (Security, System, Application, and Sysmon with XML rendering).
      4. Idempotently configures outputs.conf (pointing to 192.168.100.7:9997).
      5. Preserves existing unrelated stanzas and comments.
      6. Creates automatic timestamped backups (.bak) before modifying any files.
      7. Only restarts the SplunkForwarder service if configuration changes were applied or -ForceRestart is passed.

.PARAMETER SplunkHome
    Installation root of Splunk Universal Forwarder. Default: 'C:\Program Files\SplunkUniversalForwarder'.

.PARAMETER SplunkServer
    Target Splunk Enterprise indexer IP. Default: '192.168.100.7'.

.PARAMETER SplunkPort
    Target Splunk Enterprise receiver port. Default: 9997.

.PARAMETER ForceRestart
    Switch to force restart of the SplunkForwarder service even if no configuration modifications occurred.

.EXAMPLE
    .\configure-forwarder.ps1

.EXAMPLE
    .\configure-forwarder.ps1 -SplunkServer "192.168.100.7" -SplunkPort 9997 -ForceRestart
#>

[CmdletBinding()]
param(
    [string]$SplunkHome = "C:\Program Files\SplunkUniversalForwarder",
    [string]$SplunkServer = "192.168.100.7",
    [int]$SplunkPort = 9997,
    [switch]$ForceRestart
)

$ErrorActionPreference = "Stop"

# Helper to check administrator rights
function Test-IsAdministrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    Write-Warning "This script requires elevated Administrator privileges to modify Splunk configuration and services."
    Write-Warning "Please relaunch PowerShell as Administrator and execute again."
    exit 1
}

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  SPLUNK UNIVERSAL FORWARDER CONFIGURATION DEPLOYMENT" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "Target Splunk Home : $SplunkHome" -ForegroundColor Gray
Write-Host "Target Receiver    : ${SplunkServer}:${SplunkPort}" -ForegroundColor Gray
Write-Host ""

# Validate SplunkHome directory
if (-not (Test-Path -LiteralPath $SplunkHome)) {
    Write-Error "Splunk installation directory not found at '$SplunkHome'. Please verify path or run install-forwarder.ps1 first."
    exit 1
}

$systemLocalPath = Join-Path $SplunkHome "etc\system\local"
if (-not (Test-Path -LiteralPath $systemLocalPath)) {
    New-Item -ItemType Directory -Path $systemLocalPath -Force | Out-Null
    Write-Host "[CREATED] Directory: $systemLocalPath" -ForegroundColor Green
}

$changesMade = $false
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# ------------------------------------------------------------------------------
# 1. Ensure Service Account in Event Log Readers
# ------------------------------------------------------------------------------
Write-Host "[1/3] Verifying Event Log Readers group membership..." -ForegroundColor White
try {
    $account = "NT SERVICE\SplunkForwarder"
    $groupMembers = net localgroup "Event Log Readers" 2>$null
    $alreadyMember = $false
    if ($groupMembers) {
        foreach ($line in $groupMembers) {
            if ($line -match "SplunkForwarder") {
                $alreadyMember = $true
                break
            }
        }
    }

    if (-not $alreadyMember) {
        Write-Host "Adding '$account' to 'Event Log Readers' group..." -ForegroundColor Yellow
        $output = net localgroup "Event Log Readers" "$account" /add 2>&1
        if ($LASTEXITCODE -eq 0 -or $output -match "The command completed successfully") {
            Write-Host "[SUCCESS] Added '$account' to 'Event Log Readers'." -ForegroundColor Green
            $changesMade = $true
        } else {
            Write-Warning "Could not automatically add '$account' via net localgroup. Status: $output"
        }
    } else {
        Write-Host "[OK] '$account' is already a member of 'Event Log Readers'." -ForegroundColor Green
    }
} catch {
    Write-Warning "Error checking/adding Event Log Readers membership: $_"
}

# ------------------------------------------------------------------------------
# 2. Idempotently Apply inputs.conf
# ------------------------------------------------------------------------------
Write-Host "`n[2/3] Configuring inputs.conf..." -ForegroundColor White
$inputsFile = Join-Path $systemLocalPath "inputs.conf"

$desiredInputsStanzas = @"
[WinEventLog://Security]
disabled = 0
index = windows
renderXml = true

[WinEventLog://System]
disabled = 0
index = windows
renderXml = true

[WinEventLog://Application]
disabled = 0
index = windows
renderXml = true

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
renderXml = true
"@

if (Test-Path -LiteralPath $inputsFile) {
    $currentInputs = Get-Content -LiteralPath $inputsFile -Raw
    # Check if all desired settings are already present
    $hasSec  = $currentInputs -match "\[WinEventLog://Security\]"
    $hasSys  = $currentInputs -match "\[WinEventLog://System\]"
    $hasApp  = $currentInputs -match "\[WinEventLog://Application\]"
    $hasSysm = $currentInputs -match "\[WinEventLog://Microsoft-Windows-Sysmon/Operational\]"
    $hasSysmIndex = $currentInputs -match "index\s*=\s*sysmon"
    $hasXml  = $currentInputs -match "renderXml\s*=\s*true"

    if ($hasSec -and $hasSys -and $hasApp -and $hasSysm -and $hasSysmIndex -and $hasXml) {
        Write-Host "[OK] inputs.conf already contains required channel stanzas and XML settings. No changes needed." -ForegroundColor Green
    } else {
        # Create backup
        $backupInputs = "${inputsFile}.${timestamp}.bak"
        Copy-Item -LiteralPath $inputsFile -Destination $backupInputs -Force
        Write-Host "[BACKUP] Created backup at: $backupInputs" -ForegroundColor Gray

        # Safely append desired stanzas to preserve any other configuration
        $updatedInputs = $currentInputs.TrimEnd() + "`r`n`r`n# --- Added by Splunk SOC Lab Configuration Script ---`r`n" + $desiredInputsStanzas + "`r`n"
        Set-Content -LiteralPath $inputsFile -Value $updatedInputs -Encoding utf8
        Write-Host "[UPDATED] inputs.conf updated with required event channels." -ForegroundColor Green
        $changesMade = $true
    }
} else {
    Set-Content -LiteralPath $inputsFile -Value ($desiredInputsStanzas + "`r`n") -Encoding utf8
    Write-Host "[CREATED] inputs.conf created with required event channels." -ForegroundColor Green
    $changesMade = $true
}

# ------------------------------------------------------------------------------
# 3. Idempotently Apply outputs.conf
# ------------------------------------------------------------------------------
Write-Host "`n[3/3] Configuring outputs.conf..." -ForegroundColor White
$outputsFile = Join-Path $systemLocalPath "outputs.conf"
$expectedServer = "${SplunkServer}:${SplunkPort}"

$desiredOutputsStanzas = @"
[tcpout]
defaultGroup = splunk-enterprise

[tcpout:splunk-enterprise]
server = $expectedServer
"@

if (Test-Path -LiteralPath $outputsFile) {
    $currentOutputs = Get-Content -LiteralPath $outputsFile -Raw
    if ($currentOutputs -match [regex]::Escape($expectedServer) -and $currentOutputs -match "defaultGroup\s*=\s*splunk-enterprise") {
        Write-Host "[OK] outputs.conf already targets '$expectedServer' under 'splunk-enterprise'. No changes needed." -ForegroundColor Green
    } else {
        $backupOutputs = "${outputsFile}.${timestamp}.bak"
        Copy-Item -LiteralPath $outputsFile -Destination $backupOutputs -Force
        Write-Host "[BACKUP] Created backup at: $backupOutputs" -ForegroundColor Gray

        # Append or replace default tcpout
        $updatedOutputs = $currentOutputs.TrimEnd() + "`r`n`r`n# --- Added by Splunk SOC Lab Configuration Script ---`r`n" + $desiredOutputsStanzas + "`r`n"
        Set-Content -LiteralPath $outputsFile -Value $updatedOutputs -Encoding utf8
        Write-Host "[UPDATED] outputs.conf updated with target receiver '$expectedServer'." -ForegroundColor Green
        $changesMade = $true
    }
} else {
    Set-Content -LiteralPath $outputsFile -Value ($desiredOutputsStanzas + "`r`n") -Encoding utf8
    Write-Host "[CREATED] outputs.conf created with target receiver '$expectedServer'." -ForegroundColor Green
    $changesMade = $true
}

# ------------------------------------------------------------------------------
# 4. Restart Service Only When Necessary
# ------------------------------------------------------------------------------
Write-Host ""
$splunkService = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue

if ($changesMade -or $ForceRestart) {
    if ($null -ne $splunkService) {
        Write-Host "Changes detected (or ForceRestart specified). Restarting SplunkForwarder service..." -ForegroundColor Yellow
        Restart-Service -Name "SplunkForwarder" -Force
        Start-Sleep -Seconds 2
        $splunkService.Refresh()
        if ($splunkService.Status -eq "Running") {
            Write-Host "[SUCCESS] SplunkForwarder service restarted and running." -ForegroundColor Green
        } else {
            Write-Warning "SplunkForwarder service status after restart is: $($splunkService.Status)"
        }
    } else {
        Write-Warning "SplunkForwarder service is not installed on this host. Configuration files applied successfully."
    }
} else {
    Write-Host "[IDEMPOTENT] No configuration changes were required. Service restart skipped." -ForegroundColor Green
}

Write-Host ""
Write-Host "Configuration deployment complete! Run .\verify-splunk.ps1 to validate the end-to-end pipeline." -ForegroundColor Cyan
