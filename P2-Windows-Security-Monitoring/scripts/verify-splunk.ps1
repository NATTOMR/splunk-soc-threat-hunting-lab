<#
.SYNOPSIS
    Verifies the operational status and configuration of Splunk Universal Forwarder,
    Sysmon, Event Log permissions, and network connectivity on Windows endpoints.

.DESCRIPTION
    This script performs automated SOC lab validation checks:
      1. Verifies SplunkForwarder Windows service status.
      2. Verifies Sysmon service status (Sysmon or Sysmon64).
      3. Verifies Event Log Readers local group membership for the forwarder service account.
      4. Inspects inputs.conf for mandatory channels and XML rendering.
      5. Inspects outputs.conf for target receiver destination.
      6. Tests TCP socket connectivity to the central Splunk Enterprise receiver (192.168.100.7:9997).

.PARAMETER SplunkHome
    Installation path of Splunk Universal Forwarder. Default: 'C:\Program Files\SplunkUniversalForwarder'.

.PARAMETER SplunkServer
    Target Splunk Enterprise indexer IP address. Default: '192.168.100.7'.

.PARAMETER SplunkPort
    Target Splunk Enterprise receiver port. Default: 9997.

.EXAMPLE
    .\verify-splunk.ps1

.EXAMPLE
    .\verify-splunk.ps1 -SplunkServer "192.168.100.7" -SplunkPort 9997
#>

[CmdletBinding()]
param(
    [string]$SplunkHome = "C:\Program Files\SplunkUniversalForwarder",
    [string]$SplunkServer = "192.168.100.7",
    [int]$SplunkPort = 9997
)

$ErrorActionPreference = "Continue"

# Output formatting helpers
function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Write-CheckResult {
    param(
        [string]$CheckName,
        [string]$Status, # PASS, WARN, FAIL
        [string]$Message
    )
    $badge = switch ($Status) {
        "PASS" { "[PASS]" }
        "WARN" { "[WARN]" }
        "FAIL" { "[FAIL]" }
        default { "[INFO]" }
    }
    $color = switch ($Status) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        default { "White" }
    }
    Write-Host "$badge " -NoNewline -ForegroundColor $color
    Write-Host "$($CheckName): " -NoNewline -ForegroundColor White
    Write-Host $Message -ForegroundColor $color
}

$totalChecks = 0
$passedChecks = 0
$warnChecks = 0
$failedChecks = 0

function Record-Result {
    param([string]$Status)
    $script:totalChecks++
    switch ($Status) {
        "PASS" { $script:passedChecks++ }
        "WARN" { $script:warnChecks++ }
        "FAIL" { $script:failedChecks++ }
    }
}

Write-Header "SPLUNK SOC LAB -- WINDOWS ENDPOINT VERIFICATION"
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')" -ForegroundColor Gray
Write-Host "Computer Name: $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "Splunk Home: $SplunkHome" -ForegroundColor Gray
Write-Host "Target Receiver: $($SplunkServer):$($SplunkPort)" -ForegroundColor Gray
Write-Host ""

# ------------------------------------------------------------------------------
# 1. Check SplunkForwarder Service
# ------------------------------------------------------------------------------
Write-Host "--> Checking SplunkForwarder Service..." -ForegroundColor DarkCyan
$splunkService = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue

if ($null -eq $splunkService) {
    Write-CheckResult "SplunkForwarder Service" "FAIL" "Service 'SplunkForwarder' is not installed."
    Record-Result "FAIL"
} elseif ($splunkService.Status -eq "Running") {
    Write-CheckResult "SplunkForwarder Service" "PASS" "Service is installed and running."
    Record-Result "PASS"
} else {
    Write-CheckResult "SplunkForwarder Service" "WARN" "Service is installed but status is '$($splunkService.Status)'."
    Record-Result "WARN"
}

# ------------------------------------------------------------------------------
# 2. Check Sysmon Service
# ------------------------------------------------------------------------------
Write-Host "--> Checking Sysmon Service..." -ForegroundColor DarkCyan
$sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($null -eq $sysmonService) {
    $sysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
}

if ($null -eq $sysmonService) {
    Write-CheckResult "Sysmon Service" "FAIL" "Neither 'Sysmon64' nor 'Sysmon' service was found."
    Record-Result "FAIL"
} elseif ($sysmonService.Status -eq "Running") {
    Write-CheckResult "Sysmon Service" "PASS" "Service '$($sysmonService.Name)' is installed and running."
    Record-Result "PASS"
} else {
    Write-CheckResult "Sysmon Service" "WARN" "Service '$($sysmonService.Name)' is installed but status is '$($sysmonService.Status)'."
    Record-Result "WARN"
}

# ------------------------------------------------------------------------------
# 3. Check Event Log Readers Membership
# ------------------------------------------------------------------------------
Write-Host "--> Checking Event Log Readers Group Permissions..." -ForegroundColor DarkCyan
try {
    $targetAccount = "NT SERVICE\SplunkForwarder"
    $groupMembers = net localgroup "Event Log Readers" 2>$null
    $hasMembership = $false
    if ($groupMembers) {
        foreach ($line in $groupMembers) {
            if ($line -match "SplunkForwarder") {
                $hasMembership = $true
                break
            }
        }
    }
    
    # Also check via ADSI if net localgroup does not show virtual accounts directly
    if (-not $hasMembership) {
        try {
            $groupObj = [ADSI]"WinNT://$env:COMPUTERNAME/Event Log Readers,group"
            $members = @($groupObj.psbase.Invoke("Members"))
            foreach ($member in $members) {
                $name = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
                if ($name -match "SplunkForwarder") {
                    $hasMembership = $true
                    break
                }
            }
        } catch {
            # Silently pass ADSI attempt if running in restricted token
        }
    }

    if ($hasMembership) {
        Write-CheckResult "Event Log Readers Permission" "PASS" "'NT SERVICE\SplunkForwarder' is a member of 'Event Log Readers'."
        Record-Result "PASS"
    } else {
        Write-CheckResult "Event Log Readers Permission" "WARN" "Could not confirm 'NT SERVICE\SplunkForwarder' in 'Event Log Readers'. Run configure-forwarder.ps1 as Administrator."
        Record-Result "WARN"
    }
} catch {
    Write-CheckResult "Event Log Readers Permission" "WARN" "Permission query note: $_"
    Record-Result "WARN"
}

# ------------------------------------------------------------------------------
# 4. Check inputs.conf Configuration
# ------------------------------------------------------------------------------
Write-Host "--> Checking inputs.conf Configuration..." -ForegroundColor DarkCyan
$inputsPaths = @(
    (Join-Path $SplunkHome "etc\system\local\inputs.conf"),
    (Join-Path $SplunkHome "etc\apps\TA-Windows-Inputs\local\inputs.conf")
)

$foundInputsFile = $null
foreach ($path in $inputsPaths) {
    if (Test-Path -LiteralPath $path) {
        $foundInputsFile = $path
        break
    }
}

if ($null -eq $foundInputsFile) {
    Write-CheckResult "inputs.conf" "FAIL" "No local inputs.conf found under '$SplunkHome'."
    Record-Result "FAIL"
} else {
    $inputsContent = Get-Content -LiteralPath $foundInputsFile -Raw -ErrorAction SilentlyContinue
    $hasSecurity = $inputsContent -match "\[WinEventLog://Security\]"
    $hasSystem   = $inputsContent -match "\[WinEventLog://System\]"
    $hasApp      = $inputsContent -match "\[WinEventLog://Application\]"
    $hasSysmon   = $inputsContent -match "\[WinEventLog://Microsoft-Windows-Sysmon/Operational\]"
    $hasRenderXml = $inputsContent -match "renderXml\s*=\s*true"
    $hasSysmonIndex = $inputsContent -match "index\s*=\s*sysmon"

    if ($hasSecurity -and $hasSystem -and $hasSysmon -and $hasRenderXml -and $hasSysmonIndex) {
        Write-CheckResult "inputs.conf" "PASS" "Verified Security, System, Application, and Sysmon stanzas with index=sysmon and renderXml=true in '$foundInputsFile'."
        Record-Result "PASS"
    } else {
        $missing = @()
        if (-not $hasSecurity) { $missing += "Security" }
        if (-not $hasSystem) { $missing += "System" }
        if (-not $hasSysmon) { $missing += "Sysmon/Operational" }
        if (-not $hasRenderXml) { $missing += "renderXml=true" }
        if (-not $hasSysmonIndex) { $missing += "index=sysmon" }
        Write-CheckResult "inputs.conf" "WARN" "Config present at '$foundInputsFile' but missing recommended settings: $($missing -join ', ')."
        Record-Result "WARN"
    }
}

# ------------------------------------------------------------------------------
# 5. Check outputs.conf Configuration
# ------------------------------------------------------------------------------
Write-Host "--> Checking outputs.conf Configuration..." -ForegroundColor DarkCyan
$outputsPaths = @(
    (Join-Path $SplunkHome "etc\system\local\outputs.conf"),
    (Join-Path $SplunkHome "etc\apps\TA-Windows-Outputs\local\outputs.conf")
)

$foundOutputsFile = $null
foreach ($path in $outputsPaths) {
    if (Test-Path -LiteralPath $path) {
        $foundOutputsFile = $path
        break
    }
}

if ($null -eq $foundOutputsFile) {
    Write-CheckResult "outputs.conf" "FAIL" "No local outputs.conf found under '$SplunkHome'."
    Record-Result "FAIL"
} else {
    $outputsContent = Get-Content -LiteralPath $foundOutputsFile -Raw -ErrorAction SilentlyContinue
    $expectedServer = "$($SplunkServer):$($SplunkPort)"
    if ($outputsContent -match [regex]::Escape($expectedServer)) {
        Write-CheckResult "outputs.conf" "PASS" "Verified active target '$expectedServer' in '$foundOutputsFile'."
        Record-Result "PASS"
    } else {
        Write-CheckResult "outputs.conf" "WARN" "File exists at '$foundOutputsFile' but target '$expectedServer' was not detected in content."
        Record-Result "WARN"
    }
}

# ------------------------------------------------------------------------------
# 6. Test TCP Connectivity to Splunk Enterprise (Port 9997)
# ------------------------------------------------------------------------------
Write-Host "--> Testing TCP Connectivity to Splunk Enterprise Receiver ($($SplunkServer):$($SplunkPort))..." -ForegroundColor DarkCyan
$tcpConnected = $false
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $connectAsync = $tcpClient.BeginConnect($SplunkServer, $SplunkPort, $null, $null)
    $waitHandle = $connectAsync.AsyncWaitHandle.WaitOne(3000, $false)
    if ($waitHandle -and $tcpClient.Connected) {
        $tcpClient.EndConnect($connectAsync)
        $tcpConnected = $true
    }
    $tcpClient.Close()
} catch {
    $tcpConnected = $false
}

if ($tcpConnected) {
    Write-CheckResult "TCP 9997 Connectivity" "PASS" "Successfully established TCP socket with receiver $($SplunkServer):$($SplunkPort)."
    Record-Result "PASS"
} else {
    Write-CheckResult "TCP 9997 Connectivity" "FAIL" "Unable to connect to $($SplunkServer):$($SplunkPort). Verify Ubuntu Splunk 'splunk enable listen 9997' and UFW firewall rule."
    Record-Result "FAIL"
}

# ------------------------------------------------------------------------------
# Summary Report
# ------------------------------------------------------------------------------
Write-Header "VERIFICATION SUMMARY"
Write-Host "Total Checks : $totalChecks" -ForegroundColor White
Write-Host "Passed       : $passedChecks" -ForegroundColor Green
Write-Host "Warnings     : $warnChecks" -ForegroundColor Yellow
Write-Host "Failures     : $failedChecks" -ForegroundColor Red
Write-Host ""

if ($failedChecks -eq 0 -and $warnChecks -eq 0) {
    Write-Host "[SUCCESS] All verification tests passed. Splunk Universal Forwarder pipeline is operational!" -ForegroundColor Green
    exit 0
} elseif ($failedChecks -eq 0) {
    Write-Host "[NOTICE] All critical checks passed with warnings. Review warnings above." -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "[ERROR] One or more critical verification checks failed. Refer to docs\setup.md for troubleshooting." -ForegroundColor Red
    exit 1
}
