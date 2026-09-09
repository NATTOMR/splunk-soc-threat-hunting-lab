<#
.SYNOPSIS
    Automated installation helper for Splunk Universal Forwarder on Windows 11 endpoints.

.DESCRIPTION
    This script streamlines the installation of the Splunk Universal Forwarder MSI package.
    
    IMPORTANT PREREQUISITE:
    The Splunk Universal Forwarder MSI installer is proprietary software and cannot be
    redistributed within this repository. You MUST obtain the official 64-bit Windows MSI package
    directly from Splunk (free account required):
    https://www.splunk.com/en_us/download/universal-forwarder.html

    This script:
      1. Verifies elevated administrator privileges.
      2. Validates that the provided MSI package exists.
      3. Securely prompts for local admin credentials (NO HARDCODED SECRETS).
      4. Executes msiexec with appropriate flags and properties.
      5. Configures the 'NT SERVICE\SplunkForwarder' service account in 'Event Log Readers'.
      6. Invokes configure-forwarder.ps1 to apply production inputs and outputs.
      7. Runs verify-splunk.ps1 to validate the end-to-end telemetry pipeline.

.PARAMETER MsiPath
    Path to the downloaded Splunk Universal Forwarder MSI package.
    Example: 'C:\Users\User\Downloads\splunkforwarder-10.4.3-windows-x64.msi'

.PARAMETER InstallDir
    Target directory for Splunk Universal Forwarder installation.
    Default: 'C:\Program Files\SplunkUniversalForwarder'.

.PARAMETER SplunkServer
    IP address or hostname of the receiving Splunk Enterprise indexer.
    Default: '192.168.100.7'.

.PARAMETER SplunkPort
    Receiving port on the Splunk Enterprise indexer.
    Default: 9997.

.PARAMETER AdminUsername
    Username for the local Splunk Universal Forwarder CLI administrator.
    Default: 'admin'.

.EXAMPLE
    .\install-forwarder.ps1 -MsiPath "C:\Downloads\splunkforwarder-10.4.3.msi"

.EXAMPLE
    .\install-forwarder.ps1 -MsiPath ".\splunkforwarder-10.4.3.msi" -SplunkServer "192.168.100.7" -SplunkPort 9997
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to the Splunk Universal Forwarder MSI installer.")]
    [string]$MsiPath,

    [string]$InstallDir = "C:\Program Files\SplunkUniversalForwarder",
    [string]$SplunkServer = "192.168.100.7",
    [int]$SplunkPort = 9997,
    [string]$AdminUsername = "admin",
    [System.Security.SecureString]$AdminPassword,
    [switch]$SkipPostConfig
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    Write-Warning "This installer helper requires elevated Administrator privileges."
    Write-Warning "Please run PowerShell as Administrator."
    exit 1
}

if (-not (Test-Path -LiteralPath $MsiPath -PathType Leaf)) {
    Write-Error "MSI file not found at '$MsiPath'. Please verify path."
    exit 1
}

$resolvedMsi = (Resolve-Path -LiteralPath $MsiPath).Path

Write-Host ""
Write-Host ("=" * 75) -ForegroundColor Cyan
Write-Host "  SPLUNK UNIVERSAL FORWARDER -- AUTOMATED INSTALLATION HELPER" -ForegroundColor Cyan
Write-Host ("=" * 75) -ForegroundColor Cyan
Write-Host ""
Write-Host "NOTICE:" -ForegroundColor Yellow
Write-Host "Splunk Universal Forwarder binaries are licensed by Splunk Inc. and must be" -ForegroundColor Yellow
Write-Host "downloaded directly from: https://www.splunk.com/en_us/download/universal-forwarder.html" -ForegroundColor Yellow
Write-Host ""
Write-Host "MSI Source File    : $resolvedMsi" -ForegroundColor Gray
Write-Host "Target Directory   : $InstallDir" -ForegroundColor Gray
Write-Host "Receiving Indexer  : $($SplunkServer):$($SplunkPort)" -ForegroundColor Gray
Write-Host ""

# Prompt securely for forwarder admin password if not passed via parameter
if ($null -eq $AdminPassword) {
    Write-Host "Configure the local Splunk Universal Forwarder administrator password." -ForegroundColor Cyan
    Write-Host "(This sets local forwarder CLI access credentials; never stored in code)." -ForegroundColor Gray
    $cred = Get-Credential -UserName $AdminUsername -Message "Enter credentials for local Splunk Forwarder admin account"
    $AdminUsername = $cred.UserName
    $AdminPassword = $cred.Password
}

# Convert SecureString to BSTR for msiexec property
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword)
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

$logFilePath = Join-Path $env:TEMP "splunk_uf_install.log"

# Prepare MSI parameters
$msiArgs = @(
    "/i", ('"' + $resolvedMsi + '"'),
    "AGREETOLICENSE=Yes",
    ('INSTALLDIR="' + $InstallDir + '"'),
    ('RECEIVING_INDEXER="' + $SplunkServer + ':' + $SplunkPort + '"'),
    ('SPLUNKPASSWORD="' + $plainPassword + '"'),
    "LAUNCHSPLUNK=1",
    "/qn",
    "/l*v", ('"' + $logFilePath + '"')
)

Write-Host "Executing MSI installer in quiet mode..." -ForegroundColor White
Write-Host "Installer log will be written to: $logFilePath" -ForegroundColor Gray

$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow

# Clear plain password variable immediately from memory
$plainPassword = $null
[System.GC]::Collect()

if ($process.ExitCode -ne 0) {
    Write-Error "MSI installation failed with exit code $($process.ExitCode). Inspect '$logFilePath' for details."
    exit $process.ExitCode
}

Write-Host "[SUCCESS] Splunk Universal Forwarder MSI installed successfully!" -ForegroundColor Green

# ------------------------------------------------------------------------------
# Post-Installation Steps: Permissions & Configuration
# ------------------------------------------------------------------------------
if (-not $SkipPostConfig) {
    Write-Host ""
    Write-Host "Configuring permissions and telemetry channels..." -ForegroundColor White

    # Ensure NT SERVICE\SplunkForwarder is member of Event Log Readers
    $account = "NT SERVICE\SplunkForwarder"
    Write-Host "Adding '$account' to 'Event Log Readers' group..." -ForegroundColor Gray
    net localgroup "Event Log Readers" "$account" /add 2>$null | Out-Null

    # Execute configure-forwarder.ps1 if available in same directory
    $configureScript = Join-Path $PSScriptRoot "configure-forwarder.ps1"
    if (Test-Path -LiteralPath $configureScript) {
        Write-Host "Running configure-forwarder.ps1..." -ForegroundColor White
        & $configureScript -SplunkHome $InstallDir -SplunkServer $SplunkServer -SplunkPort $SplunkPort -ForceRestart
    }

    # Execute verify-splunk.ps1 if available
    $verifyScript = Join-Path $PSScriptRoot "verify-splunk.ps1"
    if (Test-Path -LiteralPath $verifyScript) {
        Write-Host ""
        Write-Host "Running verify-splunk.ps1 to validate operational status..." -ForegroundColor White
        & $verifyScript -SplunkHome $InstallDir -SplunkServer $SplunkServer -SplunkPort $SplunkPort
    }
}

Write-Host ""
Write-Host "[COMPLETED] Forwarder installation and environment baseline complete." -ForegroundColor Cyan
