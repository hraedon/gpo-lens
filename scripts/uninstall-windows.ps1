<#
STYLE: Never embed single quotes inside double-quoted strings. PowerShell 5.1
reads this file via the system ANSI codepage when the UTF-8 BOM is missing
(e.g. GitHub zip download), and multi-byte UTF-8 sequences corrupt the
parser's quote-tracking state. Use `" `"` (escaped double quotes) instead.

Also: this script must run on PowerShell 5.1 (the Windows default). Avoid
PS 7+ syntax: no ??, no ternary, no pipeline chain operators (&& / ||).

.SYNOPSIS
    Remove a gpo-lens IIS deployment.

.DESCRIPTION
    Stops and removes the gpo-lens IIS site, app pool, TLS cert binding, and
    firewall rule. Optionally removes the data directory (database, venv, logs,
    shared Python). Does NOT touch cert-watch or any other site. Re-running is
    safe: missing resources are skipped.

.PARAMETER InstallDir
    Data directory used by the deployment. Default: C:\ProgramData\gpo-lens

.PARAMETER AppPool
    IIS application pool name. Default: gpo-lens

.PARAMETER SiteName
    IIS site name. Default: gpo-lens

.PARAMETER Port
    HTTPS port to clean up the SSL cert binding for. Default: 8443.
    Set to 0 to skip SSL cert cleanup.

.PARAMETER RemoveData
    When passed, also removes the data directory (database, venv, logs, shared
    Python). Without this flag, data is preserved so a re-install picks up
    where it left off.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-windows.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-windows.ps1 -RemoveData
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\ProgramData\gpo-lens",
    [string]$AppPool = "gpo-lens",
    [string]$SiteName = "gpo-lens",
    [int]$Port = 8443,
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"

# --- Must be elevated ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run from an elevated (Administrator) PowerShell."
}

$appcmdExe = "$env:windir\system32\inetsrv\appcmd.exe"

# 1. Stop and remove the app pool
if (Test-Path $appcmdExe) {
    $poolExists = & $appcmdExe list apppool "$AppPool" 2>$null
    if ($poolExists) {
        Write-Host "Stopping app pool `"$AppPool`" ..."
        & $appcmdExe stop apppool /apppool.name:"$AppPool" 2>$null | Out-Null
        Start-Sleep -Seconds 2
        Write-Host "Removing app pool `"$AppPool`" ..."
        & $appcmdExe delete apppool /apppool.name:"$AppPool" 2>$null | Out-Null
    } else {
        Write-Host "App pool `"$AppPool`" not found; skipping."
    }
}

# 2. Remove the IIS site (also removes its bindings)
$sitePath = "IIS:\Sites\$SiteName"
if (Get-Module -ListAvailable WebAdministration -ErrorAction SilentlyContinue) {
    Import-Module WebAdministration
    if (Get-Item $sitePath -ErrorAction SilentlyContinue) {
        Write-Host "Removing IIS site `"$SiteName`" ..."
        Remove-Item $sitePath -Recurse -ErrorAction SilentlyContinue
    } else {
        Write-Host "IIS site `"$SiteName`" not found; skipping."
    }
} else {
    Write-Host "[warn] WebAdministration module not available; cannot remove IIS site."
}

# 3. Remove the SSL cert binding (if any) for the configured port
if ($Port -gt 0) {
    $ipport = "0.0.0.0:$Port"
    $show = & netsh http show sslcert ipport="$ipport" 2>&1 | Out-String
    if ($show -match "Certificate Hash") {
        Write-Host "Removing SSL cert binding for $ipport ..."
        & netsh http delete sslcert ipport="$ipport" 2>$null | Out-Null
    }
    # Also try hostnameport variants that may have been used in SNI mode
    foreach ($b in (Get-WebBinding -Name $SiteName -ErrorAction SilentlyContinue)) {
        if ($b.protocol -eq "https") {
            $bi = "$($b.bindingInformation)"
            $parts = $bi.Split(":")
            if ($parts.Count -ge 3 -and $parts[2]) {
                $hostnameport = "$($parts[2]):$Port"
                & netsh http delete sslcert hostnameport="$hostnameport" 2>$null | Out-Null
            }
        }
    }
}

# 4. Remove the firewall rule
$fwRule = "gpo-lens HTTPS $Port"
if (Get-Command Remove-NetFirewallRule -ErrorAction SilentlyContinue) {
    if (Get-NetFirewallRule -DisplayName $fwRule -ErrorAction SilentlyContinue) {
        Write-Host "Removing firewall rule `"$fwRule`" ..."
        Remove-NetFirewallRule -DisplayName $fwRule -ErrorAction SilentlyContinue
    } else {
        Write-Host "Firewall rule `"$fwRule`" not found; skipping."
    }
}

# 5. Optionally remove the data directory
if ($RemoveData) {
    if (Test-Path $InstallDir) {
        Write-Host "Removing data directory $InstallDir ..."
        Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "Data directory $InstallDir not found; skipping."
    }
} else {
    Write-Host "Data directory $InstallDir preserved (pass -RemoveData to delete it)."
}

# 6. Remove the site directory if it exists
$sitePathDir = "C:\inetpub\gpo-lens"
if (Test-Path $sitePathDir) {
    Write-Host "Removing site directory $sitePathDir ..."
    Remove-Item $sitePathDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Done. gpo-lens removed."
if (-not $RemoveData) {
    Write-Host "Data dir $InstallDir was preserved; re-run install-windows.ps1 to redeploy."
}
