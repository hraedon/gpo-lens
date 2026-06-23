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

    Port sharing is respected. The script inspects the gpo-lens site's own HTTPS
    binding to decide which http.sys SSL binding it owns:
      - catch-all install (sslFlags=0) -> removes ipport=0.0.0.0:<Port>
      - SNI install (-Sni, sslFlags=1) -> removes hostnameport=<host>:<Port>
        ONLY, leaving the catch-all alone (a sibling tool such as cert-watch on
        the same port may own it).
    Use -HostName to target an SNI binding when the site is already gone.

.PARAMETER InstallDir
    Data directory used by the deployment. Default: C:\ProgramData\gpo-lens

.PARAMETER AppPool
    IIS application pool name. Default: gpo-lens

.PARAMETER SiteName
    IIS site name. Default: gpo-lens

.PARAMETER SitePath
    Physical site directory to remove when the IIS site is already gone.
    Default: C:\inetpub\gpo-lens. When the site still exists, its own
    physicalPath is used instead, so a non-default -SiteName never deletes a
    different site's directory.

.PARAMETER Port
    HTTPS port to clean up the SSL cert binding for. Default: 8443.
    Set to 0 to skip SSL cert cleanup.

.PARAMETER HostName
    SNI hostname to clean up when the site is already removed (so its binding
    can no longer be inspected). When the site still exists, the hostname and
    SNI mode are discovered from its binding and this is not needed.

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
    [string]$SitePath = "C:\inetpub\gpo-lens",
    [int]$Port = 8443,
    [string]$HostName = "",
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"

# --- Helper functions (extracted for Pester testing) ---
# Placed before the main execution body so the script can be dot-sourced to load
# the functions without running the uninstall (see the dot-source guard below).

function Get-IsSniFlag {
    <#
        Interpret an IIS binding sslFlags value. sslFlags is numeric on modern
        IIS (bit 1 = SNI), but older providers return a string ("Sni"/"None").
        Handle both, mirroring install-windows.ps1 (WI-041).
    #>
    param([string]$SslFlags)
    $n = 0
    if ([int]::TryParse($SslFlags, [ref]$n)) { return (($n -band 1) -ne 0) }
    return ($SslFlags -match "Sni")
}

function Resolve-OwnedSslBinding {
    <#
        Decide which http.sys SSL binding THIS deployment owns. The discriminator
        is sslFlags (SNI), NOT hostname presence: a catch-all binding can carry a
        host header (*:PORT:host with sslFlags=0) yet bind the cert at
        ipport=0.0.0.0:PORT rather than hostnameport=host:PORT. Returns a
        hashtable @{ Mode = "sni"|"catchall"; Target = "<netsh binding arg>" }.
    #>
    param([bool]$IsSni, [string]$BindingHost, [int]$Port)
    if ($IsSni -and $BindingHost) {
        return @{ Mode = "sni"; Target = "hostnameport=${BindingHost}:$Port" }
    }
    return @{ Mode = "catchall"; Target = "ipport=0.0.0.0:$Port" }
}

# --- Main execution body (skipped when dot-sourced for testing) ---
if ($MyInvocation.InvocationName -ne ".") {

    # Must be elevated
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

    # 2. Inspect the site's HTTPS binding BEFORE removing it, so we know which
    #    http.sys SSL binding this deployment owns (catch-all vs SNI).
    $sitePath = "IIS:\Sites\$SiteName"
    $bindingHost = ""
    $isSni = $false
    $siteFound = $false
    $sitePhysical = ""
    $haveWebAdmin = [bool](Get-Module -ListAvailable WebAdministration -ErrorAction SilentlyContinue)
    if ($haveWebAdmin) {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        $siteItem = Get-Item $sitePath -ErrorAction SilentlyContinue
        if ($siteItem) {
            $siteFound = $true
            $sitePhysical = "$($siteItem.physicalPath)"
            $bindings = Get-ItemProperty $sitePath -Name bindings -ErrorAction SilentlyContinue
            if ($bindings) {
                foreach ($b in $bindings.Collection) {
                    if ($b.protocol -eq "https") {
                        $parts = "$($b.bindingInformation)".Split(":")
                        if ($parts.Count -ge 3) { $bindingHost = $parts[2] }
                        $isSni = Get-IsSniFlag -SslFlags "$($b.sslFlags)"
                        break
                    }
                }
            }
        }
    }
    # Caller override when the site is already gone: -HostName targets an SNI
    # binding (a catch-all needs no hostname to be cleaned up).
    if (-not $siteFound -and $HostName) { $bindingHost = $HostName; $isSni = $true }

    # 3. Remove the IIS site (also removes its IIS-level bindings)
    if ($haveWebAdmin) {
        if ($siteFound) {
            Write-Host "Removing IIS site `"$SiteName`" ..."
            Remove-Item $sitePath -Recurse -ErrorAction SilentlyContinue
        } else {
            Write-Host "IIS site `"$SiteName`" not found; skipping."
        }
    } else {
        Write-Host "[warn] WebAdministration module not available; cannot remove IIS site."
    }

    # 4. Remove ONLY the http.sys SSL cert binding this deployment owns
    if ($Port -gt 0) {
        $owned = Resolve-OwnedSslBinding -IsSni $isSni -BindingHost $bindingHost -Port $Port
        $show = & netsh http show sslcert $owned.Target 2>&1 | Out-String
        if ($show -match "Certificate Hash") {
            Write-Host "Removing $($owned.Mode) SSL cert binding ($($owned.Target)) ..."
            & netsh http delete sslcert $owned.Target 2>$null | Out-Null
        } else {
            Write-Host "No $($owned.Mode) SSL cert binding ($($owned.Target)); skipping."
        }
        if ($owned.Mode -eq "sni") {
            Write-Host "[note] Catch-all ipport=0.0.0.0:$Port left untouched (SNI mode -- a sibling tool such as cert-watch may own it)."
        }
    }

    # 5. Remove the firewall rule
    $fwRule = "gpo-lens HTTPS $Port"
    if (Get-Command Remove-NetFirewallRule -ErrorAction SilentlyContinue) {
        if (Get-NetFirewallRule -DisplayName $fwRule -ErrorAction SilentlyContinue) {
            Write-Host "Removing firewall rule `"$fwRule`" ..."
            Remove-NetFirewallRule -DisplayName $fwRule -ErrorAction SilentlyContinue
        } else {
            Write-Host "Firewall rule `"$fwRule`" not found; skipping."
        }
    }

    # 6. Optionally remove the data directory
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

    # 7. Remove the physical site directory. Prefer the site's OWN physicalPath
    #    (captured before removal) so a non-default -SiteName can never delete a
    #    different site's directory; fall back to -SitePath only when the site
    #    was already gone.
    $dirToRemove = $SitePath
    if ($siteFound -and $sitePhysical) { $dirToRemove = $sitePhysical }
    if ($dirToRemove -and (Test-Path $dirToRemove)) {
        Write-Host "Removing site directory $dirToRemove ..."
        Remove-Item $dirToRemove -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host "Done. gpo-lens removed."
    if (-not $RemoveData) {
        Write-Host "Data dir $InstallDir was preserved; re-run install-windows.ps1 to redeploy."
    }
}
