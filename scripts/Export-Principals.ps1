<#
.SYNOPSIS
  Collect SID -> name map from GPO SDDL strings (standalone, incremental).

.DESCRIPTION
  Produces principals.json per Plan 020 Phase A.2 format.
  Can read SDDL from: an existing export dir, or live AD via Get-ADObject.

  This is a standalone script for incremental updates. The main collector
  (Export-GpoEstate.ps1) now produces principals.json as part of the full export.

.PARAMETER SddlSource
  Path to an existing export directory. If provided, SIDs are extracted from
  the XML reports in that directory. Otherwise, reads from live AD.

.PARAMETER OutputPath
  Output file path. Defaults to principals.json in current directory.

.PARAMETER Credential
  PSCredential for AD access. If not provided, uses current user context.

.EXAMPLE
  # Incremental update from existing export
  .\Export-Principals.ps1 -SddlSource "C:\gpo-export\WORK-DOMAIN.local-20260619"

.EXAMPLE
  # From live AD with explicit credentials
  $cred = Get-Credential
  .\Export-Principals.ps1 -Credential $cred
#>
param(
    [string]$SddlSource = "",
    [string]$OutputPath = "principals.json",
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'

# Collect all unique SIDs
$allSids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

if ($SddlSource -and (Test-Path $SddlSource)) {
    Write-Host "Reading SDDL from: $SddlSource"
    $xmlFiles = @()
    $allXml = Join-Path $SddlSource "AllGPOs.xml"
    if (Test-Path $allXml) { $xmlFiles += $allXml }
    $reportsDir = Join-Path $SddlSource "reports"
    if (Test-Path $reportsDir) {
        $xmlFiles += (Get-ChildItem $reportsDir -Filter "*.xml" -ErrorAction SilentlyContinue).FullName
    }
    foreach ($f in $xmlFiles) {
        try {
            $content = Get-Content $f -Raw -ErrorAction Stop
            $matches = [regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+')
            foreach ($m in $matches) { [void]$allSids.Add($m.Value) }
        } catch { }
    }
    $metaFile = Join-Path $SddlSource "gpo-metadata.json"
    if (Test-Path $metaFile) {
        try {
            $content = Get-Content $metaFile -Raw
            $matches = [regex]::Matches($content, 'S-1-[0-9]+-[0-9-]+')
            foreach ($m in $matches) { [void]$allSids.Add($m.Value) }
        } catch { }
    }
} else {
    Write-Host "Collecting SDDL from live AD via Get-ADObject..."
    $adParams = @{}
    if ($Credential) { $adParams.Credential = $Credential }
    $dom = Get-ADDomain @adParams
    $policiesDN = "CN=Policies,CN=System,$($dom.DistinguishedName)"
    $gpcObjs = Get-ADObject -SearchBase $policiesDN -LDAPFilter "(objectClass=groupPolicyContainer)" -Properties nTSecurityDescriptor, displayName @adParams
    foreach ($gpc in $gpcObjs) {
        try {
            $sd = $gpc.nTSecurityDescriptor
            if ($sd) {
                $sddl = $sd.GetSecurityDescriptorSddlForm()
                $matches = [regex]::Matches($sddl, 'S-1-[0-9]+-[0-9-]+')
                foreach ($m in $matches) { [void]$allSids.Add($m.Value) }
            }
        } catch { }
    }
}

Write-Host "Found $($allSids.Count) unique SIDs to resolve"

$principals = [ordered]@{}
$resolved = 0
$unresolved = 0
foreach ($sid in $allSids | Sort-Object) {
    $name = ""
    $type = "Unresolved"
    $sam = ""
    $domPart = ""

    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $translated = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
        $name = $translated
        if ($translated -match '^(.+?)\\(.+)$') {
            $domPart = $matches[1]; $sam = $matches[2]
        } elseif ($translated -match '^(.+?)@(.+)$') {
            $sam = $matches[1]; $domPart = $matches[2]
        } else {
            $sam = $translated
        }
        if ($translated -match 'BUILTIN\\' -or $sid -match '^S-1-5-32-') {
            $type = "WellKnown"
        } elseif ($translated -match '\\') {
            $type = if ($sid -match '^S-1-5-21-') { "Group" } else { "User" }
            if ($sam -match '\$$') { $type = "Computer" }
        } else {
            $type = "WellKnown"
        }
        $resolved++
        Write-Host "  $sid -> $translated"
    } catch {
        $name = $sid; $type = "Unresolved"; $unresolved++
        Write-Host "  $sid -> (unresolved)"
    }
    $principals[$sid] = [ordered]@{ name = $name; sam = $sam; type = $type; domain = $domPart }
}

# Supplement unresolved domain SIDs via Get-ADObject
$domainSids = @($allSids | Where-Object { $_ -match '^S-1-5-21-' -and $principals[$_].type -eq 'Unresolved' })
if ($domainSids.Count -gt 0) {
    Write-Host "Resolving $($domainSids.Count) domain SIDs via Get-ADObject..."
    $adParams = @{}
    if ($Credential) { $adParams.Credential = $Credential }
    if (-not $dom) {
        try { $dom = Get-ADDomain @adParams } catch { $dom = $null }
    }
    foreach ($sid in $domainSids) {
        if ($principals[$sid].type -ne "Unresolved") { continue }
        try {
            $obj = Get-ADObject -Filter "objectSid -eq '$sid'" -Properties objectClass, sAMAccountName, name @adParams -ErrorAction Stop
            if ($obj) {
                $sam = if ($obj.sAMAccountName) { $obj.sAMAccountName } else { $obj.Name }
                $objClass = $obj.objectClass[-1]
                $ptype = switch ($objClass) { 'group' { 'Group' } 'computer' { 'Computer' } default { 'User' } }
                $domName = if ($dom) { $dom.NetBIOSName } else { "" }
                $principals[$sid] = [ordered]@{
                    name = "$domName\$sam"; sam = $sam; type = $ptype; domain = $domName
                }
                Write-Host "  AD: $sid -> $sam ($ptype)"
            }
        } catch {
            Write-Host "  AD resolve failed for $sid : $($_.Exception.Message)"
        }
    }
}

$domainDns = if ($dom) { $dom.DNSRoot } else { "" }
$out = [ordered]@{ collected = (Get-Date -Format "o"); domain = $domainDns; principals = $principals }
$out | ConvertTo-Json -Depth 5 | Set-Content $OutputPath -Encoding UTF8
Write-Host "Done: $resolved resolved, $unresolved unresolved -> $OutputPath"
