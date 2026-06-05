<#
.SYNOPSIS
  Export a full Group Policy estate for offline analysis by gpo-lens.

.DESCRIPTION
  Read-only collector. Produces, per domain:
    - AllGPOs.xml            combined Get-GPOReport (whole domain)
    - reports\*.xml          per-GPO XML reports (GUID in filename disambiguates dupes)
    - gpo-metadata.json      status, timestamps, version skew (DS vs SYSVOL), WMI filter
    - gp-inheritance.json    per-SOM inheritance: block, enforced, precedence order
    - ou-tree.json           raw OU tree (gPLink/gPOptions) as a topology cross-check
    - wmi-filters.json        WMI filter names + query text
    - SYSVOL-Policies\        raw SYSVOL policy files (settings + GPP XML)
  Then zips the lot for handoff.

  Performs no AD writes. Run on a Domain Controller or an RSAT management box.

.NOTES
  The SYSVOL copy contains real policy files. Any legacy Group Policy Preferences
  cpassword blobs are included (and are trivially decryptable) — which is exactly
  the kind of thing gpo-lens is meant to flag. Treat the export accordingly.
#>
#requires -Modules GroupPolicy, ActiveDirectory
[CmdletBinding()]
param(
    [string]$OutputRoot = "C:\gpo-export",
    [switch]$SkipSysvol,
    [switch]$NoZip
)

$ErrorActionPreference = 'Stop'
$dom   = Get-ADDomain
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$out   = Join-Path $OutputRoot "$($dom.DNSRoot)-$stamp"
New-Item -ItemType Directory -Force -Path (Join-Path $out 'reports') | Out-Null
Write-Host "Exporting $($dom.DNSRoot) -> $out"

# 1. GPO settings — combined + per-GPO XML
Get-GPOReport -All -ReportType Xml -Path (Join-Path $out 'AllGPOs.xml')
Get-GPO -All | ForEach-Object {
    $safe = ($_.DisplayName -replace '[\\/:*?"<>|]', '_')
    Get-GPOReport -Guid $_.Id -ReportType Xml `
        -Path (Join-Path $out "reports\${safe}__$($_.Id).xml")
}

# 2. GPO metadata + version skew + status + WMI filter
Get-GPO -All | Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime,
    @{n='UserDSVersion';e={$_.User.DSVersion}},         @{n='UserSysvolVersion';e={$_.User.SysvolVersion}},
    @{n='ComputerDSVersion';e={$_.Computer.DSVersion}}, @{n='ComputerSysvolVersion';e={$_.Computer.SysvolVersion}},
    @{n='WmiFilter';e={$_.WmiFilter.Name}} |
    ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'gpo-metadata.json') -Encoding UTF8

# 3. Topology — inheritance + block + enforced + precedence order, per SOM
$targets = @($dom.DistinguishedName) +
           (Get-ADOrganizationalUnit -Filter * | Select-Object -Expand DistinguishedName)
$inh = foreach ($t in $targets) {
    try {
        $g = Get-GPInheritance -Target $t
        [pscustomobject]@{
            Path                  = $g.Path
            Name                  = $g.Name
            ContainerType         = $g.ContainerType
            GpoInheritanceBlocked = $g.GpoInheritanceBlocked
            InheritedGpoLinks     = $g.InheritedGpoLinks |
                Select-Object DisplayName, GpoId, Enabled, Enforced, Order, Target
        }
    } catch { Write-Warning "GPInheritance failed for $t : $($_.Exception.Message)" }
}
$inh | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $out 'gp-inheritance.json') -Encoding UTF8

# 4. OU tree (raw gPLink/gPOptions) — topology cross-check
Get-ADOrganizationalUnit -Filter * -Properties gPLink, gPOptions |
    Select-Object DistinguishedName, Name, gPLink, gPOptions |
    ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'ou-tree.json') -Encoding UTF8

# 5. WMI filters (name + query text)
try {
    Get-ADObject -Filter "objectClass -eq 'msWMI-Som'" -Properties 'msWMI-Name', 'msWMI-Parm2' |
        Select-Object @{n='Name';e={$_.'msWMI-Name'}}, @{n='Query';e={$_.'msWMI-Parm2'}} |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'wmi-filters.json') -Encoding UTF8
} catch { Write-Warning "WMI filter export skipped: $($_.Exception.Message)" }

# 6. Raw SYSVOL Policies (settings + GPP XML; powers cpassword/broken-ref scans)
if (-not $SkipSysvol) {
    $src = "\\$($dom.DNSRoot)\SYSVOL\$($dom.DNSRoot)\Policies"
    Copy-Item $src -Destination (Join-Path $out 'SYSVOL-Policies') -Recurse -Force
}

# Zip for handoff (skip if SYSVOL made it huge and you'd rather send the folder)
if (-not $NoZip) {
    try   { Compress-Archive -Path (Join-Path $out '*') -DestinationPath "$out.zip" -Force; Write-Host "Done: $out.zip" }
    catch { Write-Warning "Zip failed ($($_.Exception.Message)). Send the folder instead: $out" }
}
