<#
.SYNOPSIS
  Export a full Group Policy estate for offline analysis by gpo-lens.

.DESCRIPTION
  Read-only collector. Produces, per domain:
    - AllGPOs.xml            combined Get-GPOReport (whole domain)
    - reports\*.xml          per-GPO XML reports (GUID in filename disambiguates dupes)
    - collection-errors.json GPOs that could not be read (e.g. Authenticated Users
                             Read stripped), named by GUID so coverage gaps are explicit
    - gpo-inventory.json     every GPC GUID this account could enumerate; run once as a
                             privileged account for an authoritative coverage baseline
    - gpo-metadata.json      status, timestamps, version skew (DS vs SYSVOL), WMI filter
    - gp-inheritance.json    per-SOM inheritance: block, enforced, precedence order
    - ou-tree.json           raw OU tree (gPLink/gPOptions) as a topology cross-check
    - sites.json             AD site GPO links (gPLink/gPOptions) from the Config partition
    - wmi-filters.json        WMI filter names + query text
    - SYSVOL-Policies\        raw SYSVOL policy files (settings + GPP XML)
  Then zips the lot for handoff.

  Performs no AD writes. Run on a Domain Controller or an RSAT management box.

.PARAMETER OutputRoot
  Directory where the export folder (and zip) will be created.

.PARAMETER SkipSysvol
  Do not copy the SYSVOL Policies directory.

.PARAMETER NoZip
  Do not create a zip archive; leave the export folder in place.

.PARAMETER DryRun
  List what would be exported without actually exporting.

.NOTES
  Minimum permissions:
    - Domain User (or any authenticated principal) with Read access to the
      SYSVOL \\domain\SYSVOL\domain\Policies share.
    - Group Policy Creator Owners membership is NOT required; this script is
      read-only.

  Prerequisites:
    - RSAT Group Policy tools must be installed (provides GroupPolicy module).
    - RSAT Active Directory module must be installed (provides ActiveDirectory module).
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = "C:\gpo-export",
    [switch]$SkipSysvol,
    [switch]$NoZip,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

foreach ($mod in @('GroupPolicy','ActiveDirectory')) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Error "Required module '$mod' is not available. Install RSAT."
    }
}

try {
    $testFile = Join-Path $OutputRoot "_writetest_.tmp"
    [System.IO.File]::WriteAllText($testFile, "test")
    Remove-Item $testFile -Force
} catch {
    Write-Error "OutputRoot '$OutputRoot' is not writable: $($_.Exception.Message)"
}

$dom = Get-ADDomain
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$out = Join-Path $OutputRoot "$($dom.DNSRoot)-$stamp"

$allGpos = Get-GPO -All
$gpoCount = $allGpos.Count
$ouCount = @(Get-ADOrganizationalUnit -Filter *).Count
$wmiCount = @(Get-ADObject -Filter "objectClass -eq 'msWMI-Som'" -Properties 'msWMI-Name' -ErrorAction SilentlyContinue).Count
$siteCount = @(Get-ADObject -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter "(objectClass=site)" -ErrorAction SilentlyContinue).Count

if ($DryRun) {
    $sysvolSizeStr = "skipped"
    if (-not $SkipSysvol) {
        $src = "\\$($dom.DNSRoot)\SYSVOL\$($dom.DNSRoot)\Policies"
        $sysvolSize = (Get-ChildItem $src -Recurse -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        $sysvolSizeStr = "$([math]::Round($sysvolSize / 1MB, 2)) MB"
    }
    Write-Host "DryRun: would export the following:"
    Write-Host "  Domain:        $($dom.DNSRoot)"
    Write-Host "  GPOs:          $gpoCount"
    Write-Host "  OUs:           $ouCount"
    Write-Host "  WMI filters:   $wmiCount"
    Write-Host "  AD sites:      $siteCount"
    Write-Host "  Output dir:    $out"
    Write-Host "  SYSVOL:        $(if ($SkipSysvol) {'skipped'} else {$sysvolSizeStr})"
    Write-Host "  Zip:           $(if ($NoZip) {'skipped'} else {"$out.zip"})"
    return
}

New-Item -ItemType Directory -Force -Path (Join-Path $out 'reports') | Out-Null
Write-Host "Exporting $($dom.DNSRoot) -> $out"

$successSections = [System.Collections.Generic.List[string]]::new()
$failedSections  = [System.Collections.Generic.List[string]]::new()

$totalSections = 7
$sectionNum = 0

function Set-SectionProgress {
    param([string]$Activity, [int]$Section)
    $pct = [math]::Round(($Section / $totalSections) * 100)
    Write-Progress -Activity $Activity -PercentComplete $pct
}

$sectionNum++
Set-SectionProgress -Activity "GPO settings (XML reports)" -Section $sectionNum
# Per-GPO resilience: one unreadable GPO (e.g. Authenticated Users Read stripped
# for security filtering) must not abort the rest. Each failure is captured with
# its GUID so analysis can flag incomplete coverage rather than silently omit it.
$collectionErrors = [System.Collections.Generic.List[object]]::new()

try {
    Get-GPOReport -All -ReportType Xml -Path (Join-Path $out 'AllGPOs.xml') -ErrorAction Stop
} catch {
    $collectionErrors.Add([pscustomobject]@{
        GpoId = $null; DisplayName = '(combined report)'; Stage = 'report-all'
        Error = $_.Exception.Message
    })
    Write-Warning "Combined GPO report failed: $($_.Exception.Message)"
}

$i = 0
foreach ($gpo in $allGpos) {
    $i++
    Write-Progress -Activity "GPO settings (XML reports)" `
        -Status "$i / $gpoCount" -PercentComplete ([math]::Round(($sectionNum - 1 + ($i / $gpoCount)) / $totalSections * 100))
    $safe = ($gpo.DisplayName -replace '[\\/:*?"<>|\[\]]', '_')
    try {
        Get-GPOReport -Guid $gpo.Id -ReportType Xml `
            -Path (Join-Path $out "reports\${safe}__$($gpo.Id).xml") -ErrorAction Stop
    } catch {
        $collectionErrors.Add([pscustomobject]@{
            GpoId = $gpo.Id.Guid; DisplayName = $gpo.DisplayName; Stage = 'report'
            Error = $_.Exception.Message
        })
        Write-Warning "GPO report failed for '$($gpo.DisplayName)' ($($gpo.Id)): $($_.Exception.Message)"
    }
}

# Completeness cross-check: Get-GPO -All silently omits GPOs whose properties the
# account cannot read, but the Policies container grants List Contents, so the GPC
# objects (and their GUIDs) are still enumerable. Any GUID present in AD but absent
# from Get-GPO -All is an inaccessible GPO we must name, not drop.
try {
    $policiesDN = "CN=Policies,CN=System,$($dom.DistinguishedName)"
    $allGpc = Get-ADObject -SearchBase $policiesDN -LDAPFilter "(objectClass=groupPolicyContainer)" `
        -Properties displayName -ErrorAction Stop
    # Persist the inventory (every GPC GUID this account could enumerate). Run the
    # collector once as a privileged account for an AUTHORITATIVE inventory; gpo-lens
    # reconciles it against the (least-privilege) export to name coverage gaps.
    @($allGpc | ForEach-Object { [pscustomobject]@{ Id = $_.Name.Trim('{}'); DisplayName = $_.displayName } }) |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'gpo-inventory.json') -Encoding UTF8
    $knownIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $allGpos) { $null = $knownIds.Add($g.Id.Guid) }
    foreach ($gpc in $allGpc) {
        $guid = $gpc.Name.Trim('{}')
        if (-not $knownIds.Contains($guid)) {
            $collectionErrors.Add([pscustomobject]@{
                GpoId = $guid; DisplayName = $gpc.displayName; Stage = 'enumerate'
                Error = 'GPC exists in AD but Get-GPO could not read it (Authenticated Users Read may be stripped)'
            })
            Write-Warning "Inaccessible GPO detected: $guid$(if ($gpc.displayName) { " ($($gpc.displayName))" })"
        }
    }
} catch {
    Write-Warning "GPC completeness cross-check failed: $($_.Exception.Message)"
}

# Always emit the manifest (valid JSON array even when empty) so analysis can read it.
if ($collectionErrors.Count -eq 0) {
    '[]' | Set-Content (Join-Path $out 'collection-errors.json') -Encoding UTF8
    $successSections.Add("GPO settings (XML reports)")
} else {
    $collectionErrors | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'collection-errors.json') -Encoding UTF8
    $failedSections.Add("GPO settings: $($collectionErrors.Count) GPO(s) could not be collected (see collection-errors.json)")
}

$sectionNum++
Set-SectionProgress -Activity "GPO metadata" -Section $sectionNum
try {
    $allGpos | Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime,
        @{n='UserDSVersion';e={$_.User.DSVersion}},         @{n='UserSysvolVersion';e={$_.User.SysvolVersion}},
        @{n='ComputerDSVersion';e={$_.Computer.DSVersion}}, @{n='ComputerSysvolVersion';e={$_.Computer.SysvolVersion}},
        @{n='WmiFilter';e={$_.WmiFilter.Name}} |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'gpo-metadata.json') -Encoding UTF8
    $successSections.Add("GPO metadata")
} catch {
    $failedSections.Add("GPO metadata: $($_.Exception.Message)")
}

$sectionNum++
Set-SectionProgress -Activity "Inheritance (gp-inheritance)" -Section $sectionNum
try {
    $targets = @($dom.DistinguishedName) +
               (Get-ADOrganizationalUnit -Filter * | Select-Object -Expand DistinguishedName)
    $totalTargets = $targets.Count
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
    $successSections.Add("Inheritance (gp-inheritance)")
} catch {
    $failedSections.Add("Inheritance (gp-inheritance): $($_.Exception.Message)")
}

$sectionNum++
Set-SectionProgress -Activity "OU tree" -Section $sectionNum
try {
    Get-ADOrganizationalUnit -Filter * -Properties gPLink, gPOptions |
        Select-Object DistinguishedName, Name, gPLink, gPOptions |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'ou-tree.json') -Encoding UTF8
    $successSections.Add("OU tree")
} catch {
    $failedSections.Add("OU tree: $($_.Exception.Message)")
}

$sectionNum++
Set-SectionProgress -Activity "AD sites" -Section $sectionNum
try {
    # Site GPO links live in the Configuration partition, not under the domain.
    $configNC = (Get-ADRootDSE).configurationNamingContext
    Get-ADObject -SearchBase "CN=Sites,$configNC" -LDAPFilter "(objectClass=site)" `
        -Properties gPLink, gPOptions, name |
        Select-Object DistinguishedName, Name, gPLink, gPOptions |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'sites.json') -Encoding UTF8
    $successSections.Add("AD sites")
} catch {
    $failedSections.Add("AD sites: $($_.Exception.Message)")
}

$sectionNum++
Set-SectionProgress -Activity "WMI filters" -Section $sectionNum
try {
    Get-ADObject -Filter "objectClass -eq 'msWMI-Som'" -Properties 'msWMI-Name', 'msWMI-Parm2' |
        Select-Object @{n='Name';e={$_.'msWMI-Name'}}, @{n='Query';e={$_.'msWMI-Parm2'}} |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'wmi-filters.json') -Encoding UTF8
    $successSections.Add("WMI filters")
} catch {
    $failedSections.Add("WMI filters: $($_.Exception.Message)")
}

$sectionNum++
Set-SectionProgress -Activity "SYSVOL copy" -Section $sectionNum
try {
    if (-not $SkipSysvol) {
        $src = "\\$($dom.DNSRoot)\SYSVOL\$($dom.DNSRoot)\Policies"
        Copy-Item $src -Destination (Join-Path $out 'SYSVOL-Policies') -Recurse -Force
        $successSections.Add("SYSVOL copy")
    } else {
        $successSections.Add("SYSVOL copy (skipped)")
    }
} catch {
    $failedSections.Add("SYSVOL copy: $($_.Exception.Message)")
}

Write-Progress -Activity "Export complete" -Completed

Write-Host "`nExport summary:`n  Succeeded ($($successSections.Count)):"
foreach ($s in $successSections) { Write-Host "    - $s" }
if ($failedSections.Count -gt 0) {
    Write-Host "  Failed ($($failedSections.Count)):"
    foreach ($s in $failedSections) { Write-Host "    - $s" }
} else {
    Write-Host "  All sections succeeded."
}

if (-not $NoZip) {
    try {
        Compress-Archive -Path (Join-Path $out '*') -DestinationPath "$out.zip" -Force
        Write-Host "Done: $out.zip"
    } catch {
        Write-Warning "Zip failed ($($_.Exception.Message)). Send the folder instead: $out"
    }
}
