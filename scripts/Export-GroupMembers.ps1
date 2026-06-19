<#
.SYNOPSIS
  Collect transitive group membership for Plan 020 Phase B (standalone, incremental).

.DESCRIPTION
  Reads principals.json, finds all Group SIDs, resolves members transitively.
  Produces group-members.json.

  This is a standalone script for incremental updates. The main collector
  (Export-GpoEstate.ps1) now produces group-members.json as part of the full export.

.PARAMETER PrincipalsPath
  Path to principals.json. Defaults to principals.json in current directory.

.PARAMETER OutputPath
  Output file path. Defaults to group-members.json in current directory.

.PARAMETER Credential
  PSCredential for AD access. If not provided, uses current user context.

.EXAMPLE
  .\Export-GroupMembers.ps1 -PrincipalsPath "C:\gpo-export\WORK-DOMAIN.local-20260619\principals.json"

.EXAMPLE
  $cred = Get-Credential
  .\Export-GroupMembers.ps1 -Credential $cred
#>
param(
    [string]$PrincipalsPath = "principals.json",
    [string]$OutputPath = "group-members.json",
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'

$adParams = @{}
if ($Credential) { $adParams.Credential = $Credential }

$principalsData = Get-Content $PrincipalsPath -Raw -Encoding UTF8 | ConvertFrom-Json
$groups = $principalsData.principals.PSObject.Properties | Where-Object {
    $_.Value.type -eq "Group"
}

Write-Host "Found $($groups.Count) groups to expand"

$groupMembers = [ordered]@{}
$expanded = 0
$failed = 0

foreach ($grp in $groups) {
    $sid = $grp.Name
    $name = $grp.Value.name
    Write-Host "  Expanding $name ($sid)..."

    try {
        $members = Get-ADGroupMember -Identity $sid -Recursive @adParams -ErrorAction Stop
        $memberSids = @()
        foreach ($m in $members) {
            if ($m.SID) { $memberSids += $m.SID.Value }
        }
        $groupMembers[$sid] = [ordered]@{
            name = $name; members = $memberSids; member_count = $memberSids.Count
        }
        $expanded++
        Write-Host "    $($memberSids.Count) members"
    } catch {
        Write-Host "    FAIL: $($_.Exception.Message)"
        $groupMembers[$sid] = [ordered]@{
            name = $name; members = @(); member_count = 0; error = $_.Exception.Message
        }
        $failed++
    }
}

# Well-known implicit groups
$groupMembers["s-1-5-11"] = [ordered]@{
    name = "Authenticated Users"; members = @(); member_count = 0
    implicit = "All authenticated domain principals (users + computers)"
}
$groupMembers["s-1-1-0"] = [ordered]@{
    name = "Everyone"; members = @(); member_count = 0
    implicit = "All principals including anonymous"
}

$out = [ordered]@{
    collected = (Get-Date -Format "o")
    domain = $principalsData.domain
    groups = $groupMembers
}

$out | ConvertTo-Json -Depth 5 | Set-Content $OutputPath -Encoding UTF8
Write-Host "Done: $expanded expanded, $failed failed -> $OutputPath"
