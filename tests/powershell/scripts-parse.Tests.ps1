# Pester 5 guard: every script in scripts/ must parse cleanly and stay ASCII.
#
# These run on windows-latest CI with real PowerShell, covering the collector
# (Export-GpoEstate.ps1) and the principal/group helpers that the unit-style
# install/uninstall tests do not load. A regression here is what shipped a
# parse-breaking em-dash inside a string literal to the field: PowerShell 5.1
# reads a BOM-less .ps1 as the ANSI code page, so a non-ASCII byte (em-dash,
# smart quote) corrupts the surrounding string token and aborts the whole run
# with a cascade of misleading "formatting" parser errors.

$scriptFiles = Get-ChildItem -Path "$PSScriptRoot/../../scripts" -Filter '*.ps1'

Describe "scripts/*.ps1 integrity" {
    It "<Name> parses with no syntax errors" -ForEach $scriptFiles {
        $parseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $_.FullName, [ref]$null, [ref]$parseErrors)
        $messages = if ($parseErrors) {
            ($parseErrors | ForEach-Object {
                "line $($_.Extent.StartLineNumber): $($_.Message)"
            }) -join "; "
        } else { "" }
        $messages | Should -BeNullOrEmpty
    }

    It "<Name> is ASCII-only (a BOM-less .ps1 is read as ANSI by PS 5.1)" -ForEach $scriptFiles {
        $nonAscii = [System.IO.File]::ReadAllBytes($_.FullName) |
            Where-Object { $_ -gt 127 }
        @($nonAscii).Count | Should -Be 0
    }
}

Describe "Export-GpoEstate.ps1 invariants" {
    BeforeAll {
        $script:CollectorPath =
            (Resolve-Path "$PSScriptRoot/../../scripts/Export-GpoEstate.ps1").Path
        $script:CollectorAst = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:CollectorPath, [ref]$null, [ref]$null)
    }

    It "assigns the Get-ADDomain object to `$dom exactly once (never clobbered)" {
        # The AD-domain object is read much later for the SYSVOL UNC path
        # (\\<DNSRoot>\SYSVOL\<DNSRoot>\Policies) and the principals/group domain
        # fields. A loop that reused `$dom` as a local for a "DOMAIN\user" string
        # silently emptied DNSRoot, yielding "\\\SYSVOL\\Policies" and a SYSVOL
        # copy that collected nothing. Pin it: `$dom is assigned once, full stop.
        $assignments = $script:CollectorAst.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $n.Left.VariablePath.UserPath -eq 'dom'
        }, $true)
        @($assignments).Count | Should -Be 1
    }
}
