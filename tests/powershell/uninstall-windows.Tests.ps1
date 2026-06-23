# Pester 5 tests for the SSL-binding decision functions extracted from
# scripts/uninstall-windows.ps1.
#
# The script is dot-sourced to load the functions without executing the
# uninstall body (guarded by `if ($MyInvocation.InvocationName -ne ".")`).
# These functions are pure, so no IIS/http.sys mocking is needed.

Describe "uninstall-windows.ps1" {
    BeforeAll {
        $script:SourcePath = "$PSScriptRoot/../../scripts/uninstall-windows.ps1"
        . $script:SourcePath
    }

    Describe "Get-IsSniFlag" {
        It "treats numeric sslFlags=1 as SNI" {
            Get-IsSniFlag -SslFlags "1" | Should -BeTrue
        }

        It "treats numeric sslFlags=0 as catch-all" {
            Get-IsSniFlag -SslFlags "0" | Should -BeFalse
        }

        It "treats sslFlags=3 (SNI + Central Cert Store) as SNI" {
            # bit 1 is SNI; the bitmask must be AND-ed, not equality-checked.
            Get-IsSniFlag -SslFlags "3" | Should -BeTrue
        }

        It "treats sslFlags=2 (CCS only, no SNI bit) as catch-all" {
            Get-IsSniFlag -SslFlags "2" | Should -BeFalse
        }

        It "honors the legacy string form 'Sni'" {
            Get-IsSniFlag -SslFlags "Sni" | Should -BeTrue
        }

        It "honors the legacy string form 'None'" {
            Get-IsSniFlag -SslFlags "None" | Should -BeFalse
        }
    }

    Describe "Resolve-OwnedSslBinding" {
        It "catch-all WITH a host header still resolves to ipport (the LAB-HOST-1 case)" {
            # The regression: a catch-all binding can carry a hostname. The
            # decision must follow sslFlags (IsSni=false), not hostname presence.
            $r = Resolve-OwnedSslBinding -IsSni $false -BindingHost "host.example.com" -Port 443
            $r.Mode | Should -Be "catchall"
            $r.Target | Should -Be "ipport=0.0.0.0:443"
        }

        It "catch-all with no host resolves to ipport" {
            $r = Resolve-OwnedSslBinding -IsSni $false -BindingHost "" -Port 8443
            $r.Mode | Should -Be "catchall"
            $r.Target | Should -Be "ipport=0.0.0.0:8443"
        }

        It "SNI with a host resolves to hostnameport (and never the catch-all)" {
            $r = Resolve-OwnedSslBinding -IsSni $true -BindingHost "gpo-lens.example.com" -Port 443
            $r.Mode | Should -Be "sni"
            $r.Target | Should -Be "hostnameport=gpo-lens.example.com:443"
        }

        It "SNI without a host falls back to catch-all (cannot target a hostnameport)" {
            $r = Resolve-OwnedSslBinding -IsSni $true -BindingHost "" -Port 443
            $r.Mode | Should -Be "catchall"
            $r.Target | Should -Be "ipport=0.0.0.0:443"
        }

        It "uses the requested port in the target" {
            $r = Resolve-OwnedSslBinding -IsSni $true -BindingHost "h" -Port 9443
            $r.Target | Should -Be "hostnameport=h:9443"
        }
    }
}
