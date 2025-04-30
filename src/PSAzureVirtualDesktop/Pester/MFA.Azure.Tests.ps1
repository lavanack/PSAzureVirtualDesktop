param (
    [HostPool[]] $HostPool
)

BeforeDiscovery {
    $MicrosoftEntraIDHostPool = $HostPool | Where-Object -FilterScript {$_.IdentityProvider -eq [IdentityProvider]::MicrosoftEntraID} | Select-Object -First 1
}

Describe "MFA Settings" -ForEach $MicrosoftEntraIDHostPool {
    Context "'No-MFA Users' Entra ID Group" {
        It  "'No-MFA Users' Entra ID Group exists in only one occurence" {
            Get-MgBetaGroup -Filter "DisplayName eq 'No-MFA Users'" | Should -HaveCount 1 #-ErrorAction Stop
        }
    }
}