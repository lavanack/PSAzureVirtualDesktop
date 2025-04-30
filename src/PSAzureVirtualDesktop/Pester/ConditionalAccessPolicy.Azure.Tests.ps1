param (
    [HostPool[]] $HostPool
)

BeforeDiscovery {
    $MicrosoftEntraIDHostPool = $HostPool | Where-Object -FilterScript {$_.IdentityProvider -eq [IdentityProvider]::MicrosoftEntraID} | Select-Object -First 1
}

Describe "Conditional Access Policy Settings" -ForEach $MicrosoftEntraIDHostPool {
    Context "'[AVD] Require multifactor authentication for all users' Conditional Access Policy'" {
        It  "'[AVD] Require multifactor authentication for all users' Conditional Access Policy exists in only one occurence" {
            Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq '[AVD] Require multifactor authentication for all users'" | Should -HaveCount 1 #-ErrorAction Stop
        }
    }

}