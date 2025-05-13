param (
)

Describe "Conditional Access Policy Settings" {
    Context "'[AVD] Require multifactor authentication for all users' Conditional Access Policy'" {
        It  "'[AVD] Require multifactor authentication for all users' Conditional Access Policy exists in only one occurence" {
            (Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq '[AVD] Require multifactor authentication for all users'") -as [array] | Should -HaveCount 1 #-ErrorAction Stop
        }
    }

}