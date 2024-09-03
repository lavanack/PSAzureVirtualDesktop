param (
)

Describe "MFA Settings" {
    Context "'No-MFA Users' Entra ID Group" {
        It  "'No-MFA Users' Entra ID Group exists in only one occurence" {
            Get-MgBetaGroup -Filter "DisplayName eq 'No-MFA Users'" | Should -HaveCount 1
        }
    }
}