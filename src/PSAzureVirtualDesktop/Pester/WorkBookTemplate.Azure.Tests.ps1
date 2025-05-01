param (
    [Parameter(Mandatory)]
    [string[]] $WorkBookTemplateName,
    [Parameter(Mandatory)]
    [string] $ResourceGroupName
)

Describe "Azure Virtual Desktop WorkBook Templates"{
    Context "'<_>' WorkBookTemplate" -ForEach $WorkBookTemplateName {
        It  "'<_>' WorkBookTemplate exists" {
            $DisplayName = $_
            Get-AzApplicationInsightsWorkbookTemplate -Name $DisplayName -ResourceGroupName $ResourceGroupName -ErrorAction Ignore | Should -Not -BeNullOrEmpty #-ErrorAction Stop
        }
    }
}
