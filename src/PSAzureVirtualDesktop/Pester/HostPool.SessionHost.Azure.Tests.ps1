param (
    #[Parameter(Mandatory)]
    [HostPool] $HostPool,
    [string[]] $SessionHostName
)

Describe "'$($HostPool.Name)' HostPool Session Hosts" {
    BeforeEach {
        $SessionHostNames = (Get-AzWvdSessionHost -HostpoolName $HostPool.Name -ResourceGroupName $HostPool.GetResourceGroupName()).ResourceId -replace ".*/"
    }
    Context "'<_>' HostPool Session Host" -ForEach $SessionHostName {
        It  '<_> HostPool Session Host exists' {
            $_ | Should -BeIn $SessionHostNames #-ErrorAction Stop -Verbose
        }
    }
}
