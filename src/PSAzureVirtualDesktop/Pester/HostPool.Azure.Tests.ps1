param (
    [Parameter(Mandatory)]
    [HostPool[]] $HostPool
)

BeforeAll {
    $AzAvdHostPoolHT = foreach ($CurrentHostPool in $HostPool) {
        Get-AzWvdHostPool -ResourceGroupName $CurrentHostPool.GetResourceGroupName() -Name $CurrentHostPool.Name -ErrorAction Ignore
    }
    $AzAvdHostPoolHT = $AzAvdHostPoolHT | Group-Object -Property Name -AsHashTable -AsString

    $AzWvdSessionHostHT = @{}
    foreach ($CurrentHostPool in $HostPool) {
        $AzWvdSessionHostHT.Add($CurrentHostPool.Name, (Get-AzWvdSessionHost -ResourceGroupName $CurrentHostPool.GetResourceGroupName() -HostPoolName $CurrentHostPool.Name).Count)
    }
}

Describe "<_.Name> HostPool - Azure Instantiation" -ForEach $HostPool {
    Context '<_.Name>' {
        It  '<_.Name> HostPool exists in Azure' {
            $_.Name | Should -BeIn $AzAvdHostPoolHT.Keys #-ErrorAction Stop -Verbose
        }

        It  '<_.Name> HostPool has the right HostPoolType' {
            $AzAvdHostPoolHT[$_.Name].HostPoolType.ToString() | Should -Be $_.Type.ToString() #-ErrorAction Stop
            #$_.Type | Should -Be $AzAvdHostPoolHT[$_.Name].HostPoolType #-ErrorAction Stop
        }

        It  '<_.Name> HostPool has the right Azure Location' {
            $AzAvdHostPoolHT[$_.Name].Location | Should -Be $_.Location #-ErrorAction Stop
        }

        It  '<_.Name> HostPool has the right MaxSessionLimit' {
            $AzAvdHostPoolHT[$_.Name].MaxSessionLimit | Should -BeIn @($_.maxSessionLimit, 999999)  #-ErrorAction Stop
        }

        It  '<_.Name> HostPool has the right VMNumberOfInstances' {
            $AzWvdSessionHostHT[$_.Name] | Should -Be $_.VMNumberOfInstances #-ErrorAction Stop
        }
    }
}
