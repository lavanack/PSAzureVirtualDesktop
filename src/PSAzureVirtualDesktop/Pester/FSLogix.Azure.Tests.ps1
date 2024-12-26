param (
    #[Parameter(Mandatory)]
    [HostPool[]] $HostPool
)

BeforeDiscovery {
    $FSLogixHostPools = $HostPool | Where-Object -FilterScript {$_.FSLogix} 
}

Describe "<_.Name> HostPool - FSLogix File Shares" -ForEach $FSLogixHostPools {
        BeforeEach {
            $StorageAccount = Get-AzStorageAccount -Name $_.GetFSLogixStorageAccountName() -ResourceGroupName $_.GetResourceGroupName()
            # Get the list of file shares in the storage account
            $StorageShare = Get-AzStorageShare -Context $StorageAccount.Context 
            $FSLogixStorageShare = $StorageShare | Where-Object  -FilterScript {$_.Name -eq "profiles"}
            $StorageAccountName = $FSLogixStorageShare.context.StorageAccountName
        }
        Context '<_.Name>' {
            It  '<_.Name> HostPool has the right FSLogix File Share' {
                $StorageAccountName | Should -Be $_.GetFSLogixStorageAccountName() #-ErrorAction Stop
        }
    }
}
