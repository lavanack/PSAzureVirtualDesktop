param (
    #[Parameter(Mandatory)]
    [HostPool[]] $HostPool
)

BeforeDiscovery {
    $MSIXHostPools = $HostPool | Where-Object -FilterScript {$_.MSIX} 
}

Describe "<_.Name> HostPool - MSIX File Shares" -ForEach $MSIXHostPools {
        BeforeEach {
            $StorageAccount = Get-AzStorageAccount -Name $_.GetAppAttachStorageAccountName() -ResourceGroupName $_.GetResourceGroupName()
            # Get the list of file shares in the storage account
            $StorageShare = Get-AzStorageShare -Context $StorageAccount.Context
            $MSIXStorageShare = $StorageShare | Where-Object  -FilterScript {$_.Name -eq "msix"}
            $StorageAccountName = $MSIXStorageShare.context.StorageAccountName
        }
        Context '<_.Name>' {
            It  '<_.Name> HostPool has the right MSIX File Share' {
                $StorageAccountName | Should -Be $_.GetAppAttachStorageAccountName() #-ErrorAction Stop
        }
    }
}
