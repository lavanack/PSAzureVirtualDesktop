param (
    [Parameter(Mandatory)]
    [HostPool[]] $HostPool
)

BeforeDiscovery {
    $AppAttachHostPools = $HostPool | Where-Object -FilterScript {$_.MSIX -or $_.AppAttach} 
}

Describe "<_.Name> HostPool - AppAttach File Shares" -ForEach $AppAttachHostPools {
        BeforeEach {
            $StorageAccount = Get-AzResourceGroup -Name "rg-avd-appattach-poc*" | Get-AzStorageAccount -Name $_.GetAppAttachStorageAccountName()
            # Get the list of file shares in the storage account
            $StorageShare = Get-AzStorageShare -Context $StorageAccount.Context
            $AppAttachStorageShare = $StorageShare | Where-Object  -FilterScript {$_.Name -eq "appattach"}
            $StorageAccountName = $AppAttachStorageShare.context.StorageAccountName
        }
        Context '<_.Name>' {
            It  '<_.Name> HostPool has the right AppAttach File Share' {
                $StorageAccountName | Should -Be $_.GetAppAttachStorageAccountName() #-ErrorAction Stop
        }
    }
}
