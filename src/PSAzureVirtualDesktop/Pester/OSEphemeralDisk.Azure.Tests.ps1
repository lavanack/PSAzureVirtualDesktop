param (
    [Parameter(Mandatory)]
    [HostPool[]] $HostPool
)

BeforeDiscovery {
    $OSEphemeralDiskHostPools = $HostPool | Where-Object {[DiffDiskPlacement]::None -ne $_.DiffDiskPlacement}
}

Describe "<_.Name> HostPool - Session Hosts with OS EphemeralDisk" -ForEach $OSEphemeralDiskHostPools {
        BeforeEach {
            $SessionHosts = Get-AzWvdSessionHost -HostpoolName $_.Name -ResourceGroupName $_.GetResourceGroupName() | Sort-Object -Property Name -Descending | Select-Object -First $_.VMNumberOfInstances
            $DiffDiskPlacements = foreach ($CurrentSessionHost in $SessionHosts) {
                $CurrentSessionHostVM = $CurrentSessionHost.ResourceId | Get-AzVM
                $DiffDiskPlacement = $CurrentSessionHostVM.StorageProfile.OsDisk.DiffDiskSettings.Placement
                $DiffDiskPlacement
            }
            $DiffDiskPlacements = $DiffDiskPlacements | Select-Object -Unique
        }
        Context '<_.Name>' {
            It  '<_.Name> HostPool has session hosts with a right OSEphemeralDisk configuration' {
                $DiffDiskPlacements | Should -Be $_.DiffDiskPlacement #-ErrorAction Stop
        }
    }
}
