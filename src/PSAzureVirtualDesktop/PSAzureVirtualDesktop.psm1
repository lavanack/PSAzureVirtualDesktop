#region PowerShell HostPool classes
enum IdentityProvider {
    ActiveDirectory
    MicrosoftEntraID
    #Hybrid
}

enum HostPoolType {
    Personal
    Pooled
}

enum DiffDiskPlacement {
    #Temp/Resource Disk
    ResourceDisk
    #OS Cache Disk
    CacheDisk
    None
}

Class HostPool {
    [ValidateNotNullOrEmpty()] [IdentityProvider] $IdentityProvider
    [ValidateNotNullOrEmpty()] [string] $Name
    [ValidateNotNullOrEmpty()] [HostPoolType] $Type
    [ValidateNotNullOrEmpty()] [string] $Location
    [ValidateNotNullOrEmpty()] [string] $PairedRegion
    [ValidateNotNullOrEmpty()][ValidatePattern("/subscriptions/\w{8}-\w{4}-\w{4}-\w{4}-\w{12}/resourceGroups/.*/providers/Microsoft\.Network/virtualNetworks/.*/subnets/.*")] [string] $SubnetId
    [ValidateLength(3, 11)] [string] $NamePrefix
    [ValidateRange(1, 10)] [uint16]    $VMNumberOfInstances
    [ValidateNotNullOrEmpty()] [Object] $KeyVault
    [boolean] $Intune
    [boolean] $Spot
    [boolean] $ScalingPlan
    [boolean] $Watermarking
    [ValidateNotNullOrEmpty()] [string] $VMSize
    [string] $ImagePublisherName
    [string] $ImageOffer
    [string] $ImageSku
    [string] $VMSourceImageId
    [String] $LoadBalancerType
    [string] $ASRFailOverVNetId = $null
    [DiffDiskPlacement] $DiffDiskPlacement = [DiffDiskPlacement]::None
    static [hashtable] $AzLocationShortNameHT = $null     
    static [hashtable] $AzEphemeralOsDiskSkuHT = $null
    static [hashtable] $AzPairedRegionHT = $null
    static [uint16] $VMProfileOsdiskSizeGb = 127
    
    hidden static BuildAzureLocationSortNameHashtable() {
        if ($null -eq [HostPool]::AzLocationShortNameHT) {
            $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
            $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
            [HostPool]::AzLocationShortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
        }
    }
    
    hidden static BuildAzurePairedRegionHashtable() {
        if ($null -eq [HostPool]::AzPairedRegionHT) {
            [HostPool]::AzPairedRegionHT = (Get-AzLocation -OutVariable locations) | Select-Object -Property Location, PhysicalLocation, @{Name='PairedRegion';Expression={$_.PairedRegion.Name}}, @{Name='PairedRegionPhysicalLocation';Expression={($locations | Where-Object -FilterScript {$_.location -eq $_.PairedRegion.Name}).PhysicalLocation} } | Where-Object -FilterScript { $_.PairedRegion } | Group-Object -Property Location -AsHashTable -AsString
        }
    }
    
    hidden static BuildAzureEphemeralOsDiskSkuHashtable([String] $Location, [uint16]$OSImageSizeInGB) {
        if (($null -eq [HostPool]::AzEphemeralOsDiskSkuHT) -or (-not([HostPool]::AzEphemeralOsDiskSkuHT.ContainsKey($Location)))) {
            #Based on https://learn.microsoft.com/en-us/azure/virtual-machines/ephemeral-os-disks-faq
            $VmSkus = Get-AzComputeResourceSku $Location | Where-Object -FilterScript { ($_.ResourceType -eq "virtualMachines") -and ($_.Capabilities | Where-Object -FilterScript { ($_.Name -eq "EphemeralOSDiskSupported") -and ($_.Value -eq "True") }) }
            $EphemeralOsDisk = foreach ($sku in $VmSkus) {
                $MaxResourceVolumeGB = 0
                $CachedDiskGB = 0
                foreach ($capability in $sku.Capabilities) {
                    if ($capability.Name -eq "MaxResourceVolumeMB") {
                        $MaxResourceVolumeGB = [int]($capability.Value / 1024) 
                    }
 
                    if ($capability.Name -eq "CachedDiskBytes") {
                        $CachedDiskGB = [int]($capability.Value / 1GB) 
                    }
                }
                [PSCustomObject][ordered]@{
                    Name                = $sku.Name
                    MaxResourceVolumeGB = $MaxResourceVolumeGB
                    OSImageSizeInGB     = $OSImageSizeInGB
                    ResourceDisk        = ($MaxResourceVolumeGB -ge $OSImageSizeInGB)
                    CacheDisk           = ($CachedDiskGB -ge $OSImageSizeInGB)
                }
            }
            if ($null -eq [HostPool]::AzEphemeralOsDiskSkuHT) {
                [HostPool]::AzEphemeralOsDiskSkuHT = @{}
            }
            [HostPool]::AzEphemeralOsDiskSkuHT[$Location] = $EphemeralOsDisk 
        }
    }

    static [array] GetAzureEphemeralOsDiskSku([String] $Location) {
        [HostPool]::BuildAzureEphemeralOsDiskSkuHashtable($Location, [HostPool]::VMProfileOsdiskSizeGb)
        return $([HostPool]::AzEphemeralOsDiskSkuHT[$Location])
    }

    hidden Init([Object] $KeyVault, [string] $SubnetId) {
        [HostPool]::BuildAzureLocationSortNameHashtable()
        if ($null -eq [HostPool]::AzEphemeralOsDiskSkuHT) {
            [HostPool]::AzEphemeralOsDiskSkuHT = @{}
        }
        $this.VMSize = "Standard_D2s_v5"
        $this.SubnetId = $SubnetId        
        #Getting the VNet from the Subnet
        $VirtualNetwork = $this.GetVirtualNetwork()
        $this.SetLocation($VirtualNetwork.Location)
        $this.VMNumberOfInstances = 3
        $this.DisableSpotInstance()
        $this.DisableIntune()            
        $this.DisableScalingPlan()
        $this.KeyVault = $KeyVault
        $this.IdentityProvider = [IdentityProvider]::ActiveDirectory
        $this.ASRFailOverVNetId = $null
    }
        
    HostPool([Object] $KeyVault, [string] $SubnetId) {
        #Write-Host "Calling HostPool Constructor with KeyVault parameter ..."
        $this.Init($KeyVault, $SubnetId)
    }

    HostPool([Object] $KeyVault) {
        #Write-Host "Calling HostPool Constructor with KeyVault parameter ..."
        $Subnet = Get-AzVMSubnet
        $this.Init($KeyVault, $Subnet.Id)
    }

    [object] GetVirtualNetwork() {
        return Get-AzResource -ResourceID $($this.SubnetId -replace "/subnets/.*$") | Get-AzVirtualNetwork
    }


    [string] GetAzAvdWorkSpaceName() {
        return "ws-{0}" -f $($this.Name.ToLower())
    }

    [string] GetAzAvdScalingPlanName() {
        if ($this.ScalingPlan) {
            return "sp-{0}" -f $($this.Name.ToLower())
        }
        else {
            return $null
        }
    }

    [string] GetLogAnalyticsWorkSpaceName() {
        return "log{0}" -f $($this.Name.ToLower() -replace "\W")
    }

    [string] GetResourceGroupName() {
        return "rg-avd-{0}" -f $($this.Name.ToLower())
    }

    [string] GetKeyVaultName() {
        $KeyVaultNameMaxLength = 24
        $KeyVaultName = "kv{0}" -f $($this.Name.ToLower() -replace "\W")
        $KeyVaultName = $KeyVaultName.Substring(0, [system.math]::min($KeyVaultNameMaxLength, $KeyVaultName.Length)).ToLower()
        return $KeyVaultName
    }

    static [string] GetAzurePairedRegion([string] $Location) {
        [HostPool]::BuildAzurePairedRegionHashtable()
        return ([HostPool]::AzPairedRegionHT[$Location].PairedRegion -as [string])
    }

    [string] GetAzurePairedRegion() {
        #Non working solution in case of a ThreadJob (don't know why)
        #return [HostPool]::GetAzurePairedRegion($this.Location)
        [HostPool]::BuildAzurePairedRegionHashtable()
        return ([HostPool]::AzPairedRegionHT[$this.Location].PairedRegion -as [string])
    }

    [string] GetRecoveryLocationResourceGroupName() {
        $AzurePairedRegion = $this.GetAzurePairedRegion()
        if ([string]::IsNullOrEmpty($AzurePairedRegion)) {
            return $null
        }
        else 
        {
            return $this.GetResourceGroupName() -replace [HostPool]::AzLocationShortNameHT[$this.Location].shortName, [HostPool]::AzLocationShortNameHT[$AzurePairedRegion].shortName
        }
    }

    [string] GetRecoveryServiceVaultName() {
        return $this.GetRecoveryLocationResourceGroupName() -replace "^rg", "rsv"
    }

    [object] GetPropertyForJSON() {
        return $this | Select-Object -Property *, @{Name = "ResourceGroupName"; Expression = { $_.GetResourceGroupName() } }, @{Name = "KeyVaultName"; Expression = { $_.GetKeyVaultName() } }, @{Name = "LogAnalyticsWorkSpaceName"; Expression = { $_.GetLogAnalyticsWorkSpaceName() } }, @{Name = "RecoveryLocationResourceGroupName"; Expression = { $_.GetRecoveryLocationResourceGroupName() } }, @{Name = "RecoveryServiceVaultName"; Expression = { $_.GetRecoveryServiceVaultName() } }, @{Name = "CredentialKeyVault"; Expression = { $_.KeyVault.VaultName } } -ExcludeProperty "KeyVault"
    }

    [HostPool] SetVMNumberOfInstances([uint16] $VMNumberOfInstances) {
        $this.VMNumberOfInstances = $VMNumberOfInstances
        return $this
    }

    [HostPool]DisableIntune() {
        $this.Intune = $false
        return $this
    }

    [HostPool]EnableIntune() {
        $this.Intune = $true
        $this.SetIdentityProvider([IdentityProvider]::MicrosoftEntraID)
        return $this
    }

    <#
        [bool] IsIntuneEnrolled() {
            return $this.Intune
        }
        #>

    [HostPool]DisableScalingPlan() {
        $this.ScalingPlan = $false
        return $this
    }

    [HostPool]EnableScalingPlan() {
        $this.ScalingPlan = $true
        return $this
    }

    [HostPool]DisableWatermarking() {
        $this.Watermarking = $false
        return $this
    }

    [HostPool] EnableWatermarking() {
        $this.Watermarking = $true
        return $this
    }

    [HostPool]DisableSpotInstance() {
        $this.Spot = $false
        return $this
    }

    [HostPool]EnableSpotInstance() {
        $this.Spot = $true
        return $this
    }

    [HostPool]DisableEphemeralOSDisk() {
        $this.DiffDiskPlacement = [DiffDiskPlacement]::None
        return $this
    }

    [HostPool]EnableEphemeralOSDisk([DiffDiskPlacement] $DiffDiskPlacement) {
        [HostPool]::BuildAzureEphemeralOsDiskSkuHashtable($this.Location, [HostPool]::VMProfileOsdiskSizeGb)
        $AzEphemeralOsDiskSkuForThisLocation = ([HostPool]::AzEphemeralOsDiskSkuHT)[$this.Location]
        Write-Verbose -Message "$($AzEphemeralOsDiskSkuForThisLocation | Out-String)"
        $CurrentAzEphemeralOsDiskSku = $AzEphemeralOsDiskSkuForThisLocation | Where-Object -FilterScript { $_.Name -eq $this.VMSize }
        if ($null -ne $CurrentAzEphemeralOsDiskSku) {
            Write-Verbose -Message "$($CurrentAzEphemeralOsDiskSku | Out-String)"
            if ($CurrentAzEphemeralOsDiskSku.$DiffDiskPlacement) {
                Write-Verbose -Message "'$($this.VMSize)' is eligible to Ephemeral OS Disk for '$DiffDiskPlacement'"
                $this.DiffDiskPlacement = $DiffDiskPlacement
                return $this
            }
            else {
                $this.DiffDiskPlacement = [DiffDiskPlacement]::None
                Write-Verbose -Message "'$($this.VMSize)' is eligible to Ephemeral OS Disk but NOT for '$DiffDiskPlacement'. Returning $null"
                return $null
            }
        }
        else {
            $this.DiffDiskPlacement = [DiffDiskPlacement]::None
            Write-Verbose -Message "The specified '$($this.VMSize)' VM Size is not available in the '$($this.Location)' Azure region. Returning $null"
            return $null
        }
    }

    hidden RefreshNames() {
        #Overwritten in the child classes
    }

    [bool] IsMicrosoftEntraIdJoined() {
        return ($this.IdentityProvider -eq [IdentityProvider]::MicrosoftEntraID)
    }

    [bool] IsActiveDirectoryJoined() {
        return ($this.IdentityProvider -eq [IdentityProvider]::ActiveDirectory)
    }

    [HostPool] SetIdentityProvider([IdentityProvider] $IdentityProvider) {
        $this.IdentityProvider = $IdentityProvider
        if ($IdentityProvider -eq [IdentityProvider]::ActiveDirectory) {
            $this.DisableIntune()
        }
        $this.RefreshNames()
        return $this
    }

    [HostPool] SetVMSize([string] $VMSize) {
        if ($VMSize -in (Get-AzVMSize -Location $this.Location).Name) {
            $this.VMSize = $VMSize
        }
        else {
            Write-Warning "The specified '$VMSize' VM Size is not available in the '$($this.Location)' Azure region. We keep the previously set VM Size: '$($this.VMSize)' ..."
        }

        #Changing Size resets the DiffDiskPlacement
        $this.DiffDiskPlacement = [DiffDiskPlacement]::None
        return $this
    }

    [HostPool] SetLocation([string] $Location) {
        if ([HostPool]::AzLocationShortNameHT.ContainsKey($Location)) {
            if ($this.VMSize -in (Get-AzVMSize -Location $Location).Name) {
                $this.Location = $Location
                $this.PairedRegion = $this.GetAzurePairedRegion()
                $this.RefreshNames()
            }
            else {
                Write-Warning "The specified '$($Location)' Azure region doesn't allow the '$($this.VMSize)'. We keep the previously set location: '$($this.Location)' ..."
            }
        }
        else {
            Write-Warning -Message "Unknown Azure Location: '$($Location)'. We keep the previously set location: '$($this.Location)'"
        }

        [HostPool]::BuildAzureEphemeralOsDiskSkuHashtable($this.Location, [HostPool]::VMProfileOsdiskSizeGb)

        return $this
    }

    [HostPool] SetName([string] $Name, [string] $NamePrefix) {
        $this.Name = $Name
        $this.NamePrefix = $NamePrefix
        return $this
    }

    [HostPool] SetImage([string] $ImagePublisherName, [string] $ImageOffer, [string] $ImageSku ) {
        $this.ImagePublisherName = $ImagePublisherName
        $this.ImageOffer = $ImageOffer
        $this.ImageSku = $ImageSku
        $this.RefreshNames()
        return $this
    }

    [HostPool] SetVMSourceImageId([string] $VMSourceImageId) {
        $this.VMSourceImageId = $VMSourceImageId
        $this.RefreshNames()
        return $this
    }


    [HostPool]EnableAzureSiteRecovery([string] $vNetId) {

        $RecoveryNetwork = Get-AzVirtualNetwork | Where-Object -FilterScript { $_.Id -eq $vNetId }
        $RecoveryLocation = $this.GetAzurePairedRegion()
        if ($RecoveryNetwork.Location -eq $RecoveryLocation) {
            $this.ASRFailOverVNetId = $vNetId
        }
        else{
            Write-Error -Message "The FailOver Virtual Network '$vNetId' is not in the '$RecoveryLocation' region ! Azure Site Recovery won't be enabled"
        }
        return $this
    }

    [HostPool]DisableAzureSiteRecovery() {
        $this.ASRFailOverVNetId = $null
        return $this
    }

    [int] GetIndex() {
        $this.RefreshNames()
        return $([regex]::Match($this.Name, "-(?<Index>\d+)$").Groups["Index"].Value -as [int])
    }
}

class PooledHostPool : HostPool {
    static [hashtable] $IndexHT = $null
    [ValidateRange(0, 10)] [uint16] $MaxSessionLimit
    [ValidateNotNullOrEmpty()] [boolean] $FSlogix
    [ValidateNotNullOrEmpty()] [boolean] $MSIX
    [ValidateNotNullOrEmpty()] [boolean] $AppAttach
    [ValidateNotNullOrEmpty()] [boolean] $FSLogixCloudCache = $false
    [String] $PreferredAppGroupType  


    hidden Init() {
        if ($null -eq [PooledHostPool]::IndexHT) {
            [PooledHostPool]::IndexHT = @{}
        }

        if ($null -eq [PooledHostPool]::IndexHT[$this.Location]) {
            [PooledHostPool]::IndexHT[$this.Location] = 0
        }
        [PooledHostPool]::IndexHT[$this.Location]++
        $this.Type = [HostPoolType]::Pooled
        $this.MaxSessionLimit = 5
        $this.ImagePublisherName = "microsoftwindowsdesktop"
        $this.ImageOffer = "office-365"
        $this.ImageSku = "win11-23h2-avd-m365"
        $this.FSlogix = $true
        $this.MSIX = $true
        $this.AppAttach = $false
        $this.LoadBalancerType = "BreadthFirst"
        $this.PreferredAppGroupType = "Desktop"
        $this.RefreshNames()
    }

    PooledHostPool([Object] $KeyVault, [string] $SubnetId):base($KeyVault, $SubnetId) {
        $this.Init()
    }

    PooledHostPool([Object] $KeyVault):base($KeyVault) {
        $this.Init()
    }

    static ResetIndex() {
        [PooledHostPool]::IndexHT = @{}
    }

    [string] GetFSLogixStorageAccountName() {
        if ($this.FSlogix) {
            $StorageAccountNameMaxLength = 24
            $StorageAccountName = "fsl{0}" -f $($this.Name.ToLower() -replace "\W")
            $StorageAccountName = $StorageAccountName.Substring(0, [system.math]::min($StorageAccountNameMaxLength, $StorageAccountName.Length)).ToLower()
            return $StorageAccountName
        }
        else {
            return $null
        }
    }


    [string] GetRecoveryLocationFSLogixStorageAccountName() {
        if ($this.FSlogixCloudCache) {
            if ([string]::IsNullOrEmpty($this.PairedRegion)) {
                return [string]::Empty
            }
            else 
            {
                $StorageAccountNameMaxLength = 24
                $RecoveryLocationFSLogixStorageAccountName = "fsl{0}" -f $($this.Name.ToLower() -replace "\W")
                $RecoveryLocationFSLogixStorageAccountName = $RecoveryLocationFSLogixStorageAccountName.Substring(0, [system.math]::min($StorageAccountNameMaxLength, $RecoveryLocationFSLogixStorageAccountName.Length)).ToLower() 
                $RecoveryLocationFSLogixStorageAccountName = $RecoveryLocationFSLogixStorageAccountName -replace [HostPool]::AzLocationShortNameHT[$this.Location].shortName, [HostPool]::AzLocationShortNameHT[$this.PairedRegion].shortName
                return $RecoveryLocationFSLogixStorageAccountName
            }
}
        else {
                return [string]::Empty
        }

        <#
        #Non working solution in case of a ThreadJob (don't know why)
        if ($this.FSlogixCloudCache) {
            $AzurePairedRegion = $this.GetAzurePairedRegion()
            if ([string]::IsNullOrEmpty($AzurePairedRegion)) {
                return [string]::Empty
            }
            else 
            {
                return $this.GetFSLogixStorageAccountName() -replace [HostPool]::AzLocationShortNameHT[$this.Location].shortName, [HostPool]::AzLocationShortNameHT[$AzurePairedRegion].shortName
            }
        }
        else {
            return [string]::Empty
        }
        #>
    }

    [string] GetMSIXStorageAccountName() {
        if (($this.MSIX) -or ($this.AppAttach)) {
            $StorageAccountNameMaxLength = 24
            $StorageAccountName = "msix{0}" -f $($this.Name.ToLower() -replace "\W")
            $StorageAccountName = $StorageAccountName.Substring(0, [system.math]::min($StorageAccountNameMaxLength, $StorageAccountName.Length)).ToLower()
            return $StorageAccountName
        }
        else {
            return $null
        }
    }

    [PooledHostPool] SetLoadBalancerType([String] $LoadBalancerType) {
        $this.LoadBalancerType = $LoadBalancerType
        return $this
    }

    static SetIndex([uint16] $Index, [string] $Location) {
        if ($null -eq [PooledHostPool]::IndexHT) {
            [PooledHostPool]::IndexHT[$Location] = @{}
        }
        [PooledHostPool]::IndexHT[$Location] = $Index
    }

    [PooledHostPool] SetIndex([uint16] $Index) {
        [PooledHostPool]::IndexHT[$this.Location] = $Index
        $this.RefreshNames()        
        return $this
    }

    [PooledHostPool] SetMaxSessionLimit([uint16] $MaxSessionLimit) {
        $this.MaxSessionLimit = $MaxSessionLimit
        return $this
    }

    [PooledHostPool]DisableFSLogix() {
        $this.FSLogix = $false
        $this.DisableFSLogixCloudCache()
        return $this
    }

    [PooledHostPool]EnableFSLogix() {
        $this.FSLogix = $true
        return $this
    }

    [PooledHostPool]DisableFSLogixCloudCache() {
        $this.FSLogixCloudCache = $false
        return $this
    }

    [PooledHostPool]EnableFSLogixCloudCache() {
        $this.EnableFSLogix()
        $this.FSLogixCloudCache = $true
        return $this
    }

    [PooledHostPool]DisableAppAttach() {
        $this.AppAttach = $false
        return $this
    }

    [PooledHostPool]EnableAppAttach() {
        #if (-not($this.IsMicrosoftEntraIdJoined())) {
        if ($this.IsActiveDirectoryJoined()) {
            $this.AppAttach = $true
            $this.DisableMSIX()
        }
        return $this
    }

    [PooledHostPool]DisableMSIX() {
        $this.MSIX = $false
        return $this
    }

    [PooledHostPool]EnableMSIX() {
        #if (-not($this.IsMicrosoftEntraIdJoined())) {
        if ($this.IsActiveDirectoryJoined()) {
            $this.MSIX = $true
            $this.DisableAppAttach()
        }
        return $this
    }

    [PooledHostPool] SetIdentityProvider([IdentityProvider] $IdentityProvider) {
        $this.IdentityProvider = $IdentityProvider
        if ($this.IsMicrosoftEntraIdJoined()) {
            #No MSIX with EntraID: https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-overview?pivots=msix-app-attach#identity-providers
            $this.MSIX = $false
        }
        $this.RefreshNames()
        return $this
    }

    hidden RefreshNames() {
        $TempName = "hp-np"
        $TempNamePrefix = "n"

        if ($this.IsMicrosoftEntraIdJoined()) {
            $TempName += "-ei"
            $TempNamePrefix += "e"
        }
        else {
            $TempName += "-ad"
            $TempNamePrefix += "a"
        }
        
        $TempName += "-poc"
        $TempNamePrefix += "p"

        if ($this.VMSourceImageId) {
            $TempName += "-cg"
            $TempNamePrefix += "c"
        }
        else {
            $TempName += "-mp"
            $TempNamePrefix += "m"
        }

        $this.Name = "{0}-{1}-{2:D3}" -f $TempName, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PooledHostPool]::IndexHT[$this.Location]
        $this.NamePrefix = "{0}{1}{2:D3}" -f $TempNamePrefix, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PooledHostPool]::IndexHT[$this.Location]
    }

    <#
    [object] GetPropertyForJSON() {
        return ([HostPool]$this).GetPropertyForJSON()
    }
    #>

    [PooledHostPool] SetPreferredAppGroupType ([String] $PreferredAppGroupType) {
        $this.PreferredAppGroupType = $PreferredAppGroupType 
        return $this
    }
}

class PersonalHostPool : HostPool {
    static [hashtable] $IndexHT = $null
    #Hibernation is not compatible with Spot Instance and is only allowed for Personal Dektop
    [ValidateNotNullOrEmpty()] [boolean] $HibernationEnabled = $false

    hidden Init() {
        if ($null -eq [PersonalHostPool]::IndexHT) {
            [PersonalHostPool]::IndexHT = @{}
        }

        if ($null -eq [PersonalHostPool]::IndexHT[$this.Location]) {
            [PersonalHostPool]::IndexHT[$this.Location] = 0
        }
        [PersonalHostPool]::IndexHT[$this.Location]++
        $this.Type = [HostPoolType]::Personal
        $this.ImagePublisherName = "microsoftwindowsdesktop"
        $this.ImageOffer = "windows-11"
        $this.ImageSku = "win11-23h2-ent"
        $this.HibernationEnabled = $false
        $this.LoadBalancerType = "Persistent"
        $this.RefreshNames()
    }

    PersonalHostPool([Object] $KeyVault, [string] $SubnetId):base($KeyVault, $SubnetId) {
        $this.Init()
    }

    PersonalHostPool([Object] $KeyVault):base($KeyVault) {
        $this.Init()
    }

    static ResetIndex() {
        [PersonalHostPool]::IndexHT = @{}
    }

    static SetIndex([uint16] $Index, [string] $Location) {
        if ($null -eq [PersonalHostPool]::IndexHT) {
            [PersonalHostPool]::IndexHT[$Location] = @{}
        }
        [PersonalHostPool]::IndexHT[$Location] = $Index
    }

    [PersonalHostPool] SetIndex([uint16] $Index) {
        [PersonalHostPool]::IndexHT[$this.Location] = $Index
        $this.RefreshNames()        
        return $this
    }

    [PersonalHostPool]DisableHibernation() {
        $this.HibernationEnabled = $false
        return $this
    }

    [PersonalHostPool]EnableHibernation() {
        $this.HibernationEnabled = $true
        #$this.Spot = $false
        $this.DisableSpotInstance()
        return $this
    }

    [PersonalHostPool]EnableSpotInstance() {
        ([HostPool]$this).EnableSpotInstance()
        #$this.Spot = $true
        $this.DisableHibernation()
        return $this
    }

    hidden RefreshNames() {
        $TempName = "hp-pd"
        $TempNamePrefix = "p"

        if ($this.IsMicrosoftEntraIdJoined()) {
            $TempName += "-ei"
            $TempNamePrefix += "e"
        }
        else {
            $TempName += "-ad"
            $TempNamePrefix += "a"
        }
        
        $TempName += "-poc"
        $TempNamePrefix += "p"

        if ($this.VMSourceImageId) {
            $TempName += "-cg"
            $TempNamePrefix += "c"
        }
        else {
            $TempName += "-mp"
            $TempNamePrefix += "m"
        }

        $this.Name = "{0}-{1}-{2:D3}" -f $TempName, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PersonalHostPool]::IndexHT[$this.Location]
        $this.NamePrefix = "{0}{1}{2:D3}" -f $TempNamePrefix, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PersonalHostPool]::IndexHT[$this.Location]
    }

    <#
    [object] GetPropertyForJSON() {
        return ([HostPool]$this).GetPropertyForJSON()
    }
    #>
}

#endregion

#region For Exporting PowerShell Classes
#From https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_classes?view=powershell-5.1#exporting-classes-with-type-accelerators
# Define the types to export with type accelerators.
# Note: Unlike the `using module` approach, this approach allows
#       you to *selectively* export `class`es and `enum`s.
$ExportableTypes = @(
    [IdentityProvider]
    [HostPoolType]
    [DiffDiskPlacement]
    [HostPool]
    [PooledHostPool]
    [PersonalHostPool]
)

# Get the internal TypeAccelerators class to use its static methods.
$TypeAcceleratorsClass = [psobject].Assembly.GetType(
    'System.Management.Automation.TypeAccelerators'
)
# Ensure none of the types would clobber an existing type accelerator.
# If a type accelerator with the same name exists, throw an exception.
$ExistingTypeAccelerators = $TypeAcceleratorsClass::Get
foreach ($Type in $ExportableTypes) {
    if ($Type.FullName -in $ExistingTypeAccelerators.Keys) {
        $Message = @(
            "Unable to register type accelerator '$($Type.FullName)'"
            'Accelerator already exists.'
        ) -join ' - '

        throw [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new($Message),
            'TypeAcceleratorAlreadyExists',
            [System.Management.Automation.ErrorCategory]::InvalidOperation,
            $Type.FullName
        )
    }
}
# Add type accelerators for every exportable type.
foreach ($Type in $ExportableTypes) {
    $TypeAcceleratorsClass::Add($Type.FullName, $Type)
}
# Remove type accelerators when the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    foreach ($Type in $ExportableTypes) {
        $TypeAcceleratorsClass::Remove($Type.FullName)
    }
}.GetNewClosure()
#endregion

#region Function definitions

#region Prerequisites
function Connect-PsAvdAzure {
    [CmdletBinding(PositionalBinding = $false)]
    Param()

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    #region Azure Connection

    try { 
        $null = Get-AzAccessToken -ErrorAction Stop
    }
    catch {
        Connect-AzAccount #-UseDeviceAuthentication
        #Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Account : $((Get-AzContext).Account)"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Subscription : $((Get-AzContext).Subscription.Name)"
    }
    #endregion

    #region Microsoft Graph Connection
    try {
        $null = Get-MgBetaDevice -All -ErrorAction Stop
    }
    catch {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Connecting to Microsoft Graph with all required Scopes"
        Connect-MgGraph -NoWelcome -Scopes Device.Read.All, Device.ReadWrite.All, DeviceManagementConfiguration.Read.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.PrivilegedOperations.All, DeviceManagementManagedDevices.Read.All, DeviceManagementManagedDevices.ReadWrite.All, Directory.AccessAsUser.All, Directory.Read.All, Directory.ReadWrite.All, Policy.ReadWrite.MobilityManagement
    }
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Register-PsAvdRequiredResourceProvider {
    [CmdletBinding(PositionalBinding = $false)]
    Param()

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    #region Azure Provider Registration
    #To use Azure Virtual Desktop, you have to register for the providers and to ensure that RegistrationState will be set to Registered.
    #$RequiredResourceProviders = "Microsoft.ContainerInstance", "Microsoft.DesktopVirtualization", "Microsoft.Insights", "Microsoft.VirtualMachineImages", "Microsoft.Storage", "Microsoft.Compute", "Microsoft.KeyVault", "Microsoft.ManagedIdentity"
    $RequiredResourceProviders = "Microsoft.ContainerInstance", "Microsoft.DesktopVirtualization", "Microsoft.Insights", "Microsoft.VirtualMachineImages", "Microsoft.Storage", "Microsoft.Compute", "Microsoft.KeyVault", "Microsoft.ManagedIdentity", "Microsoft.Compute/VMHibernationPreview" #,"Microsoft.Compute/AdditionalStorageTypesForEphemeralOSDiskPreview" 
    $RequiredPreviewResourceProviders = $RequiredResourceProviders | Where-Object -FilterScript { $_ -match "preview|/" }
    $RequiredNonPreviewResourceProviders = $RequiredResourceProviders | Where-Object -FilterScript { $_ -notin $RequiredPreviewResourceProviders }

    #region Non-preview Resource Providers
    $Jobs = foreach ($CurrentRequiredNonPreviewResourceProviders in $RequiredNonPreviewResourceProviders) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Registering '$CurrentRequiredNonPreviewResourceProviders' Resource Provider"
        try {
            Register-AzResourceProvider -ProviderNamespace $CurrentRequiredNonPreviewResourceProviders -ErrorAction Stop -AsJob
        }
        catch {
            # Dig into the exception to get the Response details.
            # Note that value__ is not a typo.
            Write-Warning -Message "Unable to register '$CurrentRequiredNonPreviewResourceProviders' Resource Provider"
            Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
            Write-Warning -Message "Message: $($_.Exception.Message)"
        }
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting for the 'Register-AzResourceProvider' job to finish"
    $Result = $Jobs | Receive-Job -Wait -AutoRemoveJob -ErrorAction Ignore
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Waiting is over for the 'Register-AzResourceProvider' job"
    $NonRegisteredProviders = ($Result | Where-Object -FilterScript { $_.RegistrationState -ne "Registered" }).ProviderNamespace
    if ($NonRegisteredProviders) {
        Write-Warning -Message "The following resource providers were NOT registered: $($NonRegisteredProviders -join ', ')"
    }
    #endregion

    #region Preview Resource Providers
    foreach ($CurrentRequiredPreviewResourceProviders in $RequiredPreviewResourceProviders) {
        $ProviderNamespace, $FeatureName = $CurrentRequiredPreviewResourceProviders -split "/"
        $FeatureStatus = (Get-AzProviderFeature -ProviderNamespace $ProviderNamespace -FeatureName $FeatureName).RegistrationState
        if ($FeatureStatus -ne "Registered") {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Registering '$RequiredPreviewResourceProviders' Resource Provider"
            Register-AzProviderFeature -ProviderNamespace $ProviderNamespace -FeatureName $FeatureName
            Do {
                $FeatureStatus = (Get-AzProviderFeature -ProviderNamespace $ProviderNamespace -FeatureName $FeatureName).RegistrationState
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting for '$CurrentRequiredPreviewResourceProvider' Resource Providers to be registered ... Waiting 10 seconds"
                Start-Sleep -Seconds 10
            } until ($FeatureStatus -eq "Registered")
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Wait is over for registration of the '$CurrentRequiredPreviewResourceProviders' Resource Provider"
        }
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$CurrentRequiredPreviewResourceProviders' Resource Provider is already regsitered"
        }

    }
    #endregion
    #endregion

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Install-PsAvdFSLogixGpoSettings {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [switch] $Force
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    #region Installing FSLogix GPO Setting
    if (-not(Test-Path -Path $env:SystemRoot\policyDefinitions\en-US\fslogix.adml -PathType Leaf) -or -not(Test-Path -Path $env:SystemRoot\policyDefinitions\fslogix.admx -PathType Leaf) -or $Force) {
        #From  https://aka.ms/fslogix-latest
        #Always get the latest version of FSLogix
        #$FSLogixLatestURI = ((Invoke-WebRequest -Uri "https://aka.ms/fslogix-latest" -ErrorAction Stop).Links | Where-Object -FilterScript { $_.innerText -eq "Download" }).href
        try {
            $FSLogixLatestURI = ((Invoke-WebRequest -Uri "https://aka.ms/fslogix-latest" -UseBasicParsing -ErrorAction Stop).Links | Where-Object -FilterScript { $_.href -match ".zip$" }).href
        }
        catch {
            Write-Warning -Message "'https://aka.ms/fslogix-latest' raised an error. We're using an hard-coded version URI (June 2024)"
            #Version: October 2024
            $FSLogixLatestURI = "https://download.microsoft.com/download/e/c/4/ec4b55b3-d2f3-4610-aebd-56478eb0d582/FSLogix_Apps_2.9.8884.27471.zip"
        }
        $OutFile = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $FSLogixLatestURI -Leaf)
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Downloading from '$FSLogixLatestURI' to '$OutFile'"
        Start-BitsTransfer $FSLogixLatestURI -Destination $OutFile
        $DestinationPath = Join-Path -Path $env:Temp -ChildPath "FSLogixLatest"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Unzipping '$OutFile' into '$DestinationPath'..."
        Expand-Archive -Path $OutFile -DestinationPath $DestinationPath -Force
        $ADMLFilePath = Join-Path -Path $DestinationPath -ChildPath "fslogix.adml"
        $ADMXFilePath = Join-Path -Path $DestinationPath -ChildPath "fslogix.admx"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Copying '$ADMLFilePath' into '$env:SystemRoot\policyDefinitions\en-US'"
        Copy-Item -Path $ADMLFilePath $env:SystemRoot\policyDefinitions\en-US
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Copying '$ADMXFilePath' into '$env:SystemRoot\policyDefinitions'"
        Copy-Item -Path $ADMXFilePath $env:SystemRoot\policyDefinitions
        Remove-Item -Path $OutFile, $DestinationPath -Recurse -Force
    }
    #endregion 
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Install-PsAvdAvdGpoSettings {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [switch] $Force
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    #region Installing AVD GPO Setting
    if (-not(Test-Path -Path $env:SystemRoot\policyDefinitions\en-US\terminalserver-avd.adml -PathType Leaf) -or -not(Test-Path -Path $env:SystemRoot\policyDefinitions\terminalserver-avd.admx -PathType Leaf) -or $Force) {
        $AVDGPOLatestCabName = 'AVDGPTemplate.cab'
        $null = New-Item -Path $env:Temp -ItemType Directory -Force
        $OutFile = Join-Path -Path $env:Temp -ChildPath $AVDGPOLatestCabName
        $AVDGPOLatestURI = 'https://aka.ms/avdgpo'
        Invoke-WebRequest -Uri  $AVDGPOLatestURI -OutFile $OutFile 
        $AVDGPOLatestDir = New-Item -Path $env:Temp\AVDGPOLatest -ItemType Directory -Force
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "extrac32 $OutFile /Y" -WorkingDirectory $AVDGPOLatestDir -Wait -NoNewWindow
        $ZipFiles = Get-ChildItem -Path $AVDGPOLatestDir -Filter *.zip -File 
        $ZipFiles | Expand-Archive -DestinationPath $AVDGPOLatestDir -Force
        Remove-Item -Path $ZipFiles.FullName, $OutFile  -Force

        $ADMLFilePath = Join-Path -Path $AVDGPOLatestDir -ChildPath "en-US\terminalserver-avd.adml"
        $ADMXFilePath = Join-Path -Path $AVDGPOLatestDir -ChildPath "terminalserver-avd.admx"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Copying '$ADMLFilePath' into '$env:SystemRoot\policyDefinitions\en-US'"
        Copy-Item -Path $ADMLFilePath $env:SystemRoot\policyDefinitions\en-US
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Copying '$ADMXFilePath' into '$env:SystemRoot\policyDefinitions'"
        Copy-Item -Path $ADMXFilePath $env:SystemRoot\policyDefinitions
        Remove-Item -Path $AVDGPOLatestDir -Recurse -Force

    }
    #endregion 
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}
#endregion

#region Microsoft Entra ID Conditional Access Policies
function New-PsAvdNoMFAUserEntraIDGroup {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [string] $NoMFAEntraIDGroupName = 'No-MFA Users'
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $EntraIDGroupMutex = $null
    $MutexName = "EntraIDGroupMutex"
    $EntraIDGroupMutex = New-Object System.Threading.Mutex($false, $MutexName)
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$MutexName' mutex"

    try {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting for the '$MutexName' mutex lock to be released"
        If ($EntraIDGroupMutex.WaitOne()) { 
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Received '$MutexName' mutex" -Verbose
            $NoMFAEntraIDGroup = Get-MgBetaGroup -Filter "displayName eq '$NoMFAEntraIDGroupName'"
            $MailNickname = $($NoMFAEntraIDGroupName -replace "\s" -replace "\W").ToLower()
            if (-not($NoMFAEntraIDGroup)) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$NoMFAEntraIDGroupName' Entra ID Group"
                $NoMFAEntraIDGroup = New-MgBetaGroup -DisplayName $NoMFAEntraIDGroupName -MailEnabled:$False -MailNickname $MailNickname -SecurityEnabled
            }
            $null = $EntraIDGroupMutex.ReleaseMutex()
            #$EntraIDGroupMutex.Dispose()
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$MutexName' mutex released"
        }
        Else {
            Write-Warning "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Timed out acquiring '$MutexName' mutex!"
        }
    }
    catch [System.Threading.AbandonedMutexException] {
        #AbandonedMutexException means another thread exit without releasing the mutex, and this thread has acquired the mutext, therefore, it can be ignored
        $null = $EntraIDGroupMutex.ReleaseMutex()
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$MutexName' mutex released"
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NoMFAEntraIDGroup:`r`n$($NoMFAEntraIDGroup | Select-Object -Property * | Out-String)"
    #region Pester Tests for Azure MFA - Azure Instantiation
    $ModuleBase = Get-ModuleBase
    $PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
    #$PesterDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'Pester'
    $MFAAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'MFA.Azure.Tests.ps1'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$MFAAzurePesterTests: $MFAAzurePesterTests"
    $Container = New-PesterContainer -Path $MFAAzurePesterTests -Data @{ HostPool = $HostPool }
    Invoke-Pester -Container $Container -Output Detailed -Verbose
    #endregion

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    $NoMFAEntraIDGroup
}

function New-PsAvdMFAForAllUsersConditionalAccessPolicy {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [string[]] $ExcludeGroupName = 'No-MFA Users',
        [string] $DisplayName = "[AVD] Require multifactor authentication for all users",
        [string[]] $IncludeUsers = @("All")
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $DirectorySynchronizationAccountsRole = Get-MgBetaDirectoryRole -Filter "DisplayName eq 'Directory Synchronization Accounts'"
    $ExcludeGroups = foreach ($CurrentExcludeGroupName in $ExcludeGroupName) {
        Get-MgBetaGroup -Filter "displayName eq '$CurrentExcludeGroupName'"
    }
    $ConditionalAccessPolicyMutex = $null
    $MutexName = "ConditionalAccessPolicyMutex"
    $ConditionalAccessPolicyMutex = New-Object System.Threading.Mutex($false, $MutexName)
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$MutexName' mutex"
    
    try {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting for the '$MutexName' mutex lock to be released"
        If ($ConditionalAccessPolicyMutex.WaitOne()) { 
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Received '$MutexName' mutex" -Verbose
            $MFAForAllUsersConditionalAccessPolicy = Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq '$DisplayName'"
            $policyProperties = @{
                State           = "Enabled"
                Conditions      = @{
                    Applications = @{
                        IncludeApplications = @((Get-MgBetaServicePrincipal -Filter "DisplayName eq 'Azure Virtual Desktop'").AppId)
                    }
                    Users        = @{
                        IncludeUsers  = $IncludeUsers
                        ExcludeGroups = $ExcludeGroups.Id
                        ExcludeRoles  = $DirectorySynchronizationAccountsRole.RoleTemplateId 
                    }
                    Locations    = @{
                        ExcludeLocations = @("AllTrusted")
                        IncludeLocations = @("All")
                    }
                }
                GrantControls   = @{
                    BuiltInControls = @("Mfa")
                    Operator        = "OR"
                }
                SessionControls = @{
                    SignInFrequency = @{
                        Value     = 1
                        Type      = "hours"
                        IsEnabled = $true
                    }
                }
            }
            if (-not($MFAForAllUsersConditionalAccessPolicy)) {
                # Define the policy properties
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$DisplayName' Conditional Access Policy NOT found. We're creating it "
                #Adding the DisplayName to the policy properties
                #$policyProperties["DisplayName"] = $DisplayName
                $policyProperties.Add("DisplayName", $DisplayName)
                # Create the policy
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$DisplayName' Conditional Access Policy"
                $MFAForAllUsersConditionalAccessPolicy = New-MgBetaIdentityConditionalAccessPolicy -BodyParameter $policyProperties
            }
            else {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$DisplayName' Conditional Access Policy found. We're updating it "
                # update the policy
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating '$DisplayName' Conditional Access Policy"
                $MFAForAllUsersConditionalAccessPolicy = Update-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $MFAForAllUsersConditionalAccessPolicy.Id -BodyParameter $policyProperties
                $MFAForAllUsersConditionalAccessPolicy = Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq '$DisplayName'"
            }
            $null = $ConditionalAccessPolicyMutex.ReleaseMutex()
            #$ConditionalAccessPolicyMutex.Dispose()
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$MutexName' mutex released"
        }
        Else {
            Write-Warning "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Timed out acquiring '$MutexName' mutex!"
        }
    }
    catch [System.Threading.AbandonedMutexException] {
        #AbandonedMutexException means another thread exit without releasing the mutex, and this thread has acquired the mutext, therefore, it can be ignored
        $null = $ConditionalAccessPolicyMutex.ReleaseMutex()
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$MutexName' mutex released"
    }

    #region Pester Tests for Conditional Access Policy - Azure Instantiation
    $ModuleBase = Get-ModuleBase
    $PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
    #$PesterDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'Pester'
    $ConditionalAccessPolicyAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'ConditionalAccessPolicy.Azure.Tests.ps1'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ConditionalAccessPolicyAzurePesterTests: $ConditionalAccessPolicyAzurePesterTests"
    $Container = New-PesterContainer -Path $ConditionalAccessPolicyAzurePesterTests
    Invoke-Pester -Container $Container -Output Detailed -Verbose
    #endregion

    $MFAForAllUsersConditionalAccessPolicy
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}
#endregion

#region Intune Management
#region Graph API

#From https://github.com/andrew-s-taylor/public/blob/main/Powershell%20Scripts/Intune/function-getallpagination.ps1
function Get-MgGraphObject {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [ValidateScript({ $_ -match '^https?://' })]
        [string] $Uri
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $GraphRequestUri = $Uri
    $MgGraphObject = Do {
        $Result = (Invoke-MgGraphRequest -Uri $GraphRequestUri -Method GET -OutputType PSObject)
        $GraphRequestUri = $Result."@odata.nextLink"
        if ($Result.value) {
            $Result.value
        }
        else {
            $Result
        }
    } While ($null -ne $GraphRequestUri)
    
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $MgGraphObject
}

function Update-PsAvdMgBetaPolicyMobileDeviceManagementPolicy {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [string[]] $GroupId,
        [uint16] $TimeoutInSeconds = 300
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $mobilityManagementPolicyId = "0000000a-0000-0000-c000-000000000000"  
    #Bug : returns $null
    #$PolicyMobileDeviceManagementPolicy = Get-MgBetaPolicyMobileDeviceManagementPolicy -MobilityManagementPolicyId $mobilityManagementPolicyId
    $PolicyMobileDeviceManagementPolicy = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies/$mobilityManagementPolicyId/includedGroups/$ref"
    foreach ($CurrentGroupId in $GroupId) {
        $CurrentGroup = Get-MgBetaGroup -GroupId $CurrentGroupId
        if ($CurrentGroup.Id -notin $PolicyMobileDeviceManagementPolicy.Id) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding the '$($CurrentGroup.DisplayName)' Group to the windows Intune Enrollment selected groups"
            $OdataId = "https://graph.microsoft.com/odata/groups('$($CurrentGroup.Id)')"
            $Timer = [system.diagnostics.stopwatch]::StartNew()
            Do {
                try {
                    $Result = New-MgBetaPolicyMobileDeviceManagementPolicyIncludedGroupByRef -MobilityManagementPolicyId $mobilityManagementPolicyId -OdataId $OdataId -PassThru -ErrorAction Stop
                }
                catch {
                    Write-Warning -Message "$($_.Exception)"
                    $Result = $false
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                    Start-Sleep -Seconds 30
                }
            } While (-not($Result) -and $($Timer.Elapsed.Seconds -lt $TimeoutInSeconds))
            $Timer.Stop()
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Result: $Result"
        }
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$($CurrentGroup.DisplayName)' Group is already in the windows Intune Enrollment selected group list"
        }

    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

<#
Function Sync-PsAvdIntuneSessionHostViaGraphAPI {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object[]] $HostPool
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Graph API
    #region Devices
    $RegExp = ($HostPool.NamePrefix -replace '(^[^\n]*$)', '^$1-') -join '|'
    $AllDevices = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices"
    $FilteredDevices = $AllDevices | Where-Object -FilterScript { $_.DeviceName -match $RegExp }
    $FilteredDevices | ForEach-Object -Process { 
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sending Sync request to Device with Device name '$($_.DeviceName)'"
        $RemovedDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($_.id)/microsoft.graph.syncDevice" -Method POST -OutputType PSObject
    }
    #endregion
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}
#>
<#
Function Remove-PsAvdIntuneItemViaGraphAPI {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object[]] $HostPool
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Graph API
    #region deviceManagementScripts and groupPolicyConfigurations
    $RegExp = ($HostPool.Name -replace '(^[^\n]*$)', '^\[$1\]') -join '|'
    $Topics = "deviceManagementScripts", "groupPolicyConfigurations"
    foreach ($CurrentTopic in $Topics) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$($CurrentTopic)'"
        $URI = "https://graph.microsoft.com/beta/deviceManagement/$($CurrentTopic)?`$select=id,displayname"
        $DeviceManagementTopics = Get-MgGraphObject -Uri $URI | Where-Object -FilterScript { ($_.displayName -match $RegExp) }
        foreach ($CurrentDeviceManagementTopic in $DeviceManagementTopics) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing the '$($CurrentDeviceManagementTopic.displayName)' $CurrentTopic (id: '$($CurrentDeviceManagementTopic.id)')"
            Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/$CurrentTopic/$($CurrentDeviceManagementTopic.id)" -Method DELETE -OutputType PSObject
        }
    }
    #endregion

    #region configurationPolicies
    $RegExp = ($HostPool.Name -replace '(^[^\n]*$)', '^\[$1\]') -join '|'
    $Topics = "configurationPolicies"
    foreach ($CurrentTopic in $Topics) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$($CurrentTopic)'"
        $URI = "https://graph.microsoft.com/beta/deviceManagement/$($CurrentTopic)?`$select=id,name"
        $DeviceManagementTopics = Get-MgGraphObject -Uri $URI | Where-Object -FilterScript { ($_.name -match $RegExp) }
        foreach ($CurrentDeviceManagementTopic in $DeviceManagementTopics) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing the '$($CurrentDeviceManagementTopic.name)' $CurrentTopic (id: '$($CurrentDeviceManagementTopic.id)')"
            Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/$CurrentTopic/$($CurrentDeviceManagementTopic.id)" -Method DELETE -OutputType PSObject
        }
    }
    #endregion

    #region Devices
    $RegExp = ($HostPool.NamePrefix -replace '(^[^\n]*$)', '^$1-') -join '|'
    $AllDevices = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices"
    $FilteredDevices = $AllDevices | Where-Object -FilterScript { $_.DeviceName -match $RegExp }
    $FilteredDevices | ForEach-Object -Process { 
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing Intune Enrolled Device : $($_.DeviceName)"
        $RemovedDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($_.id)" -Method DELETE -OutputType PSObject
    }
    #endregion
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}
#>
<#
#From https://learn.microsoft.com/en-us/graph/api/intune-shared-devicemanagementscript-create?view=graph-rest-beta
Function New-PsAvdIntunePowerShellScriptViaGraphAPI {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $true, ParameterSetName = 'ScriptURI')]
        [ValidateScript({ $_ -match '^https?://' })]
        [string]$ScriptURI,

        [Parameter(Mandatory = $true, ParameterSetName = 'ScriptPath')]
        [string]$ScriptPath
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Graph API
    #region Azure AD Desktop Application Group 
    $HostPoolDAGUsersAzADGroupName = "$HostPoolName - Desktop Application Group Users"
    #$HostPoolDAGUsersAzADGroup = Get-AzADGroup -DisplayName $HostPoolDAGUsersAzADGroupName
    $HostPoolDAGUsersAzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$HostPoolDAGUsersAzADGroupName'"

    if ($null -eq $HostPoolDAGUsersAzADGroup) {
        Write-Error -Message "The '$HostPoolDAGUsersAzADGroupName' doesn't exist !"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
    #endregion

    #region Azure AD Remote Application Group 
    $HostPoolRAGUsersAzADGroupName = "$HostPoolName - Remote Application Group Users"
    #$HostPoolRAGUsersAzADGroup = Get-AzADGroup -DisplayName $HostPoolRAGUsersAzADGroupName
    $HostPoolRAGUsersAzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$HostPoolRAGUsersAzADGroupName'"
    if ($null -eq $HostPoolRAGUsersAzADGroup) {
        Write-Error -Message "The '$HostPoolRAGUsersAzADGroup' doesn't exist !"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
    #endregion

    #region Uploading Powershell Script
    if ($ScriptURI) {
        $ScriptURIContent = Invoke-RestMethod -Uri $ScriptURI
        $ScriptContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ScriptURIContent))
        $FileName = Split-Path $ScriptURI -Leaf
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding the '$ScriptURI' script"
    }
    else {
        $ScriptPathContent = Get-Content -Path $ScriptPath -Encoding Byte -Raw
        $ScriptContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ScriptPathContent))
        $FileName = Split-Path $ScriptPathContent -Leaf
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding the '$ScriptPath' script"
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FileName: '$FileName'"
    $DisplayName = "[{0}] {1}" -f $HostPoolName, $FileName
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DisplayName: '$DisplayName'"
    #Checking if the script is already present (with the same naming convention)
    $AddedScript = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?`$filter=displayName+eq+'$DisplayName'"
    #If present
    if ($AddedScript) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Deleting the previously imported PowerShell Script file '$DisplayName' if any"
        $AddedScript = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($AddedScript.id)" -Method DELETE
        if ($AddedScript.Value.status -eq 'removalFailed') {
            Write-Error -Message "Removal Failed"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
            return $AddedScript
        }
    }

    $Body = @{
        #"description" = ""
        "displayName"           = $DisplayName
        "enforceSignatureCheck" = $false
        "fileName"              = $FileName
        "roleScopeTagIds"       = @("0")
        "runAs32Bit"            = $false
        "runAsAccount"          = "system"
        "scriptContent"         = $ScriptContent
    }

    $AddedScript = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    #region Assign
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$FileName' PowerShell script to '$HostPoolDAGUsersAzADGroupName'"
    $Body = @{
        deviceManagementScriptAssignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $HostPoolDAGUsersAzADGroup.Id
                }
            }
        )
    }
    $Assign = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($AddedScript.id)/assign" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$FileName' PowerShell script to '$HostPoolRAGUsersAzADGroupName'"
    $Body = @{
        deviceManagementScriptAssignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $HostPoolRAGUsersAzADGroup.Id
                }
            }
        )
    }
    $Assign = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($AddedScript.id)/assign" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}
#>
<#
function Get-PsAvdGroupPolicyDefinitionPresentationViaGraphAPI {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [array] $GroupPolicyDefinition
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Graph API
    $GroupPolicyDefinitionPresentationHT = @{}
    foreach ($CurrentGroupPolicyDefinition in $GroupPolicyDefinition) {
        $CurrentGroupPolicyDefinitionPresentation = Get-MgGraphObject -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyDefinitions/$($CurrentGroupPolicyDefinition.id)/presentations"
        $Key = "{0} (version: {1})" -f $CurrentGroupPolicyDefinition.displayName, $CurrentGroupPolicyDefinition.version
        if ($CurrentGroupPolicyDefinition.supportedOn) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$Key' (Supported On: $($CurrentGroupPolicyDefinition.supportedOn))"
            $GroupPolicyDefinitionPresentationHT.Add($("{0} (Supported On: {1})" -f $Key, $CurrentGroupPolicyDefinition.supportedOn) , $CurrentGroupPolicyDefinitionPresentation.Value)
        }
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$Key'"
            $GroupPolicyDefinitionPresentationHT.Add($Key, $CurrentGroupPolicyDefinitionPresentation.Value)
        }
    }
    $GroupPolicyDefinitionPresentationHT
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}
#>
<#
function Import-PsAvdFSLogixADMXViaGraphAPI {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Graph API
    #Checking if the ADMX is already present -
    $GroupPolicyUploadedDefinitionFile = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles?`$filter=fileName+eq+'fslogix.admx'"
    #If present
    if ($GroupPolicyUploadedDefinitionFile) {
        if ($GroupPolicyUploadedDefinitionFile.status -eq 'available') {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Returning the previously imported ADMX file"
            return $GroupPolicyUploadedDefinitionFile
        }
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Deleting the previously imported ADMX file"
            $GroupPolicyUploadedDefinitionFile = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($GroupPolicyUploadedDefinitionFile.id)" -Method DELETE
            if ($GroupPolicyUploadedDefinitionFile.Value.status -eq 'removalFailed') {
                Write-Error -Message "Removal Failed"
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
                return $GroupPolicyUploadedDefinitionFile
            }
        }
    }

    #Always get the latest version of FSLogix
    #$FSLogixLatestURI = ((Invoke-WebRequest -Uri "https://aka.ms/fslogix-latest").Links | Where-Object -FilterScript { $_.innerText -eq "Download" }).href
    $FSLogixLatestURI = ((Invoke-WebRequest -Uri "https://aka.ms/fslogix-latest" -UseBasicParsing).Links | Where-Object -FilterScript { $_.href -match ".zip$" }).href
    $OutFile = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $FSLogixLatestURI -Leaf)
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Downloading from '$FSLogixLatestURI' to '$OutFile'"
    Start-BitsTransfer $FSLogixLatestURI -Destination $OutFile
    $DestinationPath = Join-Path -Path $env:Temp -ChildPath "FSLogixLatest"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Unzipping '$OutFile' into '$DestinationPath'"
    Expand-Archive -Path $OutFile -DestinationPath $DestinationPath -Force
    $ADMLFilePath = Join-Path -Path $DestinationPath -ChildPath "fslogix.adml"
    $ADMXFilePath = Join-Path -Path $DestinationPath -ChildPath "fslogix.admx"

    #region ADML file
    $ADMLFileData = Get-Content -Path $ADMLFilePath -Encoding Byte -Raw
    #$ADMLFileContent = [System.Convert]::ToBase64String($ADMLFileData)
    $ADMLFileContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ADMLFileData))

    #endregion

    #region ADMX file
    $ADMXFileData = Get-Content -Path $ADMXFilePath -Encoding Byte -Raw
    #$ADMXFileContent = [System.Convert]::ToBase64String($ADMXFileData)
    $ADMXFileContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ADMXFileData))
    #endregion

    #From https://learn.microsoft.com/en-us/graph/api/intune-grouppolicy-grouppolicyuploadeddefinitionfile-create?view=graph-rest-beta
    $GUID = (New-Guid).Guid
    #$Now = $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssK")
    $Now = Get-Date -Format o 
    $Body = @{
        #"displayName" = $null
        #"description" = $null
        "languageCodes"                    = @("en-US")
        "targetPrefix"                     = "FSLogix{0}" -f $GUID
        "targetNamespace"                  = "FSLogix.Policies"
        "policyType"                       = "admxIngested"
        #"revision" = $null
        "fileName"                         = $ADMXFileName
        #"id" = $GUID
        #"lastModifiedDateTime" = $Now
        #"status" = "uploadInProgress"
        "content"                          = $ADMXFileContent
        #"uploadDateTime" = $Now
        "defaultLanguageCode"              = $null
        "groupPolicyUploadedLanguageFiles" = @(
            @{
                "fileName"     = $ADMLFileName
                "languageCode" = "en-US"
                "content"      = $ADMLFileContent
                #"id" = (New-Guid).Guid
                #"lastModifiedDateTime" = $Now
            }
        )
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Uploading the ADMX and ADML files"
    $GroupPolicyUploadedDefinitionFile = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyUploadedDefinitionFiles" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject).value
    
    #Waiting for the import completion
    $GroupPolicyUploadedDefinitionFileId = $GroupPolicyUploadedDefinitionFile.id
    While ($GroupPolicyUploadedDefinitionFile.status -eq 'uploadInProgress') {
        $GroupPolicyUploadedDefinitionFile = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles?`$filter=id+eq+'$GroupPolicyUploadedDefinitionFileId'"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting the upload completes. Sleeping 10 seconds"
        Start-Sleep -Seconds 10
    } 
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Final status: $($GroupPolicyUploadedDefinitionFile.status)"

    Remove-Item -Path $OutFile, $DestinationPath -Recurse -Force
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $GroupPolicyUploadedDefinitionFile
    #endregion
}
#>
<#
function Set-PsAvdGroupPolicyDefinitionSettingViaGraphAPI {
    [CmdletBinding(DefaultParameterSetName = 'Enable', PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [object] $GroupPolicyDefinition,
        [Parameter(Mandatory = $true)]
        [object] $GroupPolicyConfiguration,
        [Parameter(ParameterSetName = 'Enable')]
        #Value can be an int, a string or an hashtable for multi-valued properties
        [object] $Value,
        [Parameter(ParameterSetName = 'Enable')]
        [Alias('Enabled')]
        [switch] $Enable,
        [Parameter(ParameterSetName = 'Disable')]
        [Alias('Disabled')]
        [switch] $Disable
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Graph API
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Parameter Set: $($psCmdlet.ParameterSetName)"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$($GroupPolicyConfiguration.displayName)] Processing '$($GroupPolicyDefinition.categoryPath)\$($GroupPolicyDefinition.displayName)'"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Value: $Value"
    $GroupPolicyDefinitionPresentation = Get-MgGraphObject -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyDefinitions/$($GroupPolicyDefinition.id)/presentations"
    if ($GroupPolicyDefinitionPresentation.count -gt 1) {
        #When multiple Group Policy Definition Presentations are returned we keep only the one(s) with a 'required' property
        $GroupPolicyDefinitionPresentationValues = $GroupPolicyDefinitionPresentation | Where-Object -FilterScript { "required" -in $_.psobject.Properties.Name }
    }
    else {
        $GroupPolicyDefinitionPresentationValues = $GroupPolicyDefinitionPresentation
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$GroupPolicyDefinitionPresentationValues:`r`n$($GroupPolicyDefinitionPresentationValues | Out-String)"
    if ($GroupPolicyDefinitionPresentationValues) {
        $PresentationValues = foreach ($CurrentGroupPolicyDefinitionPresentationValue in $GroupPolicyDefinitionPresentationValues) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$($CurrentGroupPolicyDefinitionPresentationValue.label)'"
            if ($Value -is [int]) {
                $DataType = "#microsoft.graph.groupPolicyPresentationValueDecimal"
                $CurrentValue = $Value
            }
            elseif ($Value -is [hashtable]) {
                $CurrentValue = $Value[$CurrentGroupPolicyDefinitionPresentationValue.label.Trim()]
                if ($null -eq $CurrentValue) {
                    Write-Warning -Message "The value for '$($CurrentGroupPolicyDefinitionPresentationValue.label.Trim())' is NULL"
                }
                elseif ($CurrentValue -is [int]) {
                    $DataType = "#microsoft.graph.groupPolicyPresentationValueDecimal"
                }
                else {
                    $DataType = "#microsoft.graph.groupPolicyPresentationValueText"
                }
            }
            else {
                $DataType = "#microsoft.graph.groupPolicyPresentationValueText"
                $CurrentValue = $Value
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentValue: $CurrentValue"
            @{
                "@odata.type"             = $DataType
                "presentation@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($GroupPolicyDefinition.id)')/presentations('$($CurrentGroupPolicyDefinitionPresentationValue.id)')"
                "value"                   = $CurrentValue                
            }
        }
    }
    else {
        $PresentationValues = @()
    }
    
    $Body = @{
        added      = @(
            @{
                "definition@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($GroupPolicyDefinition.id)')"
                "enabled"               = $($psCmdlet.ParameterSetName -eq 'Enable')
                "presentationValues"    = @($PresentationValues)
            }    
        )
        deletedIds = @()
        updated    = @()
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$($GroupPolicyConfiguration.displayName)] Enabling '$($GroupPolicyDefinition.categoryPath)\$($GroupPolicyDefinition.displayName)'"
    #$updatedDefinitionValues = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfiguration.id)/updateDefinitionValues" -Method POST -Body $($Body | ConvertTo-Json -Depth 100| ForEach-Object -Process { [System.Text.RegularExpressions.Regex]::Unescape($_) }) -OutputType PSObject
    $JSONBody = $($Body | ConvertTo-Json -Depth 100)
    $URI = "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfiguration.id)/updateDefinitionValues"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Body :`r`n$($JSONBody | ForEach-Object -Process { [System.Text.RegularExpressions.Regex]::Unescape($_) })"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Uri :`r`n$URI"
    $updatedDefinitionValues = Invoke-MgGraphRequest -Uri $URI -Method POST -Body $JSONBody -OutputType PSObject
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}
#>
#endregion

#region Settings Catalog
#From https://www.youtube.com/watch?v=LQRXg95qTg0
function New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI {
    [CmdletBinding(DefaultParameterSetName = 'Enable', PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Setting,
        [Parameter(ParameterSetName = 'Enable')]
        [object[]] $Settings,
        [Parameter(ParameterSetName = 'Enable')]
        [Alias('Value')]
        [object] $SettingValue,
        [Parameter(ParameterSetName = 'Enable')]
        [Alias('Enabled')]
        [switch] $Enable,
        [Parameter(ParameterSetName = 'Disable')]
        [Alias('Disabled')]
        [switch] $Disable
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Parameter Set: $($psCmdlet.ParameterSetName)"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$($Setting.FullPath)'"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SettingValue: $SettingValue"

    [array] $Children = @()
    if ($PSCmdlet.ParameterSetName -eq "Enable") {
        $value = ($Setting.options | Where-Object -FilterScript { $_.Name -eq "Enabled" }).itemId
        #$ChildSettings = $Settings | Where-Object -FilterScript { $_.id -eq $Setting.options.dependedOnBy.dependedOnBy }
        $ChildSettings = $Settings | Where-Object -FilterScript { $_.id -in $Setting.options.dependedOnBy.dependedOnBy }
        $Children = foreach ($CurrentChildSetting in $ChildSettings) {
            if ($CurrentChildSetting.'@odata.type' -eq '#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition') {
                if ($null -ne $SettingValue) {
                    if ($SettingValue -is [hashtable]) {
                        $choiceSettingValueValue = $SettingValue[$CurrentChildSetting.displayName -replace "\s*\(Device\)"]
                        $choiceSettingValue = ($CurrentChildSetting.options | Where-Object -FilterScript { $_.optionValue.value -eq $choiceSettingValueValue }).ItemId
                    }
                    else {
                        $choiceSettingValue = ($CurrentChildSetting.options | Where-Object -FilterScript { $_.Name.Trim() -eq $SettingValue.ToString() }).ItemId
                    }
                    if ($null -eq $choiceSettingValue) {
                        Write-Warning -Message "No ItemId found for '$SettingValue'. Switching back to the Setting default value: '$($CurrentChildSetting.defaultOptionId)'"
                        $choiceSettingValue = $CurrentChildSetting.defaultOptionId
                    }
                }
                else {
                    $choiceSettingValue = $CurrentChildSetting.defaultOptionId
                }
                @{
                    "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    "settingDefinitionId" = $CurrentChildSetting.id
                    "choiceSettingValue"  = @{
                        "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue"
                        "value"       = $choiceSettingValue
                        "children"    = @()
                    }
                }
            }
            elseif ($CurrentChildSetting.'@odata.type' -eq '#microsoft.graph.deviceManagementConfigurationSettingGroupCollectionDefinition') {
                if ($SettingValue -is [hashtable]) {
                    $KeySettingDefinitionId = $CurrentChildSetting.dependedOnBy.dependedOnBy | Where-Object { $_ -match "_key$" }
                    $ValueSettingDefinitionId = $CurrentChildSetting.dependedOnBy.dependedOnBy | Where-Object { $_ -match "value$" }
                    [array] $groupSettingCollectionValue = foreach ($CurrentKey in $SettingValue.Keys) {
                        $CurrentValue = $SettingValue[$CurrentKey].ToString()
                        @{
                            "children" = @(
                                @{
                                    "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                                    "settingDefinitionId" = $KeySettingDefinitionId
                                    "simpleSettingValue"  = @{
                                        "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                        "value"       = $CurrentKey
                                    }
                                }
                                @{
                                    "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                                    "settingDefinitionId" = $ValueSettingDefinitionId
                                    "simpleSettingValue"  = @{
                                        "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                        "value"       = $CurrentValue
                                    }
                                }
                            )
                        }
                    }
                    @{
                        "@odata.type"                 = "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance"
                        "settingDefinitionId"         = $CurrentChildSetting.id
                        "groupSettingCollectionValue" = $groupSettingCollectionValue
                    }
                }
            }
            else {
                #if ($CurrentChildSetting.'@odata.type' -eq '#microsoft.graph.deviceManagementConfigurationSimpleSettingDefinition') {
                if ($SettingValue -is [hashtable]) {
                    $simpleSettingValue = $SettingValue[$CurrentChildSetting.displayName -replace "\s*\(Device\)"]
                }
                else {
                    $simpleSettingValue = $SettingValue.ToString()
                }
                @{
                    "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                    "settingDefinitionId" = $CurrentChildSetting.id
                    "simpleSettingValue"  = @{
                        "@odata.type" = $CurrentChildSetting.defaultValue.'@odata.type'
                        "value"       = $simpleSettingValue
                    }
                }
            }
        }
        if ($null -eq $Children) {
            $Children = @()
        }
        if (($Setting.'@odata.type' -eq '#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition') -and ([string]::IsNullOrEmpty($value))) {
            $value = ($Setting.options | Where-Object -FilterScript { $_.Name.Trim() -eq $SettingValue.ToString() }).ItemId
        }
    }
    else {
        $value = ($_.options | Where-Object -FilterScript { $_.Name -eq "Disabled" }).itemId
        $Children = @()
    }
    $CurrentSettings = @{
        "@odata.type"     = "#microsoft.graph.deviceManagementConfigurationSetting"
        "settingInstance" = @{
            "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
            "settingDefinitionId" = $_.id
            "choiceSettingValue"  = @{
                "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue"
                "value"       = $value
                "children"    = $Children
            }
        }
    }

    $CurrentSettings
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Add-PsAvdCategoryFullPath {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object[]] $Categories,
        [object] $ParentCategory
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ParentCategory: $($CurrentCategory.displayName)"
    if ($null -eq $ParentCategory) {
        #Top Category
        $ParentCategory = $Categories | Where-Object { $_.parentCategoryId -match "^(0|-)+$" }
        $ParentCategory = $ParentCategory | Add-Member -NotePropertyMembers @{ FullPath = $("\{0}" -f $ParentCategory.displayName) } -PassThru
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Parent Category Full Path: $($ParentCategory.FullPath)"
    }

    $ChildCategories = $Categories | Where-Object { $_.parentCategoryId -eq $ParentCategory.id }
    foreach ($CurrentChildCategory in $ChildCategories) {
        $CurrentChildCategory = $CurrentChildCategory | Add-Member -NotePropertyMembers @{ FullPath = $("{0}\{1}" -f $ParentCategory.FullPath, $CurrentChildCategory.displayName) } -PassThru
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Current Child Category Full Path: $($CurrentChildCategory.FullPath)"
        Add-PsAvdCategoryFullPath -Categories $Categories -ParentCategory $CurrentChildCategory
    }
    
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function New-PsAvdFSLogixIntuneSettingsCatalogConfigurationPolicyViaGraphAPI {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('StorageAccountName')]
        [string] $HostPoolStorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $false)]
        [string] $StorageEndpointSuffix = 'core.windows.net',

        [Parameter(Mandatory = $false)]
        [Alias('RecoveryLocationStorageAccountName')]
        [string] $HostPoolRecoveryLocationStorageAccountName
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Graph API
    #region Devices Azure AD group 
    $HostPoolDeviceAzADGroupName = "{0} - Devices" -f $HostPoolName
    #$HostPoolDeviceAzADGroup = Get-AzADGroup -DisplayName $HostPoolDeviceAzADGroupName
    $HostPoolDeviceAzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$HostPoolDeviceAzADGroupName'"
    if ($null -eq $HostPoolDeviceAzADGroup) {
        Write-Error -Message "The '$HostPoolDeviceAzADGroupName' doesn't exist !"
        return $null
    }
    #endregion

    [array] $settings = @()

    #region FSLogix Category and Child Categories
    #region Getting FSLogix Category and Child Categories
    $FSLogixConfigurationCategory = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=technologies+has+'mdm'+and+description+eq+'FSLogix'" -Verbose
    [array] $FSLogixConfigurationChildCategories = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=rootCategoryId+eq+'$($FSLogixConfigurationCategory.id)'"
    Add-PsAvdCategoryFullPath -Categories $FSLogixConfigurationChildCategories
    #endregion

    #region 'FSLogix > Profile Containers' Settings
    #$FSLogixProfileContainersConfigurationChildCategory = $FSLogixConfigurationChildCategories | Where-Object -FilterScript {$_.displayName -eq "Profile Containers"}
    $FSLogixProfileContainersConfigurationChildCategory = $FSLogixConfigurationChildCategories | Where-Object -FilterScript { $_.FullPath -eq "\FSLogix\Profile Containers" }
    $FSLogixProfileContainersConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($FSLogixProfileContainersConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $FSLogixProfileContainersConfigurationSettings = $FSLogixProfileContainersConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $FSLogixProfileContainersConfigurationChildCategory.FullPath -ChildPath $_.displayName } }

    [array] $settings += switch ($FSLogixProfileContainersConfigurationSettings) {
        { $_.FullPath -eq '\FSLogix\Profile Containers\Enabled' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Enable; continue 
        }  
        { $_.FullPath -eq '\FSLogix\Profile Containers\Delete Local Profile When VHD Should Apply' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Enable; continue 
        } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Locked Retry Count' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 3 -Enable; continue 
        }  
        { $_.FullPath -eq '\FSLogix\Profile Containers\Locked Retry Interval' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 15 -Enable
        }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Profile Type' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 'Normal Profile' -Enable
        }
        { $_.FullPath -eq '\FSLogix\Profile Containers\ReAttach Interval' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 15 -Enable
        }
        { $_.FullPath -eq '\FSLogix\Profile Containers\ReAttach Count' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 3 -Enable
        }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Size In MBs' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 30000 -Enable
        }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Prevent Login With Failure' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 1 -Enable; continue 
        } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Prevent Login With Temp Profile' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 1 -Enable; continue 
        }   
        { $_.FullPath -eq '\FSLogix\Profile Containers\Is Dynamic (VHD)' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 1 -Enable; continue 
        } 
        { ([string]::IsNullOrEmpty($HostPoolRecoveryLocationStorageAccountName)) -and ($_.FullPath -eq '\FSLogix\Profile Containers\VHD Locations') } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles" -Enable; continue 
        } 
        { (-not([string]::IsNullOrEmpty($HostPoolRecoveryLocationStorageAccountName))) -and ($_.FullPath -eq '\FSLogix\Profile Containers\CCD Locations') } {
            $CCDLocations = @(
                "type=smb,name=`"{0}`",connectionString=\\{0}.file.{1}\profiles" -f $HostPoolStorageAccountName, $StorageEndpointSuffix
                "type=smb,name=`"{0}`",connectionString=\\{0}.file.{1}\profiles" -f $HostPoolRecoveryLocationStorageAccountName, $StorageEndpointSuffix
            ) -join ';'
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue $CCDLocations -Enable; continue 
        } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Redirection XML Source Folder' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles" -Enable; continue 
        } 
        default {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($_.FullPath)' not modified" 
        }  
    }
    #endregion

    #region 'FSLogix > Profile Containers Settings > Container and Directory Naming' Settings
    $FSLogixProfileContainersConfigurationContainerAndDirectoryNamingChildCategory = $FSLogixConfigurationChildCategories | Where-Object -FilterScript { $_.FullPath -eq "\FSLogix\Profile Containers\Container and Directory Naming" }
    $FSLogixProfileContainersConfigurationContainerAndDirectoryNamingSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($FSLogixProfileContainersConfigurationContainerAndDirectoryNamingChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $FSLogixProfileContainersConfigurationContainerAndDirectoryNamingSettings = $FSLogixProfileContainersConfigurationContainerAndDirectoryNamingSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $FSLogixProfileContainersConfigurationContainerAndDirectoryNamingChildCategory.FullPath -ChildPath $_.displayName } }
       
    [array] $settings += switch ($FSLogixProfileContainersConfigurationContainerAndDirectoryNamingSettings) {
        { $_.FullPath -eq '\FSLogix\Profile Containers\Container and Directory Naming\Flip Flop Profile Directory Name' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Enable; continue 
        } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Container and Directory Naming\Volume Type (VHD or VHDX)' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationContainerAndDirectoryNamingSettings -Setting $_ -SettingValue 'VHDX' -Enable ; continue
        }
        default {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($_.FullPath)' not modified" 
        }  
    }
    #endregion

    #region 'FSLogix > Logging' Settings
    #$FSLogixConfigurationLoggingChildCategory = $FSLogixConfigurationChildCategories | Where-Object -FilterScript {$_.displayName -eq "Logging"}
    $FSLogixConfigurationLoggingChildCategory = $FSLogixConfigurationChildCategories | Where-Object -FilterScript { $_.FullPath -eq "\FSLogix\Logging" }
    $FSLogixConfigurationLoggingSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($FSLogixConfigurationLoggingChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $FSLogixConfigurationLoggingSettings = $FSLogixConfigurationLoggingSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $FSLogixConfigurationLoggingChildCategory.FullPath -ChildPath $_.displayName } }

    [array] $settings += switch ($FSLogixConfigurationLoggingSettings) {
        { $_.FullPath -eq '\FSLogix\Logging\Log Keeping Period' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixConfigurationLoggingSettings -Setting $_ -SettingValue 10 -Enable; continue
        }
        default {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($_.FullPath)' not modified" 
        }  
    }
    #$Body | ConvertTo-Json -Depth 100 | Set-Clipboard
    #endregion
    #endregion

    <#
    #region Windows Update For Business Category and Child Categories
    #region Getting Windows Update For Business Category and Child Categories
    $WindowsUpdateForBusinessConfigurationCategory = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=technologies+has+'mdm'+and+description+eq+'Windows Update For Business'" -Verbose
    [array] $WindowsUpdateForBusinessConfigurationChildCategories = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=rootCategoryId+eq+'$($WindowsUpdateForBusinessConfigurationCategory.id)'"
    Add-PsAvdCategoryFullPath -Categories $WindowsUpdateForBusinessConfigurationChildCategories 
    #endregion

    #region Windows Update For Business
    $WindowsUpdateForBusinessConfigurationChildCategory = $WindowsUpdateForBusinessConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\Windows Update For Business"}
    $WindowsUpdateForBusinessConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($WindowsUpdateForBusinessConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $WindowsUpdateForBusinessConfigurationSettings = $WindowsUpdateForBusinessConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $WindowsUpdateForBusinessConfigurationChildCategory.FullPath -ChildPath $_.displayName } }

    [array] $settings += switch ($WindowsUpdateForBusinessConfigurationSettings) {
        { $_.FullPath -eq '\Windows Update For Business\Allow Auto Update' } { New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $WindowsUpdateForBusinessConfigurationSettings -Setting $_ -SettingValue 'Turn off automatic updates.' -Enable; continue }  
        default { Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($_.FullPath)' not modified" }  
    }
    #endregion
    #endregion
    #>

    #region Administrative Templates Category and Child Categories
    #region Getting Administrative Templates Category and Child Categories
    $AdministrativeTemplatesConfigurationCategory = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=technologies+has+'mdm'+and+description+eq+'Administrative+Templates'" -Verbose
    [array] $AdministrativeTemplatesConfigurationChildCategories = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=rootCategoryId+eq+'$($AdministrativeTemplatesConfigurationCategory.id)'"
    Add-PsAvdCategoryFullPath -Categories $AdministrativeTemplatesConfigurationChildCategories
    #endregion

    #region 'Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Device and Resource Redirection
    $AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript { $_.FullPath -eq "\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection" }
    $AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationSettings = $AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Allow time zone redirection' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationSettings -Setting $_ -Enable; continue 
        }  
        default {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($_.FullPath)' not modified" 
        }  
    }

    #endregion

    #region 'Administrative Templates > Windows Components > Microsoft Defender Antivirus > Exclusions
    $AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript { $_.FullPath -eq "\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Exclusions" }
    $AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationSettings = $AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Exclusions\Path Exclusions' } { 
            $Exclusions = @{
                '%TEMP%\*\*.VHD'                                                                     = 0
                '%TEMP%\*\*.VHDX'                                                                    = 0
                '%Windir%\TEMP\*\*.VHD'                                                              = 0
                '%Windir%\TEMP\*\*.VHDX'                                                             = 0
                '%ProgramData%\FSLogix\Cache\*'                                                      = 0
                '%ProgramData%\FSLogix\Proxy\*'                                                      = 0
                '%ProgramFiles%\FSLogix\Apps\frxdrv.sys'                                             = 0
                '%ProgramFiles%\FSLogix\Apps\frxdrvvt.sys'                                           = 0
                '%ProgramFiles%\FSLogix\Apps\frxccd.sys'                                             = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD"           = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.lock"      = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.meta"      = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.metadata"  = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX"          = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.lock"     = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.meta"     = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.metadata" = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.CIM"           = 0
            }
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationSettings -Setting $_ -SettingValue $Exclusions -Enable; continue 
        }  
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Exclusions\Process Exclusions' } { 
            $Exclusions = @{
                '%ProgramFiles%\FSLogix\Apps\frxccd.exe'      = 0
                '%ProgramFiles%\FSLogix\Apps\frxccds.exe'     = 0
                '%ProgramFiles%\FSLogix\Apps\frxsvc.exe'      = 0
                '%ProgramFiles%\FSLogix\Apps\frxrobocopy.exe' = 0
            }
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationSettings -Setting $_ -SettingValue $Exclusions -Enable; continue 
        }  
        default {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($_.FullPath)' not modified" 
        }  
    }

    #endregion

    #region Storage Category and Child Categories
    #region Getting Storage Category and Child Categories
    $StorageConfigurationCategory = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=technologies+has+'mdm'+and+description+eq+'Storage'" -Verbose
    [array] $StorageConfigurationChildCategories = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=rootCategoryId+eq+'$($StorageConfigurationCategory.id)'"
    Add-PsAvdCategoryFullPath -Categories $StorageConfigurationChildCategories
    #endregion

    #region Storage
    $StorageConfigurationChildCategory = $StorageConfigurationChildCategories | Where-Object -FilterScript { $_.FullPath -eq "\Storage" }
    $StorageConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($StorageConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $StorageConfigurationSettings = $StorageConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $StorageConfigurationChildCategory.FullPath -ChildPath $_.displayName } }

    [array] $settings += switch ($StorageConfigurationSettings) {
        { $_.FullPath -eq '\Storage\Allow Storage Sense Global' } { 
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $StorageConfigurationSettings -Setting $_ -SettingValue 'Block' -Enable; continue 
        }  
        default {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($_.FullPath)' not modified" 
        }  
    }
    #endregion
    #endregion
    #endregion

    #endregion

    #region configurationPolicies
    $ConfigurationPolicyName = "[{0}] FSLogix Policy" -f $HostPoolName

    
    $Body = @{
        name         = $ConfigurationPolicyName
        description  = $ConfigurationPolicyName
        platforms    = "windows10"
        technologies = "mdm"
        settings     = $settings
    }

    #Checking if the Configuration Policy is already present
    [array] $ConfigurationPolicy = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=name+eq+'$ConfigurationPolicyName'+and+technologies+has+'mdm'+and+platforms+has+'windows10'"
    if (-not([string]::IsNullOrEmpty($ConfigurationPolicy.id))) {
        foreach ($CurrentValue in $ConfigurationPolicy) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Deleting the previously '$($CurrentValue.name)' groupPolicyConfigurations (id: '$($CurrentValue.id)')"
            Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($CurrentValue.id)" -Method DELETE -OutputType PSObject
        }
        Start-Sleep -Seconds 10
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$ConfigurationPolicyName' Configuration Policy"
    $ConfigurationPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/configurationPolicies" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    #region Assign
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$ConfigurationPolicyName' Configuration Policy to '$HostPoolDeviceAzADGroupName' Entra ID Group"
    $Body = @{
        assignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $HostPoolDeviceAzADGroup.Id
                }
            }
        )
    }

    $Assign = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/configurationPolicies/$($ConfigurationPolicy.id)/assign" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function New-PsAvdAvdIntuneSettingsCatalogConfigurationPolicyViaGraphAPI {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('StorageAccountName')]
        [string] $HostPoolStorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [switch] $Watermarking,

        [Parameter(Mandatory = $false)]
        [string] $StorageEndpointSuffix = 'core.windows.net'
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Graph API
    #region Devices Azure AD group 
    $HostPoolDeviceAzADGroupName = "{0} - Devices" -f $HostPoolName
    #$HostPoolDeviceAzADGroup = Get-AzADGroup -DisplayName $HostPoolDeviceAzADGroupName
    $HostPoolDeviceAzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$HostPoolDeviceAzADGroupName'"
    if ($null -eq $HostPoolDeviceAzADGroup) {
        Write-Error -Message "The '$HostPoolDeviceAzADGroupName' doesn't exist !"
        return $null
    }
    #endregion

    [array] $settings = @()

    #region Administrative Templates Category and Child Categories
    #region Getting Administrative Templates Category and Child Categories
    $AdministrativeTemplatesConfigurationCategory = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=technologies+has+'mdm'+and+description+eq+'Administrative+Templates'" -Verbose
    [array] $AdministrativeTemplatesConfigurationChildCategories = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=rootCategoryId+eq+'$($AdministrativeTemplatesConfigurationCategory.id)'"
    Add-PsAvdCategoryFullPath -Categories $AdministrativeTemplatesConfigurationChildCategories
    #endregion

    #region 'Administrative Templates > Network > Offline Files' Settings
    $AdministrativeTemplatesNetworkOfflineFilesConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript { $_.FullPath -eq "\Administrative Templates\Network\Offline Files" }
    $AdministrativeTemplatesNetworkOfflineFilesConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesNetworkOfflineFilesConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesNetworkOfflineFilesConfigurationSettings = $AdministrativeTemplatesNetworkOfflineFilesConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesNetworkOfflineFilesConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesNetworkOfflineFilesConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Network\Offline Files\Allow or Disallow use of the Offline Files feature' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Disable; continue 
        }  
        default {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($_.FullPath)' not modified" 
        }  
    }
    #endregion

    #region 'Administrative Templates > Network > Hotspot Authentication' Settings
    $AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript { $_.FullPath -eq "\Administrative Templates\Network\Hotspot Authentication" }
    $AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationSettings = $AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Network\Hotspot Authentication\Enable Hotspot Authentication' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Disable; continue 
        }  
        default {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($_.FullPath)' not modified" 
        }  
    }
    #endregion

    #region 'Administrative Templates > Network > Background Intelligent Transfer Service (BITS)' Settings
    $AdministrativeTemplatesNetworkBITSConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript { $_.FullPath -eq "\Administrative Templates\Network\Background Intelligent Transfer Service (BITS)" }
    $AdministrativeTemplatesNetworkBITSConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesNetworkBITSConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesNetworkBITSConfigurationSettings = $AdministrativeTemplatesNetworkBITSConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesNetworkBITSConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesNetworkBITSConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Network\Background Intelligent Transfer Service (BITS)\Do not allow the BITS client to use Windows Branch Cache' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Enable; continue 
        }  
        default {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($_.FullPath)' not modified" 
        }  
    }
    #endregion

    #region 'Administrative Templates > Network > Hotspot Authentication' Settings
    $AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript { $_.FullPath -eq "\Administrative Templates\Network\Hotspot Authentication" }
    $AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesNetworkHotspotAuthenticationSettingsConfigurationSettings = $AdministrativeTemplatesNetworkHotspotAuthenticationSettingsConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesNetworkHotspotAuthenticationSettingsConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesNetworkHotspotAuthenticationSettingsConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Network\Hotspot Authentication\Enable Hotspot Authentication' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Disable; continue 
        }  
        default {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($_.FullPath)' not modified" 
        }  
    }
    #endregion

    #region 'Administrative Templates > Network > BranchCache' Settings
    $AdministrativeTemplatesNetworkBranchCacheConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript { $_.FullPath -eq "\Administrative Templates\Network\BranchCache" }
    $AdministrativeTemplatesNetworkBranchCacheConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesNetworkBranchCacheConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesNetworkBranchCacheSettingsConfigurationSettings = $AdministrativeTemplatesNetworkBranchCacheSettingsConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesNetworkBranchCacheSettingsConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesNetworkBranchCacheSettingsConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Network\BranchCache\Turn On BranchCache' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Disable; continue 
        }  
        default {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($_.FullPath)' not modified" 
        }  
    }
    #endregion

    #region 'Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Azure Virtual Desktop'
    $AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript { $_.FullPath -eq "\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop" }
    $AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationSettings = $AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationSettings) {
        #{ $_.FullPath -eq '\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop\Enable screen capture protection' } { New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationSettings -Setting $_ -SettingValue 'Block screen capture on client' -Enable; continue }  
        { ($Watermarking) -and ($_.FullPath -eq '\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop\Enable watermarking') } { 
            $SettingValue = @{
                "QR code bitmap scale factor"                                     = 4
                "QR code bitmap opacity"                                          = 2000
                "Width of grid box in percent relative to QR code bitmap width"   = 320
                "Height of grid box in percent relative to QR code bitmap height" = 180
                "QR code embedded content"                                        = "0"
            }
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationSettings -Setting $_ -SettingValue $SettingValue -Enable ; continue 
        }  
        default {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($_.FullPath)' not modified" 
        }  
    }
    #endregion

    #region 'Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Session Time Limits
    $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript { $_.FullPath -eq "\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits" }
    $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings = $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for active but idle Remote Desktop Services sessions' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings -Setting $_ -SettingValue '15 minutes' -Enable; continue 
        }  
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for disconnected sessions' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings -Setting $_ -SettingValue '15 minutes' -Enable; continue 
        }  
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for active Remote Desktop Services sessions' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings -Setting $_ -SettingValue 'Never' -Enable; continue 
        }  
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\End session when time limits are reached' } {
            New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings -Setting $_ -Enable; continue 
        }  
        default {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($_.FullPath)' not modified" 
        }  
    }

    #endregion
    #endregion

    #region configurationPolicies
    $ConfigurationPolicyName = "[{0}] AVD Policy" -f $HostPoolName

    $Body = @{
        name         = $ConfigurationPolicyName
        description  = $ConfigurationPolicyName
        platforms    = "windows10"
        technologies = "mdm"
        settings     = $settings
    }
    
    #Checking if the Configuration Policy is already present
    [array] $ConfigurationPolicy = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=name+eq+'$ConfigurationPolicyName'+and+technologies+has+'mdm'+and+platforms+has+'windows10'"
    if (-not([string]::IsNullOrEmpty($ConfigurationPolicy.id))) {
        foreach ($CurrentValue in $ConfigurationPolicy) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Deleting the previously '$($CurrentValue.name)' groupPolicyConfigurations (id: '$($CurrentValue.id)')"
            Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($CurrentValue.id)" -Method DELETE -OutputType PSObject
        }
        Start-Sleep -Seconds 10
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$ConfigurationPolicyName' Configuration Policy"
    $ConfigurationPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/configurationPolicies" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    #region Assign
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$ConfigurationPolicyName' Configuration Policy to '$HostPoolDeviceAzADGroupName' Entra ID Group"
    $Body = @{
        assignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $HostPoolDeviceAzADGroup.Id
                }
            }
        )
    }

    $Assign = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/configurationPolicies/$($ConfigurationPolicy.id)/assign" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}
#endregion

#region PowerShell Cmdlets
Function Sync-PsAvdIntuneSessionHostViaCmdlet {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object[]] $HostPool
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region PowerShell Cmdlets

    #region Devices
    #Getting all session hosts starting with the Name Prefixes
    $RegExp = ($HostPool.NamePrefix -replace '(^[^\n]*$)', '^$1-') -join '|'
    $Result = Get-MgBetaDeviceManagementManagedDevice -All | Where-Object -FilterScript { $_.DeviceName -match $RegExp } | ForEach-Object -Process { 
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sending Sync request to Device with Device name '$($_.DeviceName)'"
        Sync-MgBetaDeviceManagementManagedDevice -ManagedDeviceId $_.Id -PassThru
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Synchronization result: $($Result -join ', ')"
    #endregion

    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

Function Remove-PsAvdIntuneItemViaCmdlet {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object[]] $HostPool
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region PowerShell Cmdlets
    #region deviceManagementScripts and groupPolicyConfigurations
    #The pipeline has been stopped ==> Get-MgBetaDeviceManagementGroupPolicyConfiguration -Filter "startswith(displayName,'[$HostPoolName]')" | Remove-MgBetaDeviceManagementGroupPolicyConfiguration
    #Get-MgBetaDeviceManagementGroupPolicyConfiguration -Filter "startswith(displayName,'[$HostPoolName]')" -All | ForEach-Object -Process {
    #Getting all Intune items starting with the HostPool name between brackets
    $RegExp = ($HostPool.Name -replace '(^[^\n]*$)', '^\[$1\]') -join '|'

    #region Configuration Policies - Administratives Templates
    Get-MgBetaDeviceManagementGroupPolicyConfiguration -All | Where-Object -FilterScript { $_.displayName -match $RegExp } | ForEach-Object -Process {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing Device Management Group Policy Configuration: '$($_.displayName)'"
        Remove-MgBetaDeviceManagementGroupPolicyConfiguration -GroupPolicyConfigurationId $_.Id
    }
    #endregion

    #region Configuration Policies - Settings Catalog
    Get-MgBetaDeviceManagementConfigurationPolicy -All | Where-Object -FilterScript { $_.Name -match $RegExp } | ForEach-Object -Process { 
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing Device Management Policy Configuration: '$($_.Name)'"
        Remove-MgBetaDeviceManagementConfigurationPolicy -DeviceManagementConfigurationPolicyId $_.Id
    }
    #endregion

    #The pipeline has been stopped ==> Get-MgBetaDeviceManagementScript -Filter "startswith(Name,'[$HostPoolName]')" | Remove-MgBetaDeviceManagementScript
    #Get-MgBetaDeviceManagementScript -Filter "startswith(Name,'[$HostPoolName]')" -All | ForEach-Object -Process {
    Get-MgBetaDeviceManagementScript -All | Where-Object -FilterScript { $_.DisplayName -match $RegExp } | ForEach-Object -Process {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing Device Management Script: '$($_.DisplayName)'"
        Remove-MgBetaDeviceManagementScript -DeviceManagementScriptId $_.Id
    }
    #endregion

    #region Devices
    #Getting all session hosts starting with the Name Prefixes
    $RegExp = ($HostPool.NamePrefix -replace '(^[^\n]*$)', '^$1-') -join '|'
    Get-MgBetaDeviceManagementManagedDevice -All | Where-Object -FilterScript { $_.DeviceName -match $RegExp } | ForEach-Object -Process { 
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing Intune Enrolled Device : $($_.DeviceName)"
        Remove-MgBetaDeviceManagementManagedDevice -ManagedDeviceId $_.Id 
    }
    #endregion

    #region Configuration Policies - Settings Catalog
    #endregion

    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

Function New-PsAvdIntunePowerShellScriptViaCmdlet {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $true, ParameterSetName = 'ScriptURI')]
        [ValidateScript({ $_ -match '^https?://' })]
        [string]$ScriptURI,

        [Parameter(Mandatory = $true, ParameterSetName = 'ScriptPath')]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'ScriptBlock')]
        [System.Management.Automation.ScriptBlock]$ScriptBlock
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Devices Azure AD group 
    $HostPoolDeviceAzADGroupName = "{0} - Devices" -f $HostPoolName
    #$HostPoolDeviceAzADGroup = Get-AzADGroup -DisplayName $HostPoolDeviceAzADGroupName
    $HostPoolDeviceAzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$HostPoolDeviceAzADGroupName'"
    if ($null -eq $HostPoolDeviceAzADGroup) {
        Write-Error -Message "The '$HostPoolDeviceAzADGroupName' doesn't exist !"
        return $null
    }
    #endregion

    #region Uploading Powershell Script
    if ($ScriptURI) {
        $FileName = Split-Path $ScriptURI -Leaf
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding the '$ScriptURI' script"
        $ScriptContentInputFile = Join-Path -Path $env:TEMP -ChildPath $FileName
        #$ScriptContentInputFile = Join-Path -Path $env:TEMP -ChildPath [System.IO.Path]::GetRandomFileName()
        $ScriptContent = Invoke-RestMethod -Uri $ScriptURI -OutFile $ScriptContentInputFile
    }
    elseif ($ScriptPath) {
        $FileName = Split-Path $ScriptPath -Leaf
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding the '$ScriptPath' script"
        $ScriptContentInputFile = $ScriptPath
    }
    else {
        $ScriptContentInputFile = Join-Path -Path $env:TEMP -ChildPath $([System.IO.Path]::GetRandomFileName())
        New-Item -Path $ScriptContentInputFile -ItemType File -Value $ScriptBlock.ToString()
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FileName: '$FileName'"
    $DisplayName = "[{0}] {1}" -f $HostPoolName, $FileName
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DisplayName: '$DisplayName'"
    #Checking if the script is already present (with the same naming convention)
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Deleting the previously imported PowerShell Script file '$DisplayName' if any"
    Get-MgBetaDeviceManagementScript -Filter "displayName eq '$DisplayName'" -All | Remove-MgBetaDeviceManagementScript

    $AddedScript = New-MgBetaDeviceManagementScript -DisplayName $DisplayName -FileName $FileName -RoleScopeTagIds @("0") -RunAsAccount 'system'-ScriptContentInputFile $ScriptContentInputFile
    if ($ScriptURI -or $ScriptBlock) {
        Remove-Item -Path $ScriptContentInputFile -Force
    }

    #endregion

    #region Assign
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$FileName' PowerShell script to '$HostPoolDeviceAzADGroup'"
    $BodyParameter = @{
        deviceManagementScriptAssignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $HostPoolDeviceAzADGroup.Id
                }
            }
        )
    }
    Set-MgBetaDeviceManagementScript -DeviceManagementScriptId $AddedScript.Id -BodyParameter $BodyParameter
    #endregion

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Get-PsAvdGroupPolicyDefinitionPresentationViaCmdlet {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [array] $GroupPolicyDefinition
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Powershell Cmdlets
    $GroupPolicyDefinitionPresentationHT = @{}
    foreach ($CurrentGroupPolicyDefinition in $GroupPolicyDefinition) {
        $GroupPolicyDefinitionPresentation = Get-MgBetaDeviceManagementGroupPolicyDefinition -GroupPolicyDefinitionId $CurrentGroupPolicyDefinition.id
        $Key = "{0} (version: {1})" -f $CurrentGroupPolicyDefinition.displayName, $CurrentGroupPolicyDefinition.version
        if ($CurrentGroupPolicyDefinition.supportedOn) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$Key' (Supported On: $($CurrentGroupPolicyDefinition.supportedOn))"
            $GroupPolicyDefinitionPresentationHT.Add($("{0} (Supported On: {1})" -f $Key, $CurrentGroupPolicyDefinition.supportedOn) , $GroupPolicyDefinitionPresentation)
        }
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$Key'"
            $GroupPolicyDefinitionPresentationHT.Add($Key, $GroupPolicyDefinitionPresentation)
        }
    }
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}
 
<#
function Import-PsAvdFSLogixADMXViaCmdlet {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Powershell Cmdlets
    #Checking if the ADMX is already present
    Get-MgBetaDeviceManagementGroupPolicyUploadedDefinitionFile -Filter "fileName eq 'fslogix.admx'" -All | Remove-MgBetaDeviceManagementGroupPolicyUploadedDefinitionFile

    #Always get the latest version of FSLogix
    #$FSLogixLatestURI = ((Invoke-WebRequest -Uri "https://aka.ms/fslogix-latest").Links | Where-Object -FilterScript { $_.innerText -eq "Download" }).href
    $FSLogixLatestURI = ((Invoke-WebRequest -Uri "https://aka.ms/fslogix-latest" -UseBasicParsing).Links | Where-Object -FilterScript { $_.href -match ".zip$" }).href
    $OutFile = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $FSLogixLatestURI -Leaf)
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Downloading from '$FSLogixLatestURI' to '$OutFile'"
    Start-BitsTransfer $FSLogixLatestURI -Destination $OutFile
    $DestinationPath = Join-Path -Path $env:Temp -ChildPath "FSLogixLatest"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Unzipping '$OutFile' into '$DestinationPath'"
    Expand-Archive -Path $OutFile -DestinationPath $DestinationPath -Force
    $ADMLFilePath = Join-Path -Path $DestinationPath -ChildPath "fslogix.adml"
    $ADMXFilePath = Join-Path -Path $DestinationPath -ChildPath "fslogix.admx"

    #region ADML file
    $ADMLFileData = Get-Content -Path $ADMLFilePath -Encoding Byte -Raw
    #$ADMLFileContent = [System.Convert]::ToBase64String($ADMLFileData)
    $ADMLFileContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ADMLFileData))

    #endregion

    #region ADMX file
    $ADMXFileData = Get-Content -Path $ADMXFilePath -Encoding Byte -Raw
    #$ADMXFileContent = [System.Convert]::ToBase64String($ADMXFileData)
    $ADMXFileContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ADMXFileData))
    #endregion

    #From https://learn.microsoft.com/en-us/graph/api/intune-grouppolicy-grouppolicyuploadeddefinitionfile-create?view=graph-rest-beta
    $GUID = (New-Guid).Guid
    #$Now = $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssK")
    $Now = Get-Date -Format o 
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Uploading the ADMX and ADML files"
    $GroupPolicyUploadedLanguageFiles = @(
        @{
            "fileName"     = $ADMLFileName
            "languageCode" = "en-US"
            "content"      = $ADMLFileContent
            #"id" = (New-Guid).Guid
            #"lastModifiedDateTime" = $Now
        }
    )
    New-MgBetaDeviceManagementGroupPolicyUploadedDefinitionFile -LanguageCodes @("en-US") -TargetPrefix $("FSLogix{0}" -f $GUID) -TargetNamespace "FSLogix.Policies" -PolicyType 'admxIngested' -FileName $ADMXFileName -ContentInputFile $ADMXFileContent -GroupPolicyUploadedLanguageFiles $GroupPolicyUploadedLanguageFiles
    $GroupPolicyUploadedDefinitionFileId = $GroupPolicyUploadedDefinitionFile.id
    While ($GroupPolicyUploadedDefinitionFile.status -eq 'uploadInProgress') {
        $GroupPolicyUploadedDefinitionFile = Get-MgBetaDeviceManagementGroupPolicyUploadedDefinitionFile -Filter "id eq '$GroupPolicyUploadedDefinitionFileId'" -All
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting the upload completes. Sleeping 10 seconds"
        Start-Sleep -Seconds 10
    } 
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Final status: $($GroupPolicyUploadedDefinitionFile.status)"
    Remove-Item -Path $OutFile, $DestinationPath -Recurse -Force
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}
#>
function Set-PsAvdGroupPolicyDefinitionSettingViaCmdlet {
    [CmdletBinding(DefaultParameterSetName = 'Enable', PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [object] $GroupPolicyDefinition,
        [Parameter(Mandatory = $true)]
        [object] $GroupPolicyConfiguration,
        [Parameter(ParameterSetName = 'Enable')]
        #Value can be an int, a string or an hashtable for multi-valued properties
        [object] $Value,
        [Parameter(ParameterSetName = 'Enable')]
        [Alias('Enabled')]
        [switch] $Enable,
        [Parameter(ParameterSetName = 'Disable')]
        [Alias('Disabled')]
        [switch] $Disable
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

    #region PowerShell Cmdlets
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Parameter Set: $($psCmdlet.ParameterSetName)"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$($GroupPolicyConfiguration.displayName)] Processing '$($GroupPolicyDefinition.categoryPath)\$($GroupPolicyDefinition.displayName)'"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Value: $Value"
    $GroupPolicyDefinitionPresentation = Get-MgBetaDeviceManagementGroupPolicyDefinitionPresentation -GroupPolicyDefinitionId $GroupPolicyDefinition.id -All
    if ($GroupPolicyDefinitionPresentation.count -gt 1) {
        #When multiple Group Policy Definition Presentations are returned we keep only the one(s) with a 'required' property
        $GroupPolicyDefinitionPresentationValues = $GroupPolicyDefinitionPresentation | Where-Object -FilterScript { "required" -in $_.psobject.Properties.Name }
    }
    else {
        $GroupPolicyDefinitionPresentationValues = $GroupPolicyDefinitionPresentation
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$GroupPolicyDefinitionPresentationValues:`r`n$($GroupPolicyDefinitionPresentationValues | Out-String)"
    if ($GroupPolicyDefinitionPresentationValues) {
        $PresentationValues = foreach ($CurrentGroupPolicyDefinitionPresentationValue in $GroupPolicyDefinitionPresentationValues) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$($CurrentGroupPolicyDefinitionPresentationValue.label)'"
            if ($Value -is [int]) {
                $DataType = "#microsoft.graph.groupPolicyPresentationValueDecimal"
                $CurrentValue = $Value
            }
            elseif ($Value -is [hashtable]) {
                $CurrentValue = $Value[$CurrentGroupPolicyDefinitionPresentationValue.label.Trim()]
                if ($null -eq $CurrentValue) {
                    Write-Warning -Message "The value for '$($CurrentGroupPolicyDefinitionPresentationValue.label.Trim())' is NULL"
                }
                elseif ($CurrentValue -is [int]) {
                    $DataType = "#microsoft.graph.groupPolicyPresentationValueDecimal"
                }
                else {
                    $DataType = "#microsoft.graph.groupPolicyPresentationValueText"
                }
            }
            else {
                $DataType = "#microsoft.graph.groupPolicyPresentationValueText"
                $CurrentValue = $Value
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentValue: $CurrentValue"
            @{
                "@odata.type"             = $DataType
                "presentation@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($GroupPolicyDefinition.id)')/presentations('$($CurrentGroupPolicyDefinitionPresentationValue.id)')"
                "value"                   = $CurrentValue                
            }
        }
    }
    else {
        $PresentationValues = @()
    }

    $BodyParameter = @{
        added      = @(
            @{
                "definition@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($GroupPolicyDefinition.id)')"
                "enabled"               = $($psCmdlet.ParameterSetName -eq 'Enable')
                "presentationValues"    = @($PresentationValues)
            }    
        )
        deletedIds = @()
        updated    = @()
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$($GroupPolicyConfiguration.displayName)] Enabling '$($GroupPolicyDefinition.categoryPath)\$($GroupPolicyDefinition.displayName)'"
    Update-MgBetaDeviceManagementGroupPolicyConfigurationMultipleDefinitionValue -GroupPolicyConfigurationId $GroupPolicyConfiguration.Id -BodyParameter $BodyParameter
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}
#endregion

#This function was only created because sometimes Set-GPRegistryValue returns "Access Denied" so I implemented a retry.
function Set-PsAvdGPRegistryValue {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [Parameter(Mandatory)]
        [string] $Name,
        [Parameter(Mandatory)]
        [string] $Key,
        [Parameter(Mandatory)]
        [string] $ValueName,
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryValueKind] $Type,
        [Parameter(Mandatory)]
        [object] $Value,
        [uint16] $TimeoutInSeconds = 30
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Name: $Name'"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Key: $Key'"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ValueName: $ValueName'"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Type: $Type'"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Value: $Value'"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$TimeoutInSeconds: $TimeoutInSeconds'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    $Timer = [System.Diagnostics.Stopwatch]::StartNew()
    Do {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Timer: $($Timer | Out-String)"
        try {
            $Output = Set-GPRegistryValue -Name $Name -Key $Key -ValueName $ValueName -Type $Type -Value $Value -ErrorAction Stop
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Output:`r`n$($Output | Out-String)'"
            $Result = $true
        }
        catch {
            Write-Warning -Message "Exception: $($_.Exception)"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Exception: $($_.Exception)'"
            $Result = $false
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 10 seconds"
            Start-Sleep -Seconds 10
        }
    } While (-not($Result) -and $($Timer.Elapsed.Seconds -lt $TimeoutInSeconds))
    $Timer.Stop()
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Result: $Result"
    $Output
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Update-PsAvdMgBetaUserUsageLocation {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [ValidateScript({ $_ -in $([System.Globalization.CultureInfo]::GetCultures([System.Globalization.CultureTypes]::SpecificCultures) | ForEach-Object -Process { (New-Object System.Globalization.RegionInfo $_.name).TwoLetterISORegionName } | Select-Object -Unique | Sort-Object) })]
        [string] $UsageLocation = 'US',
        [Alias('All')]
        [switch] $Force
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    if ($Force) {
        #Updating UsageLocation for all users
        $Users = Get-MgBetaUser -All
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating UsageLocation for all users: $($Users.DisplayName -join ', ')"
    }
    else {
        #Updating UsageLocation for users without an UsageLocation
        $Users = Get-MgBetaUser -All | Where-Object -FilterScript { -not($_.UsageLocation) }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating UsageLocation for users without an UsageLocation: $($Users.DisplayName -join ', ')"
    }
    $Users | ForEach-Object { Update-MgBetaUser -UserId $_.Id -UsageLocation $UsageLocation }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Set-PsAvdMgBetaUsersGroupLicense {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        #Validating only available intune licenses
        #[ValidateScript({$_ -in $((Get-MgBetaSubscribedSku -All | Where-Object -FilterScript { ($_.ServicePlans.ServicePlanName -match "intune") -and (($_.PrepaidUnits.Enabled - $_.ConsumedUnits) -gt 0)}).SkuPartNumber)})]
        [ValidateScript({ $_ -in $((Get-MgBetaSubscribedSku -All | Where-Object -FilterScript { ($_.ServicePlans.ServicePlanName -match "intune") }).SkuPartNumber) })]
        [string] $SkuPartNumber = 'Microsoft_365_E5_(no_Teams)',
        [Parameter(Mandatory)]
        [ValidateScript({ $_ -in $((Get-MgBetaGroup).DisplayName) })]
        [string] $GroupDisplayName 
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $SubscribedSku = Get-MgBetaSubscribedSku -All | Where-Object -FilterScript { $_.SkuPartNumber -eq $SkuPartNumber }
    if (($SubscribedSku.PrepaidUnits.Enabled - $SubscribedSku.ConsumedUnits) -gt 0) {
        $Group = Get-MgBetaGroup -Filter "DisplayName eq '$GroupDisplayName'"
    
        #https://developer.microsoft.com/en-us/graph/known-issues/?search=20454
        #$SkuId = (Get-MgBetaSubscribedSku -All -Search "SkuPartNumber:'$SkuPartNumber'").SkuId 
        $SkuId = (Get-MgBetaSubscribedSku -All | Where-Object -FilterScript { $_.SkuPartNumber -eq $SkuPartNumber }).SkuId
        Set-MgBetaGroupLicense -GroupId $Group.Id -AddLicenses @{SkuId = $SkuId } -RemoveLicenses @()
    }
    else {
        Write-Warning -Message "No more licenses available for '$SkuPartNumber' ($($SubscribedSku.ConsumedUnits) consumed out of $($SubscribedSku.PrepaidUnits.Enabled))"
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

#From https://github.com/sdoubleday/GetCallerPreference/blob/master/GetCallerPreference.psm1
#From https://www.powershellgallery.com/packages/AsgGroup/2.0.6/Content/Private%5CGet-CallerPreference.ps1
function Get-CallerPreference {
    <#
        .SYNOPSIS
        Fetches "Preference" variable values from the caller's scope.
        .DESCRIPTION
        Script module functions do not automatically inherit their caller's variables, but they can be obtained
        through the $PSCmdlet variable in Advanced Functions. This function is a helper function for any script
        module Advanced Function; by passing in the values of $ExecutionContext.SessionState and $PSCmdlet,
        Get-CallerPreference will set the caller's preference variables locally.
        .PARAMETER Cmdlet
        The $PSCmdlet object from a script module Advanced Function.
        .PARAMETER SessionState
        The $ExecutionContext.SessionState object from a script module Advanced Function. This is how the
        Get-CallerPreference function sets variables in its callers' scope, even if that caller is in a different
        script module.
        .PARAMETER Name
        Optional array of parameter names to retrieve from the caller's scope. Default is to retrieve all preference
        variables as defined in the about_Preference_Variables help file (as of PowerShell 4.0). This parameter may
        also specify names of variables that are not in the about_Preference_Variables help file, and the function
        will retrieve and set those as well.
       .EXAMPLE
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        Imports the default PowerShell preference variables from the caller into the local scope.
        .EXAMPLE
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name 'ErrorActionPreference', 'SomeOtherVariable'
        Imports only the ErrorActionPreference and SomeOtherVariable variables into the local scope.
        .EXAMPLE
        'ErrorActionPreference','SomeOtherVariable' | Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        Same as Example 2, but sends variable names to the Name parameter via pipeline input.
       .INPUTS
        System.String
        .OUTPUTS
        None.
        This function does not produce pipeline output.
        .LINK
        about_Preference_Variables
    #>
    #Requires -Version 2
    [CmdletBinding(DefaultParameterSetName = 'AllVariables')]
    param (
        [Parameter(Mandatory)]
        [ValidateScript( { $PSItem.GetType().FullName -eq 'System.Management.Automation.PSScriptCmdlet' })]
        $Cmdlet,
        [Parameter(Mandatory)][System.Management.Automation.SessionState]$SessionState,
        [Parameter(ParameterSetName = 'Filtered', ValueFromPipeline)][string[]]$Name
    )
    begin {
        $FilterHash = @{ }
    }
    
    process {
        if ($null -ne $Name) {
            foreach ($String in $Name) {
                $FilterHash[$String] = $true
            }
        }
    }
    end {
        # List of preference variables taken from the about_Preference_Variables help file in PowerShell version 4.0
        $Vars = @{
            'ErrorView'                     = $null
            'FormatEnumerationLimit'        = $null
            'LogCommandHealthEvent'         = $null
            'LogCommandLifecycleEvent'      = $null
            'LogEngineHealthEvent'          = $null
            'LogEngineLifecycleEvent'       = $null
            'LogProviderHealthEvent'        = $null
            'LogProviderLifecycleEvent'     = $null
            'MaximumAliasCount'             = $null
            'MaximumDriveCount'             = $null
            'MaximumErrorCount'             = $null
            'MaximumFunctionCount'          = $null
            'MaximumHistoryCount'           = $null
            'MaximumVariableCount'          = $null
            'OFS'                           = $null
            'OutputEncoding'                = $null
            'ProgressPreference'            = $null
            'PSDefaultParameterValues'      = $null
            'PSEmailServer'                 = $null
            'PSModuleAutoLoadingPreference' = $null
            'PSSessionApplicationName'      = $null
            'PSSessionConfigurationName'    = $null
            'PSSessionOption'               = $null
            'ErrorActionPreference'         = 'ErrorAction'
            'DebugPreference'               = 'Debug'
            'ConfirmPreference'             = 'Confirm'
            'WhatIfPreference'              = 'WhatIf'
            'VerbosePreference'             = 'Verbose'
            'WarningPreference'             = 'WarningAction'
        }
        foreach ($Entry in $Vars.GetEnumerator()) {
            if (([string]::IsNullOrEmpty($Entry.Value) -or -not $Cmdlet.MyInvocation.BoundParameters.ContainsKey($Entry.Value)) -and
                ($PSCmdlet.ParameterSetName -eq 'AllVariables' -or $FilterHash.ContainsKey($Entry.Name))) {
                $Variable = $Cmdlet.SessionState.PSVariable.Get($Entry.Key)
                
                if ($null -ne $Variable) {
                    if ($SessionState -eq $ExecutionContext.SessionState) {
                        Set-Variable -Scope 1 -Name $Variable.Name -Value $Variable.Value -Force -Confirm:$false -WhatIf:$false
                    }
                    else {
                        $SessionState.PSVariable.Set($Variable.Name, $Variable.Value)
                    }
                }
            }
        }
        if ($PSCmdlet.ParameterSetName -eq 'Filtered') {
            foreach ($VarName in $FilterHash.Keys) {
                if (-not $Vars.ContainsKey($VarName)) {
                    $Variable = $Cmdlet.SessionState.PSVariable.Get($VarName)
                
                    if ($null -ne $Variable) {
                        if ($SessionState -eq $ExecutionContext.SessionState) {
                            Set-Variable -Scope 1 -Name $Variable.Name -Value $Variable.Value -Force -Confirm:$false -WhatIf:$false
                        }
                        else {
                            $SessionState.PSVariable.Set($Variable.Name, $Variable.Value)
                        }
                    }
                }
            }
        }
    }
}

function Test-DomainController {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $null -ne (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'")
}

function Get-PsAvdLatestOperationalInsightsData {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [Parameter(Mandatory = $true)]
        [array] $HostPool
        #[HostPool[]] $HostPool
    )
    
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #Querying the latest HeartBeat, Performance Counter and Event Log entry sent per Computer
    [string[]] $Queries = @("Heartbeat | summarize arg_max(TimeGenerated, *) by Computer", "Perf | summarize arg_max(TimeGenerated, *) by Computer", "Event | summarize arg_max(TimeGenerated, *) by Computer")
    #Querying the latest HeartBeat, Performance Counter and Event Log entry sent
    #[string[]] $Queries = @("Heartbeat | order by TimeGenerated desc | limit 1", "Perf | order by TimeGenerated desc | limit 1", "Event | order by TimeGenerated desc | limit 1")

    foreach ($CurrentHostPool in $HostPool) {
        $CurrentLogAnalyticsWorkspaceName = $CurrentHostPool.GetLogAnalyticsWorkSpaceName()
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentLogAnalyticsWorkspaceName: $CurrentLogAnalyticsWorkspaceName"
        $CurrentLogAnalyticsWorkspace = Get-AzOperationalInsightsWorkspace -Name $CurrentLogAnalyticsWorkspaceName -ResourceGroupName $CurrentHostPool.GetResourceGroupName()

        foreach ($CurrentQuery in $Queries) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentQuery: $CurrentQuery"

            # Run the query
            $Result = Invoke-AzOperationalInsightsQuery -WorkspaceId $CurrentLogAnalyticsWorkspace.CustomerId -Query $CurrentQuery
            $Result.Results | Select-Object -Property *, @{Name = "LocalTimeGenerated"; Expression = { Get-Date $_.TimeGenerated } }, @{Name = "LogAnalyticsWorkspaceName"; Expression = { $CurrentLogAnalyticsWorkspaceName } }, @{Name = "Query"; Expression = { $CurrentQuery } }
        }
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

#From https://stackoverflow.com/questions/63529599/how-to-grant-admin-consent-to-an-azure-aad-app-in-powershell
function Set-AdminConsent {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [Parameter(Mandatory)]
        [string]$applicationId,
        # The Azure Context]
        [Parameter(Mandatory)]
        [object]$context
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, "74658136-14ec-4630-ad9b-26e160ff0fc6")
    $headers = @{
        'Authorization'          = 'Bearer ' + $token.AccessToken
        'X-Requested-With'       = 'XMLHttpRequest'
        'x-ms-client-request-id' = [guid]::NewGuid()
        'x-ms-correlation-id'    = [guid]::NewGuid()
    }

    $url = "https://main.iam.ad.ext.azure.com/api/RegisteredApplications/$applicationId/Consent?onBehalfOfAll=true"
    $null = Invoke-RestMethod -Uri $url -Headers $headers -Method POST -ErrorAction Stop
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Test-PsAvdStorageAccountNameAvailability {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HostPool[]] $HostPool
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Pester Tests for Host Pool - Class Instantiation
    $ModuleBase = Get-ModuleBase
    $PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
    #$PesterDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'Pester'
    $HostPoolClassPesterTests = Join-Path -Path $PesterDirectory -ChildPath 'HostPool.Class.Tests.ps1'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$HostPoolClassPesterTests: $HostPoolClassPesterTests"
    $Container = New-PesterContainer -Path $HostPoolClassPesterTests -Data @{ HostPool = $HostPool }
    Invoke-Pester -Container $Container -Output Detailed -Verbose
    #endregion

    $result = $true
    foreach ($CurrentHostPool in $HostPool) {
        if (($CurrentHostPool.MSIX) -or ($CurrentHostPool.AppAttach)) {
            $CurrentHostPoolStorageAccountName = $CurrentHostPool.GetMSIXStorageAccountName()
            if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentHostPoolStorageAccountName).NameAvailable) {
                Write-Error -Message "The '$CurrentHostPoolStorageAccountName' Storage Account Name is NOT available"
                $result = $false
            }
            else {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$CurrentHostPoolStorageAccountName' Storage Account Name is available"
            }
        }
        if ($CurrentHostPool.FSLogix) {
            $CurrentHostPoolStorageAccountName = $CurrentHostPool.GetFSLogixStorageAccountName()
            if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentHostPoolStorageAccountName).NameAvailable) {
                Write-Error -Message "The '$CurrentHostPoolStorageAccountName' Storage Account Name is NOT available"
                $result = $false
            }
            else {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$CurrentHostPoolStorageAccountName' Storage Account Name is available"
            }
        }
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $result
}

function Test-PsAvdKeyVaultNameAvailability {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HostPool[]] $HostPool
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $result = $true
    foreach ($CurrentHostPool in $($HostPool | Where-Object -FilterScript { $null -ne $_ })) {
        $CurrentHostPoolKeyVaultName = $CurrentHostPool.GetKeyVaultName()
        if (-not(Test-AzKeyVaultNameAvailability -Name $CurrentHostPoolKeyVaultName).NameAvailable) {
            Write-Error -Message "The '$CurrentHostPoolKeyVaultName' Key Vault Name is NOT available"
            $result = $false
        }
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$CurrentHostPoolKeyVaultName' Key Vault Account Name is available"
        }
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $result
}

function Get-LocalAdminCredential {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.KeyVault.Models.PSKeyVault]$KeyVault,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()] 
        [int]$Attempts = 10
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #Any negative value means infinite loop. 
    if ($Attempts -lt 0) {
        $Attempts = [int]::MaxValue
    }
    $Loop = 0
    Do {
        $Loop ++  
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Loop #$($Loop)"  
        try {
            $LocalAdminUserName = $KeyVault | Get-AzKeyVaultSecret -Name LocalAdminUserName -AsPlainText
            $LocalAdminPassword = ($KeyVault | Get-AzKeyVaultSecret -Name LocalAdminPassword).SecretValue
            $LocalAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($LocalAdminUserName, $LocalAdminPassword)
            $Success = $true
        }
        catch {
            $Success = $false
        }
    } While ((-not($Success)) -and ($Loop -lt $Attempts))
     
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $LocalAdminCredential
}

function Get-AdjoinCredential {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.KeyVault.Models.PSKeyVault]$KeyVault,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()] 
        [int]$Attempts = 10
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #Any negative value means infinite loop. 
    if ($Attempts -lt 0) {
        $Attempts = [int]::MaxValue
    }
    $Loop = 0
    Do {
        $Loop ++  
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Loop #$($Loop)"  
        try {
            $AdjoinUserName = $KeyVault | Get-AzKeyVaultSecret -Name AdJoinUserName -AsPlainText
            $AdjoinPassword = ($KeyVault | Get-AzKeyVaultSecret -Name AdJoinPassword).SecretValue
            $AdjoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($AdjoinUserName, $AdjoinPassword)
            $Success = $true
        }
        catch {
            $Success = $false
        }
    } While ((-not($Success)) -and ($Loop -lt $Attempts))
     
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $AdjoinCredential
}

function Get-PsAvdPrivateDnsResourceGroupName  {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('privatelink.file.core.windows.net', 'privatelink.vaultcore.azure.net')] 
        [string] $Name
    )
    $PrivateDnsZone = Get-AzPrivateDnsZone -Name $PrivateDnsZoneName -ErrorAction Ignore
    #No such Private Dns Zone found
    if ([string]::IsNullOrEmpty($PrivateDnsZone)) {
        #Returning a default name 
        $ResourceGroupName = "rg-avd-network-poc-use-001"
        $Location = "EastUS"
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    }
    else {
        if ($PrivateDnsZone -is [array]) {
            $ResourceGroupName = $PrivateDnsZone.ResourceGroupName | Select-Object -First 1
            Write-Warning "Multiple resource groups found for '$PrivateDnsZoneName' Private DNS zone ($($PrivateDnsZone.ResourceGroupName -join ', ')) .We take the first one ('$ResourceGroupName') !"
        }
        else {
            $ResourceGroupName = $PrivateDnsZone.ResourceGroupName
        }
    }
    return $ResourceGroupName
}

function New-PsAvdPrivateDnsZoneSetup  {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    [HostPool]::BuildAzureLocationSortNameHashtable()

    $PrivateDnsZoneSetup = @{}

    $PrivateDnsZoneNames = 'privatelink.vaultcore.azure.net', 'privatelink.file.core.windows.net'
    foreach ($PrivateDnsZoneName in $PrivateDnsZoneNames) {
        #region Configuring the Private DNS zone.
        $ResourceGroupName = Get-PsAvdPrivateDnsResourceGroupName -Name $PrivateDnsZoneName
        $PrivateDnsZone = Get-AzPrivateDnsZone -Name $PrivateDnsZoneName -ErrorAction Ignore
        if ([string]::IsNullOrEmpty($PrivateDnsZone)) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$PrivateDnsZoneName' Private DNS Zone (in the '$ResourceGroupName' Resource Group)"
            $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ResourceGroupName -Name $PrivateDnsZoneName
        }
        else {
            #In case of multiple Private Dns Zones, we took only the first one (thanks to the Get-PsAvdPrivateDnsResourceGroupName function).
            $PrivateDnsZone = Get-AzPrivateDnsZone -Name $PrivateDnsZoneName -ResourceGroupName $ResourceGroupName -ErrorAction Ignore
        }

        #region Configuring the DNS zone.
        $PrivateDnsZoneConfigName = $PrivateDnsZone.Name #-replace "\.", "-"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the DNS Zone Configuration of the '$PrivateDnsZoneConfigName' Private Dns Zone Group  (in the '$ResourceGroupName' Resource Group)"
        $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZoneConfigName -PrivateDnsZoneId $PrivateDnsZone.ResourceId
        #endregion

        $PrivateDnsZoneSetup[$PrivateDnsZoneName] = [PSCustomObject]@{PrivateDnsZone=$PrivateDnsZone;PrivateDnsZoneConfig=$PrivateDnsZoneConfig}
        #endregion
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $PrivateDnsZoneSetup
}

function New-PsAvdPrivateEndpointSetup {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]] $SubnetId,

        [Parameter(Mandatory = $true, ParameterSetName = 'KeyVault')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.Commands.KeyVault.Models.PSKeyVaultIdentityItem] $KeyVault,

        [Parameter(Mandatory = $true, ParameterSetName = 'StorageAccount')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.Commands.Management.Storage.Models.PSStorageAccount] $StorageAccount
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    foreach ($CurrentSubnetId in $SubnetId) {
        $Subnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $CurrentSubnetId
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$($Subnet.Name)' Subnet"
        $VirtualNetwork = Get-AzResource -ResourceID $($Subnet.Id -replace "/subnets/.*$") | Get-AzVirtualNetwork
        if ($null -ne $KeyVault) {
            $PrivateDnsZoneName = 'privatelink.vaultcore.azure.net'
            $AzResource = $KeyVault | Get-AzResource
            $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $AzResource.ResourceId).GroupId
        }
        if ($null -ne $StorageAccount) {
            $PrivateDnsZoneName = 'privatelink.file.core.windows.net' 
            $AzResource = $StorageAccount | Get-AzResource
            $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $CurrentHostPoolStorageAccount.Id).GroupId | Where-Object -FilterScript { $_ -match "file" }
        }
        $ResourceGroupName = $AzResource.ResourceGroupName
    	
        #region Private endpoint for '$($AzResource.ResourceType)' or Storage Account Setup
        #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
        #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
        #From https://ystatit.medium.com/azure-key-vault-with-azure-service-endpoints-and-private-link-part-1-bcc84b4c5fbc

        #region Create the private endpoint connection on the Subnet.
        $PrivateEndpointName = "pep-{0}-{1}" -f $($AzResource.Name -replace "\W"), $Subnet.Name
        $PrivateEndpoint = Get-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $ResourceGroupName -ErrorAction Ignore
        if ($null -eq $PrivateEndpoint) {
            $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $AzResource.ResourceId -GroupId $GroupId
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$PrivateEndpointName' Private Endpoint for the '$($AzResource.ResourceType)' '$($AzResource.Name)' (in the '$ResourceGroupName' Resource Group)"
            $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $ResourceGroupName -Location $VirtualNetwork.Location -Subnet $Subnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force
        }
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$PrivateEndpointName' Private Endpoint for the '$($AzResource.ResourceType)' '$($AzResource.Name)' (in the '$ResourceGroupName' Resource Group) already exists"
        }
        #endregion

        #region Create the private DNS Virtual Network Link and DNS Zone Group
        $PrivateDnsZoneSetup = New-PsAvdPrivateDnsZoneSetup
        $PrivateDnsZone = $PrivateDnsZoneSetup[$PrivateDnsZoneName].PrivateDnsZone
        $PrivateDnsZoneConfig = $PrivateDnsZoneSetup[$PrivateDnsZoneName].PrivateDnsZoneConfig

        #region Create the private DNS Virtual Network Link
        $PrivateDnsVirtualNetworkLinkMutex = $null
        $MutexName = "PrivateDnsVirtualNetworkLink"
        $PrivateDnsVirtualNetworkLinkMutex = New-Object System.Threading.Mutex($false, $MutexName)
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$MutexName' mutex"

        try {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting for the '$MutexName' mutex lock to be released"
            If ($PrivateDnsVirtualNetworkLinkMutex.WaitOne()) {         
            $PrivateDnsVirtualNetworkLinkResourceGroupName = Get-PsAvdPrivateDnsResourceGroupName -Name $PrivateDnsZoneName
            $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($VirtualNetwork.Name -replace "\W")
            $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $PrivateDnsVirtualNetworkLinkResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
            if ($null -eq $PrivateDnsVirtualNetworkLink) {
                $VirtualNetworkId = $VirtualNetwork.Id
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$PrivateDnsVirtualNetworkLinkName' Private DNS VNet Link (in the '$($VirtualNetwork.ResourceGroupName)' Resource Group)"
                $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $PrivateDnsVirtualNetworkLinkResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $VirtualNetworkId 
            }
            else {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$PrivateDnsVirtualNetworkLinkName' Private DNS VNet Link (in the '$($VirtualNetwork.ResourceGroupName)' Resource Group) already exists"
            }
            $null = $PrivateDnsVirtualNetworkLinkMutex.ReleaseMutex()
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$MutexName' mutex released"
        }
            Else {
            Write-Warning "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Timed out acquiring '$MutexName' mutex!"
        }
        }
        catch [System.Threading.AbandonedMutexException] {
            #AbandonedMutexException means another thread exit without releasing the mutex, and this thread has acquired the mutext, therefore, it can be ignored
            $null = $PrivateDnsVirtualNetworkLinkMutex.ReleaseMutex()
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$MutexName' mutex released"
        }
        #endregion

        #region Create the DNS zone group
        $PrivateDnsZoneGroup = Get-AzPrivateDnsZoneGroup -ResourceGroupName $ResourceGroupName -PrivateEndpointName $PrivateEndpointName
        if ([string]::IsNullOrEmpty($PrivateDnsZoneGroup)) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$ResourceGroupName' Resource Group)"
            $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $ResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force
        }
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$ResourceGroupName' Resource Group) already exists"
        }
        #endregion
        #endregion
        #endregion

    
        #region Key Vault - Disabling Public Access
        if ($null -ne $KeyVault) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Disabling the Public Access for the Key Vault '$($KeyVault.VaultName)' (in the '$ResourceGroupName' Resource Group)"
            #TODO: Implement a mutext instead of -ErrorAction Ignore
            $null = Update-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVault.VaultName -PublicNetworkAccess Disabled -ErrorAction Ignore
        }

        if ($null -ne $StorageAccount) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Disabling the Public Access for the Storage Account '$($StorageAccount.StorageAccountName)' (in the '$ResourceGroupName' Resource Group)"
            $null = Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccount.StorageAccountName -PublicNetworkAccess Disabled
        }
        #endregion
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function New-PsAvdHostPoolSessionHostCredentialKeyVault {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential] $LocalAdminCredential,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential] $ADJoinCredential,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.Commands.Network.Models.PSSubnet] $Subnet
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $VirtualNetwork = Get-AzResource -ResourceID $($Subnet.Id -replace "/subnets/.*$") | Get-AzVirtualNetwork
    $Location = $VirtualNetwork.Location

    Write-Host -Object "Azure Key Vault Setup"
    $StartTime = Get-Date
    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    [HostPool]::BuildAzureLocationSortNameHashtable()
    #endregion
    
    $Index = 0
    Do {
        $Index++
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Index: $Index"
        $KeyVaultName = "kvavdhpcred{0}{1:D3}" -f [HostPool]::AzLocationShortNameHT[$Location].shortName, $Index
        $KeyVaultName = $KeyVaultName.ToLower()
        if ($Index -gt 999) {
            Write-Error "No name available for HostPool Credential Keyvault" -ErrorAction Stop
        }
    } While (-not(Test-AzKeyVaultNameAvailability -Name $KeyVaultName).NameAvailable)
    Write-Host -Object "Azure Key Vault Name for Credentials: $KeyVaultName"
    $ResourceGroupName = "rg-avd-kv-poc-{0}-{1:D3}" -f [HostPool]::AzLocationShortNameHT[$Location].shortName, $Index

    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
    if ($null -eq $ResourceGroup) {
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    }

    #Create an Azure Key Vault
    $KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $location -EnabledForDeployment -EnabledForTemplateDeployment -SoftDeleteRetentionInDays 7 -DisableRbacAuthorization #-EnablePurgeProtection
    #As the owner of the key vault, you automatically have access to create secrets. If you need to let another user create secrets, use:
    #$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $UserPrincipalName -PermissionsToSecrets Get,Delete,List,Set -PassThru

    #region Defining local admin credential(s)
    if ($LocalAdminCredential) {
        $SecureUserName = $(ConvertTo-SecureString -String $LocalAdminCredential.UserName -AsPlainText -Force) 
        $SecurePassword = $LocalAdminCredential.Password
    }
    else {
        $UserName = "localadmin"
        $SecureUserName = $(ConvertTo-SecureString -String $UserName -AsPlainText -Force) 
        Write-Host "UserName: $UserName"
        $SecurePassword = New-RandomPassword -AsSecureString
    }
    $SecretUserName = "LocalAdminUserName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating a secret in $KeyVaultName called '$SecretUserName'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretUserName -SecretValue $SecureUserName

    $SecretPassword = "LocalAdminPassword"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating a secret in $KeyVaultName called '$SecretPassword'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretPassword -SecretValue $SecurePassword
    #endregion

    #region Defining AD join credential(s)
    if ($ADJoinCredential) {
        $SecureUserName = $(ConvertTo-SecureString -String $ADJoinCredential.UserName -AsPlainText -Force) 
        $SecurePassword = $ADJoinCredential.Password
    }
    else {
        $UserName = "adjoin"
        $SecureUserName = $(ConvertTo-SecureString -String $UserName -AsPlainText -Force) 
        Write-Host "UserName: $UserName"
        $SecurePassword = New-RandomPassword -AsSecureString
    }

    $SecretUserName = "ADJoinUserName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating a secret in $KeyVaultName called '$SecretUserName'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretUserName -SecretValue $SecureUserName

    $SecretPassword = "ADJoinPassword"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating a secret in $KeyVaultName called '$SecretPassword'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretPassword -SecretValue $SecurePassword
    #endregion

    #region Private endpoint for Key Vault Setup
    #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
    #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/


    #Creating a Private EndPoint for this KeyVault on this Subnet
    New-PsAvdPrivateEndpointSetup -SubnetId $Subnet.Id -KeyVault $KeyVault

    <#
    #region Create the private endpoint connection on the DC Subnet.
    $PrivateEndpointName = "pep{0}" -f $($KeyVaultName -replace "\W")
    $PrivateEndpoint = Get-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $ResourceGroupName
    if ($null -eq $PrivateEndpoint) {
        $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $KeyVault.ResourceId).GroupId
        $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $KeyVault.ResourceId -GroupId $GroupId
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private Endpoint for the Key Vault '$KeyVaultName' (in the '$ResourceGroupName' Resource Group)"
        $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $ResourceGroupName -Location $VirtualNetwork.Location -Subnet $Subnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force
    }
    else {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$PrivateEndpointName' Private Endpoint for the Key Vault '$KeyVaultName' (in the '$ResourceGroupName' Resource Group) already exists"
    }
    #endregion

    #region Create the private DNS Virtual Network Link and DNS Zone Group
    $PrivateDnsZoneSetup = New-PsAvdPrivateDnsZoneSetup
    $PrivateDnsZoneName = 'privatelink.vaultcore.azure.net'
    $PrivateDnsZone = $PrivateDnsZoneSetup[$PrivateDnsZoneName].PrivateDnsZone
    $PrivateDnsZoneConfig = $PrivateDnsZoneSetup[$PrivateDnsZoneName].PrivateDnsZoneConfig

    #region Create the private DNS Virtual Network Link
    $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($VirtualNetwork.Name -replace "\W")
    $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $VirtualNetwork.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
    if ($null -eq $PrivateDnsVirtualNetworkLink) {
        $VirtualNetworkId = $VirtualNetwork.Id
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$PrivateDnsVirtualNetworkLinkName' Private DNS VNet Link (in the '$($VirtualNetwork.ResourceGroupName)' Resource Group)"
        $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $VirtualNetwork.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $VirtualNetworkId
    }
    else {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$PrivateDnsVirtualNetworkLinkName' Private DNS VNet Link (in the '$($VirtualNetwork.ResourceGroupName)' Resource Group) already exists"
    }
    #endregion

    #region Create the DNS zone group
    $PrivateDnsZoneGroup = Get-AzPrivateDnsZoneGroup -ResourceGroupName $ResourceGroupName -PrivateEndpointName $PrivateEndpointName
    if ($null -eq $PrivateDnsZoneGroup) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$ResourceGroupName' Resource Group)"
        $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $ResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force
    }
    else {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$ResourceGroupName' Resource Group) already exists"
    }
    #endregion
    #endregion
    #>
    #endregion

    <#
    #region Key Vault - Disabling Public Access
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Disabling the Public Access for the Key Vault'$KeyVaultName' (in the '$ResourceGroupName' Resource Group)"
    $null = Update-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName -PublicNetworkAccess "Disabled" 
    #endregion
    #>

    $EndTime = Get-Date
    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host -Object "Azure Key Vault Setup Processing Time: $($TimeSpan.ToString())"

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $KeyVault
}

function New-PsAvdHostPoolCredentialKeyVault {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HostPool] $HostPool
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Key Vault
    #region Key Vault Name Setup
    $HostPoolKeyVaultName = $HostPool.GetKeyVaultName()
    $HostPoolResourceGroupName = $HostPool.GetResourceGroupName()
    $HostPoolVirtualNetwork = $HostPool.GetVirtualNetwork()
    #endregion 

    #region Dedicated Key Vault Setup
    $HostPoolKeyVault = Get-AzKeyVault -VaultName $HostPoolKeyVaultName -ErrorAction Ignore
    if (-not($HostPoolKeyVault)) {
        if (-not(Test-AzKeyVaultNameAvailability -Name $HostPoolKeyVaultName).NameAvailable) {
            Write-Error "The key vault name '$HostPoolKeyVaultName' is not available !" -ErrorAction Stop
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$HostPoolKeyVaultName' Key Vault (in the '$HostPoolResourceGroupName' Resource Group)"
        $HostPoolKeyVault = New-AzKeyVault -ResourceGroupName $HostPoolResourceGroupName -VaultName $HostPoolKeyVaultName -Location $HostPoolVirtualNetwork.Location -SoftDeleteRetentionInDays 7 -DisableRbacAuthorization
    }
    #endregion

    #Creating a Private EndPoint for this KeyVault on this Subnet
    New-PsAvdPrivateEndpointSetup -SubnetId $HostPool.SubnetId -KeyVault $HostPoolKeyVault

    <#
    #region Private endpoint for Key Vault Setup
    #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
    #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
    ## Create the private endpoint connection. ## 

    $PrivateEndpointName = "pep{0}" -f $($HostPoolKeyVaultName -replace "\W")
    $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $HostPoolKeyVault.ResourceId).GroupId
    $Subnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $HostPool.SubnetId
    $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $HostPoolKeyVault.ResourceId -GroupId $GroupId
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private Endpoint for the Key Vault '$HostPoolKeyVaultName' (in the '$HostPoolResourceGroupName' Resource Group)"
    $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $HostPoolResourceGroupName -Location $HostPool.Location -Subnet $Subnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

    ## Create the private DNS zone. ##
    $PrivateDnsZoneName = 'privatelink.vaultcore.azure.net'
    $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $HostPoolVirtualNetwork.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
    if ($null -eq $PrivateDnsZone) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private DNS Zone for the Key Vault '$HostPoolKeyVaultName' (in the '$($HostPoolVirtualNetwork.ResourceGroupName)' Resource Group)"
        $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $HostPoolVirtualNetwork.ResourceGroupName -Name $PrivateDnsZoneName
    }

    $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($HostPoolVirtualNetwork.Name -replace "\W")
    $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $HostPoolVirtualNetwork.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
    if ($null -eq $PrivateDnsVirtualNetworkLink) {
        $HostPoolVirtualNetworkId = $HostPoolVirtualNetwork.Id
        ## Create a DNS network link. ##
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private DNS VNet Link for the Key Vault '$HostPoolKeyVaultName' (in the '$($HostPoolVirtualNetwork.ResourceGroupName)' Resource Group)"
        $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $HostPoolVirtualNetwork.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $HostPoolVirtualNetworkId
    }


    ## Configure the DNS zone. ##
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the DNS Zone Configuration of the Private Dns Zone Group for Key Vault '$HostPoolKeyVaultName'"
    $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

    ## Create the DNS zone group. ##
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$HostPoolResourceGroupName' Resource Group)"
    $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $HostPoolResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force

    #Key Vault - Disabling Public Access
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Disabling the Public Access for the Key Vault'$HostPoolKeyVaultName' (in the '$HostPoolResourceGroupName' Resource Group)"
    $null = Update-AzKeyVault -VaultName $HostPoolKeyVaultName -ResourceGroupName $HostPoolResourceGroupName -PublicNetworkAccess "Disabled" 
    #endregion
    #>
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}


#Based from https://adamtheautomator.com/powershell-random-password/
function New-RandomPassword {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [int] $minLength = 12, ## characters
        [int] $maxLength = 15, ## characters
        [int] $nonAlphaChars = 3,
        [switch] $AsSecureString,
        [switch] $ClipBoard
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    Add-Type -AssemblyName 'System.Web'
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    $RandomPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
    Write-Host "The password is : $RandomPassword"
    if ($ClipBoard) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The password has beeen copied into the clipboard (Use Win+V)"
        $RandomPassword | Set-Clipboard
    }
    if ($AsSecureString) {
        ConvertTo-SecureString -String $RandomPassword -AsPlainText -Force
    }
    else {
        $RandomPassword
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

<#
#Was coded as an alternative to Test-AzKeyVaultNameAvailability (for testing purpose - no more used in this script)
function Get-PsAvdKeyVaultNameAvailability {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [Alias('Name')]
        [string]$VaultName
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Azure Context
    # Log in first with Connect-AzAccount if not using Cloud Shell

    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }
    #endregion
    $Body = [ordered]@{ 
        "name" = $VaultName
        "type" = "Microsoft.KeyVault/vaults"
    }

    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/providers/Microsoft.KeyVault/checkNameAvailability?api-version=2022-07-01"
    try {
        # Invoke the REST API
        #$Response = Invoke-RestMethod -Method POST -Headers $authHeader -Body $($Body | ConvertTo-Json -Depth 100) -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
        $Response = Invoke-AzRestMethod -Method POST -Payload $($Body | ConvertTo-Json -Depth 100) -Uri $URI -ErrorVariable ResponseError
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($Response.message))) {
            Write-Warning -Message $Response.message
        }
    }
    finally {
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $Response
}
#>
#Was coded as an alterative to Expand-AzWvdMsixImage (for testing purpose - no more used in this script)
function Expand-PsAvdMSIXImage {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -match "^\\\\.*\.vhdx?$" })]
        [string]$Uri
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Azure Context
    # Log in first with Connect-AzAccount if not using Cloud Shell

    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }
    #endregion

    $Body = [ordered]@{ 
        "uri" = $Uri
    }

    $expandMsixImageURI = "https://management.azure.com/subscriptions/$SubcriptionID/resourcegroups/$ResourceGroupName/providers/Microsoft.DesktopVirtualization/hostpools/$HostPoolName/expandMsixImage?api-version=2022-02-10-preview"
    try {
        # Invoke the REST API
        #$Response = Invoke-RestMethod -Method POST -Headers $authHeader -Body $($Body | ConvertTo-Json -Depth 100) -ContentType "application/json" -Uri $expandMsixImageURI -ErrorVariable ResponseError
        $Response = Invoke-AzRestMethod -Method POST -Payload $($Body | ConvertTo-Json -Depth 100) -Uri $expandMsixImageURI -ErrorVariable ResponseError
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($Response.message))) {
            Write-Warning -Message $Response.message
        }
    }
    finally {
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $Response
}

function Grant-PsAvdADJoinPermission {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $true)]
        [Alias('OU')]
        [string]$OrganizationalUnit
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    # Import the Active Directory module
    Import-Module ActiveDirectory #-DisableNameChecking

    $ComputerGUID = "bf967a86-0de6-11d0-a285-00aa003049e2"
    $ObjectTypeGUIDs = @{
        'Domain-Administer-Server'                      = 'ab721a52-1e2f-11d0-9819-00aa0040529b'
        'User-Change-Password'                          = 'ab721a53-1e2f-11d0-9819-00aa0040529b'
        'User-Force-Change-Password'                    = '00299570-246d-11d0-a768-00aa006e0529'
        'Send-As'                                       = 'ab721a54-1e2f-11d0-9819-00aa0040529b'
        'Receive-As'                                    = 'ab721a56-1e2f-11d0-9819-00aa0040529b'
        'Send-To'                                       = 'ab721a55-1e2f-11d0-9819-00aa0040529b'
        'Domain-Password'                               = 'c7407360-20bf-11d0-a768-00aa006e0529'
        'General-Information'                           = '59ba2f42-79a2-11d0-9020-00c04fc2d3cf'
        'User-Account-Restrictions'                     = '4c164200-20c0-11d0-a768-00aa006e0529'
        'User-Logon'                                    = '5f202010-79a5-11d0-9020-00c04fc2d4cf'
        'Membership'                                    = 'bc0ac240-79a9-11d0-9020-00c04fc2d4cf'
        'Open-Address-Book'                             = 'a1990816-4298-11d1-ade2-00c04fd8d5cd'
        'Personal-Information'                          = '77B5B886-944A-11d1-AEBD-0000F80367C1'
        'Email-Information'                             = 'E45795B2-9455-11d1-AEBD-0000F80367C1'
        'Web-Information'                               = 'E45795B3-9455-11d1-AEBD-0000F80367C1'
        'DS-Replication-Get-Changes'                    = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        'DS-Replication-Synchronize'                    = '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
        'DS-Replication-Manage-Topology'                = '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2'
        'Change-Schema-Master'                          = 'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd'
        'Change-Rid-Master'                             = 'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd'
        'Do-Garbage-Collection'                         = 'fec364e0-0a98-11d1-adbb-00c04fd8d5cd'
        'Recalculate-Hierarchy'                         = '0bc1554e-0a99-11d1-adbb-00c04fd8d5cd'
        'Allocate-Rids'                                 = '1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd'
        'Change-PDC'                                    = 'bae50096-4752-11d1-9052-00c04fc2d4cf'
        'Add-GUID'                                      = '440820ad-65b4-11d1-a3da-0000f875ae0d'
        'Change-Domain-Master'                          = '014bf69c-7b3b-11d1-85f6-08002be74fab'
        'Public-Information'                            = 'e48d0154-bcf8-11d1-8702-00c04fb96050'
        'msmq-Receive-Dead-Letter'                      = '4b6e08c0-df3c-11d1-9c86-006008764d0e'
        'msmq-Peek-Dead-Letter'                         = '4b6e08c1-df3c-11d1-9c86-006008764d0e'
        'msmq-Receive-computer-Journal'                 = '4b6e08c2-df3c-11d1-9c86-006008764d0e'
        'msmq-Peek-computer-Journal'                    = '4b6e08c3-df3c-11d1-9c86-006008764d0e'
        'msmq-Receive'                                  = '06bd3200-df3e-11d1-9c86-006008764d0e'
        'msmq-Peek'                                     = '06bd3201-df3e-11d1-9c86-006008764d0e'
        'msmq-Send'                                     = '06bd3202-df3e-11d1-9c86-006008764d0e'
        'msmq-Receive-journal'                          = '06bd3203-df3e-11d1-9c86-006008764d0e'
        'msmq-Open-Connector'                           = 'b4e60130-df3f-11d1-9c86-006008764d0e'
        'Apply-Group-Policy'                            = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'
        'RAS-Information'                               = '037088f8-0ae1-11d2-b422-00a0c968f939'
        'DS-Install-Replica'                            = '9923a32a-3607-11d2-b9be-0000f87a36b2'
        'Change-Infrastructure-Master'                  = 'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd'
        'Update-Schema-Cache'                           = 'be2bb760-7f46-11d2-b9ad-00c04f79f805'
        'Recalculate-Security-Inheritance'              = '62dd28a8-7f46-11d2-b9ad-00c04f79f805'
        'DS-Check-Stale-Phantoms'                       = '69ae6200-7f46-11d2-b9ad-00c04f79f805'
        'Certificate-Enrollment'                        = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
        'Self-Membership'                               = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
        'Validated-DNS-Host-Name'                       = '72e39547-7b18-11d1-adef-00c04fd8d5cd'
        'Validated-SPN'                                 = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
        'Generate-RSoP-Planning'                        = 'b7b1b3dd-ab09-4242-9e30-9980e5d322f7'
        'Refresh-Group-Cache'                           = '9432c620-033c-4db7-8b58-14ef6d0bf477'
        'SAM-Enumerate-Entire-Domain'                   = '91d67418-0135-4acc-8d79-c08e857cfbec'
        'Generate-RSoP-Logging'                         = 'b7b1b3de-ab09-4242-9e30-9980e5d322f7'
        'Domain-Other-Parameters'                       = 'b8119fd0-04f6-4762-ab7a-4986c76b3f9a'
        'DNS-Host-Name-Attributes'                      = '72e39547-7b18-11d1-adef-00c04fd8d5cd'
        'Create-Inbound-Forest-Trust'                   = 'e2a36dc9-ae17-47c3-b58b-be34c55ba633'
        'DS-Replication-Get-Changes-All'                = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
        'Migrate-SID-History'                           = 'BA33815A-4F93-4c76-87F3-57574BFF8109'
        'Reanimate-Tombstones'                          = '45EC5156-DB7E-47bb-B53F-DBEB2D03C40F'
        'Allowed-To-Authenticate'                       = '68B1D179-0D15-4d4f-AB71-46152E79A7BC'
        'DS-Execute-Intentions-Script'                  = '2f16c4a5-b98e-432c-952a-cb388ba33f2e'
        'DS-Replication-Monitor-Topology'               = 'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96'
        'Update-Password-Not-Required-Bit'              = '280f369c-67c7-438e-ae98-1d46f3c6f541'
        'Unexpire-Password'                             = 'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501'
        'Enable-Per-User-Reversibly-Encrypted-Password' = '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5'
        'DS-Query-Self-Quota'                           = '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc'
        'Private-Information'                           = '91e647de-d96f-4b70-9557-d63ff4f3ccd8'
        'Read-Only-Replication-Secret-Synchronization'  = '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2'
        'MS-TS-GatewayAccess'                           = 'ffa6f046-ca4b-4feb-b40d-04dfee722543'
        'Terminal-Server-License-Server'                = '5805bc62-bdc9-4428-a5e2-856a0f4c185e'
        'Reload-SSL-Certificate'                        = '1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8'
        'DS-Replication-Get-Changes-In-Filtered-Set'    = '89e95b76-444d-4c62-991a-0facbeda640c'
        'Run-Protect-Admin-Groups-Task'                 = '7726b9d5-a4b4-4288-a6b2-dce952e80a7f'
        'Manage-Optional-Features'                      = '7c0e2a7c-a419-48e4-a995-10180aad54dd'
        'DS-Clone-Domain-Controller'                    = '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e'
        'Validated-MS-DS-Behavior-Version'              = 'd31a8757-2447-4545-8081-3bb610cacbf2'
        'Validated-MS-DS-Additional-DNS-Host-Name'      = '80863791-dbe9-4eb8-837e-7f0ab55d9ac7'
        'Certificate-AutoEnrollment'                    = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
        'DS-Set-Owner'                                  = '4125c71f-7fac-4ff0-bcb7-f09a41325286'
        'DS-Bypass-Quota'                               = '88a9933e-e5c8-4f2a-9dd7-2527416b8092'
        'DS-Read-Partition-Secrets'                     = '084c93a2-620d-4879-a836-f0ae47de0e89'
        'DS-Write-Partition-Secrets'                    = '94825A8D-B171-4116-8146-1E34D8F54401'
        'DS-Validated-Write-Computer'                   = '9b026da6-0d3c-465c-8bee-5199d7165cba'
    }
    $ADRights = @(
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
            "InheritanceType"       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
            "ObjectType"            = "00000000-0000-0000-0000-000000000000"
            "InheritedObjectType"   = "00000000-0000-0000-0000-000000000000"
            "AccessControlType"     = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::ReadControl -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
            "InheritanceType"       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::[System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType"            = "00000000-0000-0000-0000-000000000000"
            "InheritedObjectType"   = $ComputerGUID
            "AccessControlType"     = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
            "InheritanceType"       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
            "ObjectType"            = $ComputerGUID
            "InheritedObjectType"   = "00000000-0000-0000-0000-000000000000"
            "AccessControlType"     = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::Self
            "InheritanceType"       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::[System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType"            = $ObjectTypeGUIDs.'Validated-SPN'
            "InheritedObjectType"   = $ComputerGUID
            "AccessControlType"     = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::Self
            "InheritanceType"       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::[System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType"            = $ObjectTypeGUIDs.'DNS-Host-Name-Attributes'
            "InheritedObjectType"   = $ComputerGUID
            "AccessControlType"     = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
            "InheritanceType"       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType"            = $ObjectTypeGUIDs.'User-Force-Change-Password'
            "InheritedObjectType"   = $ComputerGUID
            "AccessControlType"     = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
            "InheritanceType"       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType"            = $ObjectTypeGUIDs.'User-Change-Password'
            "InheritedObjectType"   = $ComputerGUID
            "AccessControlType"     = [System.Security.AccessControl.AccessControlType]::Allow
        }
    )
    #$ADUser = Get-ADUser -Filter "SamAccountName -eq '$($Credential.UserName)'"
    $ADUser = Get-ADUser -Identity $($Credential.UserName) -ErrorAction Ignore
    #If the user doesn't exist, we create it
    if (-not($ADUser)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($Credential.UserName)' AD User (for adding Azure VM to ADDS)"
        #$DomainName = (Get-ADDomain).DNSRoot
        $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        #$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Forest.Name
        $ADUser = New-ADUser -Name $Credential.UserName -AccountPassword $Credential.Password -PasswordNeverExpires $true -Enabled $true -Description "Created by PowerShell Script for joining AVD Session Hosts to ADDS" -UserPrincipalName $("{0}@{1}" -f $Credential.UserName, $DomainName) -PassThru
    }

    # Define the security SamAccountName (user or group) to which you want to grant the permission
    $IdentityReference = [System.Security.Principal.IdentityReference] $ADUser.SID
    Import-Module -Name ActiveDirectory #-DisableNameChecking
    $Permission = Get-Acl -Path "AD:$OrganizationalUnit"

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Applying required privileges to '$($Credential.UserName)' AD User (for adding Azure VM to ADDS)"
    foreach ($CurrentADRight in $ADRights) {
        $AccessRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($IdentityReference, $CurrentADRight.ActiveDirectoryRights, $CurrentADRight.AccessControlType, $CurrentADRight.ObjectType, $CurrentADRight.InheritanceType, $CurrentADRight.InheritedObjectType)
        $Permission.AddAccessRule($AccessRule)
    }

    # Apply the permission recursively to the OU and its descendants
    Get-ADOrganizationalUnit -Filter "DistinguishedName -like '$OrganizationalUnit'" -SearchBase $OrganizationalUnit -SearchScope Subtree | ForEach-Object {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Applying those required privileges to '$_'"
        Import-Module -Name ActiveDirectory #-DisableNameChecking
        Set-Acl -Path "AD:$_" $Permission
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Permissions granted successfully."
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

#From https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD
function New-AzureComputeGallery {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [string]$Location = "EastUS",
        [Parameter(Mandatory = $false)]
        [string[]]$TargetRegions = @($Location),
        [Parameter(Mandatory = $false)]
        [int]$ReplicaCount = 1
    )

    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString

    <#
    if ($null -eq [HostPool]::AzLocationShortNameHT) {
        [HostPool]::BuildAzureLocationSortNameHashtable()
        $shortNameHT = [HostPool]::AzLocationShortNameHT
    }
    #>
    #endregion

    #region Set up the environment and variables
    # get existing context
    $AzContext = Get-AzContext
    # Your subscription. This command gets your current subscription
    $subscriptionID = $AzContext.Subscription.Id

    #Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
    $AzureComputeGalleryPrefix = "acg"
    $ResourceGroupPrefix = "rg"

    # Location (see possible locations in the main docs)
    Write-Verbose -Message "`$Location: $Location"
    $LocationShortName = $shortNameHT[$Location].shortName
    Write-Verbose -Message "`$LocationShortName: $LocationShortName"
    if ($Location -notin $TargetRegions) {
        $TargetRegions += $Location
    }
    Write-Verbose -Message "`$TargetRegions: $($TargetRegions -join ', ')"
    [array] $TargetRegionsettings = foreach ($CurrentTargetRegion in $TargetRegions) {
        @{"name" = $CurrentTargetRegion; "replicaCount" = $ReplicaCount; "storageAccountType" = "Premium_LRS" }
    }

    $Project = "avd"
    $Role = "aib"
    #Timestamp
    $timeInt = (Get-Date $([datetime]::UtcNow) -UFormat "%s").Split(".")[0]
    $ResourceGroupName = "{0}-{1}-{2}-{3}-{4}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $TimeInt 
    $ResourceGroupName = $ResourceGroupName.ToLower()
    Write-Verbose -Message "`$ResourceGroupName: $ResourceGroupName"


    # Image template and definition names
    #AVD MultiSession Session Image Market Place Image + customizations: VSCode
    $imageDefName01 = "win11-23h2-ent-avd-custom-vscode"
    $imageTemplateName01 = $imageDefName01 + "-template-" + $timeInt
    #AVD MultiSession + Microsoft 365 Market Place Image + customizations: VSCode
    $imageDefName02 = "win11-23h2-ent-avd-m365-vscode"
    $imageTemplateName02 = $imageDefName02 + "-template-" + $timeInt
    Write-Verbose -Message "`$imageDefName01: $imageDefName01"
    Write-Verbose -Message "`$imageTemplateName01: $imageTemplateName01"
    Write-Verbose -Message "`$imageDefName02: $imageDefName02"
    Write-Verbose -Message "`$imageTemplateName02: $imageTemplateName02"

    # Distribution properties object name (runOutput). Gives you the properties of the managed image on completion
    $runOutputName01 = "cgOutput01"
    $runOutputName02 = "cgOutput02"

    #$Version = "1.0.0"
    $Version = Get-Date -UFormat "%Y.%m.%d"
    $Jobs = @()
    #endregion

    # Create resource group
    if (Get-AzResourceGroup -Name $ResourceGroupName -Location $location -ErrorAction Ignore) {
        Write-Verbose -Message "Removing '$ResourceGroupName' Resource Group Name ..."
        Remove-AzResourceGroup -Name $ResourceGroupName -Force
    }
    Write-Verbose -Message "Creating '$ResourceGroupName' Resource Group Name ..."
    $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $location -Force

    #region Permissions, user identity, and role
    # setup role def names, these need to be unique
    $imageRoleDefName = "Azure Image Builder Image Def - $timeInt"
    $identityName = "aibIdentity-$timeInt"
    Write-Verbose -Message "`$imageRoleDefName: $imageRoleDefName"
    Write-Verbose -Message "`$identityName: $identityName"


    # Create the identity
    Write-Verbose -Message "Creating User Assigned Identity '$identityName' ..."
    $AssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $identityName -Location $location

    #$aibRoleImageCreationUrl="https://raw.githubusercontent.com/PeterR-msft/M365AVDWS/master/Azure%20Image%20Builder/aibRoleImageCreation.json"
    #$aibRoleImageCreationUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/12_Creating_AIB_Security_Roles/aibRoleImageCreation.json"
    #$aibRoleImageCreationUrl="https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/aibRoleImageCreation.json"
    $aibRoleImageCreationUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/aibRoleImageCreation.json"
    #$aibRoleImageCreationPath = "aibRoleImageCreation.json"
    $aibRoleImageCreationPath = Join-Path -Path $env:TEMP -ChildPath $(Split-Path $aibRoleImageCreationUrl -Leaf)
    #Generate a unique file name 
    $aibRoleImageCreationPath = $aibRoleImageCreationPath -replace ".json$", "_$timeInt.json"
    Write-Verbose -Message "`$aibRoleImageCreationPath: $aibRoleImageCreationPath"

    # Download the config
    Invoke-WebRequest -Uri $aibRoleImageCreationUrl -OutFile $aibRoleImageCreationPath -UseBasicParsing

    ((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $aibRoleImageCreationPath
    ((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $aibRoleImageCreationPath
    ((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace 'Azure Image Builder Service Image Creation Role', $imageRoleDefName) | Set-Content -Path $aibRoleImageCreationPath

    # Create a role definition
    Write-Verbose -Message "Creating '$imageRoleDefName' Role Definition ..."
    $RoleDefinition = New-AzRoleDefinition -InputFile $aibRoleImageCreationPath

    # Grant the role definition to the VM Image Builder service principal
    Write-Verbose -Message "Assigning '$($RoleDefinition.Name)' Role to '$($AssignedIdentity.Name)' ..."
    Do {
        Write-Verbose -Message "Sleeping 10 seconds ..."
        Start-Sleep -Seconds 10
        $RoleAssignment = New-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $ResourceGroup.ResourceId -ErrorAction Ignore #-Debug
    } While ($null -eq $RoleAssignment)
  
    #endregion

    #region Create an Azure Compute Gallery
    $GalleryName = "{0}_{1}_{2}_{3}" -f $AzureComputeGalleryPrefix, $Project, $LocationShortName, $timeInt
    Write-Verbose -Message "`$GalleryName: $GalleryName"

    # Create the gallery
    Write-Verbose -Message "Creating Azure Compute Gallery '$GalleryName' ..."
    $Gallery = New-AzGallery -GalleryName $GalleryName -ResourceGroupName $ResourceGroupName -Location $location
    #endregion

    #region Template #1 via a customized JSON file
    #Based on https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD
    # Create the gallery definition
    Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$imageDefName01' (From Customized JSON)..."
    $GalleryImageDefinition01 = New-AzGalleryImageDefinition -GalleryName $GalleryName -ResourceGroupName $ResourceGroupName -Location $location -Name $imageDefName01 -OsState generalized -OsType Windows -Publisher 'Contoso' -Offer 'Windows' -Sku 'avd-win11-custom' -HyperVGeneration V2

    #region Download and configure the template
    #$templateUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/14_Building_Images_WVD/armTemplateWVD.json"
    #$templateFilePath = "armTemplateWVD.json"
    $templateUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/armTemplateAVD.json"
    $templateFilePath = Join-Path -Path $env:TEMP -ChildPath $(Split-Path $templateUrl -Leaf)
    #Generate a unique file name 
    $templateFilePath = $templateFilePath -replace ".json$", "_$timeInt.json"
    Write-Verbose -Message "`$templateFilePath: $templateFilePath  ..."

    Invoke-WebRequest -Uri $templateUrl -OutFile $templateFilePath -UseBasicParsing

    ((Get-Content -Path $templateFilePath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $templateFilePath
    #((Get-Content -path $templateFilePath -Raw) -replace '<region>',$location) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<runOutputName>', $runOutputName01) | Set-Content -Path $templateFilePath

    ((Get-Content -Path $templateFilePath -Raw) -replace '<imageDefName>', $imageDefName01) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<sharedImageGalName>', $GalleryName) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<TargetRegions>', $(ConvertTo-Json -InputObject $TargetRegionsettings)) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<imgBuilderId>', $AssignedIdentity.Id) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<version>', $version) | Set-Content -Path $templateFilePath
    #endregion

    #region Submit the template
    Write-Verbose -Message "Starting Resource Group Deployment from '$templateFilePath' ..."
    $ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $templateFilePath -TemplateParameterObject @{"api-Version" = "2022-07-01"; "imageTemplateName" = $imageTemplateName01; "svclocation" = $location }

    #region Build the image
    Write-Verbose -Message "Starting Image Builder Template from '$imageTemplateName01' (As Job) ..."
    $Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName01 -AsJob
    #endregion
    #endregion
    #endregion

    #region Template #2 via a image from the market place + customizations
    # create gallery definition
    $GalleryParams = @{
        GalleryName       = $GalleryName
        ResourceGroupName = $ResourceGroupName
        Location          = $location
        Name              = $imageDefName02
        OsState           = 'generalized'
        OsType            = 'Windows'
        Publisher         = 'Contoso'
        Offer             = 'Windows'
        Sku               = 'avd-win11-m365'
        HyperVGeneration  = 'V2'
    }
    Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$imageDefName02' (From A Market Place Image)..."
    $GalleryImageDefinition02 = New-AzGalleryImageDefinition @GalleryParams

    $SrcObjParams = @{
        PlatformImageSource = $true
        Publisher           = 'MicrosoftWindowsDesktop'
        Offer               = 'Office-365'    
        Sku                 = 'win11-23h2-avd-m365'  
        Version             = 'latest'
    }
    Write-Verbose -Message "Creating Azure Image Builder Template Source Object  ..."
    $srcPlatform = New-AzImageBuilderTemplateSourceObject @SrcObjParams

    $disObjParams = @{
        SharedImageDistributor = $true
        GalleryImageId         = "$($GalleryImageDefinition02.Id)/versions/$version"
        ArtifactTag            = @{source = 'avd-win11'; baseosimg = 'windows11' }

        # 1. Uncomment following line for a single region deployment.
        #ReplicationRegion = $location

        # 2. Uncomment following line if the custom image should be replicated to another region(s).
        TargetRegion           = $TargetRegionsettings

        RunOutputName          = $runOutputName02
        ExcludeFromLatest      = $false
    }
    Write-Verbose -Message "Creating Azure Image Builder Template Distributor Object  ..."
    $disSharedImg = New-AzImageBuilderTemplateDistributorObject @disObjParams

    $ImgTimeZoneRedirectionPowerShellCustomizerParams = @{  
        PowerShellCustomizer = $true  
        Name                 = 'Timezone Redirection'  
        RunElevated          = $true  
        runAsSystem          = $true  
        ScriptUri            = 'https://raw.githubusercontent.com/Azure/RDS-Templates/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2023-07-31/TimezoneRedirection.ps1'
    }

    Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgTimeZoneRedirectionPowerShellCustomizerParams.Name)' ..."
    $TimeZoneRedirectionCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgTimeZoneRedirectionPowerShellCustomizerParams 

    $ImgVSCodePowerShellCustomizerParams = @{  
        PowerShellCustomizer = $true  
        Name                 = 'Install Visual Studio Code'  
        RunElevated          = $true  
        runAsSystem          = $true  
        ScriptUri            = 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/Install-VSCode.ps1'
    }

    Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgVSCodePowerShellCustomizerParams.Name)' ..."
    $VSCodeCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgVSCodePowerShellCustomizerParams 

    Write-Verbose -Message "Creating Azure Image Builder Template WindowsUpdate Customizer Object ..."
    $WindowsUpdateCustomizer = New-AzImageBuilderTemplateCustomizerObject -WindowsUpdateCustomizer -Name 'WindowsUpdate' -Filter @('exclude:$_.Title -like ''*Preview*''', 'include:$true') -SearchCriterion "IsInstalled=0" -UpdateLimit 40

    $ImgDisableAutoUpdatesPowerShellCustomizerParams = @{  
        PowerShellCustomizer = $true  
        Name                 = 'Disable AutoUpdates'  
        RunElevated          = $true  
        runAsSystem          = $true  
        ScriptUri            = 'https://raw.githubusercontent.com/Azure/RDS-Templates/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2023-07-31/TimezoneRedirection.ps1'
    }

    Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgDisableAutoUpdatesPowerShellCustomizerParams.Name)' ..."
    $DisableAutoUpdatesCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgDisableAutoUpdatesPowerShellCustomizerParams 

    #Create an Azure Image Builder template and submit the image configuration to the Azure VM Image Builder service:
    $Customize = $TimeZoneRedirectionCustomizer, $VSCodeCustomizer, $WindowsUpdateCustomizer, $DisableAutoUpdatesCustomizer
    $ImgTemplateParams = @{
        ImageTemplateName      = $imageTemplateName02
        ResourceGroupName      = $ResourceGroupName
        Source                 = $srcPlatform
        Distribute             = $disSharedImg
        Customize              = $Customize
        Location               = $location
        UserAssignedIdentityId = $AssignedIdentity.Id
        VMProfileVmsize        = "Standard_D4s_v5"
        VMProfileOsdiskSizeGb  = 127
    }
    Write-Verbose -Message "Creating Azure Image Builder Template from '$imageTemplateName02' Image Template Name ..."
    $ImageBuilderTemplate = New-AzImageBuilderTemplate @ImgTemplateParams

    #region Build the image
    #Start the image building process using Start-AzImageBuilderTemplate cmdlet:
    Write-Verbose -Message "Starting Image Builder Template from '$imageTemplateName02' (As Job) ..."
    $Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName02 -AsJob
    #endregion
    #endregion
	
    Write-Verbose -Message "Waiting for jobs to complete ..."
    $Jobs | Wait-Job | Out-Null
`	

    #region imageTemplateName01 status 
    #To determine whenever or not the template upload process was successful, run the following command.
    $getStatus01 = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName01
    # Optional - if you have any errors running the preceding command, run:
    Write-Verbose -Message "'$imageTemplateName01' ProvisioningErrorCode: $($getStatus01.ProvisioningErrorCode) "
    Write-Verbose -Message "'$imageTemplateName01' ProvisioningErrorMessage: $($getStatus01.ProvisioningErrorMessage) "
    # Shows the status of the build
    Write-Verbose -Message "'$imageTemplateName01' LastRunStatusRunState: $($getStatus01.LastRunStatusRunState) "
    Write-Verbose -Message "'$imageTemplateName01' LastRunStatusMessage: $($getStatus01.LastRunStatusMessage) "
    Write-Verbose -Message "'$imageTemplateName01' LastRunStatusRunSubState: $($getStatus01.LastRunStatusRunSubState) "
    if ($getStatus01.LastRunStatusRunState -eq "Failed") {
        Write-Error -Message "The Image Builder Template for '$imageTemplateName01' has failed:\r\n$($getStatus01.LastRunStatusMessage)"
    }
    Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateName01' ..."
    #$Jobs += $getStatus01 | Remove-AzImageBuilderTemplate -AsJob
    $getStatus01 | Remove-AzImageBuilderTemplate -NoWait
    Write-Verbose -Message "Removing '$aibRoleImageCreationPath' ..."
    Write-Verbose -Message "Removing '$templateFilePath' ..."
    Remove-Item -Path $aibRoleImageCreationPath, $templateFilePath -Force
    #endregion

    #region imageTemplateName02 status
    #To determine whenever or not the template upload process was successful, run the following command.
    $getStatus02 = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName02
    # Optional - if you have any errors running the preceding command, run:
    Write-Verbose -Message "'$imageTemplateName02' ProvisioningErrorCode: $($getStatus02.ProvisioningErrorCode) "
    Write-Verbose -Message "'$imageTemplateName02' ProvisioningErrorMessage: $($getStatus02.ProvisioningErrorMessage) "
    # Shows the status of the build
    Write-Verbose -Message "'$imageTemplateName02' LastRunStatusRunState: $($getStatus02.LastRunStatusRunState) "
    Write-Verbose -Message "'$imageTemplateName02' LastRunStatusMessage: $($getStatus02.LastRunStatusMessage) "
    Write-Verbose -Message "'$imageTemplateName02' LastRunStatusRunSubState: $($getStatus02.LastRunStatusRunSubState) "
    if ($getStatus02.LastRunStatusRunState -eq "Failed") {
        Write-Error -Message "The Image Builder Template for '$imageTemplateName02' has failed:\r\n$($getStatus02.LastRunStatusMessage)"
    }
    Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateName02' ..."
    #$Jobs += $getStatus02 | Remove-AzImageBuilderTemplate -AsJob
    $getStatus02 | Remove-AzImageBuilderTemplate -NoWait
    #endregion

    #Adding a delete lock (for preventing accidental deletion)
    #New-AzResourceLock -LockLevel CanNotDelete -LockNotes "$ResourceGroupName - CanNotDelete" -LockName "$ResourceGroupName - CanNotDelete" -ResourceGroupName $ResourceGroupName -Force
    #region Clean up your resources
    <#
    ## Remove the Resource Group
    Remove-AzResourceGroup $ResourceGroupName -Force -AsJob
    ## Remove the definitions
    Remove-AzRoleDefinition -Name $RoleDefinition.Name -Force
    #>
    #endregion
  
    $Jobs | Wait-Job | Out-Null
    Write-Verbose -Message "Removing jobs ..."
    $Jobs | Remove-Job -Force
    return $Gallery
}

function Update-PsAvdSystemAssignedAzVM {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine] $VM = $(Get-AzVMCompute | Get-AzVM)
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    if ($null -eq $VM.Identity) {
        # Enable system-assigned managed identity
        $VM.Identity = New-Object Microsoft.Azure.Management.Compute.Models.VirtualMachineIdentity
        $VM.Identity.Type = "SystemAssigned"

        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Setting a 'SystemAssigned' identity to the '$($VM.Name)' VM"
        # Update the VM with the managed identity
        $null = $VM | Update-AzVM
    }
    else {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] A 'SystemAssigned' identity is already set for the '$($VM.Name)' VM"
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

#Get The Virtual Network Object for the VM executing this function
function Get-AzVMVirtualNetwork {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine] $VM = $(Get-AzVMCompute | Get-AzVM)
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    # Get the VM's network interface
    $VMNetworkInterfaceId = $VM.NetworkProfile.NetworkInterfaces[0].Id
    $VMNetworkInterface = Get-AzNetworkInterface -ResourceId $VMNetworkInterfaceId
    # Get the subnet ID
    $VMSubnetId = $VMNetworkInterface.IpConfigurations[0].Subnet.Id
    $VMSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $VMSubnetId
    # Get the vnet ID
    $VMVirtualNetwork = Get-AzResource -ResourceId $($VMSubnetId -replace "/subnets/.*$") | Get-AzVirtualNetwork
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VMVirtualNetwork:`r`n$($VMVirtualNetwork | Out-String)"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $VMVirtualNetwork
}

#Get The Virtual Network Object for the VM executing this function
function Get-AzVMSubnet {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine] $VM = $(Get-AzVMCompute | Get-AzVM)
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    # Get the VM's network interface
    $VMNetworkInterfaceId = $VM.NetworkProfile.NetworkInterfaces[0].Id
    $VMNetworkInterface = Get-AzNetworkInterface -ResourceId $VMNetworkInterfaceId
    # Get the subnet ID
    $VMSubnetId = $VMNetworkInterface.IpConfigurations[0].Subnet.Id
    $VMSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $VMSubnetId
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $VMSubnet
}

#Get The Azure VM Compute Object for the VM executing this function
function Get-AzVMCompute {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $uri = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers @{"Metadata" = "true" } -Method GET -TimeoutSec 5
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] VM Compute Object:`r`n$($response.compute | Out-String)"
        return $response.compute
    }
    catch {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
}

function New-PsAvdSessionHost {
    [CmdletBinding(DefaultParameterSetName = 'Image')]
    Param(
        [Parameter(Mandatory = $true)]
        [Alias('Id')]
        [String]$HostPoolId, 
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.KeyVault.Models.PSKeyVault]$KeyVault,
        [Parameter(Mandatory = $true)]
        [String]$RegistrationInfoToken,
        [Parameter(Mandatory = $true)]
        [String]$OUPath,
        [Parameter(Mandatory = $true)]
        [String]$DomainName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubnetId,
        [Parameter(Mandatory = $false)]
        [string]$VMSize = "Standard_D2s_v5",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image')]
        [string]$ImagePublisherName = "microsoftwindowsdesktop",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image')]
        [string]$ImageOffer = "office-365",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image')]
        [string]$ImageSku = "win11-23h2-avd-m365",
        [Parameter(Mandatory = $true, ParameterSetName = 'ACG')]
        [ValidateNotNullOrEmpty()]
        [string]$VMSourceImageId,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Location,
        [DiffDiskPlacement]$DiffDiskPlacement = [DiffDiskPlacement]::None,
        [hashtable] $Tag,
        [switch]$IsMicrosoftEntraIdJoined, 
        [switch] $Spot,
        [switch] $HibernationEnabled,
        [switch] $Intune
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $OSDiskSize = [HostPool]::VMProfileOsdiskSizeGb
    $OSDiskType = "Premium_LRS"

    Import-Module -Name Az.Compute -DisableNameChecking

    if ($null -eq (Get-AzVMSize -Location $Location | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
        Write-Error "The '$VMSize' VM Size is not available in the '$($Location)' location" -ErrorAction Stop
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$HostPoolId: $HostPoolId"
    $HostPool = Get-AzResource -ResourceId $HostPoolId
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$VMName' Session Host into the '$($HostPool.Name)' Host Pool (in the '$($HostPool.ResourceGroupName)' Resource Group)"

    $NICName = "nic-$VMName"
    $OSDiskName = '{0}_OSDisk' -f $VMName
    #$DataDiskName = "$VMName-DataDisk01"

    #Create Network Interface Card 
    $NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId $SubnetId -Force

    if ($Spot) {
        #Create a virtual machine configuration file (As a Spot Intance for saving costs . DON'T DO THAT IN A PRODUCTION ENVIRONMENT !!!)
        #We have to create a SystemAssignedIdentity for Microsoft Entra ID joined Azure VM but let's do it for all VM
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -SecurityType Standard -IdentityType SystemAssigned -Priority "Spot" -MaxPrice -1
    }
    elseif ($HibernationEnabled) {
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -SecurityType Standard -IdentityType SystemAssigned -HibernationEnabled
    }
    else {
        #Create a virtual machine configuration file
        #We have to create a SystemAssignedIdentity for Microsoft Entra ID joined Azure VM but let's do it for all VM
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -SecurityType Standard -IdentityType SystemAssigned
    }
    $null = Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

    <#
    $LocalAdminUserName = $KeyVault | Get-AzKeyVaultSecret -Name LocalAdminUserName -AsPlainText
    $LocalAdminPassword = ($KeyVault | Get-AzKeyVaultSecret -Name LocalAdminPassword).SecretValue
    $LocalAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($LocalAdminUserName, $LocalAdminPassword)
    #>
    $LocalAdminCredential = Get-LocalAdminCredential -KeyVault $KeyVault

    #Set VM operating system parameters
    $null = Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $VMName -Credential $LocalAdminCredential -ProvisionVMAgent

    #Set boot diagnostic to managed storage account
    $null = Set-AzVMBootDiagnostic -VM $VMConfig -Enable 

    #Set virtual machine source image
    if (-not([string]::IsNullOrEmpty($VMSourceImageId))) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Building Azure VM via `$VMSourceImageId:$VMSourceImageId"
        $null = Set-AzVMSourceImage -VM $VMConfig -Id $VMSourceImageId
    }
    else {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Building Azure VM via `$ImagePublisherName:$ImagePublisherName/`$ImageOffer:$ImageOffer/`$ImageSku:$ImageSku"
        $null = Set-AzVMSourceImage -VM $VMConfig -PublisherName $ImagePublisherName -Offer $ImageOffer -Skus $ImageSku -Version 'latest'
    }
    #Set OsDisk configuration
    #From https://learn.microsoft.com/en-us/azure/virtual-machines/ephemeral-os-disks-deploy#powershell
    if ($DiffDiskPlacement -eq [DiffDiskPlacement]::None) {
        $null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] No Ephemeral OS disk for '$VMName' Azure VM"
    } 
    elseif ($DiffDiskPlacement -eq [DiffDiskPlacement]::CacheDisk) {
        $null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -CreateOption fromImage -DiffDiskSetting Local -DiffDiskPlacement CacheDisk -Caching ReadOnly
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Ephemeral OS disk for '$VMName' Azure VM set to 'CacheDisk'"
    }
    else { 
        $null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -CreateOption fromImage -DiffDiskSetting Local -DiffDiskPlacement ResourceDisk -Caching ReadOnly
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Ephemeral OS disk for '$VMName' Azure VM set to 'ResourceDisk'"
    }
    try {
        $null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VMConfig -Tag $Tag -DisableBginfoExtension -ErrorAction Stop
    } 
    #Maybe: Ephemeral OS disk is not supported for specified VM size.
    catch {
        #[ComputeCloudException]
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "Message: $($_.Exception.Message)"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Disabling Ephemeral OS disk for '$VMName' Azure VM"
        $null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage
        $null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VMConfig -Tag $Tag -DisableBginfoExtension
    }
    $VM = Get-AzVM -ResourceGroup $ResourceGroupName -Name $VMName
    $null = $VM | Start-AzVM #-Name $VMName -ResourceGroupName $ResourceGroupName

    #region Enabling auto-shutdown at 11:00 PM in the user time zome
    $SubscriptionId = ($VM.Id).Split('/')[2]
    $ScheduledShutdownResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.devtestlab/schedules/shutdown-computevm-$($VM.Name)"
    $Properties = @{
        status           = 'Enabled'
        taskType         = 'ComputeVmShutdownTask'
        dailyRecurrence  = @{'time' = "2300" }
        timeZoneId       = (Get-TimeZone).Id
        targetResourceId = $VM.Id
    }
    New-AzResource -Location $VM.Location -ResourceId $ScheduledShutdownResourceId -Properties $Properties -Force
    #endregion

    if ($IsMicrosoftEntraIdJoined) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$VMName' VM will be Microsoft Entra ID joined"
        $aadJoin = [boolean]::TrueString
    }
    else {
        $ExtensionName = "joindomain_{0:yyyyMMddHHmmss}" -f (Get-Date)
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding '$VMName' VM to '$DomainName' AD domain"

        <#
        $AdJoinUserName = $KeyVault | Get-AzKeyVaultSecret -Name AdJoinUserName -AsPlainText
        $AdJoinPassword = ($KeyVault | Get-AzKeyVaultSecret -Name AdJoinPassword).SecretValue
        #>
        $ADDomainJoinCredential = Get-AdjoinCredential -KeyVault $KeyVault
        $AdJoinUserName = $ADDomainJoinCredential.UserName
        $AdJoinPassword = $ADDomainJoinCredential.Password


        $ADDomainJoinUser = Get-ADUser -Identity $AdJoinUserName -Properties UserPrincipalName -ErrorAction Ignore
        if ([string]::IsNullOrEmpty($ADDomainJoinUser.UserPrincipalName)) {
            $ADDomainJoinUPNCredential = New-Object System.Management.Automation.PSCredential -ArgumentList("$AdJoinUserName@$DomainName", $AdJoinPassword)
        }
        else {
            $ADDomainJoinUPNCredential = New-Object System.Management.Automation.PSCredential -ArgumentList($ADDomainJoinUser.UserPrincipalName, $AdJoinPassword)
        }
        $null = Set-AzVMADDomainExtension -Name $ExtensionName -DomainName $DomainName -OUPath $OUPath -VMName $VMName -Credential $ADDomainJoinUPNCredential -ResourceGroupName $ResourceGroupName -JoinOption 0x00000003 -Restart
        $aadJoin = [boolean]::FalseString
    }
    # Adding local admin Credentials to the Credential Manager (and escaping the password)
    #Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$VMName /user:$($LocalAdminCredential.UserName) /pass:$($LocalAdminCredential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait -NoNewWindow
    
    #To be sure the VM is started
    $Result = Start-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Result:`r`n$($Result | Out-String)"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 10 seconds"
    Start-Sleep -Seconds 10

    # AVD Azure AD Join domain extension
    #From https://www.rozemuller.com/avd-automation-cocktail-avd-automated-with-powershell/
    #From https://www.rozemuller.com/how-to-join-azure-ad-automated/
    #Date : 02/14/2024
    <#
    $avdModuleLocation = "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration_1.0.02599.267.zip"
    $avdDscSettings = @{
        Name               = "Microsoft.PowerShell.DSC"
        Type               = "DSC" 
        Publisher          = "Microsoft.Powershell"
        typeHandlerVersion = "2.73"
        SettingString      = "{
            ""modulesUrl"":'$avdModuleLocation',
            ""ConfigurationFunction"":""Configuration.ps1\\AddSessionHost"",
            ""Properties"": {
                ""hostPoolName"": ""$($HostPool.Name)"",
                ""RegistrationInfoToken"": ""$($RegistrationInfoToken)"",
                ""aadJoin"": $aadJoin
            }
        }"
        VMName             = $VMName
        ResourceGroupName  = $ResourceGroupName
        location           = $Location
    }
    
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding '$VMName' to '$($HostPool.Name)' Host Pool"
    $result = Set-AzVMExtension @avdDscSettings
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Result: `r`n$($result | Out-String)"
    #>

    #URI updated on : 12/11/2024
    #To Get the latest version of the zip by looking in the Resource Group Deployement
    #$avdModuleLocation = ((Get-AzWvdHostPool).ResourcegroupName | ForEach-Object -Process { Get-AzResourceGroupDeployment -ResourceGroupName $_} | Where-Object -FilterScript { $_.Parameters } | Foreach-Object -Process { $_.Parameters["artifactsLocation"]} | Sort-Object -Property Value -Descending | Select-Object -First 1).Value
    $avdModuleLocation = "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration_1.0.02872.560.zip"
    #$avdExtensionName = "DSC_{0:yyyyMMddHHmmss}" -f (Get-Date)
    $avdExtensionName = "DSC"
    $avdExtensionPublisher = "Microsoft.Powershell"
    $avdExtensionVersion = "2.73"
    $avdExtensionSetting = @{
        modulesUrl            = $avdModuleLocation
        ConfigurationFunction = "Configuration.ps1\AddSessionHost"
        Properties            = @{
            hostPoolName          = $HostPool.Name
            registrationInfoToken = $RegistrationInfoToken
            aadJoin               = $IsMicrosoftEntraIdJoined.IsPresent
        }
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding '$VMName' to '$($HostPool.Name)' Host Pool"
    $result = Set-AzVMExtension -VMName $VMName -ResourceGroupName $ResourceGroupName -Location  $Location -TypeHandlerVersion $avdExtensionVersion -Publisher $avdExtensionPublisher -ExtensionType $avdExtensionName -Name $avdExtensionName -Settings $avdExtensionSetting
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Result: `r`n$($result | Out-String)"

    if ($IsMicrosoftEntraIdJoined) {
        #region Installing the AADLoginForWindows extension
        $PreviouslyExistingAzureADDevice = Get-MgBetaDevice -Filter "displayName eq '$VMName'" -All
        if ($null -ne $PreviouslyExistingAzureADDevice) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing previously existing '$VMName' as a device into 'Microsoft Entra ID'"
            #The pipeline has been stopped ==> $PreviouslyExistingAzureADDevice | Remove-MgBetaDevice
            $PreviouslyExistingAzureADDevice | ForEach-Object -Process { 
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing Microsoft Entra ID Device : $($_.DisplayName)"
                Remove-MgBetaDevice -DeviceId $_.Id 
            }
        }
        if ($Intune) {
            #From https://rozemuller.com/how-to-join-azure-ad-automated/
            #From https://virtuallyflatfeet.com/category/intune/
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding '$VMName' as a device into 'Microsoft Entra ID' and enrolled with Intune"
            $domainJoinSettings = @{
                mdmId = "0000000a-0000-0000-c000-000000000000"
            }

            $result = Set-AzVMExtension -Publisher "Microsoft.Azure.ActiveDirectory" -Name AADLoginForWindows -ResourceGroupName  $VM.ResourceGroupName -VMName $VM.Name -Settings $domainJoinSettings -ExtensionType "AADLoginForWindows" -TypeHandlerVersion 2.0
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Result: `r`n$($result | Out-String)"
        }
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding '$VMName' as a device into 'Microsoft Entra ID'"
            $result = Set-AzVMExtension -Publisher Microsoft.Azure.ActiveDirectory -Name AADLoginForWindows -ResourceGroupName $VM.ResourceGroupName -VMName $VM.Name -ExtensionType AADLoginForWindows -TypeHandlerVersion 2.0
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Result: `r`n$($result | Out-String)"
        }
        #endregion
        <#
        #>
    }
    <#
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Restarting '$VMName'"
    Restart-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName -Confirm:$false
    #>
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VM:`r`n$($VM | Out-String)"
    $VM
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Get-PsAvdNextSessionHostName {
    [CmdletBinding(DefaultParameterSetName = 'Image')]
    Param(
        [Parameter(Mandatory = $true)]
        [Alias('Id')]
        [String]$HostPoolId, 
        [Parameter(Mandatory = $true)]
        [ValidateLength(2, 13)]
        [string]$NamePrefix,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -gt 0 })]
        [int]$VMNumberOfInstances
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$HostPoolId: $HostPoolId"
    $HostPool = Get-AzResource -ResourceId $HostPoolId
    $ExistingSessionHostNames = (Get-AzWvdSessionHost -ResourceGroupName $HostPool.ResourceGroupName -HostPoolName $HostPool.Name).ResourceId -replace ".*/"
    $ExistingSessionHostNamesWithSameNamePrefix = $ExistingSessionHostNames -match "$NamePrefix-"
    if (-not([string]::IsNullOrEmpty($ExistingSessionHostNamesWithSameNamePrefix))) {
        $VMIndexes = $ExistingSessionHostNamesWithSameNamePrefix -replace "\D"
        if ([string]::IsNullOrEmpty($VMIndexes)) {
            $Start = 0
        }
        else {
            #We take the highest existing VM index and restart just after
            $Start = ($VMIndexes | Measure-Object -Maximum).Maximum + 1
        }
    }
    else {
        $Start = 0
    }
    $End = $Start + $VMNumberOfInstances - 1

    foreach ($Index in $Start..$End) {
        '{0}-{1}' -f $NamePrefix, $Index
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Add-PsAvdSessionHost {
    [CmdletBinding(DefaultParameterSetName = 'Image')]
    Param(
        [Parameter(Mandatory = $true)]
        [Alias('Id')]
        [String]$HostPoolId, 
        [Parameter(Mandatory = $true)]
        [ValidateLength(2, 13)]
        [string]$NamePrefix,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -gt 0 })]
        [int]$VMNumberOfInstances,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.Commands.KeyVault.Models.PSKeyVault]$KeyVault,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$RegistrationInfoToken,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$OUPath,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$DomainName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubnetId,
        [Parameter(Mandatory = $false)]
        [string]$VMSize = "Standard_D2s_v5",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image')]
        [string]$ImagePublisherName = "microsoftwindowsdesktop",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image')]
        [string]$ImageOffer = "office-365",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image')]
        [string]$ImageSku = "win11-23h2-avd-m365",
        [Parameter(Mandatory = $true, ParameterSetName = 'ACG')]
        [ValidateNotNullOrEmpty()]
        [string]$VMSourceImageId,
        [DiffDiskPlacement]$DiffDiskPlacement = [DiffDiskPlacement]::None,
        [Parameter(Mandatory = $false)]
        [string]$LogDir = ".",
        [Parameter(Mandatory = $false)]
        [hashtable] $Tag,
        [switch]$IsMicrosoftEntraIdJoined,
        [switch]$Spot,
        [switch]$HibernationEnabled,
        [switch]$Intune,
        [switch]$AsJob
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #HibernationEnabled can't be used with Spot VMs
    if ($Spot) {
        $HibernationEnabled = $false
    }
    
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$HostPoolId: $HostPoolId"
    $HostPool = Get-AzResource -ResourceId $HostPoolId
    $NextSessionHostNames = Get-PsAvdNextSessionHostName -HostPoolId $HostPoolId -NamePrefix $NamePrefix -VMNumberOfInstances $VMNumberOfInstances
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NextSessionHostNames: $($NextSessionHostNames -join ', ')"

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding $VMNumberOfInstances Session Hosts to the '$($HostPool.Name)' Host Pool (in the '$($HostPool.ResourceGroupName)' Resource Group)"
    $Jobs = foreach ($NextSessionHostName in $NextSessionHostNames) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$NextSessionHostName' Session Host"
        if (-not([string]::IsNullOrEmpty($VMSourceImageId))) {
            $Params = @{
                HostPoolId               = $HostPoolId 
                VMName                   = $NextSessionHostName
                ResourceGroupName        = $HostPool.ResourceGroupName 
                KeyVault                 = $KeyVault
                RegistrationInfoToken    = $RegistrationInfoToken
                OUPath                   = $OUPath
                DomainName               = $DomainName
                VMSize                   = $VMSize 
                VMSourceImageId          = $VMSourceImageId
                DiffDiskPlacement        = $DiffDiskPlacement
                Tag                      = $Tag
                IsMicrosoftEntraIdJoined = $IsMicrosoftEntraIdJoined
                Spot                     = $Spot
                HibernationEnabled       = $HibernationEnabled
                Intune                   = $Intune
                Location                 = $HostPool.Location
                SubnetId                 = $SubnetId
                #Verbose                  = $true
            }
        }
        else {
            $Params = @{
                HostPoolId               = $HostPoolId 
                VMName                   = $NextSessionHostName
                ResourceGroupName        = $HostPool.ResourceGroupName 
                KeyVault                 = $KeyVault
                RegistrationInfoToken    = $RegistrationInfoToken
                OUPath                   = $OUPath
                DomainName               = $DomainName
                VMSize                   = $VMSize 
                DiffDiskPlacement        = $DiffDiskPlacement
                ImagePublisherName       = $ImagePublisherName
                ImageOffer               = $ImageOffer
                ImageSku                 = $ImageSku
                Tag                      = $Tag
                IsMicrosoftEntraIdJoined = $IsMicrosoftEntraIdJoined
                Spot                     = $Spot
                HibernationEnabled       = $HibernationEnabled
                Intune                   = $Intune
                Location                 = $HostPool.Location
                SubnetId                 = $SubnetId
                #Verbose                  = $true
            }
        }
        #$AsJob = $false
        if ($AsJob) {
            #From https://stackoverflow.com/questions/7162090/how-do-i-start-a-job-of-a-function-i-just-defined
            #From https://stackoverflow.com/questions/76844912/how-to-call-a-class-object-in-powershell-jobs
            $ExportedFunctions = [scriptblock]::Create(@"
            Function Get-AdjoinCredential { ${Function:Get-AdjoinCredential} }
            Function Get-LocalAdminCredential { ${Function:Get-LocalAdminCredential} }
            Function New-PsAvdSessionHost { ${Function:New-PsAvdSessionHost} }          
            Function Get-AzVMVirtualNetwork { ${Function:Get-AzVMVirtualNetwork} }          
            Function Get-AzVMCompute { ${Function:Get-AzVMCompute} }
            Function Get-CallerPreference { ${Function:Get-CallerPreference} }
"@)
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Starting background job for '$NextSessionHostName' SessionHost Creation (via New-PsAvdSessionHost) ... "
            try {
                #Getting the Log Directory if ran from a Start-ThreadJob
                $LocalLogDir = $using:LogDir
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] We are in the context of a 'Start-ThreadJob'"
            }
            catch {
                #Getting the Log Directory if NOT ran from a Start-ThreadJob
                $LocalLogDir = $LogDir
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] We are NOT in the context of a 'Start-ThreadJob'"
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$LocalLogDir: $LocalLogDir"
            $Verbose = $(( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ))
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Verbose: $Verbose"
            Start-ThreadJob -ScriptBlock { param($LogDir, $Verbose) New-PsAvdSessionHost @using:Params -Verbose:$Verbose *>&1 | Out-File -FilePath $("{0}\New-PsAvdSessionHost_{1}_{2}.txt" -f $LogDir, $using:NextSessionHostName, (Get-Date -Format 'yyyyMMddHHmmss')) } -InitializationScript $ExportedFunctions -ArgumentList $LocalLogDir, $Verbose -StreamingHost $Host
        }
        else {
            New-PsAvdSessionHost @Params
        }
    }
    if ($AsJob) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting for the 'New-PsAvdSessionHost' job to finish"
        $Jobs | Receive-Job -Wait -AutoRemoveJob
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The waiting is over for the 'New-PsAvdSessionHost' job"
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Get-GitFile {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^https://api.github.com/repos/.*|^https://(www\.)?github.com/")] 
        [string]$URI,
        [Parameter(Mandatory = $true)]
        [string]$FileRegExPattern,
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )   

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region URI transformation (in case of the end-user doesn't give an https://api.github.com/repos/... URI
    if ($URI -match "^https://(www\.)?github.com/(?<organisation>[^/]+)/(?<repository>[^/]+)/tree/master/(?<contents>.*)") {
        #https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/MSIX
        #"https://api.github.com/repos/lavanack/laurentvanacker.com/contents/Azure/Azure%20Virtual%20Desktop/MSIX/MSIX"
        $Organisation = $Matches["organisation"]
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Organisation: $Organisation"
        $Repository = $Matches["repository"]
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Repository: $Repository"
        $Contents = $Matches["contents"]
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Contents: $Contents"
        $GitHubURI = "https://api.github.com/repos/$Organisation/$Repository/contents/$Contents"
    }
    else {
        $GitHubURI = $URI
    }
    #endregion
    #region Getting all request files
    $Response = Invoke-WebRequest -Uri $GitHubURI -UseBasicParsing
    $Objects = $Response.Content | ConvertFrom-Json
    $Files = $Objects | Where-Object -FilterScript { $_.type -eq "file" } | Select-Object -ExpandProperty download_url
    $FileURIs = $Files -match $FileRegExPattern
    Start-BitsTransfer -Source $FileURIs -Destination $(@($Destination) * $($FileURIs.Count))
    $DestinationFiles = $FileURIs | ForEach-Object -Process { Join-Path -Path $Destination -ChildPath $($_ -replace ".*/") }
    #endregion

    #region non-LFS/LFS processing
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] $(Get-ChildItem -Path $DestinationFiles | Out-String)"
    $GitFile = foreach ($CurrentDestinationFile in $DestinationFiles) {
        #Checking if the file is a Github LFS file
        if ($(Get-Content -Path $CurrentDestinationFile -TotalCount 1) -match "version https://git-lfs.github.com") {
            #From https://gist.github.com/fkraeutli/66fa741d9a8c2a6a238a01d17ed0edc5#retrieving-lfs-files
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] $CurrentDestinationFile is a LFS File"
            $FileContent = Get-Content -Path $CurrentDestinationFile
            $SizeResult = [regex]::Match($FileContent, "size\s(?<size>\d+)")
            $OidResult = [regex]::Match($FileContent, "oid\ssha256:(?<oid>\w+)")
            [int]$Size = ($SizeResult.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'size' }).Value
            $Oid = ($OidResult.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'oid' }).Value
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Size: $Size"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Oid: $Oid"
            $JSONHT = @{
                "operation" = "download" 
                "transfer"  = @("basic") 
                "objects"   = @(@{"oid" = $Oid; "size" = $size })
            }
            $JSON = $JSONHT | ConvertTo-Json
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$JSON: $JSON"
            if ($GitHubURI -match "^https://api.github.com/repos/(?<organisation>[^/]+)/(?<repository>[^/]+)") {
                $Organisation = $Matches["organisation"]
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Organisation: $Organisation"
                $Repository = $Matches["repository"]
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Repository: $Repository"
                $NewURI = "https://github.com/$Organisation/$Repository.git/info/lfs/objects/batch"
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NewURI: $NewURI"
                $Result = Invoke-WebRequest -Method POST -Headers @{"Accept" = "application/vnd.git-lfs+json"; "Content-type" = "application/json" } -Body $JSON -Uri $NewURI -UseBasicParsing
                $LFSDownloadURI = ($Result.Content | ConvertFrom-Json).objects.actions.download.href
                Invoke-WebRequest -Uri $LFSDownloadURI -UseBasicParsing -OutFile $CurrentDestinationFile
                Get-Item -Path $CurrentDestinationFile
            }
            else {
                Write-Warning "Unable to determine the Organisation and the Repository from '$GitHubURI'"
            }
        }
        #Non-LFS file
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] $CurrentDestinationFile is NOT a LFS File"
            Get-Item -Path $CurrentDestinationFile
        }
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] $(Get-ChildItem -Path $GitFile | Out-String)"
    #endregion

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $GitFile
}

function Get-WebSiteFile {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$URI,
        [Parameter(Mandatory = $true)]
        [string]$FileRegExPattern,
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )   

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Getting all request files
    $Response = Invoke-WebRequest -Uri $URI -UseBasicParsing
    $Files = $Response.Links.href | Where-Object -FilterScript { $_ -match $FileRegExPattern }
    $FileURIs = $Files | ForEach-Object -Process { "{0}/{1}" -f $URI.Trim("/"), $_ }
    Start-BitsTransfer -Source $FileURIs -Destination $(@($Destination) * $($FileURIs.Count))
    $DestinationFiles = $FileURIs | ForEach-Object -Process { Join-Path -Path $Destination -ChildPath $($_ -replace ".*/") }
    #endregion

    $WebSiteFile = foreach ($CurrentDestinationFile in $DestinationFiles) {
        Get-Item -Path $CurrentDestinationFile 
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $WebSiteFile
}

function Copy-PsAvdMSIXDemoAppAttachPackage {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('GitHub', 'WebSite')]
        [string]$Source='GitHub',

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )   

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Source: $Source"

    if ($Source -eq 'GitHub') {
        $URI = "https://api.github.com/repos/lavanack/laurentvanacker.com/contents/Azure/Azure%20Virtual%20Desktop/MSIX/MSIX"
        #$URI = "https://api.github.com/repos/lavanack/laurentvanacker.com/contents/Azure/Azure%20Virtual%20Desktop/MSIX/MSIX/tests"
        $MSIXDemoPackage = Get-GitFile -URI $URI -FileRegExPattern "\.vhdx?$" -Destination $Destination -Verbose
        #$MSIXDemoPackage = Get-GitFile -URI $URI -FileRegExPattern "\.vhd$" -Destination $Destination -Verbose
    }
    else {
        $URI = "https://laurentvanacker.com/downloads/Azure/Azure%20Virtual%20Desktop/MSIX"
        $MSIXDemoPackage = Get-WebSiteFile -URI $URI -FileRegExPattern "\.vhdx?$" -Destination $Destination -Verbose
    }
    
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $MSIXDemoPackage
}

function Copy-PsAvdMSIXDemoPFXFile {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('GitHub', 'WebSite')]
        [string]$Source='GitHub',
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [string[]] $ComputerName,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()] 
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()] 
        [System.Security.SecureString]$SecurePassword = $(ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force)
    )   

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $TempFolder = New-Item -Path $(Join-Path -Path $env:TEMP -ChildPath $("{0:yyyyMMddHHmmss}" -f (Get-Date))) -ItemType Directory -Force
    if ($Source -eq 'GitHub') {
        $URI = "https://api.github.com/repos/lavanack/laurentvanacker.com/contents/Azure/Azure%20Virtual%20Desktop/MSIX/MSIX"
        #$URI = "https://api.github.com/repos/lavanack/laurentvanacker.com/contents/Azure/Azure%20Virtual%20Desktop/MSIX/MSIX/tests"
        $DownloadedPFXFiles = Get-GitFile -URI $URI -FileRegExPattern "\.pfx$" -Destination $TempFolder -Verbose
    }
    else {
        $URI = "https://laurentvanacker.com/downloads/Azure/Azure%20Virtual%20Desktop/MSIX"
        $DownloadedPFXFiles = Get-WebSiteFile -URI $URI -FileRegExPattern "\.pfx?$" -Destination $TempFolder -Verbose
    }

    if ($Credential) {
        $Session = Wait-PSSession -ComputerName $ComputerName -Credential $Credential -PassThru
    }
    else {
        $Session = Wait-PSSession -ComputerName $ComputerName -PassThru
    }

    #Copying the PFX to all session hosts
    $Session | ForEach-Object -Process { Copy-Item -Path $DownloadedPFXFiles.FullName -Destination C:\ -ToSession $_ -Force }

    Invoke-Command -Session $Session -ScriptBlock {
        $using:DownloadedPFXFiles | ForEach-Object -Process { 
            $LocalFile = $(Join-Path -Path C: -ChildPath $_.Name)
            #Adding the self-signed certificate to the Trusted People (To validate this certificate)
            $ImportPfxCertificates = Import-PfxCertificate $LocalFile -CertStoreLocation Cert:\LocalMachine\TrustedPeople\ -Password $using:SecurePassword 
            Write-Verbose -Message $($ImportPfxCertificates | Out-String)
            #Removing the PFX file (useless now)
            Remove-Item -Path $LocalFile -Force
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating GPO"
            gpupdate /force /wait:-1 /target:computer | Out-Null
        }
    }
    $Session | Remove-PSSession
    #Removing the Temp folder (useless now)
    Remove-Item -Path $TempFolder -Recurse -Force -ErrorAction Ignore
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Wait-PSSession {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [string[]] $ComputerName,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()] 
        [int]$Seconds = 30,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()] 
        [int]$Attempts = 10,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()] 
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$PassThru
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #Any negative value means infinite loop. 
    if ($Attempts -lt 0) {
        $Attempts = [int]::MaxValue
    }
    $Loop = 0
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Computer Names (Nb: $($ComputerName.Count)): $($ComputerName -join ', ')"  
    Do {
        $Loop ++  
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Loop #$($Loop)"  
        if ($Credential) {
            $Session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Ignore
        }
        else {
            $Session = New-PSSession -ComputerName $ComputerName -ErrorAction Ignore
        }
        if ($Session.Count -lt $ComputerName.Count) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping $Seconds Seconds"
            Start-Sleep -Seconds $Seconds
            $result = $false
        }
        else {
            $result = $true
        }
        if (-not($PassThru)) {
            $Session | Remove-PSSession
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Result: $result"  
    } While ((-not($Result)) -and ($Loop -lt $Attempts))
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    if (-not($PassThru)) {   
        return $result
    } 
    else {
        return $Session
    }
}

function Wait-PsAvdRunPowerShell {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [string]$HostPoolName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()] 
        [int]$Seconds = 30,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()] 
        [int]$Attempts = 10
    ) 

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #Any negative value means infinite loop. 
    if ($Attempts -lt 0) {
        $Attempts = [int]::MaxValue
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Infinite Loop Mode Enabled"  
    }
    $Loop = 0
    $SessionHosts = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName
    #Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Session Hosts (Nb: $($SessionHosts.Count)): $($SessionHosts.Name -replace "^.*/" -join ', ')"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Session Hosts (Nb: $($SessionHosts.Count)): $($SessionHosts.Name -replace "^.*/" -replace "\..*$" -join ', ')"
    Do {
        $Loop ++  
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Loop #$($Loop)"  
        $Jobs = foreach ($CurrentSessionHost in $SessionHosts) {
            $CurrentSessionHostVM = $CurrentSessionHost.ResourceId | Get-AzVM
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$($CurrentSessionHostVM.Name)'"
            Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $CurrentSessionHostVM.Name -CommandId 'RunPowerShellScript' -ScriptString 'return $true' -AsJob
        }
        $Jobs | Wait-Job | Out-Null
        #Write-Host "Job State: $($Jobs.State -join ', ')" 
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Job State:`r`n$($Jobs | Group-Object State -NoElement | Out-String)"  
        if ($Jobs.State -ne "Completed") {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping $Seconds Seconds"
            Start-Sleep -Seconds $Seconds
            $result = $false
        }
        else {
            $result = $true
        }
        $Jobs | Remove-Job -Force
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Result: $result"  
    } While ((-not($Result)) -and ($Loop -lt $Attempts))
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $result
}

function Start-MicrosoftEntraIDConnectSync {
    [CmdletBinding(PositionalBinding = $false)]
    Param()

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    if (Get-Service -Name ADSync -ErrorAction Ignore) {
        Start-Service -Name ADSync
        Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync" #-DisableNameChecking
        $ADSyncConnectorRunStatus = Get-ADSyncConnectorRunStatus
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ADSyncConnectorRunStatus: $($ADSyncConnectorRunStatus | Out-String)"
        if (-not((Get-ADSyncScheduler).SyncCycleInProgress)) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Running a sync with Microsoft Entra ID"
            try {
                $null = Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
            }
            catch {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Microsoft Entra ID Sync already in progress"
            }
            Do {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 5 seconds"
                Start-Sleep -Seconds 5
                $ADSyncConnectorRunStatus = Get-ADSyncConnectorRunStatus
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ADSyncConnectorRunStatus: $($ADSyncConnectorRunStatus | Out-String)"
            } While ((Get-ADSyncScheduler).SyncCycleInProgress)

        }
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Microsoft Entra ID Sync already in progress"
        }
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}


Function Remove-PsAvdAzRecoveryServicesAsrReplicationProtectedItem {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [array] $HostPool
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $HostPoolWithAzureSiteRecovery = $HostPool | Where-Object -FilterScript { -not([string]::IsNullOrEmpty($_.ASRFailOverVNetId)) }
    foreach ($CurrentHostPoolWithAzureSiteRecovery in $HostPoolWithAzureSiteRecovery) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$($CurrentHostPoolWithAzureSiteRecovery.Name)' Host Pool"
        $VaultName = $CurrentHostPoolWithAzureSiteRecovery.RecoveryServiceVaultName
        $ResourceGroup = $CurrentHostPoolWithAzureSiteRecovery.RecoveryLocationResourceGroupName
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Recovery Service Vault Name: $VaultName"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Recovery Location ResourceGroup Name: $ResourceGroup"

        $VaultToDelete = Get-AzRecoveryServicesVault -Name $VaultName -ResourceGroupName $ResourceGroup -ErrorAction Ignore
        if ($null -ne $VaultToDelete) {
            Set-AzRecoveryServicesAsrVaultContext -Vault $VaultToDelete

            #Deletion of ASR Items
            $fabricObjects = Get-AzRecoveryServicesAsrFabric
            if ($null -ne $fabricObjects) {
	            # First DisableDR all VMs.
	            foreach ($fabricObject in $fabricObjects) {
		            $containerObjects = Get-AzRecoveryServicesAsrProtectionContainer -Fabric $fabricObject
		            foreach ($containerObject in $containerObjects) {
			            $protectedItems = Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $containerObject
			            # DisableDR all protected items
			            foreach ($protectedItem in $protectedItems) {
				            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Triggering DisableDR(Purge) for item: $($protectedItem.Name)"
				            Remove-AzRecoveryServicesAsrReplicationProtectedItem -InputObject $protectedItem -Force
				            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] DisableDR (Purge) completed"
			            }

			            $containerMappings = Get-AzRecoveryServicesAsrProtectionContainerMapping -ProtectionContainer $containerObject
			            # Remove all Container Mappings
			            foreach ($containerMapping in $containerMappings) {
				            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Triggering Remove Container Mapping: $($containerMapping.Name)"
				            Remove-AzRecoveryServicesAsrProtectionContainerMapping -ProtectionContainerMapping $containerMapping -Force
				            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removed Container Mapping."
			            }
		            }
		            $NetworkObjects = Get-AzRecoveryServicesAsrNetwork -Fabric $fabricObject
		            foreach ($networkObject in $NetworkObjects)
		            {
			            #Get the PrimaryNetwork
			            $PrimaryNetwork = Get-AzRecoveryServicesAsrNetwork -Fabric $fabricObject -FriendlyName $networkObject
			            $NetworkMappings = Get-AzRecoveryServicesAsrNetworkMapping -Network $PrimaryNetwork
			            foreach ($networkMappingObject in $NetworkMappings)
			            {
				            #Get the Neetwork Mappings
				            $NetworkMapping = Get-AzRecoveryServicesAsrNetworkMapping -Name $networkMappingObject.Name -Network $PrimaryNetwork
				            Remove-AzRecoveryServicesAsrNetworkMapping -InputObject $NetworkMapping
			            }
		            }
		            # Remove Fabric
		            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Triggering Remove Fabric: $($fabricObject.FriendlyName)"
		            Remove-AzRecoveryServicesAsrFabric -InputObject $fabricObject -Force
		            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removed Fabric."
                }
            }
            Remove-AzRecoveryServicesVault -Vault $VaultToDelete
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    }
}

function Revoke-ActiveSASDiskAccess {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [string[]] $ResourceGroupName
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    if ([string]::IsNullOrEmpty($ResourceGroupName)) {
        $Disks = Get-AzDisk
    }
    else {
        $Disks = foreach ($CurrentResourceGroupName in $ResourceGroupName) {
            Get-AzDisk -ResourceGroupName $CurrentResourceGroupName -ErrorAction Ignore
        }
    }

    $ActiveSASDisk = $Disks | Where-Object -FilterScript { $_.DiskState -eq "ActiveSAS" }

    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }

    foreach ($CurrentActiveSASDisk in $ActiveSASDisk) {
        Write-Host -Object "Processing '$($CurrentActiveSASDisk.Name)' ..." 
        $URI = "https://management.azure.com/subscriptions/$SubcriptionID/resourceGroups/$($CurrentActiveSASDisk.ResourceGroupName)/providers/Microsoft.Compute/disks/$($CurrentActiveSASDisk.Name)/endGetAccess?api-version=2023-04-02"
        try {
            # Invoke the REST API
            $Response = Invoke-RestMethod -Method POST -Headers $authHeader -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
        }
        catch [System.Net.WebException] {   
            # Dig into the exception to get the Response details.
            # Note that value__ is not a typo.
            Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
            Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
            $respStream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($respStream)
            $Response = $reader.ReadToEnd() | ConvertFrom-Json
            if (-not([string]::IsNullOrEmpty($Response.message))) {
                Write-Warning -Message $Response.message
            }
        }
        finally {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        }
        return $Response
    }
}

function Remove-PsAvdHostPoolSetup {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'HostPool')]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [HostPool[]] $HostPool,
        [Parameter(Mandatory = $true, ParameterSetName = 'FullName')]
        [ValidateScript({ (Test-Path -Path $_ -PathType Leaf) -and ($_ -match "\.json$") })]
        [Alias('Path')]
        [string[]]$FullName
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    Write-Host -Object "HostPool Removal"
    $StartTime = Get-Date
    if ($FullName) {
        $HostPools = foreach ($CurrentFullName in $FullName) {
            $CurrentFullName = (Resolve-Path -Path $CurrentFullName).Path
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Using the '$CurrentFullName' JSON file"
            #Split Arrays to items 
            Get-Content -Path $CurrentFullName -Raw | ConvertFrom-Json | ForEach-Object -Process { $_ }
        }
        #Remove duplicated items (by name)
        $HostPools = $HostPools | Sort-Object -Property Name -Unique
    }
    else {
        $HostPools = $HostPool.GetPropertyForJSON()
    }
    $HostPools = $HostPools | Where-Object -FilterScript { $_.Name }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Cleaning up the '$($HostPools.Name -join ', ')' Host Pools"
    #region Cleanup of the previously existing resources


    #region Revoke-Active SAS Disk Access in the HostPool ResourceGroups
    Revoke-ActiveSASDiskAccess -ResourceGroupName $HostPools.ResourceGroupName
    #endregion

    #region Removing ASR Replication Protected Items
    Remove-PsAvdAzRecoveryServicesAsrReplicationProtectedItem -HostPool $HostPools
    #endregion

    #region DNS Cleanup
    $OUDistinguishedNames = (Get-ADOrganizationalUnit -Filter * | Where-Object -FilterScript { $_.Name -in $($HostPools.Name) }).DistinguishedName 
    if (-not([string]::IsNullOrEmpty($OUDistinguishedNames))) {
        $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        $OUDistinguishedNames | ForEach-Object -Process {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing OU: '$_'"
            (Get-ADComputer -Filter 'DNSHostName -like "*"' -SearchBase $_).Name } | ForEach-Object -Process { 
            try {
                if (-not([string]::IsNullOrEmpty($_))) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing DNS Record: '$_'"
                    #$DomainName = (Get-ADDomain).DNSRoot
                    Remove-DnsServerResourceRecord -ZoneName $DomainName -RRType "A" -Name "$_" -Force -ErrorAction Ignore
                }
            } 
            catch {
            } 
        }
    }
    #endregion

    #region AD OU/GPO Cleanup
    $OrganizationalUnits = Get-ADOrganizationalUnit -Filter * | Where-Object -FilterScript { $_.Name -in $($HostPools.Name) } 
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing OUs: $($OrganizationalUnits.Name -join ', ')"
    $OrganizationalUnits | Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -PassThru -ErrorAction Ignore | Remove-ADOrganizationalUnit -Recursive -Confirm:$false #-WhatIf
    $GPOs = Get-GPO -All | Where-Object -FilterScript { $_.DisplayName -match $($HostPools.Name -join "|") } 
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing GPOs: $($GPOs.DisplayName -join ', ')"
    $GPOs | Remove-GPO 
    #endregion

    #region Azure AD/Microsoft Entra ID cleanup
    $MicrosoftEntraIDHostPools = $HostPools | Where-Object -FilterScript { $_.IdentityProvider -eq [IdentityProvider]::MicrosoftEntraID }
    #Getting all session hosts starting with the Name Prefixes
    $RegExp = ($MicrosoftEntraIDHostPools.NamePrefix -replace '(^[^\n]*$)', '^$1-') -join '|'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RegExp : $RegExp"
    Get-MgBetaDevice -All | Where-Object -FilterScript { $_.DisplayName -match $RegExp } | ForEach-Object -Process { 
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing Microsoft Entra ID Device : $($_.DisplayName)"
        Remove-MgBetaDevice -DeviceId $_.Id 
    }
    #Removing the other Azure AD groups (created for Entra ID / Intune for instance)
    #Risky command :Get-AzADGroup | Where-Object -FilterScript { $_.DisplayName -match "^($($HostPools.Name -join '|'))" } | Remove-AzADGroup -WhatIf
    foreach ($CurrentHostPoolName in $HostPools.Name) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing Microsoft Entra ID Group : $CurrentHostPoolName"
        #Get-AzADGroup -DisplayNameStartsWith $CurrentHostPoolName | Remove-AzADGroup
        Get-MgBetaGroup -Filter "startsWith(DisplayName, '$CurrentHostPoolName')" | ForEach-Object -Process { Remove-MgBetaGroup -GroupId $_.Id  -Verbose }
    }
    #endregion

    #region Intune Cleanup
    #From https://therandomadmin.com/2024/03/04/get-intune-devices-with-powershell-2/
    $IntuneHostPools = $HostPools | Where-Object -FilterScript { $_.Intune }
    if ($IntuneHostPools) {
        Remove-PsAvdIntuneItemViaCmdlet -HostPool $IntuneHostPools
    }
    #endregion

    #region Azure Cleanup
    <#
    $HostPools = (Get-AzWvdHostPool | Where-Object -FilterScript {$_.Name -in $($HostPools.Name)})
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Getting HostPool(s): $($HostPools.Name -join, ', ')"
    $ResourceGroup = $HostPools | ForEach-Object { Get-AzResourceGroup $_.Id.split('/')[4]}
    #Alternative to get the Resource Group(s)
    #$ResourceGroup = Get-AzResourceGroup | Where-Object -FilterScript {($_.ResourceGroupName -match $($HostPools.Name -join "|"))
    #>
    $ResourceGroupName = $HostPools.ResourceGroupName + $HostPools.RecoveryLocationResourceGroupName | Where-Object -filterScript { $null -ne $_ } | Select-Object -Unique
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] ResourceGroup Name(s): $($ResourceGroupName -join, ', ')"
    $ResourceGroup = Get-AzResourceGroup | Where-Object -FilterScript { ($_.ResourceGroupName -in $ResourceGroupName) }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing Azure Delete Lock (if any) on Resource Group(s): $($ResourceGroup.ResourceGroupName -join, ', ')"
    $ResourceGroup | ForEach-Object -Process { Get-AzResourceLock -ResourceGroupName $_.ResourceGroupName -AtScope | Where-Object -FilterScript { $_.Properties.level -eq 'CanNotDelete' } } | Remove-AzResourceLock -Force -ErrorAction Ignore

    #region Windows Credential Manager Cleanup
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing Credentials from Windows Credential Manager"
    $StorageAccountName = ($ResourceGroup | Get-AzStorageAccount -ErrorAction Ignore).StorageAccountName
    $Pattern = $StorageAccountName -join "|"
    $StorageAccountCredentials = cmdkey /list | Select-String -Pattern "(?<Target>Target: (?<Domain>Domain:target=(?<FQDN>(?<Pattern>$Pattern)\.file\.core\.windows\.net)))" -AllMatches
    if ($StorageAccountCredentials.Matches) {
        $StorageAccountCredentials.Matches | ForEach-Object -Process { 
            $FQDN = $_.Groups['FQDN']
            $Domain = $_.Groups['Domain']
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$FQDN' credentials will be removed from the Windows Credential Manager"
            Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /delete:$Domain" -Wait -NoNewWindow
        }
    }
    #endregion

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing Resource Group(s) (As a Job): $($ResourceGroupName -join, ', ')"
    $Jobs = $ResourceGroup | Remove-AzResourceGroup -Force -AsJob
    $Jobs | Wait-Job | Out-Null
    $Jobs | Remove-Job

    <#
    #region Removing HostPool Session Credentials Key Vault
    $CredKeyVault = $HostPools.KeyVault | Select-Object -Unique
    $Jobs = $CredKeyVault.ResourceGroupName | ForEach-Object -Process { Remove-AzResourceGroup -Name $_ -Force -AsJob } 
    $Jobs | Wait-Job | Out-Null
    $Jobs | Remove-Job
    #endregion
    #>

    #region Removing Dedicated HostPool Key Vault in removed state
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing Dedicated HostPool Key Vault in removed state (As a Job)"
    if ($FullName) {
        $Jobs = Get-AzKeyVault -InRemovedState | Where-Object -FilterScript { ($_.VaultName -in $HostPool.KeyVaultName) } | Remove-AzKeyVault -InRemovedState -AsJob -Force 
    }
    else {
        $Jobs = Get-AzKeyVault -InRemovedState | Where-Object -FilterScript { ($_.VaultName -in $HostPool.GetKeyVaultName()) } | Remove-AzKeyVault -InRemovedState -AsJob -Force 
    }
    $Jobs | Wait-Job | Out-Null
    $Jobs | Remove-Job
    #endregion
    #endregion

    #region Azure Monitor Baseline Alerts for Azure Virtual Desktop Cleanup
    $Job = Get-AzMetricAlertRuleV2 | Where-Object -FilterScript { $_.Scopes -match $($HostPools.Name -join "|") } | Remove-AzMetricAlertRuleV2 -Verbose -AsJob
    Get-AzScheduledQueryRule | Where-Object -FilterScript { $_.CriterionAllOf.Query -match $($HostPools.Name -join "|") } | Remove-AzScheduledQueryRule -Verbose
    $Job | Receive-Job -Wait -AutoRemoveJob
    #endregion 
    #endregion

    #region Run a sync with Azure AD
    Start-MicrosoftEntraIDConnectSync
    #endregion
    $EndTime = Get-Date
    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host -Object "HostPool Removal Processing Time: $($TimeSpan.ToString())"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function New-PsAvdPersonalHostPoolSetup {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [object[]] $HostPool,

        [Parameter(Mandatory = $true)]
        [Alias('OU')]
        [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]$ADOrganizationalUnit,

        [Parameter(Mandatory = $false)]
        [string]$LogDir = ".",

        [switch] $AsJob
    )

    begin {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        $StartTime = Get-Date
        $AzContext = Get-AzContext

        #region Variables
        $SKUName = "Standard_LRS"

        #$DomainName = (Get-ADDomain).DNSRoot
        $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        #endregion 
    }
    process {
        Foreach ($CurrentHostPool in $HostPool) {
            Write-Host -Object "Starting '$($CurrentHostPool.Name)' Setup"
            $CurrentHostPoolStartTime = Get-Date
            $Status = @{ $true = "Enabled"; $false = "Disabled" }
            $Tag = @{LoadBalancerType = $CurrentHostPool.LoadBalancerType; VMSize = $CurrentHostPool.VMSize; KeyVault = $CurrentHostPool.KeyVault.VaultName; VMNumberOfInstances = $CurrentHostPool.VMNumberOfInstances; Location = $CurrentHostPool.Location; HostPoolName = $CurrentHostPool.Name; HostPoolType = $CurrentHostPool.Type; Intune = $Status[$CurrentHostPool.Intune]; CreationTime = [Datetime]::Now; CreatedBy = (Get-AzContext).Account.Id; EphemeralODisk = $CurrentHostPool.DiffDiskPlacement; ScalingPlan = $Status[$CurrentHostPool.ScalingPlan]; Hibernation = $Status[$CurrentHostPool.HibernationEnabled]; SpotInstance = $Status[$CurrentHostPool.Spot]; Watermarking = $Status[$CurrentHostPool.Watermarking]  }

            if ($CurrentHostPool.$PreferredAppGroupType) {
                $Tag['PreferredAppGroupType'] = $CurrentHostPool.$PreferredAppGroupType
            }
            if ($CurrentHostPool.VMSourceImageId) {
                $Tag['Image'] = 'Azure Compute Gallery'
                $Tag['VMSourceImageId'] = $CurrentHostPool.VMSourceImageId
            }
            else {
                $Tag['Image'] = 'Market Place'
                $Tag['ImagePublisherName'] = $CurrentHostPool.ImagePublisherName
                $Tag['ImageOffer'] = $CurrentHostPool.ImageOffer
                $Tag['ImageSku'] = $CurrentHostPool.ImageSku
            }
            if ($CurrentHostPool.ASRFailOverVNetId) {
                $Tag['ASRFailOverVNetId'] = $CurrentHostPool.ASRFailOverVNetId
            }

            #region Creating an <Azure Location> OU 
            $LocationOU = Get-ADOrganizationalUnit -Filter "Name -eq '$($CurrentHostPool.Location)'" -SearchBase $ADOrganizationalUnit.DistinguishedName
            if (-not($LocationOU)) {
                $LocationOU = New-ADOrganizationalUnit -Name $CurrentHostPool.Location -Path $ADOrganizationalUnit.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($LocationOU.DistinguishedName)' OU (under '$($ADOrganizationalUnit.DistinguishedName)')"
            }
            #endregion

            #region Creating an PersonalDesktops OU 
            $PersonalDesktopsOU = Get-ADOrganizationalUnit -Filter 'Name -eq "PersonalDesktops"' -SearchBase $LocationOU.DistinguishedName
            if (-not($PersonalDesktopsOU)) {
                $PersonalDesktopsOU = New-ADOrganizationalUnit -Name "PersonalDesktops" -Path $LocationOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($PersonalDesktopsOU.DistinguishedName)' OU (under '$($LocationOU.DistinguishedName)')"
            }
            #endregion

            #region General AD Management
            #region Host Pool Management: Dedicated AD OU Setup (1 OU per HostPool)
            $CurrentHostPoolOU = Get-ADOrganizationalUnit -Filter "Name -eq '$($CurrentHostPool.Name)'" -SearchBase $PersonalDesktopsOU.DistinguishedName
            if (-not($CurrentHostPoolOU)) {
                $CurrentHostPoolOU = New-ADOrganizationalUnit -Name "$($CurrentHostPool.Name)" -Path $PersonalDesktopsOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($CurrentHostPoolOU.DistinguishedName)' OU (under '$($PersonalDesktopsOU.DistinguishedName)')"
            }
            #endregion

            #region Host Pool Management: Dedicated AD users group
            $CurrentHostPoolDAGUsersAzADGroupName = "$($CurrentHostPool.Name) - Desktop Application Group Users"
            $CurrentHostPoolDAGUsersADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolDAGUsersAzADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
            if (-not($CurrentHostPoolDAGUsersADGroup)) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$CurrentHostPoolDAGUsersAzADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                $CurrentHostPoolDAGUsersADGroup = New-ADGroup -Name $CurrentHostPoolDAGUsersAzADGroupName -SamAccountName $CurrentHostPoolDAGUsersAzADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolDAGUsersAzADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
            }
            #endregion

            #region Run a sync with Azure AD
            Start-MicrosoftEntraIDConnectSync
            #endregion 
            #endregion

            #region Dedicated Resource Group Management (1 per HostPool)
            $CurrentHostPoolResourceGroupName = $CurrentHostPool.GetResourceGroupName()

            $CurrentHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -ErrorAction Ignore
            if (-not($CurrentHostPoolResourceGroup)) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$CurrentHostPoolResourceGroupName' Resource Group"
                $CurrentHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Force
            }
            #endregion

            #region Identity Provider Management
            if ($CurrentHostPool.IsActiveDirectoryJoined()) {
                <#
                $AdJoinUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name AdJoinUserName -AsPlainText
                $AdJoinPassword = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name AdJoinPassword).SecretValue
                $AdJoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($AdJoinUserName, $AdJoinPassword)
                #>
                $AdJoinCredential = Get-AdjoinCredential -KeyVault $CurrentHostPool.KeyVault

                Grant-PsAvdADJoinPermission -Credential $AdJoinCredential -OrganizationalUnit $CurrentHostPoolOU.DistinguishedName
                $Tag['IdentityProvider'] = "Active Directory Directory Services"
            }
            else {
                $Tag['IdentityProvider'] = "Microsoft Entra ID"
                #region Assign Virtual Machine Administrator Login' RBAC role to the Resource Group
                # Get the object ID of the user group you want to assign to the application group
                Do {
                    Start-MicrosoftEntraIDConnectSync
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                    Start-Sleep -Seconds 30
                    $AzADGroup = $null
                    #$AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolDAGUsersAzADGroupName
                    $AzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$CurrentHostPoolDAGUsersAzADGroupName'"
                } While (-not($AzADGroup.Id))

                # Assign users to the application group
                $parameters = @{
                    ObjectId           = $AzADGroup.Id
                    ResourceGroupName  = $CurrentHostPoolResourceGroupName
                    RoleDefinitionName = 'Virtual Machine Administrator Login'
                    #Verbose            = $true
                }

                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the 'Virtual Machine Administrator Login' RBAC role to '$CurrentHostPoolDAGUsersAzADGroupName' AD Group on the '$CurrentHostPoolResourceGroupName' Resource Group"
                $null = New-AzRoleAssignment @parameters
                #endregion 

            }
            #endregion 
            
            New-PsAvdHostPoolCredentialKeyVault -HostPool $CurrentHostPool
             
            #region Host Pool Setup
            $RegistrationInfoExpirationTime = (Get-Date).ToUniversalTime().AddDays(1)
            #Microsoft Entra ID
            if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
                # From https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files?context=%2Fazure%2Fvirtual-desktop%2Fcontext%2Fcontext#device-redirection
                # No RDP redirection for COM ports, Local Drives and printers.
                $CustomRdpProperty = "targetisaadjoined:i:1;redirectcomports:i:0;redirectlocation:i:0;redirectprinters:i:0;drivestoredirect:s:;usbdevicestoredirect:s:;enablerdsaadauth:i:1"
            }
            #Active Directory Directory Services
            else {
                # From https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files?context=%2Fazure%2Fvirtual-desktop%2Fcontext%2Fcontext#device-redirection
                # No RDP redirection for COM ports, Local Drives and printers.
                $CustomRdpProperty = "redirectcomports:i:0;redirectlocation:i:0;redirectprinters:i:0;drivestoredirect:s:;usbdevicestoredirect:s:"
            }
            $parameters = @{
                Name                          = $CurrentHostPool.Name
                ResourceGroupName             = $CurrentHostPoolResourceGroupName
                HostPoolType                  = 'Personal'
                PersonalDesktopAssignmentType = 'Automatic'
                LoadBalancerType              = $CurrentHostPool.LoadBalancerType
                PreferredAppGroupType         = "Desktop"
                Location                      = $CurrentHostPool.Location
                StartVMOnConnect              = $true
                ExpirationTime                = $RegistrationInfoExpirationTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
                CustomRdpProperty             = $CustomRdpProperty
                Tag                           = $Tag
                #Verbose                       = $true
            }

            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $CurrentAzWvdHostPool = New-AzWvdHostPool @parameters
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating Registration Token (Expiration: '$RegistrationInfoExpirationTime') for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $RegistrationInfoToken = New-AzWvdRegistrationInfo -ResourceGroupName $CurrentHostPoolResourceGroupName -HostPoolName $CurrentHostPool.Name -ExpirationTime $RegistrationInfoExpirationTime -ErrorAction SilentlyContinue


            #region Scale session hosts using Azure Automation
            #TODO : https://learn.microsoft.com/en-us/training/modules/automate-azure-virtual-desktop-management-tasks/1-introduction
            #endregion

            #region Set up Private Link with Azure Virtual Desktop
            #TODO: https://learn.microsoft.com/en-us/azure/virtual-desktop/private-link-setup?tabs=powershell%2Cportal-2#enable-the-feature
            #endregion


            #region Use Azure Firewall to protect Azure Virtual Desktop deployments
            #TODO: https://learn.microsoft.com/en-us/training/modules/protect-virtual-desktop-deployment-azure-firewall/
            #endregion
            #endregion

            #region Desktop Application Group Setup
            $parameters = @{
                Name                 = "{0}-DAG" -f $CurrentHostPool.Name
                #FriendlyName         = $CurrentHostPool.Name
                ResourceGroupName    = $CurrentHostPoolResourceGroupName
                Location             = $CurrentHostPool.Location
                HostPoolArmPath      = $CurrentAzWvdHostPool.Id
                ApplicationGroupType = 'Desktop'
                ShowInFeed           = $true
                #Verbose              = $true
            }

            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Desktop Application Group for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $CurrentAzDesktopApplicationGroup = New-AzWvdApplicationGroup @parameters

            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating the friendly name of the Desktop for the Desktop Application Group of the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) to '$($CurrentHostPool.Name)'"
            $parameters = @{
                ApplicationGroupName = $CurrentAzDesktopApplicationGroup.Name
                ResourceGroupName    = $CurrentHostPoolResourceGroupName
            }
            $null = Get-AzWvdDesktop @parameters | Update-AzWvdDesktop -FriendlyName $CurrentHostPool.Name

            #region Assign 'Desktop Virtualization User RBAC role to application groups
            # Get the object ID of the user group you want to assign to the application group
            Do {
                Start-MicrosoftEntraIDConnectSync
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                Start-Sleep -Seconds 30
                $AzADGroup = $null
                #$AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolDAGUsersAzADGroupName
                $AzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$CurrentHostPoolDAGUsersAzADGroupName'"
            } While (-not($AzADGroup.Id))

            # Assign users to the application group
            $parameters = @{
                ObjectId           = $AzADGroup.Id
                ResourceName       = $CurrentAzDesktopApplicationGroup.Name
                ResourceGroupName  = $CurrentHostPoolResourceGroupName
                RoleDefinitionName = 'Desktop Virtualization User'
                ResourceType       = 'Microsoft.DesktopVirtualization/applicationGroups'
                #Verbose            = $true
            }

            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the 'Desktop Virtualization User' RBAC role to '$CurrentHostPoolDAGUsersAzADGroupName' AD Group on the Desktop Application Group (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $null = New-AzRoleAssignment @parameters
            #endregion 

            #endregion

            #region Workspace Setup
            $Options = $CurrentHostPool.Location, $CurrentHostPool.Type, $CurrentHostPool.IdentityProvider
            if ($CurrentHostPool.ScalingPlan) {
                $Options += 'ScalingPlan'
            }
            if ($CurrentHostPool.VMSourceImageId) {
                $Options += 'Azure Compte Gallery'
            }
            else {
                $Options += 'Market Place'
            }
            if ($CurrentHostPool.Intune) {
                $Options += 'Intune'
            }
            if ($CurrentHostPool.Spot) {
                $Options += 'Spot'
            }
            if ($CurrentHostPool.HibernationEnabled) {
                $Options += 'Hibernation'
            }
            if ($CurrentHostPool.DiffDiskPlacement -eq [DiffDiskPlacement]::CacheDisk) {
                $Options += 'Ephemeral OS Disk: CacheDisk'
            }
            elseif ($CurrentHostPool.DiffDiskPlacement -eq [DiffDiskPlacement]::ResourceDisk) {
                $Options += 'Ephemeral OS Disk: ResourceDisk'
            } 
            if ($CurrentHostPool.ASRFailOverVNetId) {
                $Options += 'Azure Site Recovery'
            }
            if ($CurrentHostPool.Watermarking) {
                $Options += 'Watermarking'
            }

            $FriendlyName = "{0} ({1})" -f $CurrentHostPool.GetAzAvdWorkSpaceName(), $($Options -join ', ')
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FriendlyName: $FriendlyName"

            $ApplicationGroupReference = $CurrentAzDesktopApplicationGroup.Id
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ApplicationGroupReference: $($ApplicationGroupReference -join ', ')"

            $parameters = @{
                Name                      = $CurrentHostPool.GetAzAvdWorkSpaceName()
                FriendlyName              = $FriendlyName
                ResourceGroupName         = $CurrentHostPoolResourceGroupName
                ApplicationGroupReference = $ApplicationGroupReference
                Location                  = $CurrentHostPool.Location
                #Verbose                   = $true
            }

            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the WorkSpace for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $CurrentAzWvdWorkspace = New-AzWvdWorkspace @parameters
            #endregion

            if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
                #region Creating a dynamic device group for our AVD hosts
                $DisplayName = "{0} - Devices" -f $CurrentHostPool.Name
                $Description = "Dynamic device group for our AVD hosts for the {0} HostPool." -f $CurrentHostPool.Name
                $MailNickname = $($DisplayName -replace "\s").ToLower()
                $MembershipRule = "(device.displayName -startsWith ""$($CurrentHostPool.NamePrefix)-"")"
                #$AzADDeviceDynamicGroup = New-AzADGroup -DisplayName $DisplayName -Description $Description -MembershipRule $MembershipRule -MembershipRuleProcessingState "On" -GroupType "DynamicMembership" -MailNickname $MailNickname -SecurityEnabled
                $AzADDeviceDynamicGroup = New-MgBetaGroup -DisplayName $DisplayName -Description $Description -MembershipRule $MembershipRule -MembershipRuleProcessingState "On" -GroupTypes "DynamicMembership" -MailEnabled:$False -MailNickname $MailNickname -SecurityEnabled
                #endregion
            }

            #region Adding Session Hosts to the Host Pool
            $NextSessionHostNames = Get-PsAvdNextSessionHostName -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentHostPool.NamePrefix -VMNumberOfInstances $CurrentHostPool.VMNumberOfInstances
            if (-not([String]::IsNullOrEmpty($CurrentHostPool.VMSourceImageId))) {
                #We propagate the AsJob context to the child function
                Add-PsAvdSessionHost -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentHostPool.NamePrefix -VMNumberOfInstances $CurrentHostPool.VMNumberOfInstances -KeyVault $CurrentHostPool.KeyVault -RegistrationInfoToken $RegistrationInfoToken.Token -SubnetId $CurrentHostPool.SubnetId -DomainName $DomainName -OUPath $CurrentHostPoolOU.DistinguishedName -VMSize $CurrentHostPool.VMSize -VMSourceImageId $CurrentHostPool.VMSourceImageId -DiffDiskPlacement $CurrentHostPool.DiffDiskPlacement -Tag $Tag -IsMicrosoftEntraIdJoined:$CurrentHostPool.IsMicrosoftEntraIdJoined() -Spot:$CurrentHostPool.Spot -HibernationEnabled:$CurrentHostPool.HibernationEnabled -Intune:$CurrentHostPool.Intune -LogDir $LogDir -AsJob #:$AsJob
            }
            else {
                #We propagate the AsJob context to the child function
                Add-PsAvdSessionHost -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentHostPool.NamePrefix -VMNumberOfInstances $CurrentHostPool.VMNumberOfInstances -KeyVault $CurrentHostPool.KeyVault -RegistrationInfoToken $RegistrationInfoToken.Token -SubnetId $CurrentHostPool.SubnetId -DomainName $DomainName -OUPath $CurrentHostPoolOU.DistinguishedName -VMSize $CurrentHostPool.VMSize -DiffDiskPlacement $CurrentHostPool.DiffDiskPlacement -ImagePublisherName $CurrentHostPool.ImagePublisherName -ImageOffer $CurrentHostPool.ImageOffer -ImageSku $CurrentHostPool.ImageSku -Tag $Tag -IsMicrosoftEntraIdJoined:$CurrentHostPool.IsMicrosoftEntraIdJoined() -Spot:$CurrentHostPool.Spot -HibernationEnabled:$CurrentHostPool.HibernationEnabled -Intune:$CurrentHostPool.Intune -LogDir $LogDir -AsJob #:$AsJob
            }

            #region Pester Tests for Azure Host Pool Session Host - Azure Instantiation
            $ModuleBase = Get-ModuleBase
            $PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
            #$PesterDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'Pester'
            $HostPoolSessionHostAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'HostPool.SessionHost.Azure.Tests.ps1'
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$HostPoolSessionHostAzurePesterTests: $HostPoolSessionHostAzurePesterTests"
            $Container = New-PesterContainer -Path $HostPoolSessionHostAzurePesterTests -Data @{ HostPool = $CurrentHostPool; SessionHostName = $NextSessionHostNames }
            Invoke-Pester -Container $Container -Output Detailed -Verbose
            #endregion

            $SessionHosts = Get-AzWvdSessionHost -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            $SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
            #endregion 

            #region Restarting the Session Hosts
            $Jobs = foreach ($CurrentSessionHostName in $SessionHostNames) {
                Restart-AzVM -Name $CurrentSessionHostName -ResourceGroupName $CurrentHostPoolResourceGroupName -Confirm:$false -AsJob
            }
            $Jobs | Wait-Job | Out-Null
            $Jobs | Remove-Job -Force
            #endregion 

            #region Run a sync with Azure AD
            Start-MicrosoftEntraIDConnectSync
            #endregion 

            #region Log Analytics WorkSpace Setup : Monitor and manage performance and health
            #From https://learn.microsoft.com/en-us/training/modules/monitor-manage-performance-health/3-log-analytics-workspace-for-azure-monitor
            #From https://www.rozemuller.com/deploy-azure-monitor-for-windows-virtual-desktop-automated/#update-25-03-2021
            $LogAnalyticsWorkSpaceName = $CurrentHostPool.GetLogAnalyticsWorkSpaceName()
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Log Analytics WorkSpace '$($LogAnalyticsWorkSpaceName)' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $LogAnalyticsWorkSpace = New-AzOperationalInsightsWorkspace -Location $CurrentHostPool.Location -Name $LogAnalyticsWorkSpaceName -Sku pergb2018 -ResourceGroupName $CurrentHostPoolResourceGroupName -Force
            Do {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 10 seconds"
                Start-Sleep -Seconds 10
                $LogAnalyticsWorkSpace = $null
                $LogAnalyticsWorkSpace = Get-AzOperationalInsightsWorkspace -Name $LogAnalyticsWorkSpaceName -ResourceGroupName $CurrentHostPoolResourceGroupName
            } While ($null -eq $LogAnalyticsWorkSpace)
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
            Start-Sleep -Seconds 30

            #region Enabling Diagnostics Setting for the HostPool
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Enabling Diagnostics Setting for the '$($CurrentAzWvdHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            <#
            $Categories = "Checkpoint", "Error", "Management", "Connection", "HostRegistration", "AgentHealthStatus", "NetworkData", "AutoscaleEvaluationPooled"
            $Log = $Categories | ForEach-Object {
                New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category $_ 
            }
            #>
            $Log = New-AzDiagnosticSettingLogSettingsObject -Enabled $true -CategoryGroup allLogs 
            $HostPoolDiagnosticSetting = New-AzDiagnosticSetting -Name $CurrentAzWvdHostPool.Name -ResourceId $CurrentAzWvdHostPool.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Log $Log
            #endregion

            #region Enabling Diagnostics Setting for the WorkSpace
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Enabling Diagnostics Setting for the '$($CurrentAzWvdWorkspace.Name)' Work Space"
            <#
            $Categories = "Checkpoint", "Error", "Management", "Feed"
            $Log = $Categories | ForEach-Object {
                New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category $_ 
            }
            #>
            $Log = New-AzDiagnosticSettingLogSettingsObject -Enabled $true -CategoryGroup allLogs 
            $WorkSpaceDiagnosticSetting = New-AzDiagnosticSetting -Name $CurrentAzWvdWorkspace.Name -ResourceId $CurrentAzWvdWorkspace.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Log $Log
            #endregion

            #region Enabling Diagnostics Setting for the Desktop Application Group
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Enabling Diagnostics Setting for the '$($CurrentAzDesktopApplicationGroup.Name)' Work Space"
            <#
            $Categories = "Checkpoint", "Error", "Management"
            $Log = $Categories | ForEach-Object {
                New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category $_ 
            }
            #>
            $Log = New-AzDiagnosticSettingLogSettingsObject -Enabled $true -CategoryGroup allLogs 
            $DesktopApplicationGroupDiagnosticSetting = New-AzDiagnosticSetting -Name $CurrentAzDesktopApplicationGroup.Name -ResourceId $CurrentAzDesktopApplicationGroup.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Log $Log
            #endregion

            #endregion

            #region Installing Azure Monitor Windows Agent on Virtual Machine(s)
            #$SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            if (-not([string]::IsNullOrEmpty($SessionHosts.ResourceId))) {
                $SessionHostVMs = $SessionHosts.ResourceId | Get-AzVM
                $Jobs = foreach ($CurrentSessionHostVM in $SessionHostVMs) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Installing AzureMonitorWindowsAgent on the '$($CurrentSessionHostVM.Name)' Virtual Machine (in the '$CurrentHostPoolResourceGroupName' Resource Group) (As A Job)"
                    $ExtensionName = "AzureMonitorWindowsAgent_{0:yyyyMMddHHmmss}" -f (Get-Date)
                    $Params = @{
                        Name                   = $ExtensionName 
                        ExtensionType          = 'AzureMonitorWindowsAgent'
                        Publisher              = 'Microsoft.Azure.Monitor' 
                        VMName                 = $CurrentSessionHostVM.Name
                        ResourceGroupName      = $CurrentHostPoolResourceGroupName
                        Location               = $CurrentHostPool.Location
                        TypeHandlerVersion     = '1.0' 
                        EnableAutomaticUpgrade = $true
                        AsJob                  = $true
                    }
                    Set-AzVMExtension  @Params
                }
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting all jobs completes"
                $Jobs | Wait-Job | Out-Null
                $Jobs | Remove-Job -Force
            }
            #endregion

            <#
            #region Installing Log Analytics Agent on Virtual Machine(s)
            #$SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            if (-not([string]::IsNullOrEmpty($SessionHosts.ResourceId))) {
                $SessionHostVMs = $SessionHosts.ResourceId | Get-AzVM
                $LogAnalyticsWorkSpaceKey = ($LogAnalyticsWorkSpace | Get-AzOperationalInsightsWorkspaceSharedKey).PrimarySharedKey
                $PublicSettings = @{ "workspaceId" = $LogAnalyticsWorkSpace.CustomerId }
                $ProtectedSettings = @{ "workspaceKey" = $LogAnalyticsWorkSpaceKey }
                $Jobs = foreach ($CurrentSessionHostVM in $SessionHostVMs) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Installing Log Analytics Agent on the '$($CurrentSessionHostVM.Name)' Virtual Machine (in the '$CurrentHostPoolResourceGroupName' Resource Group) (As A Job)"
                    Set-AzVMExtension -ExtensionName "MicrosoftMonitoringAgent" -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostVM.Name -Publisher "Microsoft.EnterpriseCloud.Monitoring" -ExtensionType "MicrosoftMonitoringAgent" -Settings $PublicSettings -TypeHandlerVersion "1.0" -ProtectedSettings $ProtectedSettings -Location $CurrentHostPool.Location -AsJob
                }
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting all jobs completes"
                $Jobs | Wait-Job | Out-Null
                $Jobs | Remove-Job -Force
            }
            #endregion
            #>
            #region Data Collection Rules
            #region Event Logs
            #From https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.tracing.eventlevel?view=net-8.0
            #Levels : 1 = Critical, 2 = Error, 3 = Warning
            $EventLogs = @(
                [PSCustomObject] @{EventLogName = 'Application'; Levels = 1, 2, 3 }
                [PSCustomObject] @{EventLogName = 'System'; Levels = 1, 2, 3 }
                [PSCustomObject] @{EventLogName = 'Security'; Keywords = "4503599627370496" }
                [PSCustomObject] @{EventLogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Levels = 1, 2, 3 }
                [PSCustomObject] @{EventLogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin'; Levels = 1, 2, 3 }
                [PSCustomObject] @{EventLogName = 'Microsoft-FSLogix-Apps/Operational' ; Levels = 1, 2, 3 }
                [PSCustomObject] @{EventLogName = 'Microsoft-FSLogix-Apps/Admin' ; Levels = 1, 2, 3 }
            )
            #Building the XPath for each event log
            $XPathQuery = foreach ($CurrentEventLog in $EventLogs) {
                #Building the required level for each event log
                $Levels = foreach ($CurrentLevel in $CurrentEventLog.Levels) {
                    "Level={0}" -f $CurrentLevel
                }
                if ($CurrentEventLog.EventLogName -eq 'Security') {
                    "{0}!*[System[(band(Keywords,{1}))]]" -f $CurrentEventLog.EventLogName, $CurrentEventLog.Keywords 
                }
                else {
                    "{0}!*[System[($($Levels -join ' or '))]]" -f $CurrentEventLog.EventLogName
                }
            }
            $WindowsEventLogs = New-AzWindowsEventLogDataSourceObject -Name WindowsEventLogsDataSource -Stream Microsoft-Event -XPathQuery $XPathQuery
            #endregion

            #region Performance Counters
            $PerformanceCounters = @(
                [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = '% Free Space'; InstanceName = 'C:'; IntervalSeconds = 60 }
                [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk Queue Length'; InstanceName = 'C:'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk sec/Transfer'; InstanceName = 'C:'; IntervalSeconds = 60 }
                [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Current Disk Queue Length'; InstanceName = 'C:'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'Memory'; CounterName = 'Available Mbytes'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'Memory'; CounterName = 'Page Faults/sec'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'Memory'; CounterName = 'Pages/sec'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'Memory'; CounterName = '% Committed Bytes In Use'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Read'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Transfer'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Write'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk Queue Length'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'Processor Information'; CounterName = '% Processor Time'; InstanceName = '_Total'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'RemoteFX Network'; CounterName = 'Current TCP RTT'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'RemoteFX Network'; CounterName = 'Current UDP Bandwidth'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'Terminal Services'; CounterName = 'Active Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
                [PSCustomObject] @{ObjectName = 'Terminal Services'; CounterName = 'Inactive Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
                [PSCustomObject] @{ObjectName = 'Terminal Services'; CounterName = 'Total Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
                [PSCustomObject] @{ObjectName = 'User Input Delay per Process'; CounterName = 'Max Input Delay'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'User Input Delay per Session'; CounterName = 'Max Input Delay'; InstanceName = '*'; IntervalSeconds = 30 }
            )
            #Building and Hashtable for each Performance Counters where the key is the sample interval
            $PerformanceCountersHT = $PerformanceCounters | Group-Object -Property IntervalSeconds -AsHashTable -AsString

            $PerformanceCounters = foreach ($CurrentKey in $PerformanceCountersHT.Keys) {
                $Name = "PerformanceCounters{0}" -f $CurrentKey
                #Building the Performance Counter paths for each Performance Counter
                $CounterSpecifier = foreach ($CurrentCounter in $PerformanceCountersHT[$CurrentKey]) {
                    "\{0}({1})\{2}" -f $CurrentCounter.ObjectName, $CurrentCounter.InstanceName, $CurrentCounter.CounterName
                }
                New-AzPerfCounterDataSourceObject -Name $Name -Stream Microsoft-Perf -CounterSpecifier $CounterSpecifier -SamplingFrequencyInSecond $CurrentKey
            }
            #endregion
            <#
            $DataCollectionEndpointName = "dce-{0}" -f $LogAnalyticsWorkSpace.Name
            $DataCollectionEndpoint = New-AzDataCollectionEndpoint -Name $DataCollectionEndpointName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -NetworkAclsPublicNetworkAccess Enabled
            #>
            #From https://www.reddit.com/r/AZURE/comments/1ddac0z/avd_insights_dcr_does_not_appear/?tl=fr
            $DataCollectionRuleName = "microsoft-avdi-{0}" -f $LogAnalyticsWorkSpace.Location
            $DataFlow = New-AzDataFlowObject -Stream Microsoft-InsightsMetrics, Microsoft-Perf, Microsoft-Event -Destination $LogAnalyticsWorkSpace.Name
            $DestinationLogAnalytic = New-AzLogAnalyticsDestinationObject -Name $LogAnalyticsWorkSpace.Name -WorkspaceResourceId $LogAnalyticsWorkSpace.ResourceId
            $DataCollectionRule = New-AzDataCollectionRule -Name $DataCollectionRuleName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -DataFlow $DataFlow -DataSourcePerformanceCounter $PerformanceCounters -DataSourceWindowsEventLog $WindowsEventLogs -DestinationLogAnalytic $DestinationLogAnalytic #-DataCollectionEndpointId $DataCollectionEndpoint.Id
            #endregion

            #region Adding Data Collection Rule Association for every Session Host
            #$DataCollectionRule = Get-AzDataCollectionRule -ResourceGroupName $CurrentHostPoolResourceGroupName -RuleName $DataCollectionRuleName
            $DataCollectionRuleAssociations = foreach ($CurrentSessionHost in $SessionHosts) {
                <#
                $AssociationName = 'configurationAccessEndpoint'
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Associating the '$($DataCollectionEndpoint.Name)' Data Collection Endpoint with the '$($CurrentSessionHost.Name)' Session Host "
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AssociationName: $AssociationName"
                New-AzDataCollectionRuleAssociation -ResourceUri $CurrentSessionHost.ResourceId -AssociationName $AssociationName #-DataCollectionEndpointId $DataCollectionEndpoint.Id
                #>
                #$AssociationName = "dcr-{0}" -f $($CurrentSessionHost.ResourceId -replace ".*/").ToLower()
                $AssociationName = "{0}-VMInsights-Dcr-Association" -f $($CurrentSessionHost.ResourceId -replace ".*/").ToLower()
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Associating the '$($DataCollectionRule.Name)' Data Collection Rule with the '$($CurrentSessionHost.Name)' Session Host "
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AssociationName: $AssociationName"
                New-AzDataCollectionRuleAssociation -ResourceUri $CurrentSessionHost.ResourceId -AssociationName $AssociationName -DataCollectionRuleId $DataCollectionRule.Id
            }
            #endregion

            #region Enable VM insights on Virtual Machine(s)
            #From https://learn.microsoft.com/en-us/azure/azure-monitor/vm/vminsights-enable?tabs=powershell#enable-vm-insights-1
            if (-not(Get-InstalledScript -Name Install-VMInsights)) {
                Install-Script -Name Install-VMInsights -Force
            }
            else {
                Update-Script -Name Install-VMInsights -Force
            }
            $UserAssignedManagedIdentityName = "uami-{0}" -f $CurrentHostPool.Name
            $UserAssignedManagedIdentity = Get-AzUserAssignedIdentity -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $UserAssignedManagedIdentityName -ErrorAction Ignore
            if (-not($UserAssignedManagedIdentity)) {
                $UserAssignedManagedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $UserAssignedManagedIdentityName -Location $CurrentHostPool.Location
            }

            #region Data Collection Rule for VM Insights
            $DataCollectionRuleName = "MSVMI-{0}" -f $LogAnalyticsWorkspaceName
            $DataFlow = New-AzDataFlowObject -Stream Microsoft-InsightsMetrics -Destination $LogAnalyticsWorkspaceName
            $PerformanceCounter = New-AzPerfCounterDataSourceObject -CounterSpecifier "\VmInsights\DetailedMetrics" -Name VMInsightsPerfCounters -SamplingFrequencyInSecond 60 -Stream Microsoft-InsightsMetrics
            #$DestinationLogAnalytic = New-AzLogAnalyticsDestinationObject -Name $LogAnalyticsWorkSpace.Name -WorkspaceResourceId $LogAnalyticsWorkSpace.ResourceId
            $DataCollectionRule = New-AzDataCollectionRule -Name $DataCollectionRuleName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -DataFlow $DataFlow -DataSourcePerformanceCounter $PerformanceCounter -DestinationLogAnalytic $DestinationLogAnalytic
            #endregion

            #$SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            if (-not([string]::IsNullOrEmpty($SessionHosts.ResourceId))) {
                $SessionHostVMs = $SessionHosts.ResourceId | Get-AzVM
                foreach ($CurrentSessionHostVM in $SessionHostVMs) {
                    $Parameters = @{
                        SubscriptionId                           = (Get-AzContext).Subscription.Id
                        ResourceGroup                            = $CurrentHostPoolResourceGroupName
                        Name                                     = $CurrentSessionHostVM.Name
                        DcrResourceId                            = $DataCollectionRule.Id
                        UserAssignedManagedIdentityName          = $UserAssignedManagedIdentity.Name
                        UserAssignedManagedIdentityResourceGroup = $UserAssignedManagedIdentity.ResourceGroupName
                        Approve                                  = $true
                    }
                    Install-VMInsights.ps1 @Parameters
                }
            }
            #endregion 

            $CurrentHostPoolEndTime = Get-Date
            $TimeSpan = New-TimeSpan -Start $CurrentHostPoolStartTime -End $CurrentHostPoolEndTime
            Write-Host -Object "'$($CurrentHostPool.Name)' Setup Processing Time: $($TimeSpan.ToString())"
        }    
    }
    end {
        $EndTime = Get-Date
        $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
        Write-Host -Object "Overall Personal HostPool Setup Processing Time: $($TimeSpan.ToString())"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    }
}

function New-PsAvdPooledHostPoolSetup {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [object[]] $HostPool,

        [Parameter(Mandatory = $true)]
        [Alias('OU')]
        [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]$ADOrganizationalUnit,

        [Parameter(Mandatory = $false)]
        $NoMFAEntraIDGroupName = "No-MFA Users",

        [Parameter(Mandatory = $false)]
        [string]$LogDir = ".",

        [switch] $AsJob
    )

    begin {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        $StartTime = Get-Date
        $AzContext = Get-AzContext
        $StorageEndpointSuffix = $AzContext | Select-Object -ExpandProperty Environment | Select-Object -ExpandProperty StorageEndpointSuffix

        #region Variables
        $FSLogixContributor = "FSLogix Contributor"
        $FSLogixElevatedContributor = "FSLogix Elevated Contributor"
        $FSLogixReader = "FSLogix Reader"
        $FSLogixShareName = "profiles", "odfc" 

        $MSIXHosts = "MSIX Hosts"
        $MSIXShareAdmins = "MSIX Share Admins"
        $MSIXUsers = "MSIX Users"
        $MSIXShareName = "msix"  

        $SKUName = "Standard_LRS"

        #From https://www.youtube.com/watch?v=lvBiLj7oAG4&t=2s
        $RedirectionsXMLFileContent = @'
<?xml version="1.0"  encoding="UTF-8"?>
<FrxProfileFolderRedirection ExcludeCommonFolders="49">
<Excludes>
<Exclude Copy="0">AppData\Roaming\Microsoft\Teams\media-stack</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\Teams\meeting-addin\Cache</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\Outlook</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\OneDrive</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\Edge</Exclude>
</Excludes>
<Includes>
<Include>AppData\Local\Microsoft\Edge\User Data</Include>
</Includes>
</FrxProfileFolderRedirection>
'@

        #region Getting this Azure VM and the related Virtual Network
        $ThisDomainController = Get-AzVMCompute | Get-AzVM
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ThisDomainController: $($ThisDomainController | Select-Object -Property * | Out-String)"
        $ThisDomainControllerVirtualNetwork = Get-AzVMVirtualNetwork -VM $ThisDomainController
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ThisDomainControllerVirtualNetwork: $($ThisDomainControllerVirtualNetwork | Select-Object -Property * | Out-String)"
        $ThisDomainControllerSubnet = Get-AzVMSubnet
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ThisDomainControllerSubnet: $($ThisDomainControllerSubnet | Select-Object -Property * | Out-String)"
        #endregion

        #$DomainName = (Get-ADDomain).DNSRoot
        try {
            $DomainInformation = Get-ADDomain -ErrorAction Stop
            $DomainGuid = $DomainInformation.ObjectGUID.ToString()
            $DomainName = $DomainInformation.DnsRoot
        }
        catch {
            # Load the necessary .NET namespace
            Add-Type -AssemblyName System.DirectoryServices
            $DomainContext = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $DomainGuid = [Guid]::new(($DomainContext.GetDirectoryEntry().Properties["objectGuid"][0])).Guid
            $DomainName = $DomainContext.Name
        }
        #endregion 

    }
    process {
        Foreach ($CurrentHostPool in $HostPool) {
            Write-Host -Object "Starting '$($CurrentHostPool.Name)' Setup"
            $CurrentHostPoolStartTime = Get-Date
            #Microsoft Entra ID
            <#
            if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
                Write-Error "A Pooled HostPool must be an ADDS-joined Azure VM in this script. This is not the case for '$($CurrentHostPool.Name)'. We Skip it !!!"
                continue
            }
            else {
            }
            #>
            
            #Creating a Private EndPoint for this KeyVault on this Subnet
            #New-PsAvdPrivateEndpointSetup -SubnetId $CurrentHostPool.SubnetId -KeyVault $CurrentHostPool.KeyVault
             
            $Status = @{ $true = "Enabled"; $false = "Disabled" }
            $Tag = @{LoadBalancerType = $CurrentHostPool.LoadBalancerType; VMSize = $CurrentHostPool.VMSize; KeyVault = $CurrentHostPool.KeyVault.VaultName; VMNumberOfInstances = $CurrentHostPool.VMNumberOfInstances; Location = $CurrentHostPool.Location; MSIX = $Status[$CurrentHostPool.MSIX]; AppAttach = $Status[$CurrentHostPool.AppAttach]; FSLogix = $Status[$CurrentHostPool.FSLogix]; FSLogixCloudCache = $Status[$CurrentHostPool.FSLogixCloudCache]; Intune = $Status[$CurrentHostPool.Intune]; HostPoolName = $CurrentHostPool.Name; HostPoolType = $CurrentHostPool.Type; CreationTime = [Datetime]::Now; CreatedBy = (Get-AzContext).Account.Id; EphemeralODisk = $CurrentHostPool.DiffDiskPlacement; ScalingPlan = $Status[$CurrentHostPool.ScalingPlan]; SpotInstance = $Status[$CurrentHostPool.Spot]; Watermarking = $Status[$CurrentHostPool.Watermarking] }
            if ($CurrentHostPool.$PreferredAppGroupType) {
                $Tag['PreferredAppGroupType'] = $CurrentHostPool.$PreferredAppGroupType
            }
            if ($CurrentHostPool.VMSourceImageId) {
                $Tag['Image'] = 'Azure Compute Gallery'
                $Tag['VMSourceImageId'] = $CurrentHostPool.VMSourceImageId
            }
            else {
                $Tag['Image'] = 'Market Place'
                $Tag['ImagePublisherName'] = $CurrentHostPool.ImagePublisherName
                $Tag['ImageOffer'] = $CurrentHostPool.ImageOffer
                $Tag['ImageSku'] = $CurrentHostPool.ImageSku
            }
            if ($CurrentHostPool.ASRFailOverVNetId) {
                $Tag['ASRFailOverVNetId'] = $CurrentHostPool.ASRFailOverVNetId
            }

            #region Creating an <Azure Location> OU 
            $LocationOU = Get-ADOrganizationalUnit -Filter "Name -eq '$($CurrentHostPool.Location)'" -SearchBase $ADOrganizationalUnit.DistinguishedName
            if (-not($LocationOU)) {
                $LocationOU = New-ADOrganizationalUnit -Name $CurrentHostPool.Location -Path $ADOrganizationalUnit.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($LocationOU.DistinguishedName)' OU (under '$($ADOrganizationalUnit.DistinguishedName)')"
            }
            #endregion

            #region Creating a PooledDesktops OU 
            $PooledDesktopsOU = Get-ADOrganizationalUnit -Filter 'Name -eq "PooledDesktops"' -SearchBase $LocationOU.DistinguishedName
            if (-not($PooledDesktopsOU)) {
                $PooledDesktopsOU = New-ADOrganizationalUnit -Name "PooledDesktops" -Path $LocationOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($PooledDesktopsOU.DistinguishedName)' OU (under '$($LocationOU.DistinguishedName)')"
            }
            #endregion

            #region General AD Management
            #region Host Pool Management: Dedicated AD OU Setup (1 OU per HostPool)
            $CurrentHostPoolOU = Get-ADOrganizationalUnit -Filter "Name -eq '$($CurrentHostPool.Name)'" -SearchBase $PooledDesktopsOU.DistinguishedName
            if (-not($CurrentHostPoolOU)) {
                $CurrentHostPoolOU = New-ADOrganizationalUnit -Name "$($CurrentHostPool.Name)" -Path $PooledDesktopsOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($CurrentHostPoolOU.DistinguishedName)' OU (under '$($PooledDesktopsOU.DistinguishedName)')"
            }
            #endregion

            #region Host Pool Management: Dedicated AD users group
            $CurrentHostPoolDAGUsersAzADGroupName = "$($CurrentHostPool.Name) - Desktop Application Group Users"
            $CurrentHostPoolDAGUsersADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolDAGUsersAzADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
            if (-not($CurrentHostPoolDAGUsersADGroup)) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$CurrentHostPoolDAGUsersAzADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                $CurrentHostPoolDAGUsersADGroup = New-ADGroup -Name $CurrentHostPoolDAGUsersAzADGroupName -SamAccountName $CurrentHostPoolDAGUsersAzADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolDAGUsersAzADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
            }

            $CurrentHostPoolRAGUsersADGroupName = "$($CurrentHostPool.Name) - Remote Application Group Users"
            $CurrentHostPoolRAGUsersADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolRAGUsersADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
            if (-not($CurrentHostPoolRAGUsersADGroup)) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$CurrentHostPoolRAGUsersADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                $CurrentHostPoolRAGUsersADGroup = New-ADGroup -Name $CurrentHostPoolRAGUsersADGroupName -SamAccountName $CurrentHostPoolRAGUsersADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolRAGUsersADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
            }
            #endregion
            #region Run a sync with Azure AD
            Start-MicrosoftEntraIDConnectSync
            #endregion 
            #endregion

            #region FSLogix
            #From https://learn.microsoft.com/en-us/fslogix/reference-configuration-settings?tabs=profiles
            if ($CurrentHostPool.FSLogix) {
                #region FSLogix AD Management
                #region Dedicated HostPool AD group
                #region Dedicated HostPool AD FSLogix groups
                $CurrentHostPoolFSLogixContributorADGroupName = "$($CurrentHostPool.Name) - $FSLogixContributor"
                $CurrentHostPoolFSLogixContributorADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolFSLogixContributorADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolFSLogixContributorADGroup)) {
                    $CurrentHostPoolFSLogixContributorADGroup = New-ADGroup -Name $CurrentHostPoolFSLogixContributorADGroupName -SamAccountName $CurrentHostPoolFSLogixContributorADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolFSLogixContributorADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($CurrentHostPoolFSLogixContributorADGroup.Name)' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                }
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding the '$CurrentHostPoolDAGUsersAzADGroupName' AD group to the '$CurrentHostPoolFSLogixContributorADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                $CurrentHostPoolFSLogixContributorADGroup | Add-ADGroupMember -Members $CurrentHostPoolDAGUsersAzADGroupName

                $CurrentHostPoolFSLogixElevatedContributorADGroupName = "$($CurrentHostPool.Name) - $FSLogixElevatedContributor"
                $CurrentHostPoolFSLogixElevatedContributorADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolFSLogixElevatedContributorADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolFSLogixElevatedContributorADGroup)) {
                    $CurrentHostPoolFSLogixElevatedContributorADGroup = New-ADGroup -Name $CurrentHostPoolFSLogixElevatedContributorADGroupName -SamAccountName $CurrentHostPoolFSLogixElevatedContributorADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolFSLogixElevatedContributorADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($CurrentHostPoolFSLogixElevatedContributorADGroup.Name)' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                }

                $CurrentHostPoolFSLogixReaderADGroupName = "$($CurrentHostPool.Name) - $FSLogixReader"
                $CurrentHostPoolFSLogixReaderADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolFSLogixReaderADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolFSLogixReaderADGroup)) {
                    $CurrentHostPoolFSLogixReaderADGroup = New-ADGroup -Name $CurrentHostPoolFSLogixReaderADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolFSLogixReaderADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($CurrentHostPoolFSLogixReaderADGroup.Name)' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                }
                #endregion
                #region Run a sync with Azure AD
                Start-MicrosoftEntraIDConnectSync
                #endregion 
                #endregion
                #endregion

                #region FSLogix Storage Account Management
                #region FSLogix Storage Account Name Setup
                $CurrentHostPoolStorageAccountName = $CurrentHostPool.GetFSLogixStorageAccountName()
                #endregion 

                #region Dedicated Host Pool AD GPO Management (1 FSLogix per Host Pool)
                if ($CurrentHostPool.IsActiveDirectoryJoined()) {
                    #region FSLogix GPO
                    $CurrentHostPoolFSLogixGPO = Get-GPO -Name "$($CurrentHostPool.Name) - FSLogix Settings" -ErrorAction Ignore
                    if (-not($CurrentHostPoolFSLogixGPO)) {
                        $CurrentHostPoolFSLogixGPO = New-GPO -Name "$($CurrentHostPool.Name) - FSLogix Settings"
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($CurrentHostPoolFSLogixGPO.DisplayName)' GPO (linked to '($($CurrentHostPoolOU.DistinguishedName))'"
                    }
                    $null = $CurrentHostPoolFSLogixGPO | New-GPLink -Target $CurrentHostPoolOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 10 seconds"
                    Start-Sleep -Seconds 10
                    #region FSLogix GPO Management: Dedicated GPO settings for FSLogix profiles for this HostPool 
                    #From https://learn.microsoft.com/en-us/fslogix/tutorial-configure-profile-containers#profile-container-configuration
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Setting some 'FSLogix' related registry values for '$($CurrentHostPoolFSLogixGPO.DisplayName)' GPO (linked to '$($PooledDesktopsOU.DistinguishedName)' OU)"
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "DeleteLocalProfileWhenVHDShouldApply" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "FlipFlopProfileDirectoryName" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LockedRetryCount" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 3
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LockedRetryInterval" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 15
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ProfileType" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ReAttachIntervalSeconds" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 15
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ReAttachRetryCount" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 3
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "SizeInMBs" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 30000

                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "PreventLoginWithFailure" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "PreventLoginWithTempProfile" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "VolumeType" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "VHDX"
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LogFileKeepingPeriod" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 10
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "IsDynamic" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1

                    #For running FSLogix System Tray at Logon
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ValueName "frxtray" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "C:\Program Files\FSLogix\Apps\frxtray.exe"

                    if ($CurrentHostPool.FSLogixCloudCache) {
                        $CCDLocations = @(
                            "type=smb,name=`"{0}`",connectionString=\\{0}.file.{1}\profiles" -f $CurrentHostPoolStorageAccountName, $StorageEndpointSuffix
                            "type=smb,name=`"{0}`",connectionString=\\{0}.file.{1}\profiles" -f $CurrentHostPool.GetRecoveryLocationFSLogixStorageAccountName(), $StorageEndpointSuffix
                        ) -join ';'
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] CCDLocations: $CCDLocations"
                        $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "CCDLocations" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value $CCDLocations
                    }
                    else {
                        $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "VHDLocations" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"
                    }
                    #Use Redirections.xml. Be careful : https://twitter.com/JimMoyle/status/1247843511413755904
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "RedirXMLSourceFolder" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"

                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-automatic-updates
                    #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.WindowsUpdate::AutoUpdateCfg
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName "NoAutoUpdate" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#set-up-time-zone-redirection
                    #From https://admx.help/?Category=VMware_Horizon&Policy=VMware.Policies.Cascadia::CASCADIA_TIME_ZONE
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fEnableTimeZoneRedirection" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-storage-sense
                    #$null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -ValueName "01" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
                    #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.StorageSense::SS_AllowStorageSenseGlobal
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\StorageSense' -ValueName "AllowStorageSenseGlobal" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0

                    #region GPO Debug log file
                    #From https://blog.piservices.fr/post/2017/12/21/active-directory-debug-avance-de-l-application-des-gpos
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics' -ValueName "GPSvcDebugLevel" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0x30002
                    #endregion
                    #region Microsoft Defender Endpoint A/V General Exclusions (the *.VHD and *.VHDX exclusions applies to FSLogix and MSIX) 
                    #From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Setting some 'Microsoft Defender Endpoint A/V Exclusions for this HostPool' related registry values for '$($CurrentHostPoolFSLogixGPO.DisplayName)' GPO (linked to '$($CurrentHostPoolOU.DistinguishedName)' OU)"
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -ValueName "Exclusions_Paths" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%TEMP%\*\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%TEMP%\*\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%Windir%\TEMP\*\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%Windir%\TEMP\*\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramData%\FSLogix\Cache\*" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramData%\FSLogix\Proxy\*" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramFiles%\FSLogix\Apps\frxdrv.sys" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramFiles%\FSLogix\Apps\frxdrvvt.sys" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramFiles%\FSLogix\Apps\frxccd.sys" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0

                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.lock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.meta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.metadata" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.lock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.meta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.metadata" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.CIM" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0

                    #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.WindowsDefender::Exclusions_Processesget-job
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -ValueName "Exclusions_Processes" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -ValueName "%ProgramFiles%\FSLogix\Apps\frxccd.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -ValueName "%ProgramFiles%\FSLogix\Apps\frxccds.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -ValueName "%ProgramFiles%\FSLogix\Apps\frxsvc.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -ValueName "%ProgramFiles%\FSLogix\Apps\frxrobocopy.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    #endregion
                    <#
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Setting some 'FSLogix' related registry values for '$($CurrentHostPoolFSLogixGPO.DisplayName)' GPO (linked to '$($CurrentHostPoolOU.DistinguishedName)' OU)"
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "VHDLocations" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"
                    #Use Redirections.xml. Be careful : https://twitter.com/JimMoyle/status/1247843511413755904w
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "RedirXMLSourceFolder" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"
                    #>
                    #endregion 

                    #region GPO "Local Users and Groups" Management via groups.xml
                    #From https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/37722b69-41dd-4813-8bcd-7a1b4d44a13d
                    #From https://jans.cloud/2019/08/microsoft-fslogix-profile-container/
                    $GroupXMLGPOFilePath = "\\{0}\SYSVOL\{0}\Policies\{{{1}}}\Machine\Preferences\Groups\Groups.xml" -f $DomainName, $($CurrentHostPoolFSLogixGPO.Id)
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$GroupXMLGPOFilePath'"
                    #Generating an UTC time stamp
                    $Changed = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
                    #$ADGroupToExcludeFromFSLogix = @('Domain Admins', 'Enterprise Admins')
                    $ADGroupToExcludeFromFSLogix = @('Domain Admins')
                    $Members = foreach ($CurrentADGroupToExcludeFromFSLogix in $ADGroupToExcludeFromFSLogix) {
                        $CurrentADGroupToExcludeFromFSLogixSID = (Get-ADGroup -Filter "Name -eq '$CurrentADGroupToExcludeFromFSLogix'").SID.Value
                        if (-not([string]::IsNullOrEmpty($CurrentADGroupToExcludeFromFSLogixSID))) {
                            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Excluding '$CurrentADGroupToExcludeFromFSLogix' from '$GroupXMLGPOFilePath'"
                            "<Member name=""$((Get-ADDomain).NetBIOSName)\$CurrentADGroupToExcludeFromFSLogix"" action=""ADD"" sid=""$CurrentADGroupToExcludeFromFSLogixSID""/>"
                        }
                    }
                    $Members = $Members -join ""

                    $GroupXMLGPOFileContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix ODFC Exclude List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}"><Properties action="U" newName="" description="Members of this group are on the exclude list for Outlook Data Folder Containers" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="" groupName="FSLogix ODFC Exclude List"><Members>$Members</Members></Properties></Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix ODFC Include List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}"><Properties action="U" newName="" description="Members of this group are on the include list for Outlook Data Folder Containers" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupName="FSLogix ODFC Include List"/></Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix Profile Exclude List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}" userContext="0" removePolicy="0"><Properties action="U" newName="" description="Members of this group are on the exclude list for dynamic profiles" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="" groupName="FSLogix Profile Exclude List"><Members>$Members</Members></Properties></Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix Profile Include List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}"><Properties action="U" newName="" description="Members of this group are on the include list for dynamic profiles" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupName="FSLogix Profile Include List"/></Group>
</Groups>
"@
            
                    $null = New-Item -Path $GroupXMLGPOFilePath -ItemType File -Value $GroupXMLGPOFileContent -Force
                    <#
                    Set-Content -Path $GroupXMLGPOFilePath -Value $GroupXMLGPOFileContent -Encoding UTF8
                    $GroupXMLGPOFileContent | Out-File $GroupXMLGPOFilePath -Encoding utf8
                    #>
                    #endregion
        
                    #region GPT.INI Management
                    $GPTINIGPOFilePath = "\\{0}\SYSVOL\{0}\Policies\{{{1}}}\GPT.INI" -f $DomainName, $($CurrentHostPoolFSLogixGPO.Id)
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$GPTINIGPOFilePath'"
                    $result = Select-String -Pattern "(Version)=(\d+)" -AllMatches -Path $GPTINIGPOFilePath
                    #Getting current version
                    [int]$VersionNumber = $result.Matches.Groups[-1].Value
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Version Number: $VersionNumber"
                    #Increasing current version
                    $VersionNumber += 2
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] New Version Number: $VersionNumber"
                    #Updating file
                    (Get-Content $GPTINIGPOFilePath -Encoding UTF8) -replace "(Version)=(\d+)", "`$1=$VersionNumber" | Set-Content $GPTINIGPOFilePath -Encoding UTF8
                    Write-Verbose -Message $(Get-Content $GPTINIGPOFilePath -Encoding UTF8 | Out-String)
                    #endregion 

                    #region gPCmachineExtensionNames Management
                    #From https://www.infrastructureheroes.org/microsoft-infrastructure/microsoft-windows/guid-list-of-group-policy-client-extensions/
                    #[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]
                    #[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing gPCmachineExtensionNames Management"
                    $gPCmachineExtensionNamesToAdd = "[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]"
                    $RegExPattern = $gPCmachineExtensionNamesToAdd -replace "(\W)" , '\$1'
                    $GPOADObject = Get-ADObject -LDAPFilter "CN={$($CurrentHostPoolFSLogixGPO.Id.Guid)}" -Properties gPCmachineExtensionNames
                    #if (-not($GPOADObject.gPCmachineExtensionNames.StartsWith($gPCmachineExtensionNamesToAdd)))
                    if ($GPOADObject.gPCmachineExtensionNames -notmatch $RegExPattern) {
                        $GPOADObject | Set-ADObject -Replace @{gPCmachineExtensionNames = $($gPCmachineExtensionNamesToAdd + $GPOADObject.gPCmachineExtensionNames) }
                        #Get-ADObject -LDAPFilter "CN={$($CurrentHostPoolFSLogixGPO.Id.Guid)}" -Properties gPCmachineExtensionNames
                    }
                    #endregion
                    #endregion
                }
                #endregion 

                #region Dedicated Resource Group Management (1 per HostPool)
                $CurrentHostPoolResourceGroupName = $CurrentHostPool.GetResourceGroupName()

                $CurrentHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -ErrorAction Ignore
                if (-not($CurrentHostPoolResourceGroup)) {
                    $CurrentHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Force
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($CurrentHostPoolResourceGroup.ResourceGroupName)' Resource Group"
                }
                #endregion

                #region Dedicated Storage Account Setup
                $CurrentHostPoolStorageAccount = Get-AzStorageAccount -Name $CurrentHostPoolStorageAccountName -ResourceGroupName $CurrentHostPoolResourceGroupName -ErrorAction Ignore
                if (-not($CurrentHostPoolStorageAccount)) {
                    if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentHostPoolStorageAccountName).NameAvailable) {
                        Write-Error "The storage account name '$CurrentHostPoolStorageAccountName' is not available !" -ErrorAction Stop
                    }
                    $CurrentHostPoolStorageAccount = New-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName -Location $CurrentHostPool.Location -SkuName $SKUName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true #-AllowSharedKeyAccess $false
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($CurrentHostPoolStorageAccount.StorageAccountName)' Storage Account (in the '$($CurrentHostPoolStorageAccount.ResourceGroupName)' Resource Group)"
                }

                #Registering the Storage Account with your active directory environment under the target
                if ($CurrentHostPool.IsActiveDirectoryJoined()) {
                    if (-not(Get-ADComputer -Filter "Name -eq '$CurrentHostPoolStorageAccountName'" -SearchBase $CurrentHostPoolOU.DistinguishedName)) {
                        if (-not(Get-Module -Name AzFilesHybrid -ListAvailable)) {
                            $AzFilesHybridZipName = 'AzFilesHybrid.zip'
                            $OutFile = Join-Path -Path $env:TEMP -ChildPath $AzFilesHybridZipName
                            Start-BitsTransfer https://github.com/Azure-Samples/azure-files-samples/releases/latest/download/AzFilesHybrid.zip -Destination $OutFile
                            Expand-Archive -Path $OutFile -DestinationPath $env:TEMP\AzFilesHybrid -Force
                            Push-Location -Path $env:TEMP\AzFilesHybrid
                            .\CopyToPSPath.ps1
                            Pop-Location
                        }
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Registering the Storage Account '$CurrentHostPoolStorageAccountName' with your AD environment (under '$($CurrentHostPoolOU.DistinguishedName)') OU"
                        Import-Module AzFilesHybrid  #-DisableNameChecking #-Force
                        #$null = New-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -KeyName "kerb1"#
                        $null = Join-AzStorageAccountForAuth -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -DomainAccountType "ComputerAccount" -OrganizationUnitDistinguishedName $CurrentHostPoolOU.DistinguishedName -Confirm:$false
                        #Debug-AzStorageAccountAuth -StorageAccountName $CurrentHostPoolStorageAccountName -ResourceGroupName $CurrentHostPoolResourceGroupName -Verbose
                        
                        #Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -EnableAzureActiveDirectoryKerberosForFile $true
                        #$KerbKeys = Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -ListKerbKey 
                    }
                    # Get the target storage account
                    #$storageaccount = Get-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName

                    # List the directory service of the selected service account
                    #$CurrentHostPoolStorageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceOptions

                    # List the directory domain information if the storage account has enabled AD authentication for file shares
                    #$CurrentHostPoolStorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties
                }
                else {
                    #region Enable Kerberos authentication
                    #From https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-powershell#enable-microsoft-entra-kerberos-authentication-for-hybrid-user-accounts
                    #From https://smbtothecloud.com/azure-ad-joined-avd-with-fslogix-aad-kerberos-authentication/
                    $null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -StorageAccountName $CurrentHostPoolStorageAccountName -EnableAzureActiveDirectoryKerberosForFile $true -ActiveDirectoryDomainName $domainName -ActiveDirectoryDomainGuid $domainGuid
                    #endregion

                    #region Grant admin consent to the new service principal
                    #From https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-powershell#grant-admin-consent-to-the-new-service-principal
                    # Get the created service principal
                    Do {
                        Start-Sleep -Seconds 60
                        $ServicePrincipal = Get-MgBetaServicePrincipal -Filter "DisplayName eq '[Storage Account] $CurrentHostPoolStorageAccountName.file.core.windows.net'"
                    } While ($null -eq $ServicePrincipal)

                    # Grant admin consent to the service principal for the app role
                    Set-AdminConsent -context $AzContext -applicationId $ServicePrincipal.AppId
                    #endregion

                    #region Disable multi-factor authentication on the storage account
                    #From https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-portal#disable-multi-factor-authentication-on-the-storage-account
                    #$NoMFAEntraIDGroup = Get-AzADGroup -SearchString $NoMFAEntraIDGroupName
                    $NoMFAEntraIDGroup = Get-MgBetaGroup -Filter "DisplayName eq '$NoMFAEntraIDGroupName'"

                    if (-not($NoMFAEntraIDGroup)) {
                        Write-Warning -Message "'$NoMFAEntraIDGroupName' Entra ID group not found for disabling the MFA for the '$($ServicePrincipal.DisplayName)' Service Principal."
                        #Creating the No MFA Entra ID Group
                        $NoMFAEntraIDGroup = New-PsAvdNoMFAUserEntraIDGroup -NoMFAEntraIDGroupName $NoMFAEntraIDGroupName
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NoMFAEntraIDGroup:`r`n$($NoMFAEntraIDGroup | Select-Object -Property * | Out-String)"
                    }
                    <#
                    $NoMFAEntraIDGroup = Get-AzADGroup -SearchString $NoMFAEntraIDGroupName
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NoMFAEntraIDGroup:`r`n$($NoMFAEntraIDGroup | Select-Object -Property * | Out-String)"
                    #>
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding the '$($ServicePrincipal.DisplayName)' Service Principal as member of the '$($NoMFAEntraIDGroup.DisplayName)' Microsoft Entra ID Group"
                    #$result = Add-AzADGroupMember -TargetGroupObjectId $NoMFAEntraIDGroup.Id -MemberObjectId $ServicePrincipal.Id
                    $result = New-MgBetaGroupMember -GroupId $NoMFAEntraIDGroup.Id -DirectoryObjectId $ServicePrincipal.Id
                    #Creating the MFA Conditional Access Policy and excluding the No MFA Entra ID Group
                    $MFAForAllUsersConditionalAccessPolicy = New-PsAvdMFAForAllUsersConditionalAccessPolicy -ExcludeGroupName $NoMFAEntraIDGroup.DisplayName
                    <#
                    Start-Process -FilePath "https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-portal#disable-multi-factor-authentication-on-the-storage-account"
                    Do {
                        $Response = Read-Host -Prompt "Did you disable multi-factor authentication on the storage account ? (Y/N)"

                    } While ($Response -ne "Y")
                    #>
                    #endregion

                    #region Configuring the clients to retrieve Kerberos tickets
                    #From https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-portal#configure-the-clients-to-retrieve-kerberos-tickets
                    #endregion
                }


                # Save the password so the drive will persist on reboot
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Saving the credentials for accessing to the Storage Account '$CurrentHostPoolStorageAccountName' in the Windows Credential Manager"
                #region Getting the Storage Account Key from the Storage Account
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Getting the Storage Account Key from the Azure Key Vault"
                $CurrentHostPoolStorageAccountKey = ((Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }).Value
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentHostPoolStorageAccountKey: $CurrentHostPoolStorageAccountKey"
                #endregion

                Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "cmdkey /add:`"$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix`" /user:`"localhost\$CurrentHostPoolStorageAccountName`" /pass:`"$CurrentHostPoolStorageAccountKey`"" -Wait -NoNewWindow
                #endregion

                <#
                #region Private endpoint for Storage Setup
                #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
                #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
                #From https://ystatit.medium.com/azure-key-vault-with-azure-service-endpoints-and-private-link-part-1-bcc84b4c5fbc
                ## Create the private endpoint connection. ## 

                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private Endpoint for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($CurrentHostPoolResourceGroupName)' Resource Group)"
                $PrivateEndpointName = "pep{0}" -f $($CurrentHostPoolStorageAccountName -replace "\W")
                $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $CurrentHostPoolStorageAccount.Id).GroupId | Where-Object -FilterScript { $_ -match "file" }
                $Subnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $CurrentHostPool.SubnetId
                $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $CurrentHostPoolStorageAccount.Id -GroupId $GroupId
                $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Subnet $Subnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force


                ## Create the private DNS zone. ##
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private DNS Zone for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                $PrivateDnsZoneName = "privatelink.$GroupId.$StorageEndpointSuffix"
                $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
                if ($null -eq $PrivateDnsZone) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private DNS Zone for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                    $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
                }

                $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
                $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
                if ($null -eq $PrivateDnsVirtualNetworkLink) {
                    $ThisDomainControllerVirtualNetworkId = $ThisDomainControllerVirtualNetwork.Id
                    ## Create a DNS network link. ##
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private DNS VNet Link for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                    $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
                }


                ## Configure the DNS zone. ##
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the DNS Zone Configuration of the Private Dns Zone Group for the Storage Account '$CurrentHostPoolStorageAccountName'"
                $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

                ## Create the DNS zone group. ##
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $CurrentHostPoolResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force

                #Storage Account - Disabling Public Access
                #From https://www.jorgebernhardt.com/azure-storage-public-access/
                #From https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-powershell#change-the-default-network-access-rule
                #From https://github.com/adstuart/azure-privatelink-dns-microhack
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Disabling the Public Access for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                $null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -PublicNetworkAccess Disabled
                #(Get-AzStorageAccount -Name $CurrentHostPoolResourceGroupName -ResourceGroupName $CurrentHostPoolStorageAccountName ).AllowBlobPublicAccess
                #endregion
                #>
                Start-Sleep -Seconds 60
                #region Dedicated Share Management
                $FSLogixShareName | ForEach-Object -Process { 
                    $CurrentHostPoolShareName = $_
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                    #Create a share for FSLogix
                    #$CurrentHostPoolStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }
                    #$storageContext = New-AzStorageContext -StorageAccountName $CurrentHostPoolStorageAccountName -StorageAccountKey $CurrentHostPoolStorageAccountKey.Value
                    $storageContext = (Get-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName).Context
                    $CurrentHostPoolStorageAccountShare = New-AzStorageShare -Name $CurrentHostPoolShareName -Context $storageContext

                    #region RBAC Management
                    #Constrain the scope to the target file share
                    $SubscriptionId = $AzContext.Subscription.Id
                    $Scope = "/subscriptions/$SubscriptionId/resourceGroups/$CurrentHostPoolResourceGroupName/providers/Microsoft.Storage/storageAccounts/$CurrentHostPoolStorageAccountName/fileServices/default/fileshares/$CurrentHostPoolShareName"
                    #$Scope = "/subscriptions/$SubscriptionId/resourceGroups/$CurrentHostPoolResourceGroupName/providers/Microsoft.Storage/storageAccounts/$CurrentHostPoolStorageAccountName/$CurrentHostPoolShareName"

                    #region Setting up the file share with right RBAC: FSLogix Contributor = "Storage File Data SMB Share Contributor"
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                        Start-Sleep -Seconds 30
                        $AzADGroup = $null
                        #$AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolFSLogixContributorADGroupName
                        $AzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$CurrentHostPoolFSLogixContributorADGroupName'"
                    } While (-not($AzADGroup.Id))
                    #Assigning the "Storage File Data SMB Share Contributor" RBAC Role to the dedicated Entra ID Group
                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolFSLogixContributorADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) "
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #region Setting up the file share with right RBAC: FSLogix Elevated Contributor = "Storage File Data SMB Share Elevated Contributor"
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                        Start-Sleep -Seconds 30
                        $AzADGroup = $null
                        #$AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolFSLogixElevatedContributorADGroupName
                        $AzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$CurrentHostPoolFSLogixElevatedContributorADGroupName'"
                    } While (-not($AzADGroup.Id))

                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolFSLogixElevatedContributorADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) "
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #region Setting up the file share with right RBAC: FSLogix Reader = "Storage File Data SMB Share Reader"
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Reader"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                        Start-Sleep -Seconds 30
                        $AzADGroup = $null
                        #$AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolFSLogixReaderADGroupName
                        $AzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$CurrentHostPoolFSLogixReaderADGroupName'"
                    } While (-not($AzADGroup.Id))
                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolFSLogixReaderADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) "
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #endregion

                    #Temporary Allowing storage account key access(disabled due to SFI)
                    $null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -AllowSharedKeyAccess $true
                    # Mount the share
                    Remove-PSDrive -Name Z -ErrorAction Ignore
                    $null = New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\$CurrentHostPoolShareName"

                    #region NTFS permissions for FSLogix
                    #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
                    #From https://learn.microsoft.com/en-us/fslogix/how-to-configure-storage-permissions#recommended-acls
                    #region Sample NTFS permissions for FSLogix
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Setting the ACL for the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) "
                    $existingAcl = Get-Acl Z:

                    #Disabling inheritance
                    $existingAcl.SetAccessRuleProtection($true, $false)

                    #Remove all inherited permissions from this object.
                    $existingAcl.Access | ForEach-Object -Process { $null = $existingAcl.RemoveAccessRule($_) }

                    #Add Modify for CREATOR OWNER Group for Subfolders and files only
                    $identity = "CREATOR OWNER"
                    $colRights = [System.Security.AccessControl.FileSystemRights]::Modify
                    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly           
                    $objType = [System.Security.AccessControl.AccessControlType]::Allow
                    # Create a new FileSystemAccessRule object
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                    # Modify the existing ACL to include the new rule
                    $existingAcl.SetAccessRule($AccessRule)

                    #Add Full Control for "Administrators" Group for This folder, subfolders and files
                    $identity = "Administrators"
                    $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                    $objType = [System.Security.AccessControl.AccessControlType]::Allow
                    # Create a new FileSystemAccessRule object
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                    # Modify the existing ACL to include the new rule
                    $existingAcl.SetAccessRule($AccessRule)

                    #Add Modify for "Users" Group for This folder only
                    #$identity = "Users"
                    $identity = $CurrentHostPoolDAGUsersAzADGroupName
                    $colRights = [System.Security.AccessControl.FileSystemRights]::Modify
                    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
                    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                    $objType = [System.Security.AccessControl.AccessControlType]::Allow
                    # Create a new FileSystemAccessRule object
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                    # Modify the existing ACL to include the new rule
                    $existingAcl.SetAccessRule($AccessRule)

                    #Enabling inheritance
                    $existingAcl.SetAccessRuleProtection($false, $true)

                    # Apply the modified access rule to the folder
                    $existingAcl | Set-Acl -Path Z:
                    #endregion

                    #region redirection.xml file management
                    #Creating the redirection.xml file
                    if ($CurrentHostPoolShareName -eq "profiles") {
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the 'redirections.xml' file for the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                        $null = New-Item -Path Z: -Name "redirections.xml" -ItemType "file" -Value $RedirectionsXMLFileContent -Force
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Setting the ACL for the 'redirections.xml' file in the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                        $existingAcl = Get-Acl Z:\redirections.xml
                        #Add Read for "Users" Group for This folder only
                        #$identity = "Users"
                        $identity = $CurrentHostPoolDAGUsersAzADGroupName
                        $colRights = [System.Security.AccessControl.FileSystemRights]::Read
                        $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
                        $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                        $objType = [System.Security.AccessControl.AccessControlType]::Allow
                        # Create a new FileSystemAccessRule object
                        $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                        # Modify the existing ACL to include the new rule
                        $existingAcl.SetAccessRule($AccessRule)
                        $existingAcl | Set-Acl -Path Z:\redirections.xml
                    }
                    #endregion

                    # Unmount the share
                    Remove-PSDrive -Name Z
                    #Not Allowing storage account key access (SFI compliant)
                    #$null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -AllowSharedKeyAccess $false
                    #Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "net use z: /delete" -Wait -NoNewWindow
                    #endregion

                    #region Run a sync with Azure AD
                    Start-MicrosoftEntraIDConnectSync
                    #endregion 
                }
                #endregion

                #Creating a Private EndPoint for this Storage Account on the HostPool Subnet and the Subnet used by this DC
                New-PsAvdPrivateEndpointSetup -SubnetId $CurrentHostPool.SubnetId, $ThisDomainControllerSubnet.Id -StorageAccount $CurrentHostPoolStorageAccount
                #endregion
            }
            else {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] FSLogix NOT enabled for '$($CurrentHostPool.Name)' HostPool"
            }
            #endregion 

            #region Watermarking
            #From https://learn.microsoft.com/en-us/fslogix/reference-configuration-settings?tabs=profiles
            if ($CurrentHostPool.Watermarking) {
                #region FSLogix AD Management

                #region Dedicated Host Pool AD GPO Management (1 AVD GPO per Host Pool)
                if ($CurrentHostPool.IsActiveDirectoryJoined()) {
                    #region AVD GPO
                    $CurrentHostPoolAVDGPO = Get-GPO -Name "$($CurrentHostPool.Name) - AVD Settings" -ErrorAction Ignore
                    if (-not($CurrentHostPoolAVDGPO)) {
                        $CurrentHostPoolAVDGPO = New-GPO -Name "$($CurrentHostPool.Name) - AVD Settings"
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($CurrentHostPoolAVDGPO.DisplayName)' GPO (linked to '($($CurrentHostPoolOU.DistinguishedName))'"
                    }
                    $null = $CurrentHostPoolAVDGPO | New-GPLink -Target $CurrentHostPoolOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 10 seconds"
                    Start-Sleep -Seconds 10
                    #region AVD GPO Management: Dedicated GPO settings for AVD for this HostPool 
                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/watermarking#enable-watermarking
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Setting some 'Enable Watermarking' related registry values for '$($CurrentHostPoolAVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU)"
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolAVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fEnableWatermarking" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1

                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolAVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "WatermarkingHeightFactor" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 180
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolAVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "WatermarkingOpacity" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2000
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolAVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "WatermarkingQrScale" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 4
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolAVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "WatermarkingWidthFactor" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 320

                    #region GPO Debug log file
                    #From https://blog.piservices.fr/post/2017/12/21/active-directory-debug-avance-de-l-application-des-gpos
                    $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolAVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics' -ValueName "GPSvcDebugLevel" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0x30002
                    #endregion
                    #endregion
                    #endregion
                }
                #endregion 


                #endregion
            }
            else {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Watermarking NOT enabled for '$($CurrentHostPool.Name)' HostPool"
            }
            #endregion 

            #region MSIX or AppAttach
            #No EntraID and MSIX : https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-overview?pivots=msix-app-attach#identity-providers
            if ($CurrentHostPool.IsActiveDirectoryJoined() -and ($CurrentHostPool.MSIX -or $CurrentHostPool.AppAttach)) {
                #region MSIX AD Management
                #region Dedicated HostPool AD group

                #region Dedicated HostPool AD MSIX groups
                $CurrentHostPoolMSIXHostsADGroupName = "$($CurrentHostPool.Name) - $MSIXHosts"
                $CurrentHostPoolMSIXHostsADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolMSIXHostsADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolMSIXHostsADGroup)) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$CurrentHostPoolMSIXHostsADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                    $CurrentHostPoolMSIXHostsADGroup = New-ADGroup -Name $CurrentHostPoolMSIXHostsADGroupName -SamAccountName $CurrentHostPoolMSIXHostsADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolMSIXHostsADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                }

                $CurrentHostPoolMSIXShareAdminsADGroupName = "$($CurrentHostPool.Name) - $MSIXShareAdmins"
                $CurrentHostPoolMSIXShareAdminsADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolMSIXShareAdminsADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolMSIXShareAdminsADGroup)) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$CurrentHostPoolMSIXShareAdminsADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                    $CurrentHostPoolMSIXShareAdminsADGroup = New-ADGroup -Name $CurrentHostPoolMSIXShareAdminsADGroupName -SamAccountName $CurrentHostPoolMSIXShareAdminsADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolMSIXShareAdminsADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                }

                $CurrentHostPoolMSIXUsersADGroupName = "$($CurrentHostPool.Name) - $MSIXUsers"
                $CurrentHostPoolMSIXUsersADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolMSIXUsersADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolMSIXUsersADGroup)) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$CurrentHostPoolMSIXUsersADGroup' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                    $CurrentHostPoolMSIXUsersADGroup = New-ADGroup -Name $CurrentHostPoolMSIXUsersADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolMSIXUsersADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                }
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding the '$CurrentHostPoolDAGUsersAzADGroupName' AD group to the '$CurrentHostPoolMSIXUsersADGroup' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                $CurrentHostPoolMSIXUsersADGroup | Add-ADGroupMember -Members $CurrentHostPoolDAGUsersAzADGroupName
                #endregion
                #region Run a sync with Azure AD
                Start-MicrosoftEntraIDConnectSync
                #endregion 
                #endregion
                #endregion 

                #region MSIX Storage Account Management
                #region MSIX Storage Account Name Setup
                $CurrentHostPoolStorageAccountName = $CurrentHostPool.GetMSIXStorageAccountName()
                #endregion 

                #region Dedicated Host Pool AD GPO Management (1 GPO per Host Pool for setting up MSIX)
                if (-not($CurrentHostPoolMSIXGPO)) {
                    $CurrentHostPoolMSIXGPO = New-GPO -Name "$($CurrentHostPool.Name) - MSIX Settings"
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($CurrentHostPoolMSIXGPO.DisplayName)' GPO (linked to '($($CurrentHostPoolOU.DistinguishedName))'"
                }
                $null = $CurrentHostPoolMSIXGPO | New-GPLink -Target $CurrentHostPoolOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore

                #region Turning off automatic updates for MSIX app attach applications
                #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-azure-portal#turn-off-automatic-updates-for-msix-app-attach-applications
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Turning off automatic updates for MSIX app attach applications for '$($CurrentHostPoolMSIXGPO.DisplayName)' GPO (linked to '$($PooledDesktopsOU.DistinguishedName)' OU)"
                $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\WindowsStore' -ValueName "AutoDownload" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
                $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -ValueName "PreInstalledAppsEnabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
                $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Debug' -ValueName "ContentDeliveryAllowedOverride" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
                #Look for Disable-ScheduledTask ... in the code for the next step(s)
                #endregion

                #region Microsoft Defender Endpoint A/V Exclusions for this HostPool 
                #From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Setting some 'Microsoft Defender Endpoint A/V Exclusions for this HostPool' related registry values for '$($CurrentHostPoolMSIXGPO.DisplayName)' GPO (linked to '$($CurrentHostPoolOU.DistinguishedName)' OU)"
                $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.lock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.meta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.metadata" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.lock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.meta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.metadata" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-PsAvdGPRegistryValue -Verbose -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.CIM" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                #endregion
                #endregion

                #region Dedicated Resource Group Management (1 per HostPool)
                $CurrentHostPoolResourceGroupName = $CurrentHostPool.GetResourceGroupName()

                $CurrentHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -ErrorAction Ignore
                if (-not($CurrentHostPoolResourceGroup)) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$CurrentHostPoolResourceGroupName' Resource Group"
                    $CurrentHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Force
                }
                #endregion

                #region Dedicated Storage Account Setup
                $CurrentHostPoolStorageAccount = Get-AzStorageAccount -Name $CurrentHostPoolStorageAccountName -ResourceGroupName $CurrentHostPoolResourceGroupName -ErrorAction Ignore
                if (-not($CurrentHostPoolStorageAccount)) {
                    if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentHostPoolStorageAccountName).NameAvailable) {
                        Write-Error "The storage account name '$CurrentHostPoolStorageAccountName' is not available !" -ErrorAction Stop
                    }
                    $CurrentHostPoolStorageAccount = New-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName -Location $CurrentHostPool.Location -SkuName $SKUName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true #-AllowSharedKeyAccess $false
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($CurrentHostPoolStorageAccount.StorageAccountName)' Storage Account (in the '$($CurrentHostPoolStorageAccount.ResourceGroupName)' Resource Group)"
                }

                #Registering the Storage Account with your active directory environment under the target
                if (-not(Get-ADComputer -Filter "Name -eq '$CurrentHostPoolStorageAccountName'" -SearchBase $CurrentHostPoolOU.DistinguishedName)) {
                    if (-not(Get-Module -Name AzFilesHybrid -ListAvailable)) {
                        $AzFilesHybridZipName = 'AzFilesHybrid.zip'
                        $OutFile = Join-Path -Path $env:TEMP -ChildPath $AzFilesHybridZipName
                        Start-BitsTransfer https://github.com/Azure-Samples/azure-files-samples/releases/latest/download/AzFilesHybrid.zip -Destination $OutFile
                        Expand-Archive -Path $OutFile -DestinationPath $env:TEMP\AzFilesHybrid -Force
                        Push-Location -Path $env:TEMP\AzFilesHybrid
                        .\CopyToPSPath.ps1
                        Pop-Location
                    }
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Registering the Storage Account '$CurrentHostPoolStorageAccountName' with your AD environment (under '$($CurrentHostPoolOU.DistinguishedName)') OU"
                    Import-Module AzFilesHybrid #-DisableNameChecking #-Force
                    #$null = New-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -KeyName "kerb1"
                    $null = Join-AzStorageAccountForAuth -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -DomainAccountType "ComputerAccount" -OrganizationUnitDistinguishedName $CurrentHostPoolOU.DistinguishedName -Confirm:$false

                    # You can run the Debug-AzStorageAccountAuth cmdlet to conduct a set of basic checks on your AD configuration 
                    # with the logged on AD user. This cmdlet is supported on AzFilesHybrid v0.1.2+ version. For more details on 
                    # the checks performed in this cmdlet, see Azure Files Windows troubleshooting guide.
                    #Debug-AzStorageAccountAuth -StorageAccountName $CurrentHostPoolStorageAccountName -ResourceGroupName $CurrentHostPoolResourceGroupName

                    #$KerbKeys = Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -ListKerbKey 
                }

                # Get the target storage account
                #$storageaccount = Get-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName

                # List the directory service of the selected service account
                #$CurrentHostPoolStorageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceOptions

                # List the directory domain information if the storage account has enabled AD authentication for file shares
                #$CurrentHostPoolStorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties


                # Save the password so the drive will persist on reboot
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Saving the credentials for accessing to the Storage Account '$CurrentHostPoolStorageAccountName' in the Windows Credential Manager"
                #region Storage Account Key

                #region Storage Account Key
                #region Getting the Storage Account Key from the Storage Account
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Getting the Storage Account Key from the Storage Account"
                $CurrentHostPoolStorageAccountKey = ((Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }).Value
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentHostPoolStorageAccountKey: $CurrentHostPoolStorageAccountKey"
                #endregion 

                Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "cmdkey /add:`"$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix`" /user:`"localhost\$CurrentHostPoolStorageAccountName`" /pass:`"$CurrentHostPoolStorageAccountKey`"" -Wait -NoNewWindow
                #endregion 

                <#
                #region Private endpoint for Storage Setup
                #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
                #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
                #From https://ystatit.medium.com/azure-key-vault-with-azure-service-endpoints-and-private-link-part-1-bcc84b4c5fbc
                ## Create the private endpoint connection. ## 

                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private Endpoint for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($CurrentHostPoolResourceGroupName)' Resource Group)"
                $PrivateEndpointName = "pep{0}" -f $($CurrentHostPoolStorageAccountName -replace "\W")
                $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $CurrentHostPoolStorageAccount.Id).GroupId | Where-Object -FilterScript { $_ -match "file" }
                $Subnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $HostPool.SubnetId
                $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $CurrentHostPoolStorageAccount.Id -GroupId $GroupId
                $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Subnet $Subnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

                ## Create the private DNS zone. ##
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private DNS Zone for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                $PrivateDnsZoneName = "privatelink.$GroupId.$StorageEndpointSuffix"
                $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
                if ($null -eq $PrivateDnsZone) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private DNS Zone for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                    $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
                }

                $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
                $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
                if ($null -eq $PrivateDnsVirtualNetworkLink) {
                    $ThisDomainControllerVirtualNetworkId = $ThisDomainControllerVirtualNetwork.Id
                    ## Create a DNS network link. ##
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private DNS VNet Link for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                    $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
                }


                ## Configure the DNS zone. ##
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the DNS Zone Configuration of the Private Dns Zone Group for the Storage Account '$CurrentHostPoolStorageAccountName'"
                $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

                ## Create the DNS zone group. ##
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $CurrentHostPoolResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force

                #Storage Account - Disabling Public Access
                #From https://www.jorgebernhardt.com/azure-storage-public-access/
                #From https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-powershell#change-the-default-network-access-rule
                #From https://github.com/adstuart/azure-privatelink-dns-microhack
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Disabling the Public Access for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                $null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -PublicNetworkAccess Disabled
                #(Get-AzStorageAccount -Name $CurrentHostPoolResourceGroupName -ResourceGroupName $CurrentHostPoolStorageAccountName ).AllowBlobPublicAccess
                #endregion
                #>
                #endregion
                Start-Sleep -Seconds 60
                $MSIXDemoPackages = $null
                #region Dedicated Share Management
                $MSIXShareName | ForEach-Object -Process { 
                    $CurrentHostPoolShareName = $_
                    #Create a share for MSIX
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                    #$CurrentHostPoolStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }
                    #$storageContext = New-AzStorageContext -StorageAccountName $CurrentHostPoolStorageAccountName -StorageAccountKey $CurrentHostPoolStorageAccountKey.Value
                    $storageContext = (Get-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName).Context
                    $CurrentHostPoolStorageAccountShare = New-AzStorageShare -Name $CurrentHostPoolShareName -Context $storageContext

                    # Copying the  Demo MSIX Packages from my dedicated GitHub repository
                    $MSIXDemoPackages = Copy-PsAvdMSIXDemoAppAttachPackage -Source WebSite -Destination "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\$CurrentHostPoolShareName"

                    #region RBAC Management
                    #Constrain the scope to the target file share
                    $SubscriptionId = $AzContext.Subscription.Id
                    $Scope = "/subscriptions/$SubscriptionId/resourceGroups/$CurrentHostPoolResourceGroupName/providers/Microsoft.Storage/storageAccounts/$CurrentHostPoolStorageAccountName/fileServices/default/fileshares/$CurrentHostPoolShareName"
                    #$Scope = "/subscriptions/$SubscriptionId/resourceGroups/$CurrentHostPoolResourceGroupName/providers/Microsoft.Storage/storageAccounts/$CurrentHostPoolStorageAccountName/$CurrentHostPoolShareName"

                    #region Setting up the file share with right RBAC: MSIX Hosts & MSIX Users = "Storage File Data SMB Share Contributor" + MSIX Share Admins = Storage File Data SMB Share Elevated Contributor
                    #https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach-file-share#how-to-set-up-the-file-share
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                        Start-Sleep -Seconds 30
                        $AzADGroup = $null
                        #$AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolMSIXHostsADGroupName
                        $AzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$CurrentHostPoolMSIXHostsADGroupName'"
                    } While (-not($AzADGroup.Id))
                    #Assigning the "Storage File Data SMB Share Contributor" RBAC Role to the dedicated Entra ID Group
                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolMSIXHostsADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                        Start-Sleep -Seconds 30
                        $AzADGroup = $null
                        #$AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolMSIXUsersADGroupName
                        $AzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$CurrentHostPoolMSIXUsersADGroupName'"
                    } While (-not($AzADGroup.Id))
                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($FileShareContributorRole.Name)' RBAC role to 'CurrentPooledHostPoolMSIXUsersADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName'  (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #region Setting up the file share with right RBAC
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                        Start-Sleep -Seconds 30
                        $AzADGroup = $null
                        #$AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolMSIXShareAdminsADGroupName
                        $AzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$CurrentHostPoolMSIXShareAdminsADGroupName'"
                    } While (-not($AzADGroup.Id))
                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolMSIXShareAdminsADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #endregion

                    # Mount the share
                    #Temporary Allowing storage account key access(disabled due to SFI)
                    $null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -AllowSharedKeyAccess $true
                    Remove-PSDrive -Name Z -ErrorAction Ignore
                    $null = New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\$CurrentHostPoolShareName"
                    
                    #region NTFS permissions for MSIX
                    #From https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach-file-share#how-to-set-up-the-file-share
                    #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Setting the ACL on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                    $existingAcl = Get-Acl Z:
                    $existingAcl.Access | ForEach-Object -Process { $null = $existingAcl.RemoveAccessRule($_) }
                    #Disabling inheritance
                    $existingAcl.SetAccessRuleProtection($true, $false)

                    #Add Full Control for Administrators Group for This folder, subfolders and files
                    $identity = "BUILTIN\Administrators"
                    $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                    $objType = [System.Security.AccessControl.AccessControlType]::Allow
                    # Create a new FileSystemAccessRule object
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                    # Modify the existing ACL to include the new rule
                    $existingAcl.SetAccessRule($AccessRule)

                    #Add Full Control for MSIXShareAdmins Group for This folder, subfolders and files
                    $identity = $CurrentHostPoolMSIXShareAdminsADGroupName
                    $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                    $objType = [System.Security.AccessControl.AccessControlType]::Allow
                    # Create a new FileSystemAccessRule object
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                    # Modify the existing ACL to include the new rule
                    $existingAcl.SetAccessRule($AccessRule)

                    #Add "Read And Execute" for MSIXUsers Group for This folder, subfolders and files
                    $identity = $CurrentHostPoolMSIXUsersADGroupName
                    $colRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None           
                    $objType = [System.Security.AccessControl.AccessControlType]::Allow
                    # Create a new FileSystemAccessRule object
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                    # Modify the existing ACL to include the new rule
                    $existingAcl.SetAccessRule($AccessRule)

                    #Add "Read And Execute" for MSIXHosts Group for This folder, subfolders and files
                    $identity = $CurrentHostPoolMSIXHostsADGroupName
                    $colRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                    $objType = [System.Security.AccessControl.AccessControlType]::Allow
                    # Create a new FileSystemAccessRule object
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                    # Modify the existing ACL to include the new rule
                    $existingAcl.SetAccessRule($AccessRule)

                    #Enabling inheritance
                    $existingAcl.SetAccessRuleProtection($false, $true)

                    # Apply the modified access rule to the folder
                    $existingAcl | Set-Acl -Path Z:
                    #endregion

                    # Unmount the share
                    Remove-PSDrive -Name Z
                    #Not Allowing storage account key access (SFI compliant)
                    #$null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -AllowSharedKeyAccess $false
                    #Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "net use z: /delete" -Wait -NoNewWindow
                }
                #endregion

                #endregion
            
                #endregion
            }
            else {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] MSIX AppAttach Or Azure AppAttach NOT enabled for '$($CurrentHostPool.Name)' HostPool"
            }
            #endregion

            #region Dedicated Resource Group Management (1 per HostPool)
            $CurrentHostPoolResourceGroupName = $CurrentHostPool.GetResourceGroupName()

            $CurrentHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -ErrorAction Ignore
            if (-not($CurrentHostPoolResourceGroup)) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$CurrentHostPoolResourceGroupName' Resource Group"
                $CurrentHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Force
            }
            #endregion

            #region Identity Provider Management
            if ($CurrentHostPool.IsActiveDirectoryJoined()) {
                <#
                $AdJoinUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name AdJoinUserName -AsPlainText
                $AdJoinPassword = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name AdJoinPassword).SecretValue
                $AdJoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($AdJoinUserName, $AdJoinPassword)
                #>
                $AdJoinCredential = Get-AdjoinCredential -KeyVault $CurrentHostPool.KeyVault
                Grant-PsAvdADJoinPermission -Credential $AdJoinCredential -OrganizationalUnit $CurrentHostPoolOU.DistinguishedName
                $Tag['IdentityProvider'] = "Active Directory Directory Services"
            }
            else {
                $Tag['IdentityProvider'] = "Microsoft Entra ID"
                #region Assign Virtual Machine User Login' RBAC role to the Resource Group
                # Get the object ID of the user group you want to assign to the application group
                Do {
                    Start-MicrosoftEntraIDConnectSync
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                    Start-Sleep -Seconds 30
                    $AzADGroup = $null
                    #$AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolDAGUsersAzADGroupName
                    $AzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$CurrentHostPoolDAGUsersAzADGroupName'"
                } While (-not($AzADGroup.Id))

                # Assign users to the application group
                $parameters = @{
                    ObjectId           = $AzADGroup.Id
                    ResourceGroupName  = $CurrentHostPoolResourceGroupName
                    RoleDefinitionName = 'Virtual Machine User Login'
                    #Verbose            = $true
                }

                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($parameters.RoleDefinitionName)' RBAC role to '$CurrentHostPoolDAGUsersAzADGroupName' AD Group on the '$CurrentHostPoolResourceGroupName' Resource Group"
                $null = New-AzRoleAssignment @parameters
                #endregion 
            }
            #endregion 

            New-PsAvdHostPoolCredentialKeyVault -HostPool $CurrentHostPool

            #Microsoft Entra ID
            if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
                # From https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files?context=%2Fazure%2Fvirtual-desktop%2Fcontext%2Fcontext#device-redirection
                # No RDP redirection for COM ports, Local Drives and printers.
                $CustomRdpProperty = "targetisaadjoined:i:1;redirectcomports:i:0;redirectlocation:i:0;redirectprinters:i:0;drivestoredirect:s:;usbdevicestoredirect:s:;enablerdsaadauth:i:1"
            }
            #Active Directory Directory Services
            else {
                # From https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files?context=%2Fazure%2Fvirtual-desktop%2Fcontext%2Fcontext#device-redirection
                # No RDP redirection for COM ports, Local Drives and printers.
                $CustomRdpProperty = "redirectcomports:i:0;redirectlocation:i:0;redirectprinters:i:0;drivestoredirect:s:;usbdevicestoredirect:s:"
            }

            #region Host Pool Setup
            $RegistrationInfoExpirationTime = (Get-Date).ToUniversalTime().AddDays(1)
            $parameters = @{
                Name                  = $CurrentHostPool.Name
                ResourceGroupName     = $CurrentHostPoolResourceGroupName
                HostPoolType          = 'Pooled'
                LoadBalancerType      = $CurrentHostPool.LoadBalancerType
                PreferredAppGroupType = $CurrentHostPool.PreferredAppGroupType
                MaxSessionLimit       = $CurrentHostPool.MaxSessionLimit
                Location              = $CurrentHostPool.Location
                StartVMOnConnect      = $true
                # From https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files?context=%2Fazure%2Fvirtual-desktop%2Fcontext%2Fcontext#device-redirection
                # No RDP redirection for COM ports, Local Drives and printers.
                ExpirationTime        = $RegistrationInfoExpirationTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
                CustomRdpProperty     = $CustomRdpProperty
                Tag                   = $Tag
                #Verbose               = $true
            }

            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $CurrentAzWvdHostPool = New-AzWvdHostPool @parameters
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating Registration Token (Expiration: '$RegistrationInfoExpirationTime') for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $RegistrationInfoToken = New-AzWvdRegistrationInfo -ResourceGroupName $CurrentHostPoolResourceGroupName -HostPoolName $CurrentHostPool.Name -ExpirationTime $RegistrationInfoExpirationTime -ErrorAction SilentlyContinue

            #region Set up Private Link with Azure Virtual Desktop
            #TODO: https://learn.microsoft.com/en-us/azure/virtual-desktop/private-link-setup?tabs=powershell%2Cportal-2#enable-the-feature
            #endregion

            #region Use Azure Firewall to protect Azure Virtual Desktop deployments
            #TODO: https://learn.microsoft.com/en-us/training/modules/protect-virtual-desktop-deployment-azure-firewall/
            #endregion
            #endregion

            #region Desktop Application Group Setup
            $parameters = @{
                Name                 = "{0}-DAG" -f $CurrentHostPool.Name
                #FriendlyName         = $CurrentHostPool.Name
                ResourceGroupName    = $CurrentHostPoolResourceGroupName
                Location             = $CurrentHostPool.Location
                HostPoolArmPath      = $CurrentAzWvdHostPool.Id
                ApplicationGroupType = 'Desktop'
                ShowInFeed           = $true
                #Verbose              = $true
            }

            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Desktop Application Group for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $CurrentAzDesktopApplicationGroup = New-AzWvdApplicationGroup @parameters

            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating the friendly name of the Desktop for the Desktop Application Group of the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) to '$($CurrentHostPool.Name)'"
            $parameters = @{
                ApplicationGroupName = $CurrentAzDesktopApplicationGroup.Name
                ResourceGroupName    = $CurrentHostPoolResourceGroupName
            }
            $null = Get-AzWvdDesktop @parameters | Update-AzWvdDesktop -FriendlyName $CurrentHostPool.Name

            #region Assign 'Desktop Virtualization User' RBAC role to application groups
            # Get the object ID of the user group you want to assign to the application group
            Do {
                Start-MicrosoftEntraIDConnectSync
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                Start-Sleep -Seconds 30
                $AzADGroup = $null
                #$AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolDAGUsersAzADGroupName
                $AzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$CurrentHostPoolDAGUsersAzADGroupName'"
            } While (-not($AzADGroup.Id))

            # Assign users to the application group
            $parameters = @{
                ObjectId           = $AzADGroup.Id
                ResourceName       = $CurrentAzDesktopApplicationGroup.Name
                ResourceGroupName  = $CurrentHostPoolResourceGroupName
                RoleDefinitionName = 'Desktop Virtualization User'
                ResourceType       = 'Microsoft.DesktopVirtualization/applicationGroups'
                #Verbose            = $true
            }

            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($parameters.RoleDefinitionName)' RBAC role to '$CurrentHostPoolDAGUsersAzADGroupName' AD Group on the Desktop Application Group (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $null = New-AzRoleAssignment @parameters
            #endregion 

            #endregion

            #region Remote Application Group Setup
            $parameters = @{
                Name                 = "{0}-RAG" -f $CurrentHostPool.Name
                ResourceGroupName    = $CurrentHostPoolResourceGroupName
                Location             = $CurrentHostPool.Location
                HostPoolArmPath      = $CurrentAzWvdHostPool.Id
                ApplicationGroupType = 'RemoteApp'
                ShowInFeed           = $true
                #Verbose              = $true
            }

            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Remote Application Group for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $CurrentAzRemoteApplicationGroup = New-AzWvdApplicationGroup @parameters

            #region Assign required RBAC role to application groups
            # Get the object ID of the user group you want to assign to the application group
            Do {
                Start-MicrosoftEntraIDConnectSync
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                Start-Sleep -Seconds 30
                $AzADGroup = $null
                #$AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolRAGUsersADGroupName
                $AzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$CurrentHostPoolRAGUsersADGroupName'"
            } While (-not($AzADGroup.Id))

            # Assign users to the application group
            $parameters = @{
                ObjectId           = $AzADGroup.Id
                ResourceName       = $CurrentAzRemoteApplicationGroup.Name
                ResourceGroupName  = $CurrentHostPoolResourceGroupName
                RoleDefinitionName = 'Desktop Virtualization User'
                ResourceType       = 'Microsoft.DesktopVirtualization/applicationGroups'
                #Verbose            = $true
            }

            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($parameters.RoleDefinitionName)' RBAC role to '$CurrentHostPoolRAGUsersADGroupName' AD Group on the Remote Application Group (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $null = New-AzRoleAssignment @parameters
            #endregion 

            #endregion

            #region Workspace Setup
            $Options = $CurrentHostPool.Location, $CurrentHostPool.Type, $CurrentHostPool.IdentityProvider
            if ($CurrentHostPool.VMSourceImageId) {
                $Options += 'Azure Compte Gallery'
            }
            else {
                $Options += 'Market Place'
            }
            if ($CurrentHostPool.FSLogixCloudCache) {
                $Options += 'FSLogix Cloud Cache'
            }
            elseif ($CurrentHostPool.FSLogix) {
                $Options += 'FSLogix'
            }
            if ($CurrentHostPool.MSIX) {
                $Options += 'MSIX'
            }
            if ($CurrentHostPool.AppAttach) {
                $Options += 'AppAttach'
            }
            if ($CurrentHostPool.Intune) {
                $Options += 'Intune'
            }
            if ($CurrentHostPool.Spot) {
                $Options += 'Spot'
            }
            if ($CurrentHostPool.DiffDiskPlacement -eq [DiffDiskPlacement]::CacheDisk) {
                $Options += 'Ephemeral OS Disk: CacheDisk'
            }
            elseif ($CurrentHostPool.DiffDiskPlacement -eq [DiffDiskPlacement]::ResourceDisk) {
                $Options += 'Ephemeral OS Disk: ResourceDisk'
            } 
            if ($CurrentHostPool.ASRFailOverVNetId) {
                $Options += 'Azure Site Recovery'
            }
            if ($CurrentHostPool.Watermarking) {
                $Options += 'Watermarking'
            }

            $FriendlyName = "{0} ({1})" -f $CurrentHostPool.GetAzAvdWorkSpaceName(), $($Options -join ', ')
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FriendlyName: $FriendlyName"

            if ($CurrentHostPool.PreferredAppGroupType -eq "Desktop") {
                $ApplicationGroupReference = $CurrentAzDesktopApplicationGroup.Id
            }
            else {
                $ApplicationGroupReference = $CurrentAzRemoteApplicationGroup.Id
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ApplicationGroupReference: $($ApplicationGroupReference -join ', ')"

            $parameters = @{
                Name                      = $CurrentHostPool.GetAzAvdWorkSpaceName()
                FriendlyName              = $FriendlyName
                ResourceGroupName         = $CurrentHostPoolResourceGroupName
                ApplicationGroupReference = $ApplicationGroupReference
                Location                  = $CurrentHostPool.Location
                #Verbose                   = $true
            }

            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the WorkSpace for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $CurrentAzWvdWorkspace = New-AzWvdWorkspace @parameters
            #endregion

            if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
                #region Creating a dynamic device group for our AVD hosts
                $DisplayName = "{0} - Devices" -f $CurrentHostPool.Name
                $Description = "Dynamic device group for our AVD hosts for the {0} HostPool." -f $CurrentHostPool.Name
                $MailNickname = $($DisplayName -replace "\s").ToLower()
                $MembershipRule = "(device.displayName -startsWith ""$($CurrentHostPool.NamePrefix)-"")"
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzADDeviceDynamicGroup:`r`n$($AzADDeviceDynamicGroup | Out-String)"
                #$AzADDeviceDynamicGroup = New-AzADGroup -DisplayName $DisplayName -Description $Description -MembershipRule $MembershipRule -MembershipRuleProcessingState "On" -GroupType "DynamicMembership" -MailNickname $MailNickname -SecurityEnabled
                $AzADDeviceDynamicGroup = New-MgBetaGroup -DisplayName $DisplayName -Description $Description -MembershipRule $MembershipRule -MembershipRuleProcessingState "On" -GroupTypes "DynamicMembership" -MailEnabled:$False -MailNickname $MailNickname -SecurityEnabled
                #endregion
                if ($CurrentHostPool.Intune) {
                    Update-PsAvdMgBetaPolicyMobileDeviceManagementPolicy -GroupId $AzADDeviceDynamicGroup.Id
                }
            }

           
            #region Adding Session Hosts to the Host Pool
            #$Status = @{ $true = "Enabled"; $false = "Disabled" }
            $NextSessionHostNames = Get-PsAvdNextSessionHostName -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentHostPool.NamePrefix -VMNumberOfInstances $CurrentHostPool.VMNumberOfInstances
            if (-not([String]::IsNullOrEmpty($CurrentHostPool.VMSourceImageId))) {
                #We propagate the AsJob context to the child function
                Add-PsAvdSessionHost -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentHostPool.NamePrefix -VMNumberOfInstances $CurrentHostPool.VMNumberOfInstances -KeyVault $CurrentHostPool.KeyVault -RegistrationInfoToken $RegistrationInfoToken.Token -SubnetId $CurrentHostPool.SubnetId -DomainName $DomainName -OUPath $CurrentHostPoolOU.DistinguishedName -VMSize $CurrentHostPool.VMSize -VMSourceImageId $CurrentHostPool.VMSourceImageId -DiffDiskPlacement $CurrentHostPool.DiffDiskPlacement -Tag $Tag -IsMicrosoftEntraIdJoined:$CurrentHostPool.IsMicrosoftEntraIdJoined() -Spot:$CurrentHostPool.Spot -HibernationEnabled:$CurrentHostPool.HibernationEnabled -Intune:$CurrentHostPool.Intune -LogDir $LogDir -AsJob #:$AsJob
            }
            else {
                #We propagate the AsJob context to the child function
                Add-PsAvdSessionHost -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentHostPool.NamePrefix -VMNumberOfInstances $CurrentHostPool.VMNumberOfInstances -KeyVault $CurrentHostPool.KeyVault -RegistrationInfoToken $RegistrationInfoToken.Token -SubnetId $CurrentHostPool.SubnetId -DomainName $DomainName -OUPath $CurrentHostPoolOU.DistinguishedName -VMSize $CurrentHostPool.VMSize -DiffDiskPlacement $CurrentHostPool.DiffDiskPlacement -ImagePublisherName $CurrentHostPool.ImagePublisherName -ImageOffer $CurrentHostPool.ImageOffer -ImageSku $CurrentHostPool.ImageSku -Tag $Tag -IsMicrosoftEntraIdJoined:$CurrentHostPool.IsMicrosoftEntraIdJoined() -Spot:$CurrentHostPool.Spot -HibernationEnabled:$CurrentHostPool.HibernationEnabled -Intune:$CurrentHostPool.Intune -LogDir $LogDir -AsJob #:$AsJob
            }

            #region Pester Tests for Azure Host Pool Session Host - Azure Instantiation
            $ModuleBase = Get-ModuleBase
            $PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
            #$PesterDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'Pester'
            $HostPoolSessionHostAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'HostPool.SessionHost.Azure.Tests.ps1'
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$HostPoolSessionHostAzurePesterTests: $HostPoolSessionHostAzurePesterTests"
            $Container = New-PesterContainer -Path $HostPoolSessionHostAzurePesterTests -Data @{ HostPool = $CurrentHostPool; SessionHostName = $NextSessionHostNames }
            Invoke-Pester -Container $Container -Output Detailed -Verbose
            #endregion

            $SessionHosts = Get-AzWvdSessionHost -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            $SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
            #endregion 

            if (($CurrentHostPool.IsMicrosoftEntraIdJoined()) -and ($CurrentHostPool.FSLogix)) {
                #region Configuring the session hosts

                #region Configuring the clients to retrieve Kerberos tickets
                # From https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-powershell#configure-the-clients-to-retrieve-kerberos-tickets
                # From https://learn.microsoft.com/en-us/azure/virtual-desktop/create-profile-container-azure-ad#configure-the-session-hosts
                #$LocalAdminUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminUserName -AsPlainText
                $LocalAdminCredential = Get-LocalAdminCredential -KeyVault $CurrentHostPool.KeyVault
                $LocalAdminUserName = $LocalAdminCredential.UserName
                foreach ($CurrentSessionHostName in $SessionHostNames) {
                    $ScriptString = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "CloudKerberosTicketRetrievalEnabled" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1'
                    # Run PowerShell script on the VM
                    $Result = Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptString $ScriptString
                    Write-Verbose -Message $("{0}:`r`n{1}" -f $ScriptString, ($Result | Out-String))
                    #endregion

                    #region Excluding Administrators from FSLogix
                    #$ScriptString = "Add-LocalGroupMember -Group 'FSLogix Profile Exclude List' -Member $LocalAdminUserName -ErrorAction Ignore; Add-LocalGroupMember -Group 'FSLogix ODFC Exclude List' -Member $LocalAdminUserName -ErrorAction Ignore"
                    #$ScriptString = "Add-LocalGroupMember -Group 'FSLogix Profile Exclude List' -Member Administrators -ErrorAction Ignore; Add-LocalGroupMember -Group 'FSLogix ODFC Exclude List' -Member Administrators -ErrorAction Ignore"
                    $ScriptString = "Add-LocalGroupMember -Group 'FSLogix Profile Exclude List' -Member $LocalAdminUserName, Administrators -ErrorAction Ignore; Add-LocalGroupMember -Group 'FSLogix ODFC Exclude List' -Member $LocalAdminUserName, Administrators -ErrorAction Ignore"
                    # Run PowerShell script on the VM
                    $Result = Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptString $ScriptString
                    Write-Verbose -Message $("{0}:`r`n{1}" -f $ScriptString, ($Result | Out-String))
                    #endregion

                    #region For loading your profile on many different VMs instead of being limited to just one
                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/create-profile-container-azure-ad#configure-the-session-hosts
                    $ScriptString = '$null = New-Item -Path "HKLM:\Software\Policies\Microsoft\AzureADAccount" -Force; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\AzureADAccount" -Name "LoadCredKeyFromProfile" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1'
                    # Run PowerShell script on the VM
                    $Result = Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptString $ScriptString
                    Write-Verbose -Message $("{0}:`r`n{1}" -f $ScriptString, ($Result | Out-String))
                    #endregion
                }
                #endregion

                if (-not($CurrentHostPool.Intune)) {
                    foreach ($CurrentSessionHostName in $SessionHostNames) {
                        #region AVD Global Settings FSLogix
                        #region AVD Global Settings FSLogix - Registry
                        # Run PowerShell script on the VM
                        #$URI = "https://raw.githubusercontent.com/lavanack/PSAzureVirtualDesktop/master/src/PSAzureVirtualDesktop/HelperScripts/Set-AVDRegistryItemProperty.ps1"
                        #$ScriptPath = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $URI -Leaf)
                        $ModuleBase = Get-ModuleBase
                        $ScriptPath = Join-Path -Path $ModuleBase -ChildPath "HelperScripts\Set-AVDRegistryItemProperty.ps1"
                        $Result = Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptPath $ScriptPath -Parameter @{Watermarking = $CurrentHostPool.Watermarking}
                        Write-Verbose -Message $("{0}:`r`n{1}" -f $ScriptPath, ($Result | Out-String))
                        #Remove-Item -Path $ScriptPath -Force
                        #endregion
                        #endregion

                        #region Configuring FSLogix
                        #region Configuring FSLogix - Registry
                        # Run PowerShell script on the VM
                        #$URI = "https://raw.githubusercontent.com/lavanack/PSAzureVirtualDesktop/master/src/PSAzureVirtualDesktop/HelperScripts/Set-FSLogixRegistryItemProperty.ps1"
                        #$ScriptPath = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $URI -Leaf)
                        $ModuleBase = Get-ModuleBase
                        $ScriptPath = Join-Path -Path $ModuleBase -ChildPath "HelperScripts\Set-FSLogixRegistryItemProperty.ps1"
                        $Result = Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptPath $ScriptPath -Parameter @{HostPoolStorageAccountName = $CurrentHostPoolStorageAccountName }
                        Write-Verbose -Message $("{0}:`r`n{1}" -f $ScriptPath, ($Result | Out-String))
                        #Remove-Item -Path $ScriptPath -Force
                        #endregion
                        #endregion

                        <#
                        #region Configuring the clients to disable FSLogix
                        $ScriptString = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\FSLogix\Profiles' -Name 'Enabled' -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 0"
                        # Run PowerShell script on the VM
                        $null = Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptString $ScriptString
                        #endregion
                        #>
                    }
                }
                else {
                    #From https://smbtothecloud.com/azure-ad-joined-avd-with-fslogix-aad-kerberos-authentication/
                    #From https://andrewstaylor.com/2021/06/18/configuring-fslogix-without-gpo-part-1/
                    #From https://msendpointmgr.com/2019/01/17/use-intune-graph-api-export-and-import-intune-admx-templates/
                    #From https://msendpointmgr.com/2018/10/17/configure-admx-settings-with-microsoft-intune-administrative-templates/
                    #From https://incas-training.de/blog/azure-virtual-desktop-teil-3-user-profil-management-mit-fslogix-konfiguration/
                    #From https://github.com/microsoftgraph/powershell-intune-samples/tree/master/DeviceConfiguration

                    #region Intune Configuration Profile - Settings Catalog
                    #region AVD Global Settings FSLogix - Intune Configuration Profile - Settings Catalog
                    New-PsAvdAvdIntuneSettingsCatalogConfigurationPolicyViaGraphAPI -HostPoolStorageAccountName $CurrentHostPool.GetFSLogixStorageAccountName() -HostPoolName $CurrentHostPool.Name -Watermarking:$CurrentHostPool.Watermarking
                    #endregion

                    #region Configuring FSLogix - Intune Configuration Profile - Settings Catalog
                    New-PsAvdFSLogixIntuneSettingsCatalogConfigurationPolicyViaGraphAPI -HostPoolStorageAccountName $CurrentHostPool.GetFSLogixStorageAccountName() -HostPoolName $CurrentHostPool.Name -HostPoolRecoveryLocationStorageAccountName $CurrentHostPool.GetRecoveryLocationFSLogixStorageAccountName()
                    #endregion
                    #endregion

                    <#
                    #If you use Windows 10, version 1809 or later or Windows Server 2019 or later, you won't need to enable the registry key.
                    #Enabling New Performance Counters
                    #New-PsAvdIntunePowerShellScriptViaCmdlet -ScriptURI 'https://raw.githubusercontent.com/lavanack/PSAzureVirtualDesktop/master/src/PSAzureVirtualDesktop/HelperScripts/Enable-NewPerformanceCounter.ps1' -HostPoolName $CurrentHostPool.Name
                    $ModuleBase = Get-ModuleBase
                    $ScriptPath = Join-Path -Path $ModuleBase -ChildPath "HelperScripts\Enable-NewPerformanceCounter.ps1"
                    New-PsAvdIntunePowerShellScriptViaCmdlet -ScriptPath $ScriptPath -HostPoolName $CurrentHostPool.Name
                    #>
                }
            }

            #region Restarting the Session Hosts
            $Jobs = foreach ($CurrentSessionHostName in $SessionHostNames) {
                Restart-AzVM -Name $CurrentSessionHostName -ResourceGroupName $CurrentHostPoolResourceGroupName -Confirm:$false -AsJob
            }
            $Jobs | Wait-Job | Out-Null
            $Jobs | Remove-Job -Force
            #endregion 

            #region MSIX
            #No EntraID and MSIX : https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-overview?pivots=msix-app-attach#identity-providers
            if ($CurrentHostPool.IsActiveDirectoryJoined() -and ($CurrentHostPool.MSIX -or $CurrentHostPool.AppAttach)) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentHostPool : $($CurrentHostPool.Name)"
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SessionHostNames : $($SessionHostNames -join ',')"

                if ($CurrentHostPool.IsActiveDirectoryJoined()) {
                    #Adding the Session Hosts to the dedicated ADGroup for MSIX 
                    #$SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
                    #$SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
                    #Adding Session Hosts to the dedicated AD MSIX Host group
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding the Session Hosts Session Hosts to the '$($CurrentHostPoolMSIXHostsADGroup.Name)' AD Group"
                    $CurrentHostPoolMSIXHostsADGroup | Add-ADGroupMember -Members $($SessionHostNames | Get-ADComputer).DistinguishedName
                    Start-MicrosoftEntraIDConnectSync
                    #Copying, Installing the MSIX Demo PFX File(s) (for signing MSIX Packages) on Session Host(s)
                    #$result = Wait-PSSession -ComputerName $SessionHostNames
                    #Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$result: $result"
                    Copy-PsAvdMSIXDemoPFXFile -Source WebSite -ComputerName $SessionHostNames
                    #Copy-PsAvdMSIXDemoPFXFile -Source WebSite -HostPool $CurrentHostPool

                    #region Disabling the "\Microsoft\Windows\WindowsUpdate\Scheduled Start" Scheduled Task on Session Host(s)
                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-azure-portal#turn-off-automatic-updates-for-msix-app-attach-applications
                    $null = Disable-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsUpdate\" -TaskName "Scheduled Start" -CimSession $SessionHostNames
                    #endregion 
                }
                <#
                else {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($CurrentHostPool.Name)' is not AD joined"

                    $SessionHosts = Get-AzWvdSessionHost -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
                    $VM = $SessionHosts.ResourceId | Get-AzVM
                    
                    #$LocalAdminUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminUserName -AsPlainText
                    #$LocalAdminPassword = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminPassword).SecretValue
                    #$LocalAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($LocalAdminUserName, $LocalAdminPassword)

                    $LocalAdminCredential = Get-LocalAdminCredential -KeyVault $CurrentHostPool.KeyVault

                    $PrivateIpAddress = $VM | ForEach-Object -Process {
                        $NIC = Get-AzNetworkInterface -Name $($_.NetworkProfile.NetworkInterfaces.Id -replace ".*/")
                        $NIC.IpConfigurations.PrivateIPAddress
                    }
                    #Backing up the trustedhosts value before modifying it
                    $Trustedhosts = (Get-Item -Path WSMan:localhost\client\trustedhosts).Value
                    Set-Item -Path WSMan:localhost\client\trustedhosts -Value $($PrivateIpAddress -join ",") -Force

                    #Copying, Installing the MSIX Demo PFX File(s) (for signing MSIX Packages) on Session Host(s)
                    #$result = Wait-PSSession -ComputerName $SessionHostNames
                    #Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$result: $result"
                    Copy-PsAvdMSIXDemoPFXFile -Source WebSite -ComputerName $PrivateIpAddress -Credential $LocalAdminCredential

                    #region Disabling the "\Microsoft\Windows\WindowsUpdate\Scheduled Start" Scheduled Task on Session Host(s)
                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-azure-portal#turn-off-automatic-updates-for-msix-app-attach-applications
                    $CimSession = New-CimSession -ComputerName $PrivateIpAddress -Credential $LocalAdminCredential
                    $null = Disable-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsUpdate\" -TaskName "Scheduled Start" -CimSession $CimSession
                    #endregion 

                    #Restoring the previous trustedhosts value
                    Set-Item -Path WSMan:localhost\client\trustedhosts -Value $Trustedhosts -Force
                }
                #>
                #region Restarting the Session Hosts
                $Jobs = foreach ($CurrentSessionHostName in $SessionHostNames) {
                    Restart-AzVM -Name $CurrentSessionHostName -ResourceGroupName $CurrentHostPoolResourceGroupName -Confirm:$false -AsJob
                }
                $Jobs | Wait-Job | Out-Null
                $Jobs | Remove-Job -Force
                #endregion 

                #region MSIX
                if ($CurrentHostPool.IsActiveDirectoryJoined() -and $CurrentHostPool.MSIX) {
                    #region Adding the MSIX package(s) to the Host Pool
                    #Adding a script property to keep only the Application name (using the Basename property with the naming convention AppName_x.y.z.vhdx where x.y.z is the version number)
                    $MSIXDemoPackages | Add-Member -MemberType ScriptProperty -Name AppName -Value { $this.BaseName -replace "_.*$" } -Force
                    #Keeping only the highest version per MSI packages (only one possible version per application with MSIX)
                    $HighestVersionMSIXDemoPackages = $MSIXDemoPackages | Sort-Object -Property BaseName -Descending  | Sort-Object -Property AppName -Unique
                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-powershell
                    foreach ($CurrentMSIXDemoPackage in $HighestVersionMSIXDemoPackages) {
                        $obj = $null
                        While ($null -eq $obj) {
                            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Expanding MSIX Image '$CurrentMSIXDemoPackage'"
                            #Temporary Allowing storage account key access(disabled due to SFI)
                            $null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPool.GetFSLogixStorageAccountName() -AllowSharedKeyAccess $true
                            $MyError = $null
                            #$obj = Expand-PsAvdMSIXImage -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName -Uri $CurrentMSIXDemoPackage
                            $obj = Expand-AzWvdMsixImage -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName -Uri $CurrentMSIXDemoPackage -ErrorAction Ignore -ErrorVariable MyError
                            if (($null -eq $obj)) {
                                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Error Message: $($MyError.Exception.Message)"
                                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                                Start-Sleep -Seconds 30
                            }
                            #Not Allowing storage account key access (SFI compliant)
                            #$null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -AllowSharedKeyAccess $false
                        }

                        $DisplayName = "{0} (v{1})" -f $obj.PackageApplication.FriendlyName, $obj.Version
                        #$DisplayName = $obj.PackageApplication.FriendlyName
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding MSIX Image '$CurrentMSIXDemoPackage' as '$DisplayName'..."
                        New-AzWvdMsixPackage -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName -PackageAlias $obj.PackageAlias -DisplayName $DisplayName -ImagePath $CurrentMSIXDemoPackage -IsActive:$true
                        #Get-AzWvdMsixPackage -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName | Where-Object {$_.PackageFamilyName -eq $obj.PackageFamilyName}
                    }
                    #endregion 

                    #region Publishing MSIX apps to application groups
                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-powershell#publish-msix-apps-to-an-application-group
                    #Publishing MSIX application to a desktop application group
                    $SubscriptionId = $AzContext.Subscription.Id
                    $null = New-AzWvdApplication -ResourceGroupName $CurrentHostPoolResourceGroupName -SubscriptionId $SubscriptionId -Name $obj.PackageName -ApplicationType MsixApplication -ApplicationGroupName $CurrentAzDesktopApplicationGroup.Name -MsixPackageFamilyName $obj.PackageFamilyName -CommandLineSetting 0
            
                    #Publishing MSIX application to a RemoteApp application group
                    $null = New-AzWvdApplication -ResourceGroupName $CurrentHostPoolResourceGroupName -SubscriptionId $SubscriptionId -Name $obj.PackageName -ApplicationType MsixApplication -ApplicationGroupName $CurrentAzRemoteApplicationGroup.Name -MsixPackageFamilyName $obj.PackageFamilyName -CommandLineSetting 0 -MsixPackageApplicationId $obj.PackageApplication.AppId
                    #endregion 
                }

                #Creating a Private EndPoint for this Storage Account on the HostPool Subnet and the Subnet used by this DC
                New-PsAvdPrivateEndpointSetup -SubnetId $CurrentHostPool.SubnetId, $ThisDomainControllerSubnet.Id -StorageAccount $CurrentHostPoolStorageAccount
                #endregion

                #region AppAttach
                if ($CurrentHostPool.IsActiveDirectoryJoined() -and $CurrentHostPool.AppAttach) {
                    #region Adding the application(s) to the Host Pool

                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-powershell
                    foreach ($CurrentMSIXDemoPackage in $MSIXDemoPackages) {
                        $app = $null
                        While ($null -eq $app) {
                            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] AppAttach: Importing MSIX Image '$CurrentMSIXDemoPackage'"
                            #Temporary Allowing storage account key access(disabled due to SFI)
                            $null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPool.GetFSLogixStorageAccountName() -AllowSharedKeyAccess $true
                            $MyError = $null
                            $app = Import-AzWvdAppAttachPackageInfo -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName -Path $CurrentMSIXDemoPackage -ErrorAction Ignore -ErrorVariable MyError
                            if (($null -eq $app)) {
                                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Error Message: $($MyError.Exception.Message)"
                                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                                Start-Sleep -Seconds 30
                            }
                            #Not Allowing storage account key access (SFI compliant)
                            #$null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -AllowSharedKeyAccess $false
                        }

                        if (-not(Get-AzWvdAppAttachPackage | Where-Object -FilterScript { $_.Name -eq $app.ImagePackageAlias })) {
                            #if (-not(Get-AzWvdAppAttachPackage -Name $app.ImagePackageAlias -ResourceGroupName $CurrentHostPoolResourceGroupName -ErrorAction Ignore)) {
                            $DisplayName = "{0} (v{1})" -f $app.ImagePackageApplication.FriendlyName, $app.ImageVersion
                            #$DisplayName = "{0}" -f $app.ImagePackageApplication.FriendlyName
                            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] AppAttach: Adding MSIX Image '$CurrentMSIXDemoPackage' as '$DisplayName' ..."
                            $parameters = @{
                                Name                            = $app.ImagePackageAlias
                                ResourceGroupName               = $CurrentHostPoolResourceGroupName
                                Location                        = $CurrentHostPool.Location
                                FailHealthCheckOnStagingFailure = 'NeedsAssistance'
                                ImageIsRegularRegistration      = $false
                                ImageDisplayName                = $DisplayName
                                ImageIsActive                   = $true
                            }
                            New-AzWvdAppAttachPackage -AppAttachPackage $app @parameters
                            #Get-AzWvdAppAttachPackage -Name $app.ImagePackageAlias -ResourceGroupName $CurrentHostPoolResourceGroupName
                        }

                        #region Assigning an app attach package
                        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-setup?tabs=powershell&pivots=app-attach#assign-an-app-attach-package
                        #region Host pools
                        $AzWvdHostPool = Get-AzWvdHostPool -Name $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
                        $parameters = @{
                            Name              = $app.ImagePackageAlias
                            ResourceGroupName = $CurrentHostPoolResourceGroupName
                            HostPoolReference = $AzWvdHostPool.Id
                        }

                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] AppAttach: Assigning the MSIX Image '$CurrentMSIXDemoPackage' to the '$($CurrentHostPool.Name)' HostPool ..."
                        Update-AzWvdAppAttachPackage @parameters
                        #endregion

                        #region Groups and users
                        $parameters = @{
                            Name              = $app.ImagePackageAlias
                            ResourceGroupName = $CurrentHostPoolResourceGroupName
                        }

                        $appAttachPackage = Get-AzWvdAppAttachPackage @parameters
                        $CurrentHostPoolDAGUsersAzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$CurrentHostPoolDAGUsersAzADGroupName'"
                        foreach ($objId in $CurrentHostPoolDAGUsersAzADGroup.Id) {
                            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] AppAttach: Assigning the MSIX Image '$CurrentMSIXDemoPackage' to the '$($CurrentHostPool.Name)' HostPool ..."
                            New-AzRoleAssignment -ObjectId $objId -RoleDefinitionName "Desktop Virtualization User" -Scope $appAttachPackage.Id
                        }
                        #endregion
                        #endregion

                        #region Publishing AppAttach application to a RemoteApp application group
                        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-setup?tabs=powershell&pivots=app-attach#publish-an-msix-or-appx-application-with-a-remoteapp-application-group
                        if ($CurrentHostPool.PreferredAppGroupType -eq "RailApplications") {
                            $null = New-AzWvdApplication -ResourceGroupName $CurrentHostPoolResourceGroupName -SubscriptionId $SubscriptionId -Name $app.ImagePackageName -ApplicationType MsixApplication -ApplicationGroupName $CurrentAzRemoteApplicationGroup.Name -MsixPackageFamilyName $app.ImagePackageFamilyName -CommandLineSetting 0 -MsixPackageApplicationId $app.ImagePackageApplication.AppId
                        }
                        #endregion 

                    }
                    #endregion 
                }
                #endregion
            }
            else {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] MSIX AppAttach Or Azure AppAttach NOT enabled for '$($CurrentHostPool.Name)' HostPool"
            }
            #endregion

            #region Adding Some Apps in the Remote Application Group
            #$RemoteApps = "Edge","Excel"
            #$SelectedAzWvdStartMenuItem = (Get-AzWvdStartMenuItem -ApplicationGroupName $CurrentAzRemoteApplicationGroup.Name -ResourceGroupName $CurrentHostPoolResourceGroupName | Where-Object -FilterScript {$_.Name -match $($RemoteApps -join '|')} | Select-Object -Property *)
            
            #2 Random Applications
            $result = Wait-PsAvdRunPowerShell -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            try {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Picking up 2 Start Menu applications (for RemoteApp) in the '$($CurrentAzRemoteApplicationGroup.Name)' Application Group"
                $SelectedAzWvdStartMenuItem = Get-AzWvdStartMenuItem -ApplicationGroupName $CurrentAzRemoteApplicationGroup.Name -ResourceGroupName $CurrentHostPoolResourceGroupName -ErrorAction Stop | Get-Random -Count 2
            }
            catch {
                Write-Warning -Message "Unable to get a Start Menu application (for RemoteApp) in the '$($CurrentAzRemoteApplicationGroup.Name)' Application Group"
                Write-Warning -Message "Exception: $($_ | Out-String)"
            }
            $AzWvdApplications = foreach ($CurrentAzWvdStartMenuItem in $SelectedAzWvdStartMenuItem) {
                #$Name = $CurrentAzWvdStartMenuItem.Name -replace "(.*)/"
                $Name = $CurrentAzWvdStartMenuItem.Name -replace "$($CurrentAzRemoteApplicationGroup.Name)/"
                try {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding the '$($CurrentAzRemoteApplicationGroup.Name)' Start Menu applications (for RemoteApp) in the '$($CurrentAzRemoteApplicationGroup.Name)' Application Group"
                    New-AzWvdApplication -AppAlias $CurrentAzWvdStartMenuItem.appAlias -GroupName $CurrentAzRemoteApplicationGroup.Name -Name $Name -ResourceGroupName $CurrentHostPoolResourceGroupName -CommandLineSetting DoNotAllow
                }
                catch {
                    Write-Warning -Message "Unable to add '$($CurrentAzWvdStartMenuItem.appAlias)' application as Remoteapp in the '$($CurrentAzRemoteApplicationGroup.Name)' Application Group"
                }
            }
            #endregion

            #region Log Analytics WorkSpace Setup : Monitor and manage performance and health
            #From https://learn.microsoft.com/en-us/training/modules/monitor-manage-performance-health/3-log-analytics-workspace-for-azure-monitor
            #From https://www.rozemuller.com/deploy-azure-monitor-for-windows-virtual-desktop-automated/#update-25-03-2021
            $LogAnalyticsWorkSpaceName = $CurrentHostPool.GetLogAnalyticsWorkSpaceName()
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Log Analytics WorkSpace '$($LogAnalyticsWorkSpaceName)' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $LogAnalyticsWorkSpace = New-AzOperationalInsightsWorkspace -Location $CurrentHostPool.Location -Name $LogAnalyticsWorkSpaceName -Sku pergb2018 -ResourceGroupName $CurrentHostPoolResourceGroupName -Force


            #region Enabling Diagnostics Setting for the HostPool
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Enabling Diagnostics Setting for the '$($CurrentAzWvdHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            #$HostPoolDiagnosticSetting = Set-AzDiagnosticSetting -Name $CurrentAzWvdHostPool.Name -ResourceId $CurrentAzWvdHostPool.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Enabled $true -Category "Checkpoint", "Error", "Management", "Connection", "HostRegistration", "AgentHealthStatus"
            <#
            $Categories = "Checkpoint", "Error", "Management", "Connection", "HostRegistration", "AgentHealthStatus", "NetworkData", "AutoscaleEvaluationPooled"
            $Log = $Categories | ForEach-Object {
                New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category $_ 
            }
            #>
            $Log = New-AzDiagnosticSettingLogSettingsObject -Enabled $true -CategoryGroup allLogs 
            $HostPoolDiagnosticSetting = New-AzDiagnosticSetting -Name $CurrentAzWvdHostPool.Name -ResourceId $CurrentAzWvdHostPool.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Log $Log
            #endregion

            #region Enabling Diagnostics Setting for the WorkSpace
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Enabling Diagnostics Setting for the '$($CurrentAzWvdWorkspace.Name)' Work Space"
            <#
            $Categories = "Checkpoint", "Error", "Management", "Feed"
            $Log = $Categories | ForEach-Object {
                New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category $_ 
            }
            #>
            $Log = New-AzDiagnosticSettingLogSettingsObject -Enabled $true -CategoryGroup allLogs 
            $WorkSpaceDiagnosticSetting = New-AzDiagnosticSetting -Name $CurrentAzWvdWorkspace.Name -ResourceId $CurrentAzWvdWorkspace.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Log $Log
            #endregion

            #region Enabling Diagnostics Setting for the Desktop Application Group
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Enabling Diagnostics Setting for the '$($CurrentAzDesktopApplicationGroup.Name)' Work Space"
            <#
            $Categories = "Checkpoint", "Error", "Management"
            $Log = $Categories | ForEach-Object {
                New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category $_ 
            }
            #>
            $Log = New-AzDiagnosticSettingLogSettingsObject -Enabled $true -CategoryGroup allLogs 
            $DesktopApplicationGroupDiagnosticSetting = New-AzDiagnosticSetting -Name $CurrentAzDesktopApplicationGroup.Name -ResourceId $CurrentAzDesktopApplicationGroup.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Log $Log
            #endregion

            #region Enabling Diagnostics Setting for the Remote Application Group
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Enabling Diagnostics Setting for the '$($CurrentAzRemoteApplicationGroup.Name)' Work Space"
            <#
            $Categories = "Checkpoint", "Error", "Management"
            $Log = $Categories | ForEach-Object {
                New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category $_ 
            }
            #>
            $Log = New-AzDiagnosticSettingLogSettingsObject -Enabled $true -CategoryGroup allLogs 
            $RemoteApplicationGroupDiagnosticSetting = New-AzDiagnosticSetting -Name $CurrentAzRemoteApplicationGroup.Name -ResourceId $CurrentAzRemoteApplicationGroup.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Log $Log
            #endregion
            #endregion

            #region Installing Azure Monitor Windows Agent on Virtual Machine(s)
            #$SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            if (-not([string]::IsNullOrEmpty($SessionHosts.ResourceId))) {
                $SessionHostVMs = $SessionHosts.ResourceId | Get-AzVM
                $Jobs = foreach ($CurrentSessionHostVM in $SessionHostVMs) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Installing AzureMonitorWindowsAgent on the '$($CurrentSessionHostVM.Name)' Virtual Machine (in the '$CurrentHostPoolResourceGroupName' Resource Group) (As A Job)"
                    $ExtensionName = "AzureMonitorWindowsAgent_{0:yyyyMMddHHmmss}" -f (Get-Date)
                    $Params = @{
                        Name                   = $ExtensionName 
                        ExtensionType          = 'AzureMonitorWindowsAgent'
                        Publisher              = 'Microsoft.Azure.Monitor' 
                        VMName                 = $CurrentSessionHostVM.Name
                        ResourceGroupName      = $CurrentHostPoolResourceGroupName
                        Location               = $CurrentHostPool.Location
                        TypeHandlerVersion     = '1.0' 
                        EnableAutomaticUpgrade = $true
                        AsJob                  = $true
                    }
                    Set-AzVMExtension  @Params
                }
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting all jobs completes"
                $Jobs | Wait-Job | Out-Null
                $Jobs | Remove-Job -Force
            }
            #endregion

            <#
            #region Installing Log Analytics Agent on Virtual Machine(s)
            #$SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            if (-not([string]::IsNullOrEmpty($SessionHosts.ResourceId))) {
                $SessionHostVMs = $SessionHosts.ResourceId | Get-AzVM
                $LogAnalyticsWorkSpaceKey = ($LogAnalyticsWorkSpace | Get-AzOperationalInsightsWorkspaceSharedKey).PrimarySharedKey
                $PublicSettings = @{ "workspaceId" = $LogAnalyticsWorkSpace.CustomerId }
                $ProtectedSettings = @{ "workspaceKey" = $LogAnalyticsWorkSpaceKey }
                $Jobs = foreach ($CurrentSessionHostVM in $SessionHostVMs) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Installing Log Analytics Agent on the '$($CurrentSessionHostVM.Name )' Virtual Machine (in the '$CurrentHostPoolResourceGroupName' Resource Group) (As A Job)"
                    Set-AzVMExtension -ExtensionName "MicrosoftMonitoringAgent" -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostVM.Name -Publisher "Microsoft.EnterpriseCloud.Monitoring" -ExtensionType "MicrosoftMonitoringAgent" -Settings $PublicSettings -TypeHandlerVersion "1.0" -ProtectedSettings $ProtectedSettings -Location $CurrentHostPool.Location -AsJob
                }
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting all jobs completes"
                $Jobs | Wait-Job | Out-Null
                $Jobs | Remove-Job -Force
            }
            #endregion
            #>

            #region Data Collection Rules
            #region Event Logs
            #Levels : 1 = Critical, 2 = Error or Failure, 3 = Warning
            $EventLogs = @(
                [PSCustomObject] @{EventLogName = 'Application'; Levels = 1, 2, 3 }
                [PSCustomObject] @{EventLogName = 'System'; Levels = 1, 2, 3 }
                [PSCustomObject] @{EventLogName = 'Security'; Keywords = "4503599627370496" }
                [PSCustomObject] @{EventLogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Levels = 1, 2, 3 }
                [PSCustomObject] @{EventLogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin'; Levels = 1, 2, 3 }
                [PSCustomObject] @{EventLogName = 'Microsoft-FSLogix-Apps/Operational' ; Levels = 1, 2, 3 }
                [PSCustomObject] @{EventLogName = 'Microsoft-FSLogix-Apps/Admin' ; Levels = 1, 2, 3 }
            )
            #Building the XPath for each event log
            $XPathQuery = foreach ($CurrentEventLog in $EventLogs) {
                #Building the required level for each event log
                $Levels = foreach ($CurrentLevel in $CurrentEventLog.Levels) {
                    "Level={0}" -f $CurrentLevel
                }
                "{0}!*[System[($($Levels -join ' or '))]]" -f $CurrentEventLog.EventLogName
            }
            $WindowsEventLogs = New-AzWindowsEventLogDataSourceObject -Name WindowsEventLogsDataSource -Stream Microsoft-Event -XPathQuery $XPathQuery
            #endregion

            #region Performance Counters
            $PerformanceCounters = @(
                [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = '% Free Space'; InstanceName = 'C:'; IntervalSeconds = 60 }
                [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk Queue Length'; InstanceName = 'C:'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk sec/Transfer'; InstanceName = 'C:'; IntervalSeconds = 60 }
                [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Current Disk Queue Length'; InstanceName = 'C:'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'Memory'; CounterName = 'Available Mbytes'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'Memory'; CounterName = 'Page Faults/sec'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'Memory'; CounterName = 'Pages/sec'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'Memory'; CounterName = '% Committed Bytes In Use'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Read'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Transfer'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Write'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk Queue Length'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'Processor Information'; CounterName = '% Processor Time'; InstanceName = '_Total'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'RemoteFX Network'; CounterName = 'Current TCP RTT'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'RemoteFX Network'; CounterName = 'Current UDP Bandwidth'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'Terminal Services'; CounterName = 'Active Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
                [PSCustomObject] @{ObjectName = 'Terminal Services'; CounterName = 'Inactive Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
                [PSCustomObject] @{ObjectName = 'Terminal Services'; CounterName = 'Total Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
                [PSCustomObject] @{ObjectName = 'User Input Delay per Process'; CounterName = 'Max Input Delay'; InstanceName = '*'; IntervalSeconds = 30 }
                [PSCustomObject] @{ObjectName = 'User Input Delay per Session'; CounterName = 'Max Input Delay'; InstanceName = '*'; IntervalSeconds = 30 }
            )
            #Building and Hashtable for each Performance Counters where the key is the sample interval
            $PerformanceCountersHT = $PerformanceCounters | Group-Object -Property IntervalSeconds -AsHashTable -AsString

            $PerformanceCounters = foreach ($CurrentKey in $PerformanceCountersHT.Keys) {
                $Name = "PerformanceCounters{0}" -f $CurrentKey
                #Building the Performance Counter paths for each Performance Counter
                $CounterSpecifier = foreach ($CurrentCounter in $PerformanceCountersHT[$CurrentKey]) {
                    "\{0}({1})\{2}" -f $CurrentCounter.ObjectName, $CurrentCounter.InstanceName, $CurrentCounter.CounterName
                }
                New-AzPerfCounterDataSourceObject -Name $Name -Stream Microsoft-Perf -CounterSpecifier $CounterSpecifier -SamplingFrequencyInSecond $CurrentKey
            }
            #endregion
            <#
            $DataCollectionEndpointName = "dce-{0}" -f $LogAnalyticsWorkSpace.Name
            $DataCollectionEndpoint = New-AzDataCollectionEndpoint -Name $DataCollectionEndpointName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -NetworkAclsPublicNetworkAccess Enabled
            #>
            #From https://www.reddit.com/r/AZURE/comments/1ddac0z/avd_insights_dcr_does_not_appear/?tl=fr
            $DataCollectionRuleName = "microsoft-avdi-{0}" -f $LogAnalyticsWorkSpace.Location
            $DataFlow = New-AzDataFlowObject -Stream Microsoft-InsightsMetrics, Microsoft-Perf, Microsoft-Event -Destination $LogAnalyticsWorkSpace.Name
            $DestinationLogAnalytic = New-AzLogAnalyticsDestinationObject -Name $LogAnalyticsWorkSpace.Name -WorkspaceResourceId $LogAnalyticsWorkSpace.ResourceId
            $DataCollectionRule = New-AzDataCollectionRule -Name $DataCollectionRuleName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -DataFlow $DataFlow -DataSourcePerformanceCounter $PerformanceCounters -DataSourceWindowsEventLog $WindowsEventLogs -DestinationLogAnalytic $DestinationLogAnalytic #-DataCollectionEndpointId $DataCollectionEndpoint.Id
            #endregion

            #region Adding Data Collection Rule Association for every Session Host
            #$DataCollectionRule = Get-AzDataCollectionRule -ResourceGroupName $CurrentHostPoolResourceGroupName -RuleName $DataCollectionRuleName
            $DataCollectionRuleAssociations = foreach ($CurrentSessionHost in $SessionHosts) {
                <#
                $AssociationName = 'configurationAccessEndpoint'
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Associating the '$($DataCollectionEndpoint.Name)' Data Collection Endpoint with the '$($CurrentSessionHost.Name)' Session Host "
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AssociationName: $AssociationName"
                New-AzDataCollectionRuleAssociation -ResourceUri $CurrentSessionHost.ResourceId -AssociationName $AssociationName -DataCollectionEndpointId $DataCollectionEndpoint.Id
                #>
                #$AssociationName = "dcr-{0}" -f $($CurrentSessionHost.ResourceId -replace ".*/").ToLower()
                $AssociationName = "{0}-VMInsights-Dcr-Association" -f $($CurrentSessionHost.ResourceId -replace ".*/").ToLower()
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Associating the '$($DataCollectionRule.Name)' Data Collection Rule with the '$($CurrentSessionHost.Name)' Session Host "
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AssociationName: $AssociationName"
                New-AzDataCollectionRuleAssociation -ResourceUri $CurrentSessionHost.ResourceId -AssociationName $AssociationName -DataCollectionRuleId $DataCollectionRule.Id
            }
            #endregion

            #region Enable VM insights on Virtual Machine(s)
            #From http://aka.ms/OnBoardVMInsights
            #From https://learn.microsoft.com/en-us/azure/azure-monitor/vm/vminsights-enable?tabs=powershell#enable-vm-insights-1
            if (-not(Get-InstalledScript -Name Install-VMInsights)) {
                Install-Script -Name Install-VMInsights -Force
            }
            else {
                Update-Script -Name Install-VMInsights -Force
            }
            $UserAssignedManagedIdentityName = "uami-{0}" -f $CurrentHostPool.Name
            $UserAssignedManagedIdentity = Get-AzUserAssignedIdentity -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $UserAssignedManagedIdentityName -ErrorAction Ignore
            if (-not($UserAssignedManagedIdentity)) {
                $UserAssignedManagedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $UserAssignedManagedIdentityName -Location $CurrentHostPool.Location
            }

            #region Data Collection Rule for VM Insights
            $DataCollectionRuleName = "MSVMI-{0}" -f $LogAnalyticsWorkspaceName
            $DataFlow = New-AzDataFlowObject -Stream Microsoft-InsightsMetrics -Destination $LogAnalyticsWorkspaceName
            $PerformanceCounter = New-AzPerfCounterDataSourceObject -CounterSpecifier "\VmInsights\DetailedMetrics" -Name VMInsightsPerfCounters -SamplingFrequencyInSecond 60 -Stream Microsoft-InsightsMetrics
            #$DestinationLogAnalytic = New-AzLogAnalyticsDestinationObject -Name $LogAnalyticsWorkSpace.Name -WorkspaceResourceId $LogAnalyticsWorkSpace.ResourceId
            $DataCollectionRule = New-AzDataCollectionRule -Name $DataCollectionRuleName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -DataFlow $DataFlow -DataSourcePerformanceCounter $PerformanceCounter -DestinationLogAnalytic $DestinationLogAnalytic
            #endregion


            #$SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            if (-not([string]::IsNullOrEmpty($SessionHosts.ResourceId))) {
                $SessionHostVMs = $SessionHosts.ResourceId | Get-AzVM
                foreach ($CurrentSessionHostVM in $SessionHostVMs) {
                    $Parameters = @{
                        SubscriptionId                           = (Get-AzContext).Subscription.Id
                        ResourceGroup                            = $CurrentHostPoolResourceGroupName
                        Name                                     = $CurrentSessionHostVM.Name
                        DcrResourceId                            = $DataCollectionRule.Id
                        UserAssignedManagedIdentityName          = $UserAssignedManagedIdentity.Name
                        UserAssignedManagedIdentityResourceGroup = $UserAssignedManagedIdentity.ResourceGroupName
                        Approve                                  = $true
                    }
                    Install-VMInsights.ps1 @Parameters
                }
            }
            #endregion 

            $CurrentHostPoolEndTime = Get-Date
            $TimeSpan = New-TimeSpan -Start $CurrentHostPoolStartTime -End $CurrentHostPoolEndTime
            Write-Host -Object "'$($CurrentHostPool.Name)' Setup Processing Time: $($TimeSpan.ToString())"
        }    
    }
    end {
        $EndTime = Get-Date
        $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
        Write-Host -Object "Overall Pooled HostPool Setup Processing Time: $($TimeSpan.ToString())"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    }
}

function New-PsAvdHostPoolSetup {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [HostPool[]] $HostPool,

        [Parameter(Mandatory = $false)]
        [string]$NoMFAEntraIDGroupName = "No-MFA Users",

        [Parameter(Mandatory = $false)]
        [string]$LogDir = ".",

        [switch] $AMBA,
        [switch] $WorkBook,
        [switch] $Restart,
        [switch] $RDCMan,
        [switch] $AsJob
    )

    begin {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        $StartTime = Get-Date
        $AzContext = Get-AzContext
        <#
        $StorageEndpointSuffix = $AzContext | Select-Object -ExpandProperty Environment | Select-Object -ExpandProperty StorageEndpointSuffix
        $AzureKeyVaultDnsSuffix = $AzContext | Select-Object -ExpandProperty Environment | Select-Object -ExpandProperty AzureKeyVaultDnsSuffix
        $AzureKeyVaultDnsSuffix2 = "vaultcore.azure.net"
        $DnsServerConditionalForwarderZones = $StorageEndpointSuffix, $AzureKeyVaultDnsSuffix, $AzureKeyVaultDnsSuffix2
        #>

        #Update-PsAvdSystemAssignedAzVM

        #region Pester Tests for Host Pool - Class Instantiation
        $ModuleBase = Get-ModuleBase
        $PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
        #$PesterDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'Pester'
        $HostPoolClassPesterTests = Join-Path -Path $PesterDirectory -ChildPath 'HostPool.Class.Tests.ps1'
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$HostPoolClassPesterTests: $HostPoolClassPesterTests"
        $Container = New-PesterContainer -Path $HostPoolClassPesterTests -Data @{ HostPool = $HostPool }
        Invoke-Pester -Container $Container -Output Detailed -Verbose
        #endregion

        Import-Module -Name DnsServer #-DisableNameChecking
        $DnsServerConditionalForwarderZones = "file.core.windows.net", "vaultcore.azure.net", "vault.azure.net"
        #region DNS Conditional Forwarders
        foreach ($CurrentDnsServerConditionalForwarderZone in $DnsServerConditionalForwarderZones) {
            if ($null -eq (Get-DnsServerZone -Name $CurrentDnsServerConditionalForwarderZone -ErrorAction Ignore)) {
                #Adding Dns Server Conditional Forwarder Zone
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding Dns Server Conditional Forwarder Zone for '$CurrentDnsServerConditionalForwarderZone'"
                #From https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16
                Add-DnsServerConditionalForwarderZone -Name $CurrentDnsServerConditionalForwarderZone -MasterServers "168.63.129.16"
            }
        }
        #endregion

        #region AVD OU Management
        $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext
        #$DomainName = (Get-ADDomain).DNSRoot
        $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

        $AVDRootOU = Get-ADOrganizationalUnit -Filter 'Name -eq "AVD"' -SearchBase $DefaultNamingContext
        if (-not($AVDRootOU)) {
            $AVDRootOU = New-ADOrganizationalUnit -Name "AVD" -Path $DefaultNamingContext -ProtectedFromAccidentalDeletion $true -PassThru
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($AVDRootOU.DistinguishedName)' OU (under '$DefaultNamingContext')"
        }
        #Blocking Inheritance
        $null = $AVDRootOU | Set-GPInheritance -IsBlocked Yes

        #endregion

        #region AVD GPO Management
        $AVDGPO = Get-GPO -Name "AVD - Global Settings" -ErrorAction Ignore
        if (-not($AVDGPO)) {
            $AVDGPO = New-GPO -Name "AVD - Global Settings" -ErrorAction Ignore
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU)"
        }
        $null = $AVDGPO | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore

        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Setting GPO Setting for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU)"
        #region Network Settings
        #From https://learn.microsoft.com/en-us/training/modules/configure-user-experience-settings/4-configure-user-settings-through-group-policies
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Setting some 'Network Settings' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU)"
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.BITS::BITS_DisableBranchCache
        $null = Set-PsAvdGPRegistryValue -Verbose -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\BITS' -ValueName "DisableBranchCache" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.PoliciesContentWindowsBranchCache::EnableWindowsBranchCache
        $null = Set-PsAvdGPRegistryValue -Verbose -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\PeerDist\Service' -ValueName "Enable" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.HotspotAuthentication::HotspotAuth_Enable
        $null = Set-PsAvdGPRegistryValue -Verbose -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\HotspotAuthentication' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.PlugandPlay::P2P_Disabled
        $null = Set-PsAvdGPRegistryValue -Verbose -Name $AVDGPO.DisplayName -Key 'HKLM\Software\policies\Microsoft\Peernet' -ValueName "Disabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.OfflineFiles::Pol_Enabled
        $null = Set-PsAvdGPRegistryValue -Verbose -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\NetCache' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #endregion

        #region Session Time Settings
        #From https://learn.microsoft.com/en-us/training/modules/configure-user-experience-settings/6-configure-session-timeout-properties
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Idle_Limit_1
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Setting some 'Session Time Settings' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU)"
        $null = Set-PsAvdGPRegistryValue -Verbose -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxIdleTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 900000
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Disconnected_Timeout_1
        $null = Set-PsAvdGPRegistryValue -Verbose -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxDisconnectionTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 900000
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Limits_2
        $null = Set-PsAvdGPRegistryValue -Verbose -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxConnectionTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_Session_End_On_Limit_2
        $null = Set-PsAvdGPRegistryValue -Verbose -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fResetBroken" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #endregion

        #region Enable Screen Capture Protection
        #From https://learn.microsoft.com/en-us/training/modules/manage-access/5-configure-screen-capture-protection-for-azure-virtual-desktop
        #Value 2 is for blocking screen capture on client and server.
        #Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Setting some 'Enable Screen Capture Protection' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU)"
        #$null = Set-PsAvdGPRegistryValue -Verbose -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fEnableScreenCaptureProtection" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #endregion

        #region Enabling and using the new performance counters
        #From https://learn.microsoft.com/en-us/training/modules/install-configure-apps-session-host/10-troubleshoot-application-issues-user-input-delay
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Setting some 'Performance Counters' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU)"
        $null = Set-PsAvdGPRegistryValue -Verbose -Name $AVDGPO.DisplayName -Key 'HKLM\System\CurrentControlSet\Control\Terminal Server' -ValueName "EnableLagCounter" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #endregion 

        #region Starter GPOs Management
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Starter GPOs Management"
        try {
            $null = Get-GPStarterGPO -Name "Group Policy Reporting Firewall Ports" -ErrorAction Stop
        }
        catch {
            <#
            Write-Warning "The required starter GPOs are not installed. Please click on the 'Create Starter GPOs Folder' under Group Policy Management / Forest / Domains / $DomainName / Starter GPOs before continuing"
            Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "gpmc.msc" -Wait -NoNewWindow
            #>
            $OutFile = Join-Path -Path $env:Temp -ChildPath StarterGPOs.zip
            Invoke-WebRequest -Uri https://raw.githubusercontent.com/lavanack/PSAzureVirtualDesktop/master/StarterGPOs.zip -UseBasicParsing -OutFile $OutFile
            #$DomainName = (Get-ADDomain).DNSRoot
            #$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
            $DestinationPath = "\\{0}\SYSVOL\{0}" -f $DomainName
            Expand-Archive -Path $OutFile -DestinationPath $DestinationPath
            Remove-Item -Path $OutFile -Force -ErrorAction Ignore
        }
        #region These Starter GPOs include policy settings to configure the firewall rules required for GPO operations
        $GPO = Get-GPO -Name "Group Policy Reporting Firewall Ports" -ErrorAction Ignore
        if (-not($GPO)) {
            $GPO = Get-GPStarterGPO -Name "Group Policy Reporting Firewall Ports" | New-GPO -Name "Group Policy Reporting Firewall Ports"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($GPO.DisplayName)' Starter GPO"
        }
        $GPLink = $GPO | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Linking '$($GPO.DisplayName)' Starter GPO to '$($AVDRootOU.DistinguishedName)' OU"

        $GPO = Get-GPO -Name "Group Policy Remote Update Firewall Ports" -ErrorAction Ignore
        if (-not($GPO)) {
            $GPO = Get-GPStarterGPO -Name "Group Policy Remote Update Firewall Ports" | New-GPO -Name "Group Policy Remote Update Firewall Ports"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$($GPO.DisplayName)' Starter GPO"
        }
        $GPLink = $GPO | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Linking '$($GPO.DisplayName)' Starter GPO to '$($AVDRootOU.DistinguishedName)' OU"
        #endregion
        #endregion
        #endregion

        #region Assigning the Desktop Virtualization Power On Off Contributor
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/start-virtual-machine-connect?tabs=azure-portal#assign-the-desktop-virtualization-power-on-contributor-role-with-the-azure-portal
        $objId = (Get-MgBetaServicePrincipal -Filter "DisplayName eq 'Azure Virtual Desktop'").Id
        $SubscriptionId = $AzContext.Subscription.Id
        $Scope = "/subscriptions/$SubscriptionId"
        if (-not(Get-AzRoleAssignment -ObjectId $objId -RoleDefinitionName "Desktop Virtualization Power On Off Contributor" -Scope $Scope)) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the 'Desktop Virtualization Power On Off Contributor' RBAC role to Service Principal '$objId' on the Subscription '$SubscriptionId'"
            $null = New-AzRoleAssignment -ObjectId $objId -RoleDefinitionName "Desktop Virtualization Power On Off Contributor" -Scope $Scope
        }
        #endregion

        $PrivateDnsZoneSetup = New-PsAvdPrivateDnsZoneSetup 
    }
    process {
        #No pipeline input and No -AsJob switch specified
        $PooledHostPools = $HostPool | Where-Object -FilterScript { ($null -ne $_ ) -and ($_.Type -eq [HostPoolType]::Pooled) }
        $PersonalHostPools = $HostPool | Where-Object -FilterScript { ($null -ne $_ ) -and ($_.Type -eq [HostPoolType]::Personal) }

        #From https://stackoverflow.com/questions/7162090/how-do-i-start-a-job-of-a-function-i-just-defined
        #From https://stackoverflow.com/questions/76844912/how-to-call-a-class-object-in-powershell-jobs
        if ($AsJob) {
            #Setting the ThrottleLimit to the total number of host pool VM instances + 1
            $ThrottleLimit = $($HostPool.VMNumberOfInstances | Measure-Object -Sum).Sum + $HostPool.Count + 1
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ThrottleLimit: $ThrottleLimit"
            $null = Start-ThreadJob -ScriptBlock { $null } -ThrottleLimit $ThrottleLimit

            $ExportedFunctions = [scriptblock]::Create(@"
                Set-Variable -Name MaximumFunctionCount -Value 32768 -Scope Global -Force
                New-Variable -Name ModuleBase -Value "$((Get-Module -Name $MyInvocation.MyCommand.ModuleName).ModuleBase)" -Scope Global
                Function Get-AdjoinCredential { ${Function:Get-AdjoinCredential} }
                Function Get-LocalAdminCredential { ${Function:Get-LocalAdminCredential} }
                Function Get-AzVMVirtualNetwork { ${Function:Get-AzVMVirtualNetwork} }
                Function Wait-PsAvdRunPowerShell { ${Function:Wait-PsAvdRunPowerShell} }
                Function Update-PsAvdMgBetaPolicyMobileDeviceManagementPolicy { ${Function:Update-PsAvdMgBetaPolicyMobileDeviceManagementPolicy} }
                Function Set-PsAvdGPRegistryValue { ${Function:Set-PsAvdGPRegistryValue} }
                Function New-PsAvdPooledHostPoolSetup { ${Function:New-PsAvdPooledHostPoolSetup} }
                Function New-PsAvdPersonalHostPoolSetup { ${Function:New-PsAvdPersonalHostPoolSetup} }
                Function Grant-PsAvdADJoinPermission { ${Function:Grant-PsAvdADJoinPermission} }
                Function Start-MicrosoftEntraIDConnectSync { ${Function:Start-MicrosoftEntraIDConnectSync} }
                Function Get-AzVMCompute { ${Function:Get-AzVMCompute} }
                Function Wait-PSSession { ${Function:Wait-PSSession} }
                function Set-AdminConsent { ${Function:Set-AdminConsent} }
                Function Get-GitFile { ${Function:Get-GitFile} }
                Function Get-WebSiteFile { ${Function:Get-WebSiteFile} }
                Function Copy-PsAvdMSIXDemoAppAttachPackage { ${Function:Copy-PsAvdMSIXDemoAppAttachPackage} }
                Function Copy-PsAvdMSIXDemoPFXFile { ${Function:Copy-PsAvdMSIXDemoPFXFile} }
                Function Get-PsAvdKeyVaultNameAvailability { ${Function:Get-PsAvdKeyVaultNameAvailability} }
                Function Add-PsAvdSessionHost { ${Function:Add-PsAvdSessionHost} }                       
                Function Get-PsAvdNextSessionHostName { ${Function:Get-PsAvdNextSessionHostName} }                       
                Function New-PsAvdSessionHost { ${Function:New-PsAvdSessionHost} }
                Function Add-PsAvdCategoryFullPath { ${Function:Add-PsAvdCategoryFullPath} }                
                Function New-PsAvdFSLogixIntuneSettingsCatalogConfigurationPolicyViaGraphAPI { ${Function:New-PsAvdFSLogixIntuneSettingsCatalogConfigurationPolicyViaGraphAPI} }  
                Function New-PsAvdAvdIntuneSettingsCatalogConfigurationPolicyViaGraphAPI { ${Function:New-PsAvdAvdIntuneSettingsCatalogConfigurationPolicyViaGraphAPI} }  
                Function New-PsAvdIntunePowerShellScriptViaCmdlet { ${Function:New-PsAvdIntunePowerShellScriptViaCmdlet} }  
                Function Set-PsAvdGroupPolicyDefinitionSettingViaCmdlet { ${Function:New-PsAvdGroupPolicyDefinitionSettingViaCmdlet} } 
                Function Get-PsAvdGroupPolicyDefinitionPresentationViaCmdlet { ${Get-PsAvdGroupPolicyDefinitionPresentationViaCmdlet} } 
                Function Get-CallerPreference { ${Function:Get-CallerPreference} }
                Function New-PsAvdNoMFAUserEntraIDGroup { ${Function:New-PsAvdNoMFAUserEntraIDGroup} }
                Function Get-ModuleBase { ${Function:Get-ModuleBase} }
                Function New-PsAvdMFAForAllUsersConditionalAccessPolicy { ${Function:New-PsAvdMFAForAllUsersConditionalAccessPolicy} }
                Function Get-MgGraphObject { ${Function:Get-MgGraphObject} }
                Function New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI { ${Function:New-PsAvdIntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI} }   
                Function New-PsAvdHostPoolCredentialKeyVault { ${Function:New-PsAvdHostPoolCredentialKeyVault} }
                Function New-PsAvdPrivateDnsZoneSetup { ${Function:New-PsAvdPrivateDnsZoneSetup} }
                Function New-PsAvdPrivateEndpointSetup { ${Function:New-PsAvdPrivateEndpointSetup} }
                Function Get-PsAvdPrivateDnsResourceGroupName { ${Function:Get-PsAvdPrivateDnsResourceGroupName} }
                Function Get-AzVMSubnet { ${Function:Get-AzVMSubnet} }
"@)
            $Jobs = @()
            $Jobs += foreach ($CurrentPooledHostPool in $PooledHostPools) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Starting background job for '$($CurrentPooledHostPool.Name)' Pooled HostPool Creation (via New-PsAvdPooledHostPoolSetup) ... "
                $Verbose = $(( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ))
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Verbose: $Verbose"
                Start-ThreadJob -ScriptBlock { param($Verbose) New-PsAvdPooledHostPoolSetup -HostPool $using:CurrentPooledHostPool -ADOrganizationalUnit $using:AVDRootOU -NoMFAEntraIDGroupName $using:NoMFAEntraIDGroupName -LogDir $LogDir -AsJob -Verbose:$Verbose *>&1 | Out-File -FilePath $("{0}\New-PsAvdPooledHostPoolSetup_{1}_{2}.txt" -f $using:LogDir, $($using:CurrentPooledHostPool).Name, (Get-Date -Format 'yyyyMMddHHmmss')) } -InitializationScript $ExportedFunctions -ArgumentList $Verbose -StreamingHost $Host
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting for the 'New-PsAvdPooledHostPoolSetup' job to finish"
            }

            $Jobs += foreach ($CurrentPersonalHostPool in $PersonalHostPools) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Starting background job for '$($CurrentPersonalHostPool.Name)' Personal HostPool Creation (via New-PsAvdPersonalHostPoolSetup)"
                $Verbose = $(( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ))
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Verbose: $Verbose"
                Start-ThreadJob -ScriptBlock { param($Verbose) New-PsAvdPersonalHostPoolSetup -HostPool $using:CurrentPersonalHostPool -ADOrganizationalUnit $using:AVDRootOU -LogDir $LogDir -AsJob -Verbose:$Verbose *>&1 | Out-File -FilePath $("{0}\New-PsAvdPersonalHostPoolSetup_{1}_{2}.txt" -f $using:LogDir, $($using:CurrentPersonalHostPool).Name, (Get-Date -Format 'yyyyMMddHHmmss')) } -InitializationScript $ExportedFunctions -ArgumentList $Verbose -StreamingHost $Host
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting for the 'New-PsAvdPersonalHostPoolSetup' job to finish"
            }

            $Jobs | Receive-Job -Wait -AutoRemoveJob
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Waiting is over for the 'New-PsAvdPersonalHostPoolSetup' and/or 'New-PsAvdPooledHostPoolSetup' job(s)"
            #Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing the background jobs"
            #$Jobs | Remove-Job -Force
        }
        else {
            if ($null -ne $PooledHostPools) {
                #$PooledHostPools | New-PsAvdPooledHostPoolSetup -ADOrganizationalUnit $AVDRootOU -NoMFAEntraIDGroupName $NoMFAEntraIDGroupName -LogDir $LogDir 
                New-PsAvdPooledHostPoolSetup -HostPool $PooledHostPools -ADOrganizationalUnit $AVDRootOU -NoMFAEntraIDGroupName $NoMFAEntraIDGroupName -LogDir $LogDir 
                <#
                foreach ($CurrentPooledHostPool in $PooledHostPools) {
                    New-PsAvdPooledHostPoolSetup -HostPool $CurrentPooledHostPool -ADOrganizationalUnit $AVDRootOU -NoMFAEntraIDGroupName $NoMFAEntraIDGroupName -LogDir $LogDir
                }
                #>
            }
            if ($null -ne $PersonalHostPools) {
                #$PersonalHostPools | New-PsAvdPersonalHostPoolSetup -ADOrganizationalUnit $AVDRootOU -LogDir $LogDir
                New-PsAvdPersonalHostPoolSetup -HostPool $PersonalHostPools -ADOrganizationalUnit $AVDRootOU -LogDir $LogDir
                <#
                foreach ($CurrentPersonalHostPool in $PersonalHostPools) {
                    New-PsAvdPersonalHostPoolSetup -HostPool $CurrentPersonalHostPool -ADOrganizationalUnit $AVDRootOU -LogDir $LogDir
                }
                #>  
            }
        }
    }
    end {
        $IntuneHostPools = $HostPool | Where-Object -FilterScript { $_.Intune }
        if ($IntuneHostPools) {
            Sync-PsAvdIntuneSessionHostViaCmdlet -HostPool $IntuneHostPools
        }
        
        #region Pester Tests for Host Pool - Azure Instantiation
        $ModuleBase = Get-ModuleBase
        $PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
        #$PesterDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'Pester'
        $HostPoolAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'HostPool.Azure.Tests.ps1'
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$HostPoolAzurePesterTests: $HostPoolAzurePesterTests"
        $Container = New-PesterContainer -Path $HostPoolAzurePesterTests -Data @{ HostPool = $HostPool }
        Invoke-Pester -Container $Container -Output Detailed -Verbose
        #endregion

        #region Pester Tests for Azure Host Pool Session Host - OS Ephemeral Disk
        $ModuleBase = Get-ModuleBase
        $PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
        #$PesterDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'Pester'
        $OSEphemeralDiskAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'OSEphemeralDisk.Azure.Tests.ps1'
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$OSEphemeralDiskAzurePesterTests: $OSEphemeralDiskAzurePesterTests"
        $Container = New-PesterContainer -Path $OSEphemeralDiskAzurePesterTests -Data @{ HostPool = $HostPool }
        Invoke-Pester -Container $Container -Output Detailed -Verbose
        #endregion

        #region Pester Tests for Azure Host Pool Session Host - Operational Insights
        $ModuleBase = Get-ModuleBase
        $PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
        #$PesterDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'Pester'
        $OperationalInsightsQueryAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'OperationalInsightsQuery.Azure.Tests.ps1'
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$OperationalInsightsQueryAzurePesterTests: $OperationalInsightsQueryAzurePesterTests"
        $Container = New-PesterContainer -Path $OperationalInsightsQueryAzurePesterTests -Data @{ HostPool = $HostPool }
        Invoke-Pester -Container $Container -Output Detailed -Verbose
        #endregion

        $Location = (Get-AzVMCompute).Location

        #Setting up the hostpool scaling plan(s)
        New-PsAvdScalingPlan -HostPool $HostPool 

        #Setting up the Azure site Recovery for the Hostpools 
        New-PsAvdAzureSiteRecoveryPolicyAssignement -HostPool $HostPool

        if ($WorkBook) {
            #Importing some useful AVD Worbooks
            Import-PsAvdWorkbook -Location $Location
        }
        
        if ($AMBA) {
            #Setting up Azure Monitor Baseline Alerts for Azure Virtual Desktop
            $AMBAResourceGroup = New-PsAvdAzureMonitorBaselineAlertsDeployment -Location $Location -HostPool $HostPool -PassThru -Verbose
        }

        if ($Restart) {
            #region Restarting all session hosts
            Restart-PsAvdSessionHost -HostPool $HostPool -Wait
            #endregion
        }
        
        if ($RDCMan) {
            #region Running RDCMan to connect to all Session Hosts (for administration purpose if needed)
            New-PsAvdRdcMan -HostPool $HostPool -Install -Open
            #endregion
        }

        $EndTime = Get-Date
        $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
        Write-Host -Object "Overall HostPool Setup Processing Time: $($TimeSpan.ToString())"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    }
}

function Invoke-PsAvdErrorLogFilePester {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        [string] $LogDir
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Pester Tests Errors - Log Files
    $ModuleBase = Get-ModuleBase
    $PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
    #$PesterDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'Pester'
    $ErrorLogFilePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'Error.LogFile.Tests.ps1'
    $Container = New-PesterContainer -Path $ErrorLogFilePesterTests -Data @{ LogDir = $LogDir }
    Invoke-Pester -Container $Container -Output Detailed -Verbose
    #endregion

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Restart-PsAvdSessionHost {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HostPool[]] $HostPool,
        [switch] $Wait
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $SessionHostNames = foreach ($CurrentHostPool in $HostPool) {
 (Get-AzWvdSessionHost -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPool.GetResourceGroupName() -ErrorAction Ignore).ResourceId -replace ".*/" | Where-Object -FilterScript { -not([string]::IsNullOrEmpty($_)) } 
    }

    $Jobs = foreach ($CurrentSessionHostName in $SessionHostNames) {
        Write-Host -Object "Restarting '$CurrentSessionHostName' Azure VM"
        Get-AzVM -Name $CurrentSessionHostName | Restart-AzVM -AsJob
    }
    if ($Wait) {
        Write-Host -Object "Waiting for all restarts"
        $Jobs | Wait-Job | Out-Null
        Write-Host -Object "All restarts complete"
        $Jobs | Remove-Job -Force
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function New-PsAvdHostPoolBackup {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HostPool[]] $HostPool,
        [Parameter(Mandatory = $false)]
        [Alias('BackupDir')]
        [string]$Directory = [Environment]::GetFolderPath("MyDocuments")
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $null = New-Item -Path $Directory -ItemType Directory -Force
    $JSONFilePath = Join-Path -Path $Directory -ChildPath $("HostPool_{0:yyyyMMddHHmmss}.json" -f (Get-Date))
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Backing up Host Pool Configuration into '$JSONFilePath'"
    $HostPool.GetPropertyForJSON() | ConvertTo-Json -Depth 100 | Out-File -FilePath $JSONFilePath -Force
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $(Get-Item -Path $JSONFilePath)
}

#Use the AD OU for generating the RDG file. Had to be called after the AD Object creation (at the end of the processing)
function New-PsAvdRdcMan {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $false)]
        #[string]$FullName = $(Join-Path -Path $([Environment]::GetFolderPath("Desktop")) -ChildPath "$((Get-ADDomain).DNSRoot).rdg"),
        [string]$FullName = $(Join-Path -Path $([Environment]::GetFolderPath("Desktop")) -ChildPath "$([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name).rdg"),
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HostPool[]] $HostPool,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,
        [switch] $Open,
        [switch] $Install,
        [switch] $Update
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $null = Add-Type -AssemblyName System.Security
    #region variables
    $RootAVDOUName = 'AVD'
    #$DomainName = (Get-ADDomain).DNSRoot
    $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $RDGFileContentTemplate = @"
<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.83" schemaVersion="3">
    <file>
        <credentialsProfiles />
        <properties>
            <expanded>True</expanded>
            <name>$($DomainName)</name>
        </properties>
        <remoteDesktop inherit="None">
            <sameSizeAsClientArea>True</sameSizeAsClientArea>
            <fullScreen>False</fullScreen>
            <colorDepth>24</colorDepth>
        </remoteDesktop>
        <localResources inherit="None">
            <audioRedirection>Client</audioRedirection>
            <audioRedirectionQuality>Dynamic</audioRedirectionQuality>
            <audioCaptureRedirection>DoNotRecord</audioCaptureRedirection>
            <keyboardHook>FullScreenClient</keyboardHook>
            <redirectClipboard>True</redirectClipboard>
            <redirectDrives>True</redirectDrives>
            <redirectDrivesList>
            </redirectDrivesList>
            <redirectPrinters>False</redirectPrinters>
            <redirectPorts>False</redirectPorts>
            <redirectSmartCards>False</redirectSmartCards>
            <redirectPnpDevices>False</redirectPnpDevices>
        </localResources>
        <group>
            <properties>
                <expanded>True</expanded>
                <name>$RootAVDOUName</name>
            </properties>
        </group>
    </file>
    <connected />
    <favorites />
    <recentlyUsed />
</RDCMan>
"@
    #endregion

    #Remove-Item -Path $FullName -Force 
    If ((-not(Test-Path -Path $FullName)) -or (-not($Update))) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$FullName' file"
        Set-Content -Value $RDGFileContentTemplate -Path $FullName
    }

    $AVDRDGFileContent = [xml](Get-Content -Path $FullName)
    $AVDFileElement = $AVDRDGFileContent.RDCMan.file
    $AVDGroupElement = $AVDFileElement.group | Where-Object -FilterScript {
        $_.ChildNodes.Name -eq $RootAVDOUName
    }

    foreach ($CurrentHostPool in $HostPool) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$($CurrentHostPool.Name)' HostPool"
        $CurrentOU = Get-ADOrganizationalUnit -SearchBase "OU=$RootAVDOUName,$((Get-ADDomain).DistinguishedName)" -Filter "Name -eq '$($CurrentHostPool.Name)'" -Properties *
        #region Remove all previously existing nodes in the same host pool name
        #$PreviouslyExistingNodes = $AVDRDGFileContent.SelectNodes("//group/group/group/properties[contains(name, '$($CurrentOU.Name)')]")
        $PreviouslyExistingNodes = $AVDRDGFileContent.SelectNodes("//properties[contains(name, '$($CurrentHostPool.Name)')]")
        #$PreviouslyExistingNodes | ForEach-Object -Process {$_.ParentNode.RemoveAll()}
        $PreviouslyExistingNodes | ForEach-Object -Process {
            $ParentNode = $_.ParentNode
            $null = $ParentNode.ParentNode.RemoveChild($ParentNode)
        }
        #endregion 


        $ResourceGroupName = $CurrentHostPool.GetResourceGroupName()

        #region Dedicated RDG Group creation
        $ParentCurrentOUs = ($CurrentOU.DistinguishedName -replace ",OU=$RootAVDOUName.*$" -replace "OU=" -split ",")
        [array]::Reverse($ParentCurrentOUs)
        $groupElement = $AVDGroupElement
        foreach ($ParentCurrentOU in $ParentCurrentOUs) {
            
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$ParentCurrentOU'"
            $ParentElement = $groupElement.group | Where-Object -FilterScript { $_.ChildNodes.Name -eq $ParentCurrentOU }
            if ($ParentElement) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$ParentCurrentOU' found under '$($groupElement.FirstChild.name)'"
            } 
            else {
                $ParentElement = $groupElement.AppendChild($AVDRDGFileContent.CreateElement('group'))
                $propertiesElement = $ParentElement.AppendChild($AVDRDGFileContent.CreateElement('properties'))
                $nameElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('name'))
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$ParentCurrentOU' level"
                $nameTextNode = $nameElement.AppendChild($AVDRDGFileContent.CreateTextNode($ParentCurrentOU))
                $expandedElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('expanded'))
                $expandedTextNode = $expandedElement.AppendChild($AVDRDGFileContent.CreateTextNode('True'))
            }
            $groupElement = $ParentElement
        }

        if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
            if ($null -ne $CurrentHostPool.KeyVault) {
                <#
                $LocalAdminUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminUserName -AsPlainText
                $LocalAdminPassword = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminPassword).SecretValue
                $LocalAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($LocalAdminUserName, $LocalAdminPassword)
                #>
                $LocalAdminCredential = Get-LocalAdminCredential -KeyVault $CurrentHostPool.KeyVault
                $RDCManCredential = $LocalAdminCredential
            }
            else {
                $RDCManCredential = $null
            }
        }
        elseif ($null -ne $Credential) {
            $RDCManCredential = $Credential
        }
        else {
            $RDCManCredential = $null
        }

        #region Credential Management
        if ($null -ne $RDCManCredential) {
            if ($RDCManCredential.UserName -match '(?<Domain>\w+)\\(?<SAMAccountName>\w+)') {
                $UserName = $Matches['SAMAccountName']
                $DomainName = $Matches['Domain']
            }
            else {
                $UserName = $RDCManCredential.UserName
                $DomainName = '.'
            }
            $Password = $RDCManCredential.GetNetworkCredential().Password
            #Write-Host -Object "`$UserName: $UserName"
            #Write-Host -Object "`$Password: $Password"
            $PasswordBytes = [System.Text.Encoding]::Unicode.GetBytes($Password)
            $SecurePassword = [Security.Cryptography.ProtectedData]::Protect($PasswordBytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
            $SecurePasswordStr = [System.Convert]::ToBase64String($SecurePassword)
            $logonCredentialsElement = $groupElement.AppendChild($AVDRDGFileContent.CreateElement('logonCredentials'))
            $logonCredentialsElement.SetAttribute('inherit', 'None')
            $profileNameElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('profileName'))
            $profileNameElement.SetAttribute('scope', 'Local')
            $profileNameTextNode = $profileNameElement.AppendChild($AVDRDGFileContent.CreateTextNode('Custom'))
            $UserNameElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('UserName'))
            $UserNameTextNode = $UserNameElement.AppendChild($AVDRDGFileContent.CreateTextNode($UserName))
            $PasswordElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('Password'))
            $PasswordTextNode = $PasswordElement.AppendChild($AVDRDGFileContent.CreateTextNode($SecurePasswordStr))
            $DomainElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('Domain'))
            #$DomainTextNode = $DomainElement.AppendChild($AVDRDGFileContent.CreateTextNode($DomainName))
            $DomainTextNode = $DomainElement.AppendChild($AVDRDGFileContent.CreateTextNode('.'))
        }
        #endregion

        #region Server Nodes Management
        #$Machines = Get-ADComputer -SearchBase $CurrentOU -Properties DNSHostName -Filter 'DNSHostName -like "*"' -SearchScope OneLevel
        $Machines = Get-ADComputer -SearchBase $CurrentOU -Properties DNSHostName -Filter 'DNSHostName -like "*"' -SearchScope OneLevel | Select-Object -Property Name
        if ($null -eq $Machines) {
            $SessionHosts = Get-AzWvdSessionHost -HostPoolName $CurrentHostPool.Name -ResourceGroupName $ResourceGroupName
            if ($null -ne $SessionHosts) {
                $SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
                $Machines = foreach ($CurrentSessionHostName in $SessionHostNames) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$CurrentSessionHostName' Session Host"
                    $VM = Get-AzVM -Name $CurrentSessionHostName -ResourceGroupName $resourceGroupName
                    $NIC = Get-AzNetworkInterface -Name $($VM.NetworkProfile.NetworkInterfaces.Id -replace ".*/")
                    $PrivateIpAddress = $NIC.IpConfigurations.PrivateIPAddress
                    [pscustomobject]@{DisplayName = $CurrentSessionHostName; Name = $PrivateIpAddress }
                }
            }
        }
        foreach ($CurrentMachine in $Machines) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$($CurrentMachine.Name)' Machine"
            $serverElement = $groupElement.AppendChild($AVDRDGFileContent.CreateElement('server'))
            $propertiesElement = $serverElement.AppendChild($AVDRDGFileContent.CreateElement('properties'))
            $displayNameElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('displayName'))
            $displayNameTextNode = $displayNameElement.AppendChild($AVDRDGFileContent.CreateTextNode($CurrentMachine.DisplayName))
            $nameElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('name'))
            $NameTextNode = $nameElement.AppendChild($AVDRDGFileContent.CreateTextNode($CurrentMachine.Name))
        }
        #endregion
        #endregion 
    }
    $AVDRDGFileContent.Save($FullName)
    if ($Install) {
        $OutFile = Join-Path -Path $env:Temp -ChildPath "RDCMan.zip"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Downloading the latest RDCMan version form SysInternals"
        $Response = Invoke-WebRequest -Uri "https://download.sysinternals.com/files/RDCMan.zip" -UseBasicParsing -OutFile $OutFile -PassThru
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Extracting the downloaded archive file to system32"
        $System32 = $(Join-Path -Path $env:windir -ChildPath "system32")
        $RDCManProcess = (Get-Process -Name rdcman -ErrorAction Ignore)
        #If RDCMan is running for system32 folder
        if (($null -ne $RDCManProcess) -and ((Split-Path -Path $RDCManProcess.Path -Parent) -eq $System32)) {
            Write-Warning "RDCMan is running. Unable to update the executable in the '$System32' folder."
        }
        else { 
            Expand-Archive -Path $OutFile -DestinationPath $System32 -Force
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing the downloaded archive file to system32"
        Remove-Item -Path $OutFile -Force
        if ($Open) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Opening RDC Manager"
            #Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "rdcman ""$FullName""" -Wait -NoNewWindow
            Start-Process -FilePath "rdcman" -ArgumentList """$FullName"""
        }
    }
    elseif ($Open) {
        & $FullName
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

#Use the HostPool properties for generating the RDG file. Doesn't required to be called after the AD Object creation. 
function New-PsAvdRdcManV2 {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $false)]
        #[string]$FullName = $(Join-Path -Path $([Environment]::GetFolderPath("Desktop")) -ChildPath "$((Get-ADDomain).DNSRoot).rdg"),
        [string]$FullName = $(Join-Path -Path $([Environment]::GetFolderPath("Desktop")) -ChildPath "$([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name).rdg"),
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HostPool[]] $HostPool,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,
        [switch] $Open,
        [switch] $Install,
        [switch] $Update
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $null = Add-Type -AssemblyName System.Security
    #region variables
    $RootAVDOUName = 'AVD'
    #$DomainName = (Get-ADDomain).DNSRoot
    $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $RDGFileContentTemplate = @"
<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.83" schemaVersion="3">
    <file>
        <credentialsProfiles />
        <properties>
            <expanded>True</expanded>
            <name>$($DomainName)</name>
        </properties>
        <remoteDesktop inherit="None">
            <sameSizeAsClientArea>True</sameSizeAsClientArea>
            <fullScreen>False</fullScreen>
            <colorDepth>24</colorDepth>
        </remoteDesktop>
        <localResources inherit="None">
            <audioRedirection>Client</audioRedirection>
            <audioRedirectionQuality>Dynamic</audioRedirectionQuality>
            <audioCaptureRedirection>DoNotRecord</audioCaptureRedirection>
            <keyboardHook>FullScreenClient</keyboardHook>
            <redirectClipboard>True</redirectClipboard>
            <redirectDrives>True</redirectDrives>
            <redirectDrivesList>
            </redirectDrivesList>
            <redirectPrinters>False</redirectPrinters>
            <redirectPorts>False</redirectPorts>
            <redirectSmartCards>False</redirectSmartCards>
            <redirectPnpDevices>False</redirectPnpDevices>
        </localResources>
        <group>
            <properties>
                <expanded>True</expanded>
                <name>$RootAVDOUName</name>
            </properties>
        </group>
    </file>
    <connected />
    <favorites />
    <recentlyUsed />
</RDCMan>
"@
    #endregion

    #Remove-Item -Path $FullName -Force 
    If ((-not(Test-Path -Path $FullName)) -or (-not($Update))) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$FullName' file"
        Set-Content -Value $RDGFileContentTemplate -Path $FullName
    }

    $AVDRDGFileContent = [xml](Get-Content -Path $FullName)
    $AVDFileElement = $AVDRDGFileContent.RDCMan.file
    $AVDGroupElement = $AVDFileElement.group | Where-Object -FilterScript {
        $_.ChildNodes.Name -eq $RootAVDOUName
    }

    foreach ($CurrentHostPool in $HostPool) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$($CurrentHostPool.Name)' HostPool"
        #region Remove all previously existing nodes in the same host pool name
        $PreviouslyExistingNodes = $AVDRDGFileContent.SelectNodes("//properties[contains(name, '$($CurrentHostPool.Name)')]")
        #$PreviouslyExistingNodes | ForEach-Object -Process {$_.ParentNode.RemoveAll()}
        $PreviouslyExistingNodes | ForEach-Object -Process {
            $ParentNode = $_.ParentNode
            $null = $ParentNode.ParentNode.RemoveChild($ParentNode)
        }
        #endregion 


        $ResourceGroupName = $CurrentHostPool.GetResourceGroupName()

        #region Dedicated RDG Group creation
        $ParentLevels = $CurrentHostPool.Location, $("{0}Desktops" -f $CurrentHostPool.Type), $CurrentHostPool.Name
        $groupElement = $AVDGroupElement
        foreach ($ParentLevel in $ParentLevels) {
            
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$ParentLevel'"
            $ParentElement = $groupElement.group | Where-Object -FilterScript { $_.ChildNodes.Name -eq $ParentLevel }
            if ($ParentElement) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$ParentLevel' found under '$($groupElement.FirstChild.name)'"
            } 
            else {
                $ParentElement = $groupElement.AppendChild($AVDRDGFileContent.CreateElement('group'))
                $propertiesElement = $ParentElement.AppendChild($AVDRDGFileContent.CreateElement('properties'))
                $nameElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('name'))
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$ParentLevel' level"
                $nameTextNode = $nameElement.AppendChild($AVDRDGFileContent.CreateTextNode($ParentLevel))
                $expandedElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('expanded'))
                $expandedTextNode = $expandedElement.AppendChild($AVDRDGFileContent.CreateTextNode('True'))
            }
            $groupElement = $ParentElement
        }

        if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
            if ($null -ne $CurrentHostPool.KeyVault) {
                <#
                $LocalAdminUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminUserName -AsPlainText
                $LocalAdminPassword = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminPassword).SecretValue
                $LocalAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($LocalAdminUserName, $LocalAdminPassword)
                #>
                $LocalAdminCredential = Get-LocalAdminCredential -KeyVault $CurrentHostPool.KeyVault
                $RDCManCredential = $LocalAdminCredential
            }
            else {
                $RDCManCredential = $null
            }
        }
        elseif ($null -ne $Credential) {
            $RDCManCredential = $Credential
        }
        else {
            $RDCManCredential = $null
        }

        #region Credential Management
        if ($null -ne $RDCManCredential) {
            if ($RDCManCredential.UserName -match '(?<Domain>\w+)\\(?<SAMAccountName>\w+)') {
                $UserName = $Matches['SAMAccountName']
                $DomainName = $Matches['Domain']
            }
            else {
                $UserName = $RDCManCredential.UserName
                $DomainName = '.'
            }
            $Password = $RDCManCredential.GetNetworkCredential().Password
            #Write-Host -Object "`$UserName: $UserName"
            #Write-Host -Object "`$Password: $Password"
            $PasswordBytes = [System.Text.Encoding]::Unicode.GetBytes($Password)
            $SecurePassword = [Security.Cryptography.ProtectedData]::Protect($PasswordBytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
            $SecurePasswordStr = [System.Convert]::ToBase64String($SecurePassword)
            $logonCredentialsElement = $groupElement.AppendChild($AVDRDGFileContent.CreateElement('logonCredentials'))
            $logonCredentialsElement.SetAttribute('inherit', 'None')
            $profileNameElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('profileName'))
            $profileNameElement.SetAttribute('scope', 'Local')
            $profileNameTextNode = $profileNameElement.AppendChild($AVDRDGFileContent.CreateTextNode('Custom'))
            $UserNameElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('UserName'))
            $UserNameTextNode = $UserNameElement.AppendChild($AVDRDGFileContent.CreateTextNode($UserName))
            $PasswordElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('Password'))
            $PasswordTextNode = $PasswordElement.AppendChild($AVDRDGFileContent.CreateTextNode($SecurePasswordStr))
            $DomainElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('Domain'))
            #$DomainTextNode = $DomainElement.AppendChild($AVDRDGFileContent.CreateTextNode($DomainName))
            $DomainTextNode = $DomainElement.AppendChild($AVDRDGFileContent.CreateTextNode('.'))
        }
        #endregion

        #region Server Nodes Management
        #$Machines = Get-ADComputer -SearchBase $Level -Properties DNSHostName -Filter 'DNSHostName -like "*"' -SearchScope OneLevel | Select-Object -Property @{Name = 'DisplayName'; Expression = { $_.Name } }, Name
        $Machines = for ($index = 0; $index -lt $CurrentHostPool.VMNumberOfInstances; $index++) {
            "{0}-{1}" -f $CurrentHostPool.NamePrefix, $index
        }
        if ($null -eq $Machines) {
            $SessionHosts = Get-AzWvdSessionHost -HostPoolName $CurrentHostPool.Name -ResourceGroupName $ResourceGroupName
            if ($null -ne $SessionHosts) {
                $SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
                $Machines = foreach ($CurrentSessionHostName in $SessionHostNames) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$CurrentSessionHostName' Session Host"
                    $VM = Get-AzVM -Name $CurrentSessionHostName -ResourceGroupName $resourceGroupName
                    $NIC = Get-AzNetworkInterface -Name $($VM.NetworkProfile.NetworkInterfaces.Id -replace ".*/")
                    $PrivateIpAddress = $NIC.IpConfigurations.PrivateIPAddress
                    [pscustomobject]@{DisplayName = $CurrentSessionHostName; Name = $PrivateIpAddress }
                }
            }
        }
        foreach ($CurrentMachine in $Machines) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$($CurrentMachine)' Machine"
            $serverElement = $groupElement.AppendChild($AVDRDGFileContent.CreateElement('server'))
            $propertiesElement = $serverElement.AppendChild($AVDRDGFileContent.CreateElement('properties'))
            $displayNameElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('displayName'))
            $displayNameTextNode = $displayNameElement.AppendChild($AVDRDGFileContent.CreateTextNode($CurrentMachine))
            $nameElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('name'))
            $NameTextNode = $nameElement.AppendChild($AVDRDGFileContent.CreateTextNode($CurrentMachine))
        }
        #endregion
        #endregion 
    }
    $AVDRDGFileContent.Save($FullName)
    if ($Install) {
        $OutFile = Join-Path -Path $env:Temp -ChildPath "RDCMan.zip"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Downloading the latest RDCMan version form SysInternals"
        $Response = Invoke-WebRequest -Uri "https://download.sysinternals.com/files/RDCMan.zip" -UseBasicParsing -OutFile $OutFile -PassThru
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Extracting the downloaded archive file to system32"
        $System32 = $(Join-Path -Path $env:windir -ChildPath "system32")
        $RDCManProcess = (Get-Process -Name rdcman -ErrorAction Ignore)
        #If RDCMan is running for system32 folder
        if (($null -ne $RDCManProcess) -and ((Split-Path -Path $RDCManProcess.Path -Parent) -eq $System32)) {
            Write-Warning "RDCMan is running. Unable to update the update the executable in the '$System32' folder."
        }
        else { 
            Expand-Archive -Path $OutFile -DestinationPath $System32 -Force
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing the downloaded archive file to system32"
        Remove-Item -Path $OutFile -Force
        if ($Open) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Opening RDC Manager"
            #Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "rdcman ""$FullName""" -Wait -NoNewWindow
            Start-Process -FilePath "rdcman" -ArgumentList """$FullName"""
        }
    }
    elseif ($Open) {
        & $FullName
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Get-PsAvdFSLogixProfileShare {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HostPool[]] $HostPool
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    $ThisDomainControllerSubnet = Get-AzVMSubnet

    foreach ($CurrentHostPool in $HostPool) {
        if ($CurrentHostPool.FSLogix) {
            $PrivateEndpointSubnetId = (Get-AzPrivateEndpoint | Where-Object -FilterScript {$_.PrivateLinkServiceConnections.PrivateLinkServiceId -match $((Get-AzStorageAccount -Name $CurrentHostPool.GetFSLogixStorageAccountName() -ResourceGroupName $CurrentHostPool.GetResourceGroupName()).Id)}).Subnet.Id
            if ($ThisDomainControllerSubnet.Id -in $PrivateEndpointSubnetId) {
                $CurrentHostPoolStorageAccount = Get-AzStorageAccount -Name $CurrentHostPool.GetFSLogixStorageAccountName() -ResourceGroupName $CurrentHostPool.GetResourceGroupName()
                # Get the list of file shares in the storage account
                $CurrentHostPoolStorageShare = Get-AzStorageShare -Context $CurrentHostPoolStorageAccount.Context
                $CurrentHostPoolProfilesStorageShare = $CurrentHostPoolStorageShare | Where-Object  -FilterScript { $_.Name -eq "profiles" }
                if ($null -ne $CurrentHostPoolProfilesStorageShare) {
                    Start-Process $("\\{0}.file.{1}\{2}" -f $CurrentHostPoolProfilesStorageShare.context.StorageAccountName, ($CurrentHostPoolProfilesStorageShare.context.EndPointSuffix -replace "/"), $CurrentHostPoolProfilesStorageShare.Name)
                }
            }
            else {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The FSLogix FileShare is not accessible from this subnet ('$($ThisDomainControllerSubnet.Id)')"
            }
        }
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] FSLogix is not enabled for '$($CurrentHostPool.Name)' HostPool"
        }
    }
    #region Pester Tests for Azure Host Pool - FSLogix File Share - Azure Instantiation
    $ModuleBase = Get-ModuleBase
    $PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
    #$PesterDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'Pester'
    $FSLogixAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'FSLogix.Azure.Tests.ps1'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FSLogixAzurePesterTests: $FSLogixAzurePesterTests"
    $Container = New-PesterContainer -Path $FSLogixAzurePesterTests -Data @{ HostPool = $HostPool }
    Invoke-Pester -Container $Container -Output Detailed -Verbose
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Get-PsAvdMSIXProfileShare {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HostPool[]] $HostPool
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    $ThisDomainControllerSubnet = Get-AzVMSubnet

    foreach ($CurrentHostPool in $HostPool) {
        if (($CurrentHostPool.MSIX) -or ($CurrentHostPool.AppAttach)) {
            $PrivateEndpointSubnetId = (Get-AzPrivateEndpoint | Where-Object -FilterScript {$_.PrivateLinkServiceConnections.PrivateLinkServiceId -match $((Get-AzStorageAccount -Name $CurrentHostPool.GetMSIXStorageAccountName() -ResourceGroupName $CurrentHostPool.GetResourceGroupName()).Id)}).Subnet.Id
            if ($ThisDomainControllerSubnet.Id -in $PrivateEndpointSubnetId) {
                $CurrentHostPoolStorageAccount = Get-AzStorageAccount -Name $CurrentHostPool.GetMSIXStorageAccountName() -ResourceGroupName $CurrentHostPool.GetResourceGroupName()
                # Get the list of file shares in the storage account
                $CurrentHostPoolStorageShare = Get-AzStorageShare -Context $CurrentHostPoolStorageAccount.Context
                $CurrentHostPoolMSIXStorageShare = $CurrentHostPoolStorageShare | Where-Object  -FilterScript { $_.Name -eq "msix" }
                if ($null -ne $CurrentHostPoolMSIXStorageShare) {
                    Start-Process $("\\{0}.file.{1}\{2}" -f $CurrentHostPoolMSIXStorageShare.context.StorageAccountName, ($CurrentHostPoolMSIXStorageShare.context.EndPointSuffix -replace "/"), $CurrentHostPoolMSIXStorageShare.Name)
                }
            }
            else {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The MSIX FileShare is not accessible from this subnet ('$($ThisDomainControllerSubnet.Id)')"
            }
        }
        else {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] MSIX is not enabled for '$($CurrentHostPool.Name)' HostPool"
        }
    }
    #region Pester Tests for Azure Host Pool - MSIX File Share - Azure Instantiation
    $ModuleBase = Get-ModuleBase
    $PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
    #$PesterDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'Pester'
    $MSIXAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'MSIX.Azure.Tests.ps1'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$MSIXAzurePesterTests: $MSIXAzurePesterTests"
    $Container = New-PesterContainer -Path $MSIXAzurePesterTests -Data @{ HostPool = $HostPool }
    Invoke-Pester -Container $Container -Output Detailed -Verbose
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

#From https://learn.microsoft.com/en-us/azure/virtual-desktop/autoscale-scaling-plan?tabs=powershell
function New-PsAvdScalingPlan {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HostPool[]] $HostPool
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $HostPoolWithScalingPlan = $HostPool | Where-Object -FilterScript { $_.ScalingPlan }
    foreach ($CurrentHostPoolWithScalingPlan in $HostPoolWithScalingPlan) {
        #region Sclaing Plan
        $AzWvdHostPool = (Get-AzWvdHostPool | Where-Object -FilterScript { $_.Name -eq $($CurrentHostPoolWithScalingPlan.Name) })
        $ResourceGroupName = $CurrentHostPoolWithScalingPlan.GetResourceGroupName()
        $ScalingPlanName = $CurrentHostPoolWithScalingPlan.GetAzAvdScalingPlanName()
        Write-Host -Object "Setting up a Scaling Plan for the '$($CurrentHostPoolWithScalingPlan.Name)' HostPool"
        $scalingPlanParams = @{
            ResourceGroupName = $ResourceGroupName
            Name              = $ScalingPlanName
            Location          = $CurrentHostPoolWithScalingPlan.Location
            Description       = $CurrentHostPoolWithScalingPlan.Name
            FriendlyName      = $CurrentHostPoolWithScalingPlan.Name
            HostPoolType      = $CurrentHostPoolWithScalingPlan.Type
            TimeZone          = (Get-TimeZone).Id
            HostPoolReference = @(@{'hostPoolArmPath' = $AzWvdHostPool.Id; 'scalingPlanEnabled' = $CurrentHostPoolWithScalingPlan.ScalingPlan })
        }
        $scalingPlan = New-AzWvdScalingPlan @scalingPlanParams
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$scalingPlan:`r`n$($scalingPlan | Out-String)"
        Start-Sleep -Seconds 10

        if ($CurrentHostPoolWithScalingPlan.Type -eq [HostPoolType]::Pooled) {
            $scalingPlanPooledScheduleParams = @{
                ResourceGroupName              = $ResourceGroupName
                ScalingPlanName                = $ScalingPlanName
                ScalingPlanScheduleName        = 'PooledWeekDaySchedule'
                DaysOfWeek                     = 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'
                RampUpStartTimeHour            = '8'
                RampUpStartTimeMinute          = '0'
                RampUpLoadBalancingAlgorithm   = 'BreadthFirst'
                RampUpMinimumHostsPct          = '20'
                RampUpCapacityThresholdPct     = '50'
                PeakStartTimeHour              = '9'
                PeakStartTimeMinute            = '0'
                PeakLoadBalancingAlgorithm     = 'DepthFirst'
                RampDownStartTimeHour          = '18'
                RampDownStartTimeMinute        = '0'
                RampDownLoadBalancingAlgorithm = 'BreadthFirst'
                RampDownMinimumHostsPct        = '20'
                RampDownCapacityThresholdPct   = '20'
                RampDownForceLogoffUser        = $true
                RampDownWaitTimeMinute         = '30'
                RampDownNotificationMessage    = '"Log out now, please."'
                RampDownStopHostsWhen          = 'ZeroSessions'
                OffPeakStartTimeHour           = '19'
                OffPeakStartTimeMinute         = '00'
                OffPeakLoadBalancingAlgorithm  = 'DepthFirst'
                #Verbose                        = $true
            }

            $scalingPlanPooledSchedule = New-AzWvdScalingPlanPooledSchedule @scalingPlanPooledScheduleParams
        }
        else {
            if ($CurrentHostPoolWithScalingPlan.HibernationEnabled) {
                $PeakActionOnDisconnect    = 'Hibernate'
                $RampDownActionOnLogoff    = 'Hibernate'
                $RampUpActionOnDisconnect  = 'Hibernate'
                $RampUpActionOnLogoff      = 'Hibernate'
                $PeakActionOnLogoff        = 'Hibernate'
                $OffPeakActionOnDisconnect = 'Hibernate'
                $OffPeakActionOnLogoff     = 'Hibernate'
            }
            else {
                $PeakActionOnDisconnect    = 'Deallocate'
                $RampDownActionOnLogoff    = 'Deallocate'
                $RampUpActionOnDisconnect  = 'Deallocate'
                $RampUpActionOnLogoff      = 'Deallocate'
                $PeakActionOnLogoff        = 'Deallocate'
                $OffPeakActionOnDisconnect = 'Deallocate'
                $OffPeakActionOnLogoff     = 'Deallocate'
            }
            $scalingPlanPersonalScheduleParams = @{
                ResourceGroupName                 = $ResourceGroupName
                ScalingPlanName                   = $ScalingPlanName
                ScalingPlanScheduleName           = 'PersonalWeekDaySchedule'
                DaysOfWeek                        = 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'
                RampUpStartTimeHour               = '8'
                RampUpStartTimeMinute             = '0'
                RampUpAutoStartHost               = 'WithAssignedUser'
                RampUpStartVMOnConnect            = 'Enable'
                RampUpMinutesToWaitOnDisconnect   = '30'
                RampUpActionOnDisconnect          = $RampUpActionOnDisconnect
                RampUpMinutesToWaitOnLogoff       = '30'
                RampUpActionOnLogoff              = $RampUpActionOnLogoff
                PeakStartTimeHour                 = '10'
                PeakStartTimeMinute               = '0'
                PeakStartVMOnConnect              = 'Enable'
                PeakMinutesToWaitOnDisconnect     = '10'
                PeakActionOnDisconnect            = $PeakActionOnDisconnect
                PeakMinutesToWaitOnLogoff         = '15'
                PeakActionOnLogoff                = $PeakActionOnLogoff
                RampDownStartTimeHour             = '18'
                RampDownStartTimeMinute           = '0'
                RampDownStartVMOnConnect          = 'Disable'
                RampDownMinutesToWaitOnDisconnect = '10'
                RampDownActionOnDisconnect        = 'None'
                RampDownMinutesToWaitOnLogoff     = '15'
                RampDownActionOnLogoff            = $RampDownActionOnLogoff
                OffPeakStartTimeHour              = '19'
                OffPeakStartTimeMinute            = '0'
                OffPeakStartVMOnConnect           = 'Disable'
                OffPeakMinutesToWaitOnDisconnect  = '10'
                OffPeakActionOnDisconnect         = $OffPeakActionOnDisconnect
                OffPeakMinutesToWaitOnLogoff      = '15'
                OffPeakActionOnLogoff             = $OffPeakActionOnLogoff
                #Verbose                           = $true
            }

            $scalingPlanPersonalSchedule = New-AzWvdScalingPlanPersonalSchedule @scalingPlanPersonalScheduleParams
        }
        #endregion
    }
    #region Pester Tests for Azure Host Pool - Scaling Plan - Azure Instantiation
    $ModuleBase = Get-ModuleBase
    $PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
    #$PesterDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'Pester'
    $ScalingPlanAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'ScalingPlan.Azure.Tests.ps1'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ScalingPlanAzurePesterTests: $ScalingPlanAzurePesterTests"
    $Container = New-PesterContainer -Path $ScalingPlanAzurePesterTests -Data @{ HostPool = $HostPool }
    Invoke-Pester -Container $Container -Output Detailed -Verbose
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

#From https://learn.microsoft.com/en-us/azure/site-recovery/azure-to-azure-how-to-enable-policy
function New-PsAvdAzureSiteRecoveryPolicyAssignement {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HostPool[]] $HostPool
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    #region Building an Hashtable to get the azure region pairs
    [HostPool]::BuildAzurePairedRegionHashtable()

    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    [HostPool]::BuildAzureLocationSortNameHashtable()
    #endregion

    $HostPoolWithAzureSiteRecovery = $HostPool | Where-Object -FilterScript { -not([string]::IsNullOrEmpty($_.ASRFailOverVNetId)) }
    foreach ($CurrentHostPoolWithAzureSiteRecovery in $HostPoolWithAzureSiteRecovery) {
        #region Azure Site Recovery
        $PrimaryLocationResourceGroupName = $CurrentHostPoolWithAzureSiteRecovery.GetResourceGroupName()
        $PrimaryLocationResourceGroup = Get-AzResourceGroup -Name $CurrentHostPoolWithAzureSiteRecovery.GetResourceGroupName() -Location $CurrentHostPoolWithAzureSiteRecovery.Location -ErrorAction Ignore
        $PrimaryLocation = $CurrentHostPoolWithAzureSiteRecovery.Location
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Primary Location ResourceGroup Name: '$PrimaryLocationResourceGroupName'..."
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Primary Location: '$PrimaryLocation'..."

        $RecoveryLocation = $CurrentHostPoolWithAzureSiteRecovery.GetAzurePairedRegion()
        $RecoveryLocationResourceGroupName = $CurrentHostPoolWithAzureSiteRecovery.GetRecoveryLocationResourceGroupName()
        $RecoveryServicesVaultName = $CurrentHostPoolWithAzureSiteRecovery.GetRecoveryServiceVaultName()

        $RecoveryLocationResourceGroup = New-AzResourceGroup -Name $RecoveryLocationResourceGroupName -Location $RecoveryLocation
        $RecoveryServicesVault = New-AzRecoveryServicesVault -Name $RecoveryServicesVaultName -Location $RecoveryLocation -ResourceGroupName $RecoveryLocationResourceGroupName
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Recovery Location ResourceGroup Name: '$RecoveryLocationResourceGroupName'..."
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Recovery Location: '$RecoveryLocation'..."
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Recovery Services Vault Name: '$RecoveryServicesVaultName'..."

        $RecoveryNetwork = Get-AzVirtualNetwork | Where-Object -FilterScript { $_.Id -eq $CurrentHostPoolWithAzureSiteRecovery.ASRFailOverVNetId }
        Write-Host -Object "Recovery Network: '$($RecoveryNetwork.Name)'..."
        if ($RecoveryNetwork.Location -eq $RecoveryLocation) {
                #region Azure Policy Management
                $PolicyDefinition = Get-AzPolicyDefinition | Where-Object -FilterScript { $_.DisplayName -eq "Configure disaster recovery on virtual machines by enabling replication via Azure Site Recovery" }
                $PolicyParameterObject = @{
                    SourceRegion          = $PrimaryLocation 
                    TargetRegion          = $RecoveryLocation 
                    targetResourceGroupId = $RecoveryLocationResourceGroup.ResourceId 
                    vaultResourceGroupId  = $RecoveryLocationResourceGroup.ResourceId 
                    vaultId               = $RecoveryServicesVault.ID
                    recoveryNetworkId     = $RecoveryNetwork.Id
                    <#
                    tagName               = "ASRIncluded"
                    tagValue              = "True"
                    tagType               = "Inclusion"
                    #>
                }

                $PolicyAssignment = New-AzPolicyAssignment -Name "pa-$($PrimaryLocationResourceGroupName)" -DisplayName "Configure disaster recovery on virtual machines by enabling replication via Azure Site Recovery (AVD)" -Scope $PrimaryLocationResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -EnforcementMode Default -IdentityType SystemAssigned -Location $RecoveryLocation -PolicyParameterObject $PolicyParameterObject 

                # Grant defined roles to the primary and recovery resource groups with PowerShell
                $roleDefinitionIds = $PolicyDefinition | Select-Object @{Name = "roleDefinitionIds"; Expression = { $_.policyRule.then.details.roleDefinitionIds } } | Select-Object -ExpandProperty roleDefinitionIds #-Unique
                Start-Sleep -Seconds 30
                if ($roleDefinitionIds.Count -gt 0) {
                    $roleDefinitionIds | ForEach-Object -Process {
                        $roleDefId = $_.Split("/") | Select-Object -Last 1
                        if (-not(Get-AzRoleAssignment -Scope $PrimaryLocationResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId)) {
                            New-AzRoleAssignment -Scope $PrimaryLocationResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId
                            New-AzRoleAssignment -Scope $RecoveryLocationResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId
                        }
                    }
                }

                Write-Host -Object "Creating remediation for '$($PolicyDefinition.DisplayName)' Policy ..."
                $PolicyRemediation = Start-AzPolicyRemediation -Name $PolicyAssignment.Name -PolicyAssignmentId $PolicyAssignment.Id -ResourceGroupName $PrimaryLocationResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance
                $PolicyRemediation

                <#
                Write-Host -Object "Starting Compliance Scan for '$PrimaryLocationResourceGroupName' Resource Group ..."
                $PolicyComplianceScan = Start-AzPolicyComplianceScan -ResourceGroupName $PrimaryLocationResourceGroup
                $PolicyComplianceScan


                # Get the resources in your resource group that are non-compliant to the policy assignment
                Get-AzPolicyState -ResourceGroupName $PrimaryLocationResourceGroup -PolicyAssignmentName $PolicyAssignment.Name #-Filter 'IsCompliant eq false'

                #Get latest non-compliant policy states summary in resource group scope
                Get-AzPolicyStateSummary -ResourceGroupName $PrimaryLocationResourceGroup | Select-Object -ExpandProperty PolicyAssignments 
                #>
                #endregion
            }
        else {
            Write-Error -Message "The FailOver Virtual Network '$($CurrentHostPoolWithAzureSiteRecovery.ASRFailOverVNetId)' is not in the '$RecoveryLocation' region ! Azure Site Recovery won't be enabled"
        }

        #endregion 

    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

#From https://azure.github.io/azure-monitor-baseline-alerts/patterns/specialized/avd/
function New-PsAvdAzureMonitorBaselineAlertsDeployment {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HostPool[]] $HostPool,

        [Parameter(Mandatory = $false)]
        [string] $Location = "EastUs",
        
        [switch] $PassThru
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $StartTime = Get-Date

    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    [HostPool]::BuildAzureLocationSortNameHashtable()
    #endregion

    $Index = 1
    $ResourceGroupName = "rg-avd-amba-poc-{0}-{1:D3}" -f [HostPool]::AzLocationShortNameHT[$Location].shortName, $Index
    $LogAnalyticsWorkSpaceName = "logavdambapoc{0}{1:D3}" -f [HostPool]::AzLocationShortNameHT[$Location].shortName, $Index

    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
    if ($null -eq $ResourceGroup) {
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    }

    $LogAnalyticsWorkSpace = New-AzOperationalInsightsWorkspace -Location $Location -Name $LogAnalyticsWorkSpaceName -Sku pergb2018 -ResourceGroupName $ResourceGroupName -Force


    #region AMBA Template Download
    $AMBAAVDURI = "https://raw.githubusercontent.com/Azure/azure-monitor-baseline-alerts/main/patterns/avd/avdArm.json"
    $TemplateFileName = Split-Path -Path $AMBAAVDURI -Leaf
    $TemplateFile = Join-Path -Path $env:Temp -ChildPath $TemplateFileName
    Invoke-RestMethod -Uri $AMBAAVDURI -OutFile $TemplateFile
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$TemplateFilePath: $TemplateFilePath ..."
    #endregion

    #region AMBA Template Deployment
    $hostPoolInfo = @()
    $storageAccountResourceIds =  @()
    foreach ($CurrentHostPool in $HostPools) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$($CurrentHostPool.Name)' HostPool ..."
        $colHostPoolName = (Get-AzWvdHostPool -Name $CurrentHostPool.Name -ResourceGroupName $CurrentHostPool.GetResourceGroupName()).Id
        $colVMresGroup = (Get-AzResourceGroup -Name $CurrentHostPool.GetResourceGroupName() -Location $CurrentHostPool.Location).ResourceId
        $hostPoolInfo += @{colHostPoolName = $colHostPoolName; colVMresGroup = $colVMresGroup}

        if ($CurrentHostPool.MSIX) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$($CurrentHostPool.Name)' MSIX: $($CurrentHostPool.MSIX)"
            $StorageAccount = Get-AzStorageAccount -Name $CurrentHostPool.GetMSIXStorageAccountName() -ResourceGroupName $CurrentHostPool.GetResourceGroupName()
            $storageAccountResourceIds += $StorageAccount.Id
        }
        if ($CurrentHostPool.AppAttach) {
            Write-Verbose "'$($CurrentHostPool.Name)' AppAttach: $($CurrentHostPool.AppAttach)"
            $StorageAccount = Get-AzStorageAccount -Name $CurrentHostPool.GetMSIXStorageAccountName() -ResourceGroupName $CurrentHostPool.GetResourceGroupName()
            $storageAccountResourceIds += $StorageAccount.Id
        }
        if ($CurrentHostPool.FSlogix) {
            Write-Verbose "'$($CurrentHostPool.Name)' FSlogix: $($CurrentHostPool.FSlogix)"
            $StorageAccount = Get-AzStorageAccount -Name $CurrentHostPool.GetFSLogixStorageAccountName() -ResourceGroupName $CurrentHostPool.GetResourceGroupName()
            $storageAccountResourceIds += $StorageAccount.Id
        }

    }
    $TemplateParameterObject = @{
        "optoutTelemetry" = $false
        "AlertNamePrefix" = "AVD"
        "AllResourcesSameRG" = $false
        "AutoResolveAlert" = $true
        "DistributionGroup" = (Get-AzContext).Account.Id
        "Environment" = "t"
        "hostPoolInfo" = $hostPoolInfo
        "location" = $Location
        "logAnalyticsWorkspaceResourceId" = $LogAnalyticsWorkSpace.ResourceId
        "resourceGroupName" = $ResourceGroup.ResourceGroupName
        "resourceGroupStatus" = "Existing"
        "storageAccountResourceIds" = $storageAccountResourceIds
    }
    $TemplateParameterObject | ConvertTo-Json -Depth 100 | Set-Clipboard
    Write-Host -Object "Starting Subscription Deployment from '$TemplateFile' ..."
    $Attempts = 0
    Do {
        $Attempts++
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Attempts: $Attempts"
        #Don't know why but the first deployment always fails
        $SubscriptionDeployment = New-AzDeployment -Location $Location -TemplateFile $TemplateFile -TemplateParameterObject $TemplateParameterObject -ErrorAction Ignore #-Verbose
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Subscription Deployment Provisioning State: $($SubscriptionDeployment.ProvisioningState)"
    }  while (($SubscriptionDeployment.ProvisioningState -ne "Succeeded") -and ($Attempts -lt 3))
    #endregion

    $EndTime = Get-Date
    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host -Object "Azure Subscription Deployment Processing Time: $($TimeSpan.ToString())"

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    if ($PassThru) {
        return $ResourceGroup
    }
}

function Import-PsAvdWorkbook {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $false)]
        [string] $Location = "EastUs"
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $WorkBooks = @{
        #From https://github.com/Azure/avdaccelerator/tree/main/workload/workbooks/deepInsightsWorkbook
        "Deep Insights Workbook - AVD Accelerator"      = "https://raw.githubusercontent.com/Azure/avdaccelerator/main/workload/workbooks/deepInsightsWorkbook/deepInsights.workbook"
        #From https://github.com/scautomation/Azure-Inventory-Workbook/tree/master/galleryTemplate
        "Windows Virtual Desktop Workbook - Billy York" = "https://raw.githubusercontent.com/scautomation/WVD-Workbook/master/galleryTemplate/template.json"
        #From https://blog.itprocloud.de/AVD-Azure-Virtual-Desktop-Error-Drill-Down-Workbook/
        #Commented the line below because sometimes ==> Invoke-RestMethod : The remote name could not be resolved: 'blog.itprocloud.de'
        #"AVD - Deep-Insights - ITProCloud"              = "https://blog.itprocloud.de/assets/files/AzureDeployments/Workbook-AVD-Error-Logging.json"
        #Hsoting a copy on my own github
        "AVD - Deep-Insights - ITProCloud"              = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/refs/heads/master/Azure/Azure%20Virtual%20Desktop/Workbook/Workbook-AVD-Error-Logging.json"
        #From https://github.com/microsoft/Application-Insights-Workbooks/tree/master/Workbooks/Windows%20Virtual%20Desktop/AVD%20Insights
        "AVD Insights - Application-Insights-Workbooks" = "https://raw.githubusercontent.com/microsoft/Application-Insights-Workbooks/master/Workbooks/Windows%20Virtual%20Desktop/AVD%20Insights/AVDWorkbookV2.workbook"
    }

    [HostPool]::BuildAzureLocationSortNameHashtable()
    $ResourceGroupName = "rg-avd-workbook-poc-{0}-001" -f [HostPool]::AzLocationShortNameHT[$Location].shortname
    if ($null -eq (Get-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Ignore)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$ResourceGroupName' Resource Group in the '$Location' Location"
        $null = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    }

    #From https://github.com/Azure/avdaccelerator/tree/main/workload/workbooks/deepInsightsWorkbook
    foreach ($DisplayName in $WorkBooks.Keys) {
        $ExistingWorkBook = (Get-AzApplicationInsightsWorkbook -Category 'workbook' | Where-Object -FilterScript { $_.DisplayName -eq $DisplayName })
        if ($null -eq $ExistingWorkBook) {
            $URI = $WorkBooks[$DisplayName]
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$DisplayName' Workbook in the '$Location' Location from '$$URI'"
            $Name = (New-Guid).ToString()
            $WorkbookContent = Invoke-RestMethod -Uri $URI | ConvertTo-Json -Depth 100
            $AzApplicationInsightsWorkbook = New-AzApplicationInsightsWorkbook -ResourceGroupName $ResourceGroupName -Name $Name -Location $Location -DisplayName $DisplayName -SourceId "microsoft_azure_wvd" -Category 'workbook' -SerializedData $workbookContent
        }
        else {
            Write-Warning -Message "The '$DisplayName' Worbook already exists:`r`n:$($ExistingWorkBook | Out-String)"
        }
    }
    #region Pester Tests for Azure Host Pool - Workbook - Azure Instantiation
    $ModuleBase = Get-ModuleBase
    $PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
    #$PesterDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'Pester'
    $WorkbookAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'WorkBook.Azure.Tests.ps1'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$WorkbookAzurePesterTests: $WorkbookAzurePesterTests"
    $Container = New-PesterContainer -Path $WorkbookAzurePesterTests -Data @{ WorkBook = $WorkBooks }
    Invoke-Pester -Container $Container -Output Detailed -Verbose
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Get-ModuleBase {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
    )
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    if (-not([string]::IsNullOrEmpty($Global:ModuleBase))) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Global:ModuleBase: $Global:ModuleBase"
        $ModuleBase = $Global:ModuleBase
    }
    else {
        $ModuleBase = (Get-Module -Name $MyInvocation.MyCommand.ModuleName).ModuleBase
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ModuleBase: $ModuleBase"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    $ModuleBase
}

function Get-AzurePairedRegion {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    (Get-AzLocation -OutVariable locations) | Select-Object -Property Location, PhysicalLocation, @{Name='PairedRegion';Expression={$_.PairedRegion.Name}}, @{Name='PairedRegionPhysicalLocation';Expression={($locations | Where-Object -FilterScript {$_.location -eq $_.PairedRegion.Name}).PhysicalLocation} } | Where-Object -FilterScript { $_.PairedRegion } | Group-Object -Property Location -AsHashTable -AsString

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}

function Get-PsAvdAzGalleryImageDefinition {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [Parameter(Mandatory = $true, ParameterSetName = 'RegionDisplayName')]
        [ValidateNotNullOrEmpty()]
        [string[]] $RegionDisplayName,
        [Parameter(Mandatory = $true, ParameterSetName = 'Region')]
        [ValidateNotNullOrEmpty()]
        [string[]] $Region
    )

    if ([string]::IsNullOrEmpty($RegionDisplayName)) {
        $RegionDisplayName = (Get-AzLocation | Where-Object {$_.Location -in $Region}).DisplayName
    }
    
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    Get-AzGallery | Select-Object -Property ResourceGroupName, @{Name="GalleryName";Expression={$_.Name}} | Get-AzGalleryImageDefinition | Where-Object -FilterScript { 
        [string[]]$TargetRegionNames = (Get-AzGalleryImageVersion -ResourceGroupName $_.ResourceGroupName -GalleryName $($_.Id  -replace "^.*/galleries/" -replace "/images/.*$") -GalleryImageDefinitionName $_.Name).PublishingProfile.TargetRegions.Name 
        $count = $0;
        foreach( $TargetRegionName in $TargetRegionNames) { 
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$TargetRegionName: $TargetRegionName"
            if ($RegionDisplayName -contains $TargetRegionName) {
                $count++
            }
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$count: $count"
        if ($count -eq $RegionDisplayName.Count) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
            return $true
        }
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}
#endregion

#endregion