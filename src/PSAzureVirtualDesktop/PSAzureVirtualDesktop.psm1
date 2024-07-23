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
    ResourceDisk
    CacheDisk
    None
}

Class HostPool {
        [ValidateNotNullOrEmpty()] [IdentityProvider] $IdentityProvider
        [ValidateNotNullOrEmpty()] [string] $Name
        [ValidateNotNullOrEmpty()] [HostPoolType] $Type
        [ValidateNotNullOrEmpty()] [string] $Location
        [ValidateLength(3, 11)] [string] $NamePrefix
        [ValidateRange(0, 10)] [int]    $VMNumberOfInstances
        [ValidateNotNullOrEmpty()] [Object] $KeyVault
        [boolean] $Intune
        [boolean] $Spot
        [boolean] $ScalingPlan
        [ValidateNotNullOrEmpty()] [string] $VMSize
        [string] $ImagePublisherName
        [string] $ImageOffer
        [string] $ImageSku
        [string] $VMSourceImageId 
        static [hashtable] $AzLocationShortNameHT = $null     
        static [hashtable] $AzEphemeralOsDiskSkuHT = $null
        [DiffDiskPlacement] $DiffDiskPlacement = [DiffDiskPlacement]::None
    
        hidden static BuildAzureLocationSortNameHashtable() {
            $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
            $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
            [HostPool]::AzLocationShortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
        }
    
        hidden static BuildAzureEphemeralOsDiskSkuHashtable([String] $Location) {
            $Skus = Get-AzComputeResourceSku -Location $Location | Where-Object -FilterScript { ($_.ResourceType -eq "virtualMachines") -and ($null -eq $_.Restrictions.ReasonCode) }
            $EphemeralOsDisk = foreach ($Sku in $Skus) {
                if ((($Sku.Capabilities | Where-Object -FilterScript { $_.Name -eq "EphemeralOSDiskSupported" }).Value) -and (($Sku.Capabilities | Where-Object { $_.Name -eq "PremiumIO" }).Value) -and ($null -ne ($Sku.Capabilities | Where-Object { $_.Name -eq "CachedDiskBytes" }).Value)) {
                    $VmSku = [PSCustomObject]@{
                        Name                     = $Sku.Name
                        #Family                   = $Sku.Family -replace "standard" -replace "Family" -replace "\s", ""
                        Family                   = $Sku.Family -replace "standard|Family|\s"
                        EphemeralOsDiskSupported = [bool]($Sku.Capabilities | Where-Object -FilterScript { $_.Name -eq "EphemeralOSDiskSupported" }).Value
                        MaxEphemeralOsDiskSizeGb = [Math]::Min(2048, (($Sku.Capabilities | Where-Object -FilterScript { $_.Name -eq "CachedDiskBytes" }).Value / 1GB))
                    }
                    $VmSku
                }
            }
            [HostPool]::AzEphemeralOsDiskSkuHT[$Location] = $EphemeralOsDisk
        }

        HostPool([Object] $KeyVault) {
            #Write-Host "Calling HostPool Constructor with KeyVault parameter ..."
            if ($null -eq [HostPool]::AzLocationShortNameHT) {
                [HostPool]::BuildAzureLocationSortNameHashtable()
            }
            if ($null -eq [HostPool]::AzEphemeralOsDiskSkuHT) {
                [HostPool]::AzEphemeralOsDiskSkuHT = @{}
            }
            $this.Location = "EastUS"
            $this.VMNumberOfInstances = 3
            $this.VMSize = "Standard_D2s_v5"
            $this.DisableSpotInstance()
            $this.DisableIntune()            
            $this.EnableScalingPlan()
            $this.KeyVault = $KeyVault
            $this.IdentityProvider = [IdentityProvider]::ActiveDirectory
        }

        [string] GetAzAvdWorkSpaceName() {
            return "ws-{0}" -f $($this.Name.ToLower())
        }

        [string] GetAzAvdScalingPlanName() {
            return "sp-avd-{0}" -f $($this.Name.ToLower())
        }

        [string] GetLogAnalyticsWorkSpaceName() {
            return "log{0}" -f $($this.Name.ToLower() -replace "\W")
        }

        [string] GetResourceGroupName() {
            return "rg-avd-{0}" -f $($this.Name.ToLower())
        }

        [string] GetKeyVaultName() {
            return "kv{0}" -f $($this.Name.ToLower() -replace "\W")
        }

        [object] GetPropertyForJSON() {
            return $this | Select-Object -Property *, @{Name = "ResourceGroupName"; Expression = { $_.GetResourceGroupName() } }, @{Name = "KeyVaultName"; Expression = { $_.GetKeyVaultName() } }, @{Name = "LogAnalyticsWorkSpaceName"; Expression = { $_.GetLogAnalyticsWorkSpaceName() } } -ExcludeProperty "KeyVault"
        }


        [HostPool] SetVMNumberOfInstances([int] $VMNumberOfInstances) {
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
            if (-not([HostPool]::AzEphemeralOsDiskSkuHT.ContainsKey($this.Location))) {
                [HostPool]::BuildAzureEphemeralOsDiskSkuHashtable($this.Location)
            }
            if ($this.VMSize -in (([HostPool]::AzEphemeralOsDiskSkuHT)[$this.Location]).Name) {
                Write-Host -Object "'$($this.VMSize)' is eligible to Ephemeral OS Disk"
            }
            else {
                Write-Error -Message "'$($this.VMSize)' is NOT eligible to Ephemeral Os Disk. Stopping !" -ErrorAction Stop
            }
            $this.DiffDiskPlacement = $DiffDiskPlacement
            return $this
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
                Write-Warning "The specified '$VMSize' is not available in the '$($this.Location)' Azure region. We keep the previously set VMSize: '$($this.VMSize)' ..."
            }

            if ($this.DiffDiskPlacement -ne [DiffDiskPlacement]::None) {
                if ($this.VMSize -in (([HostPool]::AzEphemeralOsDiskSkuHT)[$this.Location]).Name) {
                    Write-Verbose -Message "'$($this.VMSize)' is eligible to Ephemeral Os Disk"
                }
                else {
                    Write-Error -Message "'$($this.VMSize)' is NOT eligible to Ephemeral Os Disk" -ErrorAction Stop
                }
            }

            return $this
        }

        [HostPool] SetLocation([string] $Location) {
            if ([HostPool]::AzLocationShortNameHT.ContainsKey($Location)) {
                if ($this.VMSize -in (Get-AzVMSize -Location $Location).Name) {
                    $this.Location = $Location
                    $this.RefreshNames()
                }
                else {
                    Write-Warning "The specified '$($Location)' Azure region doesn't allow the '$($this.VMSize)'. We keep the previously set location: '$($this.Location)' ..."
                }
            }
            else {
                Write-Warning -Message "Unknown Azure Location: '$($Location)'. We keep the previously set location: '$($this.Location)'"
            }

            if (-not([HostPool]::AzEphemeralOsDiskSkuHT.ContainsKey($this.Location))) {
                [HostPool]::BuildAzureEphemeralOsDiskSkuHashtable($this.Location)
            }

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

    }

class PooledHostPool : HostPool {
        hidden [ValidateRange(0, 999)] static [int] $Index = 0
        [ValidateRange(0, 10)] [int] $MaxSessionLimit
        [ValidateNotNullOrEmpty()] [boolean] $FSlogix
        [ValidateNotNullOrEmpty()] [boolean] $MSIX

        PooledHostPool([Object] $KeyVault):base($KeyVault) {
            [PooledHostPool]::Index++
            $this.Type = [HostPoolType]::Pooled
            $this.MaxSessionLimit = 5
            $this.ImagePublisherName = "microsoftwindowsdesktop"
            $this.ImageOffer = "office-365"
            $this.ImageSku = "win11-23h2-avd-m365"
            $this.FSlogix = $true
            $this.MSIX = $true
            $this.RefreshNames()
        }

        static ResetIndex() {
            [PooledHostPool]::Index = 0
        }

        [string] GetFSLogixStorageAccountName() {
            if ($this.FSlogix) {
                return "fsl{0}" -f $($this.Name.ToLower() -replace "\W")
            }
            else {
                return $null
            }
        }

        [string] GetMSIXStorageAccountName() {
            if ($this.MSIX) {
                return "msix{0}" -f $($this.Name.ToLower() -replace "\W")
            }
            else {
                return $null
            }
        }

        [PooledHostPool] SetIndex([int] $Index) {
            [PooledHostPool]::Index = $Index
            $this.RefreshNames()        
            return $this
        }

        [PooledHostPool] SetMaxSessionLimit([int] $MaxSessionLimit) {
            $this.MaxSessionLimit = $MaxSessionLimit
            return $this
        }

        [PooledHostPool]DisableFSLogix() {
            $this.FSLogix = $false
            return $this
        }

        [PooledHostPool]EnableFSLogix() {
            $this.FSLogix = $true
            return $this
        }

        [PooledHostPool]DisableMSIX() {
            $this.MSIX = $false
            return $this
        }

        [PooledHostPool]EnableMSIX() {
            if (-not($this.IsMicrosoftEntraIdJoined())) {
                $this.MSIX = $true
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
            $TempNamePrefix += "pc"

            if ($this.VMSourceImageId) {
                $TempName += "-cg"
                $TempNamePrefix += "c"
            }
            else {
                $TempName += "-mp"
                $TempNamePrefix += "m"
            }

            $this.Name = "{0}-{1}-{2:D3}" -f $TempName, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PooledHostPool]::Index
            $this.NamePrefix = "{0}{1}{2:D3}" -f $TempNamePrefix, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PooledHostPool]::Index
        }
    }

class PersonalHostPool : HostPool {
        hidden [ValidateRange(0, 999)] static [int] $Index = 0
        #Hibernation is not compatible with Spot Instance and is only allowed for Personal Dektop
        [ValidateNotNullOrEmpty()] [boolean] $HibernationEnabled = $false

        PersonalHostPool([Object] $KeyVault):base($KeyVault) {
            [PersonalHostPool]::Index++
            $this.Type = [HostPoolType]::Personal
            $this.ImagePublisherName = "microsoftwindowsdesktop"
            $this.ImageOffer = "windows-11"
            $this.ImageSku = "win11-23h2-ent"
            $this.HibernationEnabled = $false
            $this.RefreshNames()
        }

        static ResetIndex() {
            [PersonalHostPool]::Index = 0
        }

        [PersonalHostPool] SetIndex([int] $Index) {
            [PersonalHostPool]::Index = $Index
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
            $TempNamePrefix += "pc"

            if ($this.VMSourceImageId) {
                $TempName += "-cg"
                $TempNamePrefix += "c"
            }
            else {
                $TempName += "-mp"
                $TempNamePrefix += "m"
            }

            $this.Name = "{0}-{1}-{2:D3}" -f $TempName, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PersonalHostPool]::Index
            $this.NamePrefix = "{0}{1}{2:D3}" -f $TempNamePrefix, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PersonalHostPool]::Index
        }
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
    foreach($Type in $ExportableTypes) {
        $TypeAcceleratorsClass::Remove($Type.FullName)
    }
}.GetNewClosure()
#endregion

#region Function definitions

#region Prerequisites
function Install-RequiredModule {
    [CmdletBinding()]
    Param()

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"
    #For installing required modules if needed
    #Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    $null = Get-PackageProvider -Name NuGet -Force
    $RequiredModules = 'Az.Accounts', @{ ModuleName='Az.Compute'; MinimumVersion='7.1.2' }, 'Az.DesktopVirtualization', 'Az.ImageBuilder', 'Az.ManagedServiceIdentity', 'Az.KeyVault', 'Az.Monitor', 'Az.Network', 'Az.OperationalInsights', 'Az.PrivateDns', 'Az.Resources', 'Az.Storage', @{ ModuleName='Microsoft.Graph.Authentication'; MaximumVersion='2.17.0' }, @{ ModuleName='Microsoft.Graph.Beta.DeviceManagement'; MaximumVersion='2.17.0' }, @{ ModuleName='Microsoft.Graph.Beta.DeviceManagement.Actions'; MaximumVersion='2.17.0' }, @{ ModuleName='Microsoft.Graph.Beta.DeviceManagement.Administration'; MaximumVersion='2.17.0' }, @{ ModuleName='Microsoft.Graph.Beta.Groups'; MaximumVersion='2.17.0' }, @{ ModuleName='Microsoft.Graph.Beta.Identity.DirectoryManagement'; MaximumVersion='2.17.0' }, @{ ModuleName='Microsoft.Graph.Beta.Identity.SignIns'; MaximumVersion='2.17.0' }, 'ThreadJob'

    $NonVersionedRequiredModules = $RequiredModules | Where-Object { $_ -is [string]}
    $NonVersionedInstalledModules = Get-InstalledModule -Name $NonVersionedRequiredModules -ErrorAction Ignore
    if (-not([String]::IsNullOrEmpty($NonVersionedInstalledModules))) {
        $NonVersionedMissingModules = (Compare-Object -ReferenceObject $NonVersionedRequiredModules -DifferenceObject $NonVersionedInstalledModules.Name).InputObject
    }
    else {
        $NonVersionedMissingModules = $NonVersionedRequiredModules
    }
    if (-not([String]::IsNullOrEmpty($NonVersionedMissingModules))) {
        Write-Verbose -Message "Installing PowerShell Modules: $($NonVersionedMissingModules -join ', ')"
        Install-Module -Name $NonVersionedMissingModules -Force -AllowClobber -Scope AllUsers
    }

    $VersionedRequiredModules = $RequiredModules | Where-Object { $_ -is [hashtable] }
    foreach ($CurrentVersionedRequiredModule in $VersionedRequiredModules)
    {
        Write-Verbose -Message "`$CurrentVersionedRequiredModule:`r`n$($CurrentVersionedRequiredModule | Out-String)"
        if ($CurrentVersionedRequiredModule.ContainsKey('MinimumVersion')) {
            $InstalledModule = Get-InstalledModule -Name $CurrentVersionedRequiredModule['ModuleName'] -MinimumVersion $CurrentVersionedRequiredModule['MinimumVersion'] -ErrorAction Ignore
            if ($null -eq $InstalledModule) {
                Write-Verbose -Message $("Installing PowerShell Module: {0} - {1}" -f $CurrentVersionedRequiredModule['ModuleName'], $CurrentVersionedRequiredModule['MinimumVersion'])
                Install-Module -Name $CurrentVersionedRequiredModule['ModuleName'] -MinimumVersion $CurrentVersionedRequiredModule['MinimumVersion'] -Force -AllowClobber -Scope AllUsers #-WhatIf
            }
            else {
                Write-Verbose -Message $("MinimumVersion '{0}': PowerShell Module '{1}' already installed in version '{2}'" -f $CurrentVersionedRequiredModule['MinimumVersion'], $InstalledModule.Name, $InstalledModule.Version)
            }
        }
        elseif ($CurrentVersionedRequiredModule.ContainsKey('MaximumVersion')) {
            $InstalledModule = Get-InstalledModule -Name $CurrentVersionedRequiredModule['ModuleName'] -MaximumVersion $CurrentVersionedRequiredModule['MaximumVersion'] -ErrorAction Ignore
            if ($null -eq $InstalledModule) {
                Write-Verbose -Message $("Installing PowerShell Module: {0} - {1}" -f $CurrentVersionedRequiredModule['ModuleName'], $CurrentVersionedRequiredModule['MaximumVersion'])
                Install-Module -Name $CurrentVersionedRequiredModule['ModuleName'] -MaximumVersion $CurrentVersionedRequiredModule['MaximumVersion'] -Force -AllowClobber -Scope AllUsers #-WhatIf
            }
            else {
                Write-Verbose -Message $("MaximumVersion '{0}': PowerShell Module '{1}' already installed in version '{2}'" -f $CurrentVersionedRequiredModule['MaximumVersion'], $InstalledModule.Name, $InstalledModule.Version)
            }
        }
    }

    $InstalledModule = Get-InstalledModule -Name $($NonVersionedRequiredModules+($VersionedRequiredModules | ForEach-Object -Process { $_['ModuleName']})) -ErrorAction Ignore
    Write-Verbose "Installed Modules: `r`n$InstalledModule"
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function Connect-Azure {
    [CmdletBinding()]
    Param()

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"
    #region Azure Connection

    try { 
        $null = Get-AzAccessToken -ErrorAction Stop
    } catch {
        Connect-AzAccount -UseDeviceAuthentication
        Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
        Write-Verbose -Message "Account : $((Get-AzContext).Account)"
        Write-Verbose -Message "Subscription : $((Get-AzContext).Subscription.Name)"
    }
    #endregion

    #region Microsoft Graph Connection
    try {
        $null = Get-MgBetaDevice -All -ErrorAction Stop
    }
    catch {
        Write-Verbose -Message "Connecting to Microsoft Graph with all required Scopes"
        Connect-MgGraph -NoWelcome -Scopes Device.Read.All, Device.ReadWrite.All, DeviceManagementConfiguration.Read.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.PrivilegedOperations.All, DeviceManagementManagedDevices.Read.All, DeviceManagementManagedDevices.ReadWrite.All, Directory.AccessAsUser.All, Directory.Read.All, Directory.ReadWrite.All
    }
    #endregion
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function Register-AzRequiredResourceProvider {
    [CmdletBinding()]
    Param()

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"
    #region Azure Provider Registration
    #To use Azure Virtual Desktop, you have to register for the providers and to ensure that RegistrationState will be set to Registered.
    #$RequiredResourceProviders = "Microsoft.ContainerInstance", "Microsoft.DesktopVirtualization", "Microsoft.Insights", "Microsoft.VirtualMachineImages", "Microsoft.Storage", "Microsoft.Compute", "Microsoft.KeyVault", "Microsoft.ManagedIdentity"
    $RequiredResourceProviders = "Microsoft.ContainerInstance", "Microsoft.DesktopVirtualization", "Microsoft.Insights", "Microsoft.VirtualMachineImages", "Microsoft.Storage", "Microsoft.Compute", "Microsoft.KeyVault", "Microsoft.ManagedIdentity", "Microsoft.Compute/VMHibernationPreview" #,"Microsoft.Compute/AdditionalStorageTypesForEphemeralOSDiskPreview" 
    $RequiredPreviewResourceProviders = $RequiredResourceProviders | Where-Object -FilterScript { $_ -match "preview|/"}
    $RequiredNonPreviewResourceProviders = $RequiredResourceProviders | Where-Object -FilterScript { $_ -notin $RequiredPreviewResourceProviders }

    #region Non-preview Resource Providers
    $Jobs = foreach ($CurrentRequiredNonPreviewResourceProviders in $RequiredNonPreviewResourceProviders) {
        Write-Verbose -Message "Registering '$CurrentRequiredNonPreviewResourceProviders' Resource Provider"
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
    $Result = $Jobs | Receive-Job -Wait -AutoRemoveJob
    $NonRegisteredProviders = ($Result | Where-Object -FilterScript {$_.RegistrationState -ne "Registered"}).ProviderNamespace
    if ($NonRegisteredProviders) {
        Write-Warning -Message "The following resource providers were NOT registered: $($NonRegisteredProviders -join ', ')"
    }
    #endregion

    #region Preview Resource Providers
    $Result = foreach ($CurrentRequiredPreviewResourceProviders in $RequiredPreviewResourceProviders) {
        $ProviderNamespace, $FeatureName = $CurrentRequiredPreviewResourceProviders -split "/"
        Write-Verbose -Message "Registering '$RequiredPreviewResourceProviders' Resource Provider"
        try {
            Register-AzProviderFeature -FeatureName $FeatureName -ProviderNamespace $ProviderNamespace -ErrorAction Stop
        }
        catch {
            # Dig into the exception to get the Response details.
            # Note that value__ is not a typo.
            Write-Warning -Message "Unable to register '$CurrentRequiredPreviewResourceProviders' Resource Provider"
            Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
            Write-Warning -Message "Message: $($_.Exception.Message)"
        }
    }
    $NonRegisteredProviders = ($Result | Where-Object -FilterScript {$_.RegistrationState -ne "Registered"}).ProviderNamespace
    if ($NonRegisteredProviders) {
        Write-Warning -Message "The following resource providers were NOT registered: $($NonRegisteredProviders -join ', ')"
    }
    #endregion
    #endregion

    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function Install-FSLogixGPOSettings {
    [CmdletBinding()]
    Param(
        [switch] $Force
    )
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"
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
            #Version: June 2024
            $FSLogixLatestURI = "https://download.microsoft.com/download/e/c/4/ec4b55b3-d2f3-4610-aebd-56478eb0d582/FSLogix_Apps_2.9.8884.27471.zip"
        }
        $OutFile = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $FSLogixLatestURI -Leaf)
        Write-Verbose -Message "Downloading from '$FSLogixLatestURI' to '$OutFile'"
        Start-BitsTransfer $FSLogixLatestURI -destination $OutFile
        $DestinationPath = Join-Path -Path $env:Temp -ChildPath "FSLogixLatest"
        Write-Verbose -Message "Unzipping '$OutFile' into '$DestinationPath'..."
        Expand-Archive -Path $OutFile -DestinationPath $DestinationPath -Force
        $ADMLFilePath = Join-Path -Path $DestinationPath -ChildPath "fslogix.adml"
        $ADMXFilePath = Join-Path -Path $DestinationPath -ChildPath "fslogix.admx"
        Write-Verbose -Message "Copying '$ADMLFilePath' into '$env:SystemRoot\policyDefinitions\en-US'"
        Copy-Item -Path $ADMLFilePath $env:SystemRoot\policyDefinitions\en-US
        Write-Verbose -Message "Copying '$ADMXFilePath' into '$env:SystemRoot\policyDefinitions'"
        Copy-Item -Path $ADMXFilePath $env:SystemRoot\policyDefinitions
        Remove-Item -Path $OutFile, $DestinationPath -Recurse -Force
    }
    #endregion 
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function Install-AVDGPOSettings {
    [CmdletBinding()]
    Param(
        [switch] $Force
    )
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    #region Installing AVD GPO Setting
    if (-not(Test-Path -Path $env:SystemRoot\policyDefinitions\en-US\terminalserver-avd.adml -PathType Leaf) -or -not(Test-Path -Path $env:SystemRoot\policyDefinitions\terminalserver-avd.admx -PathType Leaf) -or $Force) {
        $AVDGPOLatestCabName = 'AVDGPTemplate.cab'
        $null = New-Item -Path $env:Temp -ItemType Directory -Force
        $OutFile = Join-Path -Path $env:Temp -ChildPath $AVDGPOLatestCabName
        $AVDGPOLatestURI = 'https://aka.ms/avdgpo'
        Invoke-WebRequest -Uri  $AVDGPOLatestURI -OutFile $OutFile 
        $AVDGPOLatestDir = New-Item -Path $env:Temp\AVDGPOLatest -ItemType Directory -Force
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "extrac32 $OutFile /Y" -WorkingDirectory $AVDGPOLatestDir -Wait 
        $ZipFiles = Get-ChildItem -Path $AVDGPOLatestDir -Filter *.zip -File 
        $ZipFiles | Expand-Archive -DestinationPath $AVDGPOLatestDir -Force
        Remove-Item -Path $ZipFiles.FullName, $OutFile  -Force

        $ADMLFilePath = Join-Path -Path $AVDGPOLatestDir -ChildPath "en-US\terminalserver-avd.adml"
        $ADMXFilePath = Join-Path -Path $AVDGPOLatestDir -ChildPath "terminalserver-avd.admx"
        Write-Verbose -Message "Copying '$ADMLFilePath' into '$env:SystemRoot\policyDefinitions\en-US'"
        Copy-Item -Path $ADMLFilePath $env:SystemRoot\policyDefinitions\en-US
        Write-Verbose -Message "Copying '$ADMXFilePath' into '$env:SystemRoot\policyDefinitions'"
        Copy-Item -Path $ADMXFilePath $env:SystemRoot\policyDefinitions
        Remove-Item -Path $AVDGPOLatestDir -Recurse -Force

    }
    #endregion 
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}
#endregion

#region Microsoft Entra ID Conditional Access Policies
function New-NoMFAUserEntraIDGroup {
    [CmdletBinding()]
    Param (
        [string] $NoMFAEntraIDGroupName = 'No-MFA Users'
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    $NoMFAEntraIDGroup = Get-MgBetaGroup -Filter "displayName eq '$NoMFAEntraIDGroupName'"
    $MailNickname = $($NoMFAEntraIDGroupName -replace "\s" -replace "\W").ToLower()
    if (-not($NoMFAEntraIDGroup)) {
        Write-Verbose -Message "Creating '$NoMFAEntraIDGroupName' Entra ID Group"
        $NoMFAEntraIDGroup = New-MgBetaGroup -DisplayName $NoMFAEntraIDGroupName -MailEnabled:$False -MailNickname $MailNickname -SecurityEnabled
    }
    $NoMFAEntraIDGroup
    Write-Host -Object "Leaving  function '$($MyInvocation.MyCommand)'"
}

function New-MFAForAllUsersConditionalAccessPolicy {
    [CmdletBinding()]
    Param (
        [string[]] $ExcludeGroupName = 'No-MFA Users',
        [string] $DisplayName = "[AVD] Require multifactor authentication for all users"
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    $DirectorySynchronizationAccountsRole = Get-MgBetaDirectoryRole -Filter "DisplayName eq 'Directory Synchronization Accounts'"
    $ExcludeGroups = foreach ($CurrentExcludeGroupName in $ExcludeGroupName) {
        Get-MgBetaGroup -Filter "displayName eq '$CurrentExcludeGroupName'"
    }

    $MFAForAllUsersConditionalAccessPolicy = Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq '$DisplayName'"
    if (-not($MFAForAllUsersConditionalAccessPolicy)) {
        # Define the policy properties
        Write-Verbose -Message "'$DisplayName' Conditional Access Policy NOT found. We're creating it "
        $policyProperties = @{
            DisplayName = $DisplayName
            State = "Enabled"
            Conditions = @{
                Applications = @{
                    IncludeApplications = @("All")
                }
                Users = @{
                    IncludeUsers = @("All")
                    ExcludeGroups = $ExcludeGroups.Id
                    ExcludeRoles = $DirectorySynchronizationAccountsRole.RoleTemplateId 
                }
            }
            GrantControls = @{
                BuiltInControls = @("Mfa")
                Operator = "OR"
            }
        }
        # Create the policy
        Write-Verbose -Message "Creating '$DisplayName' Conditional Access Policy"
        $MFAForAllUsersConditionalAccessPolicy = New-MgBetaIdentityConditionalAccessPolicy -BodyParameter $policyProperties
    }
    else {
        Write-Verbose -Message "'$DisplayName' Conditional Access Policy found. We're updating it "
        $policyProperties = @{
            State = "Enabled"
            Conditions = @{
                Applications = @{
                    IncludeApplications = @("All")
                }
                Users = @{
                    IncludeUsers = @("All")
                    ExcludeGroups = $ExcludeGroups.Id
                    ExcludeRoles = $DirectorySynchronizationAccountsRole.RoleTemplateId 
                }
            }
            GrantControls = @{
                BuiltInControls = @("Mfa")
                Operator = "OR"
            }
        }
        # Create the policy
        Write-Verbose -Message "Updating '$DisplayName' Conditional Access Policy"
        $MFAForAllUsersConditionalAccessPolicy = Update-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $MFAForAllUsersConditionalAccessPolicy.Id -BodyParameter $policyProperties
        $MFAForAllUsersConditionalAccessPolicy = Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq '$DisplayName'"
    }
    $MFAForAllUsersConditionalAccessPolicy
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}
#endregion

#region Intune Management
#region Graph API

#From https://github.com/andrew-s-taylor/public/blob/main/Powershell%20Scripts/Intune/function-getallpagination.ps1
function Get-MgGraphObject {
    [CmdletBinding()]
    Param (
        [ValidateScript({ $_ -match '^https?://' })]
        [string] $Uri
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

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
    
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    return $MgGraphObject
}

Function Sync-IntuneSessionHostViaGraphAPI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $HostPool
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Graph API
    #region Devices
    $RegExp = ($HostPool.NamePrefix -replace '(^[^\n]*$)', '^$1-') -join '|'
    $AllDevices = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices"
    $FilteredDevices = $AllDevices | Where-Object -FilterScript {$_.DeviceName -match $RegExp }
    $FilteredDevices | ForEach-Object -Process { 
        Write-Verbose -Message "Sending Sync request to Device with Device name '$($_.DeviceName)'"
        $RemovedDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($_.id)/microsoft.graph.syncDevice" -Method POST -OutputType PSObject
    }
    #endregion
    #endregion
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

Function Remove-IntuneItemViaGraphAPI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $HostPool
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Graph API
    #region deviceManagementScripts and groupPolicyConfigurations
    $RegExp = ($HostPool.Name -replace '(^[^\n]*$)', '^\[$1\]') -join '|'
    $Topics = "deviceManagementScripts", "groupPolicyConfigurations"
    foreach($CurrentTopic in $Topics) {
        Write-Verbose -Message "Processing '$($CurrentTopic)'"
        $URI = "https://graph.microsoft.com/beta/deviceManagement/$($CurrentTopic)?`$select=id,displayname"
        $DeviceManagementTopics = Get-MgGraphObject -Uri $URI | Where-Object -FilterScript { ($_.displayName -match $RegExp) }
        foreach ($CurrentDeviceManagementTopic in $DeviceManagementTopics) {
            Write-Verbose -Message "Removing the '$($CurrentDeviceManagementTopic.displayName)' $CurrentTopic (id: '$($CurrentDeviceManagementTopic.id)')"
            Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/$CurrentTopic/$($CurrentDeviceManagementTopic.id)" -Method DELETE -OutputType PSObject
        }
    }
    #endregion

    #region configurationPolicies
    $RegExp = ($HostPool.Name -replace '(^[^\n]*$)', '^\[$1\]') -join '|'
    $Topics = "configurationPolicies"
    foreach($CurrentTopic in $Topics) {
        Write-Verbose -Message "Processing '$($CurrentTopic)'"
        $URI = "https://graph.microsoft.com/beta/deviceManagement/$($CurrentTopic)?`$select=id,name"
        $DeviceManagementTopics = Get-MgGraphObject -Uri $URI | Where-Object -FilterScript { ($_.name -match $RegExp) }
        foreach ($CurrentDeviceManagementTopic in $DeviceManagementTopics) {
            Write-Verbose -Message "Removing the '$($CurrentDeviceManagementTopic.name)' $CurrentTopic (id: '$($CurrentDeviceManagementTopic.id)')"
            Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/$CurrentTopic/$($CurrentDeviceManagementTopic.id)" -Method DELETE -OutputType PSObject
        }
    }
    #endregion

    #region Devices
    $RegExp = ($HostPool.NamePrefix -replace '(^[^\n]*$)', '^$1-') -join '|'
    $AllDevices = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices"
    $FilteredDevices = $AllDevices | Where-Object -FilterScript {$_.DeviceName -match $RegExp }
    $FilteredDevices | ForEach-Object -Process { 
        Write-Verbose -Message "Removing Intune Enrolled Device : $($_.DeviceName)"
        $RemovedDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($_.id)" -Method DELETE -OutputType PSObject
    }
    #endregion
    #endregion
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

#From https://learn.microsoft.com/en-us/graph/api/intune-shared-devicemanagementscript-create?view=graph-rest-beta
Function New-IntunePowerShellScriptViaGraphAPI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $true, ParameterSetName = 'ScriptURI')]
        [ValidateScript({ $_ -match '^https?://' })]
        [string]$ScriptURI,

        [Parameter(Mandatory = $true, ParameterSetName = 'ScriptPath')]
        [string]$ScriptPath
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Graph API
    #region Azure AD Desktop Application Group 
    $HostPoolDAGUsersAzADGroupName = "$HostPoolName - Desktop Application Group Users"
    $HostPoolDAGUsersAzADGroup = Get-AzADGroup -DisplayName $HostPoolDAGUsersAzADGroupName
    if ($null -eq $HostPoolDAGUsersAzADGroup) {
        Write-Error -Message "The '$HostPoolDAGUsersAzADGroupName' doesn't exist !"
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
    #endregion

    #region Azure AD Remote Application Group 
    $HostPoolRAGUsersAzADGroupName = "$HostPoolName - Remote Application Group Users"
    $HostPoolRAGUsersAzADGroup = Get-AzADGroup -DisplayName $HostPoolRAGUsersAzADGroupName
    if ($null -eq $HostPoolRAGUsersAzADGroup) {
        Write-Error -Message "The '$HostPoolRAGUsersAzADGroup' doesn't exist !"
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
    #endregion

    #region Uploading Powershell Script
    if ($ScriptURI) {
        $ScriptURIContent = Invoke-RestMethod -Uri $ScriptURI
        $ScriptContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ScriptURIContent))
        $FileName = Split-Path $ScriptURI -Leaf
        Write-Verbose -Message "Adding the '$ScriptURI' script"
    }
    else {
        $ScriptPathContent = Get-Content -Path $ScriptPath -Encoding Byte -Raw
        $ScriptContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ScriptPathContent))
        $FileName = Split-Path $ScriptPathContent -Leaf
        Write-Verbose -Message "Adding the '$ScriptPath' script"
    }

    Write-Verbose -Message "`$FileName: '$FileName'"
    $DisplayName = "[{0}] {1}" -f $HostPoolName, $FileName
    Write-Verbose -Message "`$DisplayName: '$DisplayName'"
    #Checking if the script is already present (with the same naming convention)
    $AddedScript = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?`$filter=displayName+eq+'$DisplayName'"
    #If present
    if ($AddedScript) {
        Write-Verbose -Message "Deleting the previously imported PowerShell Script file '$DisplayName' if any"
        $AddedScript = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($AddedScript.id)" -Method DELETE
        if ($AddedScript.Value.status -eq 'removalFailed') {
            Write-Error -Message "Removal Failed"
            Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
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
    Write-Verbose -Message "Assigning the '$FileName' PowerShell script to '$HostPoolDAGUsersAzADGroupName'"
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

    Write-Verbose -Message "Assigning the '$FileName' PowerShell script to '$HostPoolRAGUsersAzADGroupName'"
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
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function Get-GroupPolicyDefinitionPresentationViaGraphAPI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array] $GroupPolicyDefinition
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Graph API
    $GroupPolicyDefinitionPresentationHT = @{}
    foreach ($CurrentGroupPolicyDefinition in $GroupPolicyDefinition) {
        $CurrentGroupPolicyDefinitionPresentation = Get-MgGraphObject -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyDefinitions/$($CurrentGroupPolicyDefinition.id)/presentations"
        $Key = "{0} (version: {1})" -f $CurrentGroupPolicyDefinition.displayName, $CurrentGroupPolicyDefinition.version
        if ($CurrentGroupPolicyDefinition.supportedOn) {
            Write-Verbose -Message "Processing '$Key' (Supported On: $($CurrentGroupPolicyDefinition.supportedOn))"
            $GroupPolicyDefinitionPresentationHT.Add($("{0} (Supported On: {1})" -f $Key, $CurrentGroupPolicyDefinition.supportedOn) , $CurrentGroupPolicyDefinitionPresentation.Value)
        }
        else {
            Write-Verbose -Message "Processing '$Key'"
            $GroupPolicyDefinitionPresentationHT.Add($Key, $CurrentGroupPolicyDefinitionPresentation.Value)
        }
    }
    $GroupPolicyDefinitionPresentationHT
    #endregion
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function Import-FSLogixADMXViaGraphAPI {
    [CmdletBinding()]
    Param (
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Graph API
    #Checking if the ADMX is already present -
    $GroupPolicyUploadedDefinitionFile = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles?`$filter=fileName+eq+'fslogix.admx'"
    #If present
    if ($GroupPolicyUploadedDefinitionFile) {
        if ($GroupPolicyUploadedDefinitionFile.status -eq 'available') {
            Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
            Write-Verbose -Message "Returning the previously imported ADMX file"
            return $GroupPolicyUploadedDefinitionFile
        }
        else {
            Write-Verbose -Message "Deleting the previously imported ADMX file"
            $GroupPolicyUploadedDefinitionFile = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($GroupPolicyUploadedDefinitionFile.id)" -Method DELETE
            if ($GroupPolicyUploadedDefinitionFile.Value.status -eq 'removalFailed') {
                Write-Error -Message "Removal Failed"
                Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
                return $GroupPolicyUploadedDefinitionFile
            }
        }
    }

    #Always get the latest version of FSLogix
    #$FSLogixLatestURI = ((Invoke-WebRequest -Uri "https://aka.ms/fslogix-latest").Links | Where-Object -FilterScript { $_.innerText -eq "Download" }).href
    $FSLogixLatestURI = ((Invoke-WebRequest -Uri "https://aka.ms/fslogix-latest" -UseBasicParsing).Links | Where-Object -FilterScript { $_.href -match ".zip$" }).href
    $OutFile = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $FSLogixLatestURI -Leaf)
    Write-Verbose -Message "Downloading from '$FSLogixLatestURI' to '$OutFile'"
    Start-BitsTransfer $FSLogixLatestURI -destination $OutFile
    $DestinationPath = Join-Path -Path $env:Temp -ChildPath "FSLogixLatest"
    Write-Verbose -Message "Unzipping '$OutFile' into '$DestinationPath'"
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

    Write-Verbose -Message "Uploading the ADMX and ADML files"
    $GroupPolicyUploadedDefinitionFile = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyUploadedDefinitionFiles" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject).value
    
    #Waiting for the import completion
    $GroupPolicyUploadedDefinitionFileId = $GroupPolicyUploadedDefinitionFile.id
    While ($GroupPolicyUploadedDefinitionFile.status -eq 'uploadInProgress') {
        $GroupPolicyUploadedDefinitionFile = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles?`$filter=id+eq+'$GroupPolicyUploadedDefinitionFileId'"
        Write-Verbose -Message "Waiting the upload completes. Sleeping 10 seconds"
        Start-Sleep -Seconds 10
    } 
    Write-Verbose -Message "Final status: $($GroupPolicyUploadedDefinitionFile.status)"

    Remove-Item -Path $OutFile, $DestinationPath -Recurse -Force
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    return $GroupPolicyUploadedDefinitionFile
    #endregion
}

function Set-GroupPolicyDefinitionSettingViaGraphAPI {
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
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Graph API
    Write-Verbose -Message "Parameter Set: $($psCmdlet.ParameterSetName)"
    Write-Verbose -Message "[$($GroupPolicyConfiguration.displayName)] Processing '$($GroupPolicyDefinition.categoryPath)\$($GroupPolicyDefinition.displayName)'"
    Write-Verbose -Message "`$Value: $Value"
    $GroupPolicyDefinitionPresentation = Get-MgGraphObject -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyDefinitions/$($GroupPolicyDefinition.id)/presentations"
    if ($GroupPolicyDefinitionPresentation.count -gt 1) {
        #When multiple Group Policy Definition Presentations are returned we keep only the one(s) with a 'required' property
        $GroupPolicyDefinitionPresentationValues = $GroupPolicyDefinitionPresentation | Where-Object -FilterScript { "required" -in $_.psobject.Properties.Name }
    }
    else {
        $GroupPolicyDefinitionPresentationValues = $GroupPolicyDefinitionPresentation
    }
    Write-Verbose -Message "`$GroupPolicyDefinitionPresentationValues:`r`n$($GroupPolicyDefinitionPresentationValues | Out-String)"
    if ($GroupPolicyDefinitionPresentationValues) {
        $PresentationValues = foreach ($CurrentGroupPolicyDefinitionPresentationValue in $GroupPolicyDefinitionPresentationValues) {
            Write-Verbose -Message "Processing '$($CurrentGroupPolicyDefinitionPresentationValue.label)'"
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
            Write-Verbose -Message "`$CurrentValue: $CurrentValue"
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
        added = @(
            @{
                "definition@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($GroupPolicyDefinition.id)')"
                "enabled"               = $($psCmdlet.ParameterSetName -eq 'Enable')
                "presentationValues"    = @($PresentationValues)
            }    
        )
        deletedIds = @()
        updated    = @()
    }
    Write-Verbose -Message "[$($GroupPolicyConfiguration.displayName)] Enabling '$($GroupPolicyDefinition.categoryPath)\$($GroupPolicyDefinition.displayName)'"
    #$updatedDefinitionValues = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfiguration.id)/updateDefinitionValues" -Method POST -Body $($Body | ConvertTo-Json -Depth 100| ForEach-Object -Process { [System.Text.RegularExpressions.Regex]::Unescape($_) }) -OutputType PSObject
    $JSONBody = $($Body | ConvertTo-Json -Depth 100)
    $URI = "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfiguration.id)/updateDefinitionValues"
    Write-Verbose -Message "Body :`r`n$($JSONBody | ForEach-Object -Process { [System.Text.RegularExpressions.Regex]::Unescape($_) })"
    Write-Verbose -Message "Uri :`r`n$URI"
    $updatedDefinitionValues = Invoke-MgGraphRequest -Uri $URI -Method POST -Body $JSONBody -OutputType PSObject
    #endregion
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

#region Administrative Templates: DO NOT USE - Use Settings Catalog instead
function New-FSLogixIntuneAdministrativeTemplateConfigurationPolicyViaGraphAPI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('StorageAccountName')]
        [string] $CurrentHostPoolStorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $false)]
        [string] $StorageEndpointSuffix = 'core.windows.net'
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Graph API
    #region Azure AD Desktop Application Group 
    $HostPoolDAGUsersAzADGroupName = "$HostPoolName - Desktop Application Group Users"
    $HostPoolDAGUsersAzADGroup = Get-AzADGroup -DisplayName $HostPoolDAGUsersAzADGroupName
    if ($null -eq $HostPoolDAGUsersAzADGroup) {
        Write-Error -Message "The '$HostPoolDAGUsersAzADGroupName' doesn't exist !"
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
    #endregion

    #region Azure AD Remote Application Group 
    $HostPoolRAGUsersAzADGroupName = "$HostPoolName - Remote Application Group Users"
    $HostPoolRAGUsersAzADGroup = Get-AzADGroup -DisplayName $HostPoolRAGUsersAzADGroupName
    if ($null -eq $HostPoolRAGUsersAzADGroup) {
        Write-Error -Message "The '$HostPoolRAGUsersAzADGroup' doesn't exist !"
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
    #endregion

    #region groupPolicyConfigurations
    $GroupPolicyConfigurationName = "[{0}] FSLogix Policy" -f $HostPoolName
    #$Now = $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssK")
    $Now = Get-Date -Format o 
    Write-Verbose -Message "Creating the '$GroupPolicyConfigurationName' Group Policy Configuration"
    $Body = @{
        #"createdDateTime" = $Now
        "displayName" = $GroupPolicyConfigurationName
        #"description" = ""
        #"roleScopeTagIds" = @("0")
        #"policyConfigurationIngestionType" = "custom"
        #"id" = (New-Guid).Guid
        #"lastModifiedDateTime" = $Now
    }

    #Checking if the groupPolicyConfigurations is already present
    $GroupPolicyConfiguration = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?`$filter=displayName+eq+'$GroupPolicyConfigurationName'"
    if ($GroupPolicyConfiguration) {
        foreach ($CurrentValue in $GroupPolicyConfiguration) {
            Write-Verbose -Message "Deleting the previously '$($CurrentValue.displayName)' groupPolicyConfigurations (id: '$($CurrentValue.id)')"
            Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($CurrentValue.id)" -Method DELETE -OutputType PSObject
        }
    }
    $GroupPolicyConfiguration = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    #region Assign
    Write-Verbose -Message "Assigning the '$GroupPolicyConfigurationName' Group Policy Configuration to '$HostPoolDAGUsersAzADGroupName'"
    $Body = @{
        assignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $HostPoolDAGUsersAzADGroup.Id
                }
            }
        )
    }

    $Assign = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfiguration.id)/assign" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject

    Write-Verbose -Message "Assigning the '$GroupPolicyConfigurationName' Group Policy Configuration to '$HostPoolRAGUsersAzADGroupName'"
    $Body = @{
        assignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $HostPoolRAGUsersAzADGroup.Id
                }
            }
        )
    }
    $Assign = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfiguration.id)/assign" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    #region ADMX Management
    $FSLogixProfileContainersGroupPolicyDefinitions = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\FSLogix\Profile Containers')"
    if (-not($FSLogixProfileContainersGroupPolicyDefinitions)) {
        $GroupPolicyUploadedDefinitionFile = Import-FSLogixADMXViaGraphAPI
    }
    #endregion


    #region FSLogix Profile Containers Settings
    $FSLogixProfileContainersGroupPolicyDefinitions = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\FSLogix\Profile Containers')"
    #Adding a FullPath Property
    $FSLogixProfileContainersGroupPolicyDefinitions = $FSLogixProfileContainersGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($FSLogixProfileContainersGroupPolicyDefinitions) {
        { $_.FullPath -eq '\FSLogix\Profile Containers\Enabled' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_; continue }  
        { $_.FullPath -eq '\FSLogix\Profile Containers\Delete Local Profile When VHD Should Apply' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Container and Directory Naming\Flip Flop Profile Directory Name' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Locked Retry Count' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 3; continue }  
        { $_.FullPath -eq '\FSLogix\Profile Containers\Locked Retry Interval' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 15; continue }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Profile Type' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "0"; continue }
        { $_.FullPath -eq '\FSLogix\Profile Containers\ReAttach Interval' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 15; continue }
        { $_.FullPath -eq '\FSLogix\Profile Containers\ReAttach Count' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 3; continue }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Size In MBs' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 30000; continue }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Prevent Login With Failure' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 1; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Prevent Login With Temp Profile' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 1; continue }   
        { $_.FullPath -eq '\FSLogix\Profile Containers\Container and Directory Naming\Volume Type (VHD or VHDX)' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 'VHDX'; continue }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Is Dynamic (VHD)' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 1; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\VHD Locations' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Redirection XML Source Folder' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"; continue } 
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region FSLogix Logging Settings
    $FSLogixLoggingGroupPolicyDefinitions = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\FSLogix\Logging')"
    $FSLogixLoggingGroupPolicyDefinitions = $FSLogixLoggingGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($FSLogixLoggingGroupPolicyDefinitions) {
        { $_.FullPath -eq '\FSLogix\Logging\Log Keeping Period' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 10 }
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #endregion
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function New-AzAvdIntuneAdministrativeTemplateConfigurationPolicyViaGraphAPI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostPoolName
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Graph API
    #region Azure AD Desktop Application Group 
    $HostPoolDAGUsersAzADGroupName = "$HostPoolName - Desktop Application Group Users"
    $HostPoolDAGUsersAzADGroup = Get-AzADGroup -DisplayName $HostPoolDAGUsersAzADGroupName
    if ($null -eq $HostPoolDAGUsersAzADGroup) {
        Write-Error -Message "The '$HostPoolDAGUsersAzADGroupName' doesn't exist !"
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
    #endregion

    #region Azure AD Remote Application Group 
    $HostPoolRAGUsersAzADGroupName = "$HostPoolName - Remote Application Group Users"
    $HostPoolRAGUsersAzADGroup = Get-AzADGroup -DisplayName $HostPoolRAGUsersAzADGroupName
    if ($null -eq $HostPoolRAGUsersAzADGroup) {
        Write-Error -Message "The '$HostPoolRAGUsersAzADGroup' doesn't exist !"
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
    #endregion

    #region groupPolicyConfigurations
    $GroupPolicyConfigurationName = "[{0}] AVD Policy" -f $HostPoolName
    #$Now = $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssK")
    $Now = Get-Date -Format o 
    Write-Verbose -Message "Creating the '$GroupPolicyConfigurationName' Group Policy Configuration"
    $Body = @{
        #"createdDateTime" = $Now
        "displayName" = $GroupPolicyConfigurationName
        #"description" = ""
        #"roleScopeTagIds" = @("0")
        #"policyConfigurationIngestionType" = "custom"
        #"id" = (New-Guid).Guid
        #"lastModifiedDateTime" = $Now
    }

    #Checking if the groupPolicyConfigurations is already present
    $GroupPolicyConfiguration = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?`$filter=displayName+eq+'$GroupPolicyConfigurationName'"
    if ($GroupPolicyConfiguration) {
        foreach ($CurrentGroupPolicyConfiguration in $GroupPolicyConfiguration) {
            Write-Verbose -Message "Deleting the previously '$($CurrentGroupPolicyConfiguration.displayName)' groupPolicyConfigurations (id: '$($CurrentGroupPolicyConfiguration.id)')"
            Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($CurrentGroupPolicyConfiguration.id)" -Method DELETE -OutputType PSObject
        }
    }
    $GroupPolicyConfiguration = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    #region Assign
    Write-Verbose -Message "Assigning the '$GroupPolicyConfigurationName' Group Policy Configuration to '$HostPoolDAGUsersAzADGroupName'"
    $Body = @{
        assignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $HostPoolDAGUsersAzADGroup.Id
                }
            }
        )
    }
    $Assign = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfiguration.id)/assign" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject

    Write-Verbose -Message "Assigning the '$GroupPolicyConfigurationName' Group Policy Configuration to '$HostPoolRAGUsersAzADGroupName'"
    $Body = @{
        assignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $HostPoolRAGUsersAzADGroup.Id
                }
            }
        )
    }
    $Assign = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfiguration.id)/assign" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    #region Network\Background Intelligent Transfer Service (BITS) Settings
    $NetworkBITSGroupPolicyDefinitions = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\Network\Background Intelligent Transfer Service (BITS)')"
    $NetworkBITSGroupPolicyDefinitions = $NetworkBITSGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($NetworkBITSGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\Background Intelligent Transfer Service (BITS)\Do not allow the BITS client to use Windows Branch Cache' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region Network\BranchCache Settings
    $NetworkBranchCacheGroupPolicyDefinitions = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\Network\BranchCache')"
    $NetworkBranchCacheGroupPolicyDefinitions = $NetworkBranchCacheGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($NetworkBranchCacheGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\BranchCache\Enable Hotspot Authentication' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Disable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region Network\Hotspot Authentication Settings
    $NetworkHotspotAuthenticationGroupPolicyDefinitions = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\Network\Hotspot Authentication')"
    $NetworkHotspotAuthenticationGroupPolicyDefinitions = $NetworkHotspotAuthenticationGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($NetworkHotspotAuthenticationGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\Hotspot Authentication\Enable Hotspot Authentication' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Disable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region Network\Microsoft Peer-to-Peer Networking Services Settings
    $NetworkP2PGroupPolicyDefinitions = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\Network\Microsoft Peer-to-Peer Networking Services')"
    switch ($NetworkP2PGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\Microsoft Peer-to-Peer Networking Services\Turn off Microsoft Peer-to-Peer Networking Services' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region Network\Offline Files Settings
    $NetworkOfflineFilesGroupPolicyDefinitions = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\Network\Offline Files')"
    $NetworkOfflineFilesGroupPolicyDefinitions = $NetworkOfflineFilesGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($NetworkOfflineFilesGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\Offline Files\Allow or Disallow use of the Offline Files feature' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Disable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region Remote Desktop Services Settings
    $RDSSessionTimeLimitsGroupPolicyDefinitions = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits')"
    $RDSSessionTimeLimitsGroupPolicyDefinitions = $RDSSessionTimeLimitsGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($RDSSessionTimeLimitsGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for active but idle Remote Desktop Services sessions' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "900000"; continue }  
        { $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for disconnected sessions' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "900000"; continue }  
        { $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for active Remote Desktop Services sessions' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "0"; continue }  
        { $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\End session when time limits are reached' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 1; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region Remote Desktop Services Settings
    $RDSAVDGroupPolicyDefinitions = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startsWith(categoryPath,'\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop')"
    $RDSAVDGroupPolicyDefinitions = $RDSAVDGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    $GroupPolicyDefinitionPresentation = Get-GroupPolicyDefinitionPresentationViaGraphAPI -GroupPolicyDefinition $RDSAVDGroupPolicyDefinitions
    switch ($RDSAVDGroupPolicyDefinitions) {
        #{ $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop\Enable screen capture protection' } { Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "1"; continue }  
        { ($_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop\Enable watermarking') -and ($_.version -eq '2.0') } { 
            $Value = @{
                "QR code bitmap scale factor"                                     = 4
                "QR code bitmap opacity"                                          = 2000
                "Width of grid box in percent relative to QR code bitmap width"   = 320
                "Height of grid box in percent relative to QR code bitmap height" = 180
                "QR code embedded content"                                        = "0"
            }
            Set-GroupPolicyDefinitionSettingViaGraphAPI -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value $Value; continue 
        }
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion
    #endregion
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

#endregion

#region Settings Catalog
#From https://www.youtube.com/watch?v=LQRXg95qTg0
function New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI {
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

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"
    Write-Verbose -Message "Parameter Set: $($psCmdlet.ParameterSetName)"
    Write-Verbose -Message "Processing '$($Setting.FullPath)'"
    Write-Verbose -Message "`$SettingValue: $SettingValue"

    [array] $Children = @()
    if ($PSCmdlet.ParameterSetName -eq "Enable") {
        $value = ($Setting.options | Where-Object -FilterScript { $_.Name -eq "Enabled"}).itemId
        #$ChildSettings = $Settings | Where-Object -FilterScript { $_.id -eq $Setting.options.dependedOnBy.dependedOnBy }
        $ChildSettings = $Settings | Where-Object -FilterScript { $_.id -in $Setting.options.dependedOnBy.dependedOnBy }
        $Children = foreach ($CurrentChildSetting in $ChildSettings) {
            if ($CurrentChildSetting.'@odata.type' -eq '#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition') {
                if ($null -ne $SettingValue) {
                    if ($SettingValue -is [hashtable]) {
                        $choiceSettingValueValue = $SettingValue[$CurrentChildSetting.displayName -replace "\s*\(Device\)"]
                        $choiceSettingValue = ($CurrentChildSetting.options | Where-Object -FilterScript { $_.optionValue.value -eq $choiceSettingValueValue}).ItemId
                    }
                    else {
                        $choiceSettingValue = ($CurrentChildSetting.options | Where-Object -FilterScript {$_.Name.Trim() -eq $SettingValue.ToString()}).ItemId
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
                    "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    "settingDefinitionId" = $CurrentChildSetting.id
                    "choiceSettingValue" = @{
                        "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue"
                        "value" = $choiceSettingValue
                        "children" = @()
                    }
                }
            }
            elseif ($CurrentChildSetting.'@odata.type' -eq '#microsoft.graph.deviceManagementConfigurationSettingGroupCollectionDefinition') {
                if ($SettingValue -is [hashtable]) {
                    $KeySettingDefinitionId = $CurrentChildSetting.dependedOnBy.dependedOnBy | Where-Object { $_ -match "_key$"}
                    $ValueSettingDefinitionId = $CurrentChildSetting.dependedOnBy.dependedOnBy | Where-Object { $_ -match "value$"}
                    [array] $groupSettingCollectionValue = foreach ($CurrentKey in $SettingValue.Keys) {
                        $CurrentValue = $SettingValue[$CurrentKey].ToString()
                        @{
                            "children" = @(
                            @{
                                "@odata.type" = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                                "settingDefinitionId" = $KeySettingDefinitionId
                                "simpleSettingValue" = @{
                                    "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                    "value" = $CurrentKey
                                }
                            }
                            @{
                                "@odata.type" = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                                "settingDefinitionId" = $ValueSettingDefinitionId
                                "simpleSettingValue" = @{
                                    "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                    "value" = $CurrentValue
                                }
                            }
                        )
                        }
                    }
                    @{
                        "@odata.type" = "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance"
                        "settingDefinitionId" = $CurrentChildSetting.id
                        "groupSettingCollectionValue" = $groupSettingCollectionValue
                    }
                }
            }
            else #if ($CurrentChildSetting.'@odata.type' -eq '#microsoft.graph.deviceManagementConfigurationSimpleSettingDefinition') {
            {
                if ($SettingValue -is [hashtable]) {
                    $simpleSettingValue = $SettingValue[$CurrentChildSetting.displayName -replace "\s*\(Device\)"]
                }
                else {
                    $simpleSettingValue = $SettingValue.ToString()
                }
                @{
                    "@odata.type" = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                    "settingDefinitionId" = $CurrentChildSetting.id
                    "simpleSettingValue" = @{
                        "@odata.type" = $CurrentChildSetting.defaultValue.'@odata.type'
                        "value" = $simpleSettingValue
                    }
                }
            }
        }
        if ($null -eq $Children) {
            $Children = @()
        }
        if (($Setting.'@odata.type' -eq '#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition') -and ([string]::IsNullOrEmpty($value))) {
                $value = ($Setting.options | Where-Object -FilterScript {$_.Name.Trim() -eq $SettingValue.ToString()}).ItemId
        }
    } else {
        $value = ($_.options | Where-Object -FilterScript { $_.Name -eq "Disabled"}).itemId
        $Children = @()
    }
    $CurrentSettings = @{
        "@odata.type" = "#microsoft.graph.deviceManagementConfigurationSetting"
        "settingInstance" = @{
            "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
            "settingDefinitionId" = $_.id
            "choiceSettingValue" = @{
                "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue"
                "value" = $value
                "children" = $Children
            }
        }
    }

    $CurrentSettings
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function Add-CategoryFullPath {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object[]] $Categories,
        [object] $ParentCategory
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    Write-Verbose -Message "`$ParentCategory: $($CurrentCategory.displayName)"
    if ($null -eq $ParentCategory) {
        #Top Category
        $ParentCategory = $Categories | Where-Object {$_.parentCategoryId -match "^(0|-)+$"}
        $ParentCategory = $ParentCategory | Add-Member -NotePropertyMembers @{ FullPath=$("\{0}" -f $ParentCategory.displayName) } -PassThru
        Write-Verbose -Message "Parent Category Full Path: $($ParentCategory.FullPath)"
    }

    $ChildCategories = $Categories | Where-Object {$_.parentCategoryId -eq $ParentCategory.id}
    foreach ($CurrentChildCategory in $ChildCategories) {
        $CurrentChildCategory = $CurrentChildCategory | Add-Member -NotePropertyMembers @{ FullPath=$("{0}\{1}" -f $ParentCategory.FullPath, $CurrentChildCategory.displayName) } -PassThru
        Write-Verbose -Message "Current Child Category Full Path: $($CurrentChildCategory.FullPath)"
        Add-CategoryFullPath -Categories $Categories -ParentCategory $CurrentChildCategory
    }
    
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function New-FSLogixIntuneSettingsCatalogConfigurationPolicyViaGraphAPI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('StorageAccountName')]
        [string] $HostPoolStorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $false)]
        [string] $StorageEndpointSuffix = 'core.windows.net'
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Graph API
    #region Devices Azure AD group 
    $HostPoolDeviceAzADGroupName = "{0} - Devices" -f $HostPoolName
    $HostPoolDeviceAzADGroup = Get-AzADGroup -DisplayName $HostPoolDeviceAzADGroupName
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
    Add-CategoryFullPath -Categories $FSLogixConfigurationChildCategories
    #endregion

    #region 'FSLogix > Profile Containers' Settings
    #$FSLogixProfileContainersConfigurationChildCategory = $FSLogixConfigurationChildCategories | Where-Object -FilterScript {$_.displayName -eq "Profile Containers"}
    $FSLogixProfileContainersConfigurationChildCategory = $FSLogixConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\FSLogix\Profile Containers"}
    $FSLogixProfileContainersConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($FSLogixProfileContainersConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $FSLogixProfileContainersConfigurationSettings = $FSLogixProfileContainersConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $FSLogixProfileContainersConfigurationChildCategory.FullPath -ChildPath $_.displayName } }

    [array] $settings += switch ($FSLogixProfileContainersConfigurationSettings) {
        { $_.FullPath -eq '\FSLogix\Profile Containers\Enabled' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Enable; continue }  
        { $_.FullPath -eq '\FSLogix\Profile Containers\Delete Local Profile When VHD Should Apply' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Enable; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Locked Retry Count' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 3 -Enable; continue }  
        { $_.FullPath -eq '\FSLogix\Profile Containers\Locked Retry Interval' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 15 -Enable}
        { $_.FullPath -eq '\FSLogix\Profile Containers\Profile Type' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 'Normal Profile' -Enable}
        { $_.FullPath -eq '\FSLogix\Profile Containers\ReAttach Interval' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 15 -Enable}
        { $_.FullPath -eq '\FSLogix\Profile Containers\ReAttach Count' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 3 -Enable}
        { $_.FullPath -eq '\FSLogix\Profile Containers\Size In MBs' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 30000 -Enable}
        { $_.FullPath -eq '\FSLogix\Profile Containers\Prevent Login With Failure' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 1 -Enable; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Prevent Login With Temp Profile' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 1 -Enable; continue }   
        { $_.FullPath -eq '\FSLogix\Profile Containers\Is Dynamic (VHD)' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue 1 -Enable; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\VHD Locations' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles" -Enable; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Redirection XML Source Folder' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationSettings -Setting $_ -SettingValue "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles" -Enable; continue } 
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region 'FSLogix > Profile Containers Settings > Container and Directory Naming' Settings
    $FSLogixProfileContainersConfigurationContainerAndDirectoryNamingChildCategory = $FSLogixConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\FSLogix\Profile Containers\Container and Directory Naming"}
    $FSLogixProfileContainersConfigurationContainerAndDirectoryNamingSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($FSLogixProfileContainersConfigurationContainerAndDirectoryNamingChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $FSLogixProfileContainersConfigurationContainerAndDirectoryNamingSettings = $FSLogixProfileContainersConfigurationContainerAndDirectoryNamingSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $FSLogixProfileContainersConfigurationContainerAndDirectoryNamingChildCategory.FullPath -ChildPath $_.displayName } }
       
    [array] $settings += switch ($FSLogixProfileContainersConfigurationContainerAndDirectoryNamingSettings) {
        { $_.FullPath -eq '\FSLogix\Profile Containers\Container and Directory Naming\Flip Flop Profile Directory Name' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Enable; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Container and Directory Naming\Volume Type (VHD or VHDX)' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixProfileContainersConfigurationContainerAndDirectoryNamingSettings -Setting $_ -SettingValue 'VHDX' -Enable ; continue}
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region 'FSLogix > Logging' Settings
    #$FSLogixConfigurationLoggingChildCategory = $FSLogixConfigurationChildCategories | Where-Object -FilterScript {$_.displayName -eq "Logging"}
    $FSLogixConfigurationLoggingChildCategory = $FSLogixConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\FSLogix\Logging"}
    $FSLogixConfigurationLoggingSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($FSLogixConfigurationLoggingChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $FSLogixConfigurationLoggingSettings = $FSLogixConfigurationLoggingSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $FSLogixConfigurationLoggingChildCategory.FullPath -ChildPath $_.displayName } }

    [array] $settings += switch ($FSLogixConfigurationLoggingSettings) {
        { $_.FullPath -eq '\FSLogix\Logging\Log Keeping Period' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $FSLogixConfigurationLoggingSettings -Setting $_ -SettingValue 10 -Enable; continue}
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #$Body | ConvertTo-Json -Depth 100 | Set-Clipboard
    #endregion
    #endregion

    <#
    #region Windows Update For Business Category and Child Categories
    #region Getting Windows Update For Business Category and Child Categories
    $WindowsUpdateForBusinessConfigurationCategory = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=technologies+has+'mdm'+and+description+eq+'Windows Update For Business'" -Verbose
    [array] $WindowsUpdateForBusinessConfigurationChildCategories = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=rootCategoryId+eq+'$($WindowsUpdateForBusinessConfigurationCategory.id)'"
    Add-CategoryFullPath -Categories $WindowsUpdateForBusinessConfigurationChildCategories 
    #endregion

    #region Windows Update For Business
    $WindowsUpdateForBusinessConfigurationChildCategory = $WindowsUpdateForBusinessConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\Windows Update For Business"}
    $WindowsUpdateForBusinessConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($WindowsUpdateForBusinessConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $WindowsUpdateForBusinessConfigurationSettings = $WindowsUpdateForBusinessConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $WindowsUpdateForBusinessConfigurationChildCategory.FullPath -ChildPath $_.displayName } }

    [array] $settings += switch ($WindowsUpdateForBusinessConfigurationSettings) {
        { $_.FullPath -eq '\Windows Update For Business\Allow Auto Update' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $WindowsUpdateForBusinessConfigurationSettings -Setting $_ -SettingValue 'Turn off automatic updates.' -Enable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion
    #endregion
    #>

    #region Administrative Templates Category and Child Categories
    #region Getting Administrative Templates Category and Child Categories
    $AdministrativeTemplatesConfigurationCategory = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=technologies+has+'mdm'+and+description+eq+'Administrative Templates'" -Verbose
    [array] $AdministrativeTemplatesConfigurationChildCategories = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=rootCategoryId+eq+'$($AdministrativeTemplatesConfigurationCategory.id)'"
    Add-CategoryFullPath -Categories $AdministrativeTemplatesConfigurationChildCategories
    #endregion

    #region 'Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Device and Resource Redirection
    $AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection"}
    $AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationSettings = $AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Allow time zone redirection' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsRDSRDSHConfigurationSettings -Setting $_ -Enable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }

    #endregion

    #region 'Administrative Templates > Windows Components > Microsoft Defender Antivirus > Exclusions
    $AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Exclusions"}
    $AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationSettings = $AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Exclusions\Path Exclusions' } { 
            $Exclusions = @{
                '%TEMP%\*\*.VHD' = 0
                '%TEMP%\*\*.VHDX' = 0
                '%Windir%\TEMP\*\*.VHD' = 0
                '%Windir%\TEMP\*\*.VHDX' = 0
                '%ProgramData%\FSLogix\Cache\*' = 0
                '%ProgramData%\FSLogix\Proxy\*' = 0
                '%ProgramFiles%\FSLogix\Apps\frxdrv.sys' = 0
                '%ProgramFiles%\FSLogix\Apps\frxdrvvt.sys' = 0
                '%ProgramFiles%\FSLogix\Apps\frxccd.sys' = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD" = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.lock" = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.meta" = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.metadata" = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX" = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.lock" = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.meta" = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.metadata" = 0
                "\\$HostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.CIM" = 0
            }
            New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationSettings -Setting $_ -SettingValue $Exclusions -Enable; continue 
        }  
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Exclusions\Process Exclusions' } { 
            $Exclusions = @{
                '%ProgramFiles%\FSLogix\Apps\frxccd.exe' = 0
                '%ProgramFiles%\FSLogix\Apps\frxccds.exe' = 0
                '%ProgramFiles%\FSLogix\Apps\frxsvc.exe' = 0
                '%ProgramFiles%\FSLogix\Apps\frxrobocopy.exe' = 0
            }
            New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsMicrosoftDefenderAVExclusionsConfigurationSettings -Setting $_ -SettingValue $Exclusions -Enable; continue 
        }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }

    #endregion

    #region Storage Category and Child Categories
    #region Getting Storage Category and Child Categories
    $StorageConfigurationCategory = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=technologies+has+'mdm'+and+description+eq+'Storage'" -Verbose
    [array] $StorageConfigurationChildCategories = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=rootCategoryId+eq+'$($StorageConfigurationCategory.id)'"
    Add-CategoryFullPath -Categories $StorageConfigurationChildCategories
    #endregion

    #region Storage
    $StorageConfigurationChildCategory = $StorageConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\Storage"}
    $StorageConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($StorageConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $StorageConfigurationSettings = $StorageConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $StorageConfigurationChildCategory.FullPath -ChildPath $_.displayName } }

    [array] $settings += switch ($StorageConfigurationSettings) {
        { $_.FullPath -eq '\Storage\Allow Storage Sense Global' } { 
        New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $StorageConfigurationSettings -Setting $_ -SettingValue 'Block' -Enable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion
    #endregion
    #endregion

    #endregion

    #region configurationPolicies
    $ConfigurationPolicyName = "[{0}] FSLogix Policy" -f $HostPoolName

    
    $Body = @{
        name = $ConfigurationPolicyName
        description = $ConfigurationPolicyName
        platforms = "windows10"
        technologies = "mdm"
        settings = $settings
    }

    #Checking if the Configuration Policy is already present
    [array] $ConfigurationPolicy = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=name+eq+'$ConfigurationPolicyName'+and+technologies+has+'mdm'+and+platforms+has+'windows10'"
    if (-not([string]::IsNullOrEmpty($ConfigurationPolicy.id))) {
        foreach ($CurrentValue in $ConfigurationPolicy) {
            Write-Verbose -Message "Deleting the previously '$($CurrentValue.name)' groupPolicyConfigurations (id: '$($CurrentValue.id)')"
            Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($CurrentValue.id)" -Method DELETE -OutputType PSObject
        }
        Start-Sleep -Seconds 10
    }

    Write-Verbose -Message "Creating the '$ConfigurationPolicyName' Configuration Policy"
    $ConfigurationPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/configurationPolicies" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    #region Assign
    Write-Verbose -Message "Assigning the '$ConfigurationPolicyName' Configuration Policy to '$HostPoolDeviceAzADGroupName' Entra ID Group"
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

    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function New-AVDIntuneSettingsCatalogConfigurationPolicyViaGraphAPI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('StorageAccountName')]
        [string] $HostPoolStorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $false)]
        [string] $StorageEndpointSuffix = 'core.windows.net'
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Graph API
    #region Devices Azure AD group 
    $HostPoolDeviceAzADGroupName = "{0} - Devices" -f $HostPoolName
    $HostPoolDeviceAzADGroup = Get-AzADGroup -DisplayName $HostPoolDeviceAzADGroupName
    if ($null -eq $HostPoolDeviceAzADGroup) {
        Write-Error -Message "The '$HostPoolDeviceAzADGroupName' doesn't exist !"
        return $null
    }
    #endregion

    [array] $settings = @()

    #region Administrative Templates Category and Child Categories
    #region Getting Administrative Templates Category and Child Categories
    $AdministrativeTemplatesConfigurationCategory = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=technologies+has+'mdm'+and+description+eq+'Administrative Templates'" -Verbose
    [array] $AdministrativeTemplatesConfigurationChildCategories = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$filter=rootCategoryId+eq+'$($AdministrativeTemplatesConfigurationCategory.id)'"
    Add-CategoryFullPath -Categories $AdministrativeTemplatesConfigurationChildCategories
    #endregion

    #region 'Administrative Templates > Network > Offline Files' Settings
    $AdministrativeTemplatesNetworkOfflineFilesConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\Administrative Templates\Network\Offline Files"}
    $AdministrativeTemplatesNetworkOfflineFilesConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesNetworkOfflineFilesConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesNetworkOfflineFilesConfigurationSettings = $AdministrativeTemplatesNetworkOfflineFilesConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesNetworkOfflineFilesConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesNetworkOfflineFilesConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Network\Offline Files\Allow or Disallow use of the Offline Files feature' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Disable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region 'Administrative Templates > Network > Hotspot Authentication' Settings
    $AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\Administrative Templates\Network\Hotspot Authentication"}
    $AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationSettings = $AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Network\Hotspot Authentication\Enable Hotspot Authentication' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Disable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region 'Administrative Templates > Network > Background Intelligent Transfer Service (BITS)' Settings
    $AdministrativeTemplatesNetworkBITSConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\Administrative Templates\Network\Background Intelligent Transfer Service (BITS)"}
    $AdministrativeTemplatesNetworkBITSConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesNetworkBITSConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesNetworkBITSConfigurationSettings = $AdministrativeTemplatesNetworkBITSConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesNetworkBITSConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesNetworkBITSConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Network\Background Intelligent Transfer Service (BITS)\Do not allow the BITS client to use Windows Branch Cache' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Enable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region 'Administrative Templates > Network > Hotspot Authentication' Settings
    $AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\Administrative Templates\Network\Hotspot Authentication"}
    $AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesNetworkHotspotAuthenticationConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesNetworkHotspotAuthenticationSettingsConfigurationSettings = $AdministrativeTemplatesNetworkHotspotAuthenticationSettingsConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesNetworkHotspotAuthenticationSettingsConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesNetworkHotspotAuthenticationSettingsConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Network\Hotspot Authentication\Enable Hotspot Authentication' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Disable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region 'Administrative Templates > Network > BranchCache' Settings
    $AdministrativeTemplatesNetworkBranchCacheConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\Administrative Templates\Network\BranchCache"}
    $AdministrativeTemplatesNetworkBranchCacheConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesNetworkBranchCacheConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesNetworkBranchCacheSettingsConfigurationSettings = $AdministrativeTemplatesNetworkBranchCacheSettingsConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesNetworkBranchCacheSettingsConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesNetworkBranchCacheSettingsConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Network\BranchCache\Turn On BranchCache' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Setting $_ -Disable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region 'Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Azure Virtual Desktop'
    $AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop"}
    $AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationSettings = $AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationSettings) {
        #{ $_.FullPath -eq '\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop\Enable screen capture protection' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationSettings -Setting $_ -SettingValue 'Block screen capture on client' -Enable; continue }  
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop\Enable watermarking' } { 
            $SettingValue = @{
                "QR code bitmap scale factor"                                     = 4
                "QR code bitmap opacity"                                          = 2000
                "Width of grid box in percent relative to QR code bitmap width"   = 320
                "Height of grid box in percent relative to QR code bitmap height" = 180
                "QR code embedded content"                                        = "0"
            }
            New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsRDSRDSHAVDConfigurationSettings -Setting $_ -SettingValue $SettingValue -Enable ; continue 
            }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region 'Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Session Time Limits
    $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationChildCategory = $AdministrativeTemplatesConfigurationChildCategories | Where-Object -FilterScript {$_.FullPath -eq "\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits"}
    $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId%20eq%20%27$($AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationChildCategory.id)%27%20and%20visibility%20has%20%27settingsCatalog%27%20and%20(applicability/platform%20has%20%27windows10%27)%20and%20(applicability/technologies%20has%20%27mdm%27)"

    #Adding a FullPath Property
    $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings = $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationChildCategory.FullPath -ChildPath $_.displayName } }
    
    [array] $settings += switch ($AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings) {
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for active but idle Remote Desktop Services sessions' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings -Setting $_ -SettingValue '15 minutes' -Enable; continue }  
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for disconnected sessions' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings -Setting $_ -SettingValue '15 minutes' -Enable; continue }  
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for active Remote Desktop Services sessions' } {  New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings -Setting $_ -SettingValue 'Never' -Enable; continue }  
        { $_.FullPath -eq '\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\End session when time limits are reached' } { New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI -Settings $AdministrativeTemplatesWindowsComponentsRDSRDSHSessionTimeLimitsConfigurationSettings -Setting $_ -Enable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }

    #endregion
    #endregion

    #region configurationPolicies
    $ConfigurationPolicyName = "[{0}] AVD Policy" -f $HostPoolName

    $Body = @{
        name = $ConfigurationPolicyName
        description = $ConfigurationPolicyName
        platforms = "windows10"
        technologies = "mdm"
        settings = $settings
    }
    
    #Checking if the Configuration Policy is already present
    [array] $ConfigurationPolicy = Get-MgGraphObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=name+eq+'$ConfigurationPolicyName'+and+technologies+has+'mdm'+and+platforms+has+'windows10'"
    if (-not([string]::IsNullOrEmpty($ConfigurationPolicy.id))) {
        foreach ($CurrentValue in $ConfigurationPolicy) {
            Write-Verbose -Message "Deleting the previously '$($CurrentValue.name)' groupPolicyConfigurations (id: '$($CurrentValue.id)')"
            Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($CurrentValue.id)" -Method DELETE -OutputType PSObject
        }
        Start-Sleep -Seconds 10
    }

    Write-Verbose -Message "Creating the '$ConfigurationPolicyName' Configuration Policy"
    $ConfigurationPolicy = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/Beta/deviceManagement/configurationPolicies" -Method POST -Body $($Body | ConvertTo-Json -Depth 100) -OutputType PSObject
    #endregion

    #region Assign
    Write-Verbose -Message "Assigning the '$ConfigurationPolicyName' Configuration Policy to '$HostPoolDeviceAzADGroupName' Entra ID Group"
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
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}
#endregion

#endregion

#region PowerShell Cmdlets
Function Sync-IntuneSessionHostViaCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $HostPool
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region PowerShell Cmdlets

    #region Devices
    #Getting all session hosts starting with the Name Prefixes
    $RegExp = ($HostPool.NamePrefix -replace '(^[^\n]*$)', '^$1-') -join '|'
    $Result = Get-MgBetaDeviceManagementManagedDevice -All | Where-Object -FilterScript {$_.DeviceName -match $RegExp } | ForEach-Object -Process { 
        Write-Verbose -Message "Sending Sync request to Device with Device name '$($_.DeviceName)'"
        Sync-MgBetaDeviceManagementManagedDevice -ManagedDeviceId $_.Id -PassThru
    }
    Write-Verbose -Message "Synchronization result: $($Result -join ', ')"
    #endregion

    #endregion
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

Function Remove-IntuneItemViaCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $HostPool
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region PowerShell Cmdlets
    #region deviceManagementScripts and groupPolicyConfigurations
    #The pipeline has been stopped ==> Get-MgBetaDeviceManagementGroupPolicyConfiguration -Filter "startswith(displayName,'[$HostPoolName]')" | Remove-MgBetaDeviceManagementGroupPolicyConfiguration
    #Get-MgBetaDeviceManagementGroupPolicyConfiguration -Filter "startswith(displayName,'[$HostPoolName]')" -All | ForEach-Object -Process {
    #Getting all Intune items starting with the HostPool name between brackets
    $RegExp = ($HostPool.Name -replace '(^[^\n]*$)', '^\[$1\]') -join '|'

    #region Configuration Policies - Administratives Templates
    Get-MgBetaDeviceManagementGroupPolicyConfiguration -All | Where-Object -FilterScript {$_.displayName -match $RegExp } | ForEach-Object -Process {
        Write-Verbose -Message "Removing Device Management Group Policy Configuration: '$($_.displayName)'"
        Remove-MgBetaDeviceManagementGroupPolicyConfiguration -GroupPolicyConfigurationId $_.Id
    }
    #endregion

    #region Configuration Policies - Settings Catalog
    Get-MgBetaDeviceManagementConfigurationPolicy -All | Where-Object -FilterScript {$_.Name -match $RegExp } | ForEach-Object -Process { 
        Write-Verbose -Message "Removing Device Management Policy Configuration: '$($_.Name)'"
        Remove-MgBetaDeviceManagementConfigurationPolicy -DeviceManagementConfigurationPolicyId $_.Id
    }
    #endregion

    #The pipeline has been stopped ==> Get-MgBetaDeviceManagementScript -Filter "startswith(Name,'[$HostPoolName]')" | Remove-MgBetaDeviceManagementScript
    #Get-MgBetaDeviceManagementScript -Filter "startswith(Name,'[$HostPoolName]')" -All | ForEach-Object -Process {
    Get-MgBetaDeviceManagementScript -All | Where-Object -FilterScript {$_.DisplayName -match $RegExp } | ForEach-Object -Process {
        Write-Verbose -Message "Removing Device Management Script: '$($_.DisplayName)'"
        Remove-MgBetaDeviceManagementScript -DeviceManagementScriptId $_.Id
    }
    #endregion

    #region Devices
    #Getting all session hosts starting with the Name Prefixes
    $RegExp = ($HostPool.NamePrefix -replace '(^[^\n]*$)', '^$1-') -join '|'
    Get-MgBetaDeviceManagementManagedDevice -All | Where-Object -FilterScript {$_.DeviceName -match $RegExp } | ForEach-Object -Process { 
        Write-Verbose -Message "Removing Intune Enrolled Device : $($_.DeviceName)"
        Remove-MgBetaDeviceManagementManagedDevice -ManagedDeviceId $_.Id 
    }
    #endregion

    #region Configuration Policies - Settings Catalog
    #endregion

    #endregion
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

Function New-IntunePowerShellScriptViaCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $true, ParameterSetName = 'ScriptURI')]
        [ValidateScript({ $_ -match '^https?://' })]
        [string]$ScriptURI,

        [Parameter(Mandatory = $true, ParameterSetName = 'ScriptPath')]
        [string]$ScriptPath
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Devices Azure AD group 
    $HostPoolDeviceAzADGroupName = "{0} - Devices" -f $HostPoolName
    $HostPoolDeviceAzADGroup = Get-AzADGroup -DisplayName $HostPoolDeviceAzADGroupName
    if ($null -eq $HostPoolDeviceAzADGroup) {
        Write-Error -Message "The '$HostPoolDeviceAzADGroupName' doesn't exist !"
        return $null
    }
    #endregion

    #region Uploading Powershell Script
    if ($ScriptURI) {
        $FileName = Split-Path $ScriptURI -Leaf
        Write-Verbose -Message "Adding the '$ScriptURI' script"
        $ScriptContentInputFile = Join-Path -Path $env:TEMP -ChildPath $FileName
        #$ScriptContentInputFile = Join-Path -Path $env:TEMP -ChildPath [System.IO.Path]::GetRandomFileName()
        $ScriptContent = Invoke-RestMethod -Uri $ScriptURI -OutFile $ScriptContentInputFile
    }
    else {
        $FileName = Split-Path $ScriptPath -Leaf
        Write-Verbose -Message "Adding the '$ScriptPath' script"
        $ScriptContentInputFile = $ScriptPath
    }

    Write-Verbose -Message "`$FileName: '$FileName'"
    $DisplayName = "[{0}] {1}" -f $HostPoolName, $FileName
    Write-Verbose -Message "`$DisplayName: '$DisplayName'"
    #Checking if the script is already present (with the same naming convention)
    Write-Verbose -Message "Deleting the previously imported PowerShell Script file '$DisplayName' if any"
    Get-MgBetaDeviceManagementScript -Filter "displayName eq '$DisplayName'" -All | Remove-MgBetaDeviceManagementScript

    $AddedScript = New-MgBetaDeviceManagementScript -DisplayName $DisplayName -FileName $FileName -RoleScopeTagIds @("0") -RunAsAccount 'system'-ScriptContentInputFile $ScriptContentInputFile
    if ($ScriptURI) {
        Remove-Item -Path $ScriptContentInputFile -Force
    }

    #endregion

    #region Assign
    Write-Verbose -Message "Assigning the '$FileName' PowerShell script to '$HostPoolDeviceAzADGroup'"
    $BodyParameter = @{
	    deviceManagementScriptAssignments = @(
		    @{
			    target = @{
				    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
				    groupId = $HostPoolDeviceAzADGroup.Id
			    }
		    }
	    )
    }
    Set-MgBetaDeviceManagementScript -DeviceManagementScriptId $AddedScript.Id -BodyParameter $BodyParameter
    #endregion

    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function Get-GroupPolicyDefinitionPresentationViaCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array] $GroupPolicyDefinition
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Powershell Cmdlets
    $GroupPolicyDefinitionPresentationHT = @{}
    foreach ($CurrentGroupPolicyDefinition in $GroupPolicyDefinition) {
        $GroupPolicyDefinitionPresentation = Get-MgBetaDeviceManagementGroupPolicyDefinition -GroupPolicyDefinitionId $CurrentGroupPolicyDefinition.id
        $Key = "{0} (version: {1})" -f $CurrentGroupPolicyDefinition.displayName, $CurrentGroupPolicyDefinition.version
        if ($CurrentGroupPolicyDefinition.supportedOn) {
            Write-Verbose -Message "Processing '$Key' (Supported On: $($CurrentGroupPolicyDefinition.supportedOn))"
            $GroupPolicyDefinitionPresentationHT.Add($("{0} (Supported On: {1})" -f $Key, $CurrentGroupPolicyDefinition.supportedOn) , $GroupPolicyDefinitionPresentation)
        }
        else {
            Write-Verbose -Message "Processing '$Key'"
            $GroupPolicyDefinitionPresentationHT.Add($Key, $GroupPolicyDefinitionPresentation)
        }
    }
    #endregion
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}
 
function Import-FSLogixADMXViaCmdlet {
    [CmdletBinding()]
    Param (
        [switch] $Wait
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Powershell Cmdlets
    #Checking if the ADMX is already present
    Get-MgBetaDeviceManagementGroupPolicyUploadedDefinitionFile -Filter "fileName eq 'fslogix.admx'" -All | Remove-MgBetaDeviceManagementGroupPolicyUploadedDefinitionFile

    #Always get the latest version of FSLogix
    #$FSLogixLatestURI = ((Invoke-WebRequest -Uri "https://aka.ms/fslogix-latest").Links | Where-Object -FilterScript { $_.innerText -eq "Download" }).href
    $FSLogixLatestURI = ((Invoke-WebRequest -Uri "https://aka.ms/fslogix-latest" -UseBasicParsing).Links | Where-Object -FilterScript { $_.href -match ".zip$" }).href
    $OutFile = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $FSLogixLatestURI -Leaf)
    Write-Verbose -Message "Downloading from '$FSLogixLatestURI' to '$OutFile'"
    Start-BitsTransfer $FSLogixLatestURI -destination $OutFile
    $DestinationPath = Join-Path -Path $env:Temp -ChildPath "FSLogixLatest"
    Write-Verbose -Message "Unzipping '$OutFile' into '$DestinationPath'"
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
    Write-Verbose -Message "Uploading the ADMX and ADML files"
    $GroupPolicyUploadedLanguageFiles = @(
            @{
                "fileName"     = $ADMLFileName
                "languageCode" = "en-US"
                "content"      = $ADMLFileContent
                #"id" = (New-Guid).Guid
                #"lastModifiedDateTime" = $Now
            }
        )
    New-MgBetaDeviceManagementGroupPolicyUploadedDefinitionFile -LanguageCodes @("en-US") -TargetPrefix $("FSLogix{0}" -f $GUID) -TargetNamespace "FSLogix.Policies" -policyType 'admxIngested' -FileName $ADMXFileName -ContentInputFile $ADMXFileContent -GroupPolicyUploadedLanguageFiles $GroupPolicyUploadedLanguageFiles
    $GroupPolicyUploadedDefinitionFileId = $GroupPolicyUploadedDefinitionFile.id
    While ($GroupPolicyUploadedDefinitionFile.status -eq 'uploadInProgress') {
        $GroupPolicyUploadedDefinitionFile = Get-MgBetaDeviceManagementGroupPolicyUploadedDefinitionFile -Filter "id eq '$GroupPolicyUploadedDefinitionFileId'" -All
        Write-Verbose -Message "Waiting the upload completes. Sleeping 10 seconds"
        Start-Sleep -Seconds 10
    } 
    Write-Verbose -Message "Final status: $($GroupPolicyUploadedDefinitionFile.status)"
    Remove-Item -Path $OutFile, $DestinationPath -Recurse -Force
    #endregion
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function Set-GroupPolicyDefinitionSettingViaCmdlet {
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
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region PowerShell Cmdlets
    Write-Verbose -Message "Parameter Set: $($psCmdlet.ParameterSetName)"
    Write-Verbose -Message "[$($GroupPolicyConfiguration.displayName)] Processing '$($GroupPolicyDefinition.categoryPath)\$($GroupPolicyDefinition.displayName)'"
    Write-Verbose -Message "`$Value: $Value"
    $GroupPolicyDefinitionPresentation = Get-MgBetaDeviceManagementGroupPolicyDefinitionPresentation -GroupPolicyDefinitionId $GroupPolicyDefinition.id -All
    if ($GroupPolicyDefinitionPresentation.count -gt 1) {
        #When multiple Group Policy Definition Presentations are returned we keep only the one(s) with a 'required' property
        $GroupPolicyDefinitionPresentationValues = $GroupPolicyDefinitionPresentation | Where-Object -FilterScript { "required" -in $_.psobject.Properties.Name }
    }
    else {
        $GroupPolicyDefinitionPresentationValues = $GroupPolicyDefinitionPresentation
    }
    Write-Verbose -Message "`$GroupPolicyDefinitionPresentationValues:`r`n$($GroupPolicyDefinitionPresentationValues | Out-String)"
    if ($GroupPolicyDefinitionPresentationValues) {
        $PresentationValues = foreach ($CurrentGroupPolicyDefinitionPresentationValue in $GroupPolicyDefinitionPresentationValues) {
            Write-Verbose -Message "Processing '$($CurrentGroupPolicyDefinitionPresentationValue.label)'"
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
            Write-Verbose -Message "`$CurrentValue: $CurrentValue"
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
        added = @(
            @{
                "definition@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($GroupPolicyDefinition.id)')"
                "enabled"               = $($psCmdlet.ParameterSetName -eq 'Enable')
                "presentationValues"    = @($PresentationValues)
            }    
        )
        deletedIds = @()
        updated    = @()
    }

    Write-Verbose -Message "[$($GroupPolicyConfiguration.displayName)] Enabling '$($GroupPolicyDefinition.categoryPath)\$($GroupPolicyDefinition.displayName)'"
    Update-MgBetaDeviceManagementGroupPolicyConfigurationMultipleDefinitionValue -GroupPolicyConfigurationId $GroupPolicyConfiguration.Id -BodyParameter $BodyParameter
    #endregion
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

#region Administrative Templates: DO NOT USE - Use Settings Catalog instead
function New-FSLogixIntuneAdministrativeTemplateConfigurationPolicyViaCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('StorageAccountName')]
        [string] $CurrentHostPoolStorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $false)]
        [string] $StorageEndpointSuffix = 'core.windows.net'
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Azure AD Desktop Application Group 
    $HostPoolDAGUsersAzADGroupName = "$HostPoolName - Desktop Application Group Users"
    $HostPoolDAGUsersAzADGroup = Get-AzADGroup -DisplayName $HostPoolDAGUsersAzADGroupName
    if ($null -eq $HostPoolDAGUsersAzADGroup) {
        Write-Error -Message "The '$HostPoolDAGUsersAzADGroupName' doesn't exist !"
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
    #endregion

    #region Azure AD Remote Application Group 
    $HostPoolRAGUsersAzADGroupName = "$HostPoolName - Remote Application Group Users"
    $HostPoolRAGUsersAzADGroup = Get-AzADGroup -DisplayName $HostPoolRAGUsersAzADGroupName
    if ($null -eq $HostPoolRAGUsersAzADGroup) {
        Write-Error -Message "The '$HostPoolRAGUsersAzADGroup' doesn't exist !"
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
    #region groupPolicyConfigurations
    $GroupPolicyConfigurationName = "[{0}] FSLogix Policy" -f $HostPoolName
    #$Now = $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssK")
    $Now = Get-Date -Format o 
    Write-Verbose -Message "Creating the '$GroupPolicyConfigurationName' Group Policy Configuration"
    #Removing the groupPolicyConfigurations if already present
    #The pipeline has been stopped ==> Get-MgBetaDeviceManagementGroupPolicyConfiguration -Filter "displayName eq '$GroupPolicyConfigurationName'" -All | Remove-MgBetaDeviceManagementGroupPolicyConfiguration
    Get-MgBetaDeviceManagementGroupPolicyConfiguration -Filter "displayName eq '$GroupPolicyConfigurationName'" -All | ForEach-Object -Process {
        Remove-MgBetaDeviceManagementGroupPolicyConfiguration -GroupPolicyConfigurationId  $_.Id
    }
    $GroupPolicyConfiguration = New-MgBetaDeviceManagementGroupPolicyConfiguration -DisplayName $GroupPolicyConfigurationName
    #endregion

    #region Assign
    Write-Verbose -Message "Assigning the '$GroupPolicyConfigurationName' Group Policy Configuration to '$HostPoolDAGUsersAzADGroupName'"
    $BodyParameter = @{
        target = @{
            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
            groupId       = $HostPoolDAGUsersAzADGroup.Id
        }
    }
    $Assign = New-MgBetaDeviceManagementGroupPolicyConfigurationAssignment -GroupPolicyConfigurationId $GroupPolicyConfiguration.Id -BodyParameter $BodyParameter

    Write-Verbose -Message "Assigning the '$GroupPolicyConfigurationName' Group Policy Configuration to '$HostPoolRAGUsersAzADGroupName'"
    $BodyParameter = @{
        target = @{
            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
            groupId       = $HostPoolRAGUsersAzADGroup.Id
        }
    }
    $Assign = New-MgBetaDeviceManagementGroupPolicyConfigurationAssignment -GroupPolicyConfigurationId $GroupPolicyConfiguration.Id -BodyParameter $BodyParameter
    #endregion

    #region ADMX Management
    $FSLogixProfileContainersGroupPolicyDefinitions = Get-MgBetaDeviceManagementGroupPolicyDefinition -Filter "startsWith(categoryPath,'\FSLogix\Profile Containers')" -All
    if (-not($FSLogixProfileContainersGroupPolicyDefinitions)) {
        $GroupPolicyUploadedDefinitionFile = Import-FSLogixADMXViaCmdlet
    }
    #endregion

    #region FSLogix Profile Containers Settings
    $FSLogixProfileContainersGroupPolicyDefinitions = Get-MgBetaDeviceManagementGroupPolicyDefinition -Filter "startsWith(categoryPath,'\FSLogix\Profile Containers')" -All
    #Adding a FullPath Property
    $FSLogixProfileContainersGroupPolicyDefinitions = $FSLogixProfileContainersGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($FSLogixProfileContainersGroupPolicyDefinitions) {
        { $_.FullPath -eq '\FSLogix\Profile Containers\Enabled' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_; continue }  
        { $_.FullPath -eq '\FSLogix\Profile Containers\Delete Local Profile When VHD Should Apply' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Container and Directory Naming\Flip Flop Profile Directory Name' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Locked Retry Count' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 3; continue }  
        { $_.FullPath -eq '\FSLogix\Profile Containers\Locked Retry Interval' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 15; continue }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Profile Type' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "0"; continue }
        { $_.FullPath -eq '\FSLogix\Profile Containers\ReAttach Interval' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 15; continue }
        { $_.FullPath -eq '\FSLogix\Profile Containers\ReAttach Count' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 3; continue }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Size In MBs' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 30000; continue }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Prevent Login With Failure' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 1; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Prevent Login With Temp Profile' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 1; continue }   
        { $_.FullPath -eq '\FSLogix\Profile Containers\Container and Directory Naming\Volume Type (VHD or VHDX)' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 'VHDX' }
        { $_.FullPath -eq '\FSLogix\Profile Containers\Is Dynamic (VHD)' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 1; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\VHD Locations' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"; continue } 
        { $_.FullPath -eq '\FSLogix\Profile Containers\Redirection XML Source Folder' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"; continue } 
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region FSLogix Logging Settings
    $FSLogixLoggingGroupPolicyDefinitions = Get-MgBetaDeviceManagementGroupPolicyDefinition -Filter "startsWith(categoryPath,'\FSLogix\Logging')" -All
    #Adding a FullPath Property
    $FSLogixLoggingGroupPolicyDefinitions = $FSLogixLoggingGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($FSLogixLoggingGroupPolicyDefinitions) {
        { $_.FullPath -eq '\FSLogix\Logging\Log Keeping Period' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 10 }
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion
    #endregion
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function New-AzAvdIntuneAdministrativeTemplateConfigurationPolicyViaCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostPoolName
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #region Azure AD Desktop Application Group 
    $HostPoolDAGUsersAzADGroupName = "$HostPoolName - Desktop Application Group Users"
    $HostPoolDAGUsersAzADGroup = Get-AzADGroup -DisplayName $HostPoolDAGUsersAzADGroupName
    if ($null -eq $HostPoolDAGUsersAzADGroup) {
        Write-Error -Message "The '$HostPoolDAGUsersAzADGroupName' doesn't exist !"
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
    #endregion

    #region Azure AD Remote Application Group 
    $HostPoolRAGUsersAzADGroupName = "$HostPoolName - Remote Application Group Users"
    $HostPoolRAGUsersAzADGroup = Get-AzADGroup -DisplayName $HostPoolRAGUsersAzADGroupName
    if ($null -eq $HostPoolRAGUsersAzADGroup) {
        Write-Error -Message "The '$HostPoolRAGUsersAzADGroup' doesn't exist !"
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
    #region groupPolicyConfigurations
    $GroupPolicyConfigurationName = "[{0}] AVD Policy" -f $HostPoolName
    #$Now = $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssK")
    $Now = Get-Date -Format o 
    Write-Verbose -Message "Creating the '$GroupPolicyConfigurationName' Group Policy Configuration"
    #Removing any existing groupPolicyConfigurations with the same name (if any)
    Write-Verbose -Message "Deleting the previously '$GroupPolicyConfigurationName' groupPolicyConfigurations"
    $GroupPolicyConfiguration = Get-MgBetaDeviceManagementGroupPolicyConfiguration -Filter "displayName eq '$GroupPolicyConfigurationName'" -All | Remove-MgBetaDeviceManagementGroupPolicyConfiguration
    Write-Verbose -Message "Creating the '$GroupPolicyConfigurationName' groupPolicyConfigurations"
    $GroupPolicyConfiguration = New-MgBetaDeviceManagementGroupPolicyConfiguration -DisplayName $GroupPolicyConfigurationName
    #endregion

    #region Assign
    Write-Verbose -Message "Assigning the '$GroupPolicyConfigurationName' Group Policy Configuration to '$HostPoolDAGUsersAzADGroupName'"
    $BodyParameter = @{
        target = @{
            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
            groupId       = $HostPoolDAGUsersAzADGroup.Id
        }
    }
    $Assign = New-MgBetaDeviceManagementGroupPolicyConfigurationAssignment -GroupPolicyConfigurationId $GroupPolicyConfiguration.Id -BodyParameter $BodyParameter

    Write-Verbose -Message "Assigning the '$GroupPolicyConfigurationName' Group Policy Configuration to '$HostPoolRAGUsersAzADGroupName'"
    $BodyParameter = @{
        target = @{
            "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
            groupId       = $HostPoolRAGUsersAzADGroup.Id
        }
    }
    $Assign = New-MgBetaDeviceManagementGroupPolicyConfigurationAssignment -GroupPolicyConfigurationId $GroupPolicyConfiguration.Id -BodyParameter $BodyParameter
    #endregion

    #region Network\Background Intelligent Transfer Service (BITS) Settings
    $NetworkBITSGroupPolicyDefinitions = Get-MgBetaDeviceManagementGroupPolicyDefinition -Filter "startsWith(categoryPath,'\Network\Background Intelligent Transfer Service (BITS)')" -All
    $NetworkBITSGroupPolicyDefinitions = $NetworkBITSGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($NetworkBITSGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\Background Intelligent Transfer Service (BITS)\Do not allow the BITS client to use Windows Branch Cache' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region Network\BranchCache Settings
    $NetworkBranchCacheGroupPolicyDefinitions = Get-MgBetaDeviceManagementGroupPolicyDefinition -Filter "startsWith(categoryPath,'\Network\BranchCache')" -All
    $NetworkBranchCacheGroupPolicyDefinitions = $NetworkBranchCacheGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($NetworkBranchCacheGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\BranchCache\Turn on BranchCache' } { 
        Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Disable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region Network\Hotspot Authentication Settings
    $NetworkHotspotAuthenticationGroupPolicyDefinitions = Get-MgBetaDeviceManagementGroupPolicyDefinition -Filter "startsWith(categoryPath,'\Network\Hotspot Authentication')" -All
    $NetworkHotspotAuthenticationGroupPolicyDefinitions = $NetworkHotspotAuthenticationGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($NetworkHotspotAuthenticationGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\Hotspot Authentication\Enable Hotspot Authentication' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Disable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region Network\Microsoft Peer-to-Peer Networking Services Settings
    $NetworkP2PGroupPolicyDefinitions = Get-MgBetaDeviceManagementGroupPolicyDefinition -Filter "startsWith(categoryPath,'\Network\Microsoft Peer-to-Peer Networking Services')" -All
    switch ($NetworkP2PGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\Microsoft Peer-to-Peer Networking Services\Turn off Microsoft Peer-to-Peer Networking Services' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region Network\Offline Files Settings
    $NetworkOfflineFilesGroupPolicyDefinitions = Get-MgBetaDeviceManagementGroupPolicyDefinition -Filter "startsWith(categoryPath,'\Network\Offline Files')" -All
    $NetworkOfflineFilesGroupPolicyDefinitions = $NetworkOfflineFilesGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($NetworkOfflineFilesGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Network\Offline Files\Allow or Disallow use of the Offline Files feature' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Disable; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region Remote Desktop Services Settings\Session Time Limits
    $RDSSessionTimeLimitsGroupPolicyDefinitions = Get-MgBetaDeviceManagementGroupPolicyDefinition -Filter "startsWith(categoryPath,'\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits')" -All
    $RDSSessionTimeLimitsGroupPolicyDefinitions = $RDSSessionTimeLimitsGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    switch ($RDSSessionTimeLimitsGroupPolicyDefinitions) {
        { $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for active but idle Remote Desktop Services sessions' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "900000"; continue }  
        { $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for disconnected sessions' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "900000"; continue }  
        { $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for active Remote Desktop Services sessions' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "0"; continue }  
        { $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\End session when time limits are reached' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value 1; continue }  
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion

    #region Remote Desktop Services Settings\Azure Virtual Desktop
    $RDSAVDGroupPolicyDefinitions = Get-MgBetaDeviceManagementGroupPolicyDefinition -Filter "startsWith(categoryPath,'\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop')" -All
    $RDSAVDGroupPolicyDefinitions = $RDSAVDGroupPolicyDefinitions | Select-Object -Property *, @{Name = "FullPath"; Expression = { Join-Path -Path $_.categoryPath -ChildPath $_.displayName } }
    $GroupPolicyDefinitionPresentation = Get-GroupPolicyDefinitionPresentationViaCmdlet -GroupPolicyDefinition $RDSAVDGroupPolicyDefinitions
    switch ($RDSAVDGroupPolicyDefinitions) {
        #{ $_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop\Enable screen capture protection' } { Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value "2"; continue }  
        { ($_.FullPath -eq '\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Azure Virtual Desktop\Enable watermarking') -and ($_.version -eq '2.0') } { 
            $Value = @{
                "QR code bitmap scale factor"                                     = 4
                "QR code bitmap opacity"                                          = 2000
                "Width of grid box in percent relative to QR code bitmap width"   = 320
                "Height of grid box in percent relative to QR code bitmap height" = 180
                "QR code embedded content"                                        = "0"
            }
            Set-GroupPolicyDefinitionSettingViaCmdlet -GroupPolicyConfiguration $GroupPolicyConfiguration -GroupPolicyDefinition $_ -Value $Value; continue 
        }
        default { Write-Verbose -Message "'$($_.FullPath)' not modified" }  
    }
    #endregion
    #endregion
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}
#endregion
#endregion
#endregion


function Update-MgBetaUserUsageLocation {
    [CmdletBinding()]
    Param (
        [ValidateScript({$_ -in $([System.Globalization.CultureInfo]::GetCultures([System.Globalization.CultureTypes]::SpecificCultures) | ForEach-Object -Process { (New-Object System.Globalization.RegionInfo $_.name).TwoLetterISORegionName } | Select-Object -Unique | Sort-Object)})]
        [string] $UsageLocation = 'US',
        [Alias('All')]
        [switch] $Force
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    if ($Force) {
        #Updating UsageLocation for all users
        $Users = Get-MgBetaUser -All
        Write-Verbose -Message "Updating UsageLocation for all users: $($Users.DisplayName -join ', ')"
    }
    else {
        #Updating UsageLocation for users without an UsageLocation
        $Users = Get-MgBetaUser -All | Where-Object -FilterScript { -not($_.UsageLocation) }
        Write-Verbose -Message "Updating UsageLocation for users without an UsageLocation: $($Users.DisplayName -join ', ')"
    }
    $Users | ForEach-Object { Update-MgBetaUser -UserId $_.Id -UsageLocation $UsageLocation }
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function Set-MgBetaAVDUsersGroupLicense {
    [CmdletBinding()]
    Param (
        #Avlidating only avialable intune licenses
        [ValidateScript({$_ -in $((Get-MgBetaSubscribedSku -All | Where-Object -FilterScript { ($_.ServicePlans.ServicePlanName -match "intune") -and (($_.PrepaidUnits.Enabled - $_.ConsumedUnits) -gt 0)}).SkuPartNumber)})]
        [string] $SkuPartNumber = 'SPE_E5',
        [Parameter(Mandatory)]
        [ValidateScript({$_ -in $((Get-MgBetaGroup).DisplayName)})]
        [string] $GroupDisplayName 
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    $Group = Get-MgBetaGroup -Filter "DisplayName eq '$GroupDisplayName'"
    $SkuId = (Get-MgBetaSubscribedSku -All -Search "SkuPartNumber:'$SkuPartNumber'").SkuId 
    Set-MgBetaGroupLicense -GroupId $Group.Id -AddLicenses @{SkuId = $SkuId} -RemoveLicenses @()

    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
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

function Test-Domaincontroller {
    [CmdletBinding()]
    Param (
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    return $null -ne (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'")
}

function Invoke-AzAvdOperationalInsightsQuery {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [array] $HostPool,
        #Querying the latest HeartBeat, Performance Counter and Event Log entry sent
        [string[]] $Queries = @("Heartbeat | order by TimeGenerated desc | limit 1", "Perf | order by TimeGenerated desc | limit 1", "Event | order by TimeGenerated desc | limit 1")
    )
    
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    foreach ($CurrentHostPool in $HostPool) {
        $CurrentLogAnalyticsWorkspaceName = $CurrentHostPool.GetLogAnalyticsWorkSpaceName()
        Write-Verbose -Message "`$CurrentLogAnalyticsWorkspaceName: $CurrentLogAnalyticsWorkspaceName"
        $CurrentLogAnalyticsWorkspace = Get-AzOperationalInsightsWorkspace -Name $CurrentLogAnalyticsWorkspaceName -ResourceGroupName $CurrentHostPool.GetResourceGroupName()

        foreach ($CurrentQuery in $Queries) {
            Write-Verbose -Message "`$CurrentQuery: $CurrentQuery"

            # Run the query
            $Result = Invoke-AzOperationalInsightsQuery -WorkspaceId $CurrentLogAnalyticsWorkspace.CustomerId -Query $CurrentQuery
            [PSCustomObject]@{LogAnalyticsWorkspaceName = $CurrentLogAnalyticsWorkspaceName ; Query = $CurrentQuery; Results = $($Result.Results | Select-Object -Property *, @{Name = "LocalTimeGenerated"; Expression = {Get-Date $_.TimeGenerated}}) }
        }
    }
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

#From https://stackoverflow.com/questions/63529599/how-to-grant-admin-consent-to-an-azure-aad-app-in-powershell
function Set-AdminConsent {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string]$applicationId,
        # The Azure Context]
        [Parameter(Mandatory)]
        [object]$context
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, "74658136-14ec-4630-ad9b-26e160ff0fc6")
    $headers = @{
        'Authorization'          = 'Bearer ' + $token.AccessToken
        'X-Requested-With'       = 'XMLHttpRequest'
        'x-ms-client-request-id' = [guid]::NewGuid()
        'x-ms-correlation-id'    = [guid]::NewGuid()
    }

    $url = "https://main.iam.ad.ext.azure.com/api/RegisteredApplications/$applicationId/Consent?onBehalfOfAll=true"
    $null = Invoke-RestMethod -Uri $url -Headers $headers -Method POST -ErrorAction Stop
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function Test-AzAvdStorageAccountNameAvailability {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [HostPool[]] $HostPool
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    $result = $true
    foreach ($CurrentHostPool in $HostPool) {
        if ($CurrentHostPool.MSIX) {
            $CurrentHostPoolStorageAccountName = $CurrentHostPool.GetMSIXStorageAccountName()
            if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentHostPoolStorageAccountName).NameAvailable) {
                Write-Error -Message "The '$CurrentHostPoolStorageAccountName' Storage Account Name is NOT available"
                $result = $false
            }
            else {
                Write-Verbose -Message "The '$CurrentHostPoolStorageAccountName' Storage Account Name is available"
            }
        }
        if ($CurrentHostPool.FSLogix) {
            $CurrentHostPoolStorageAccountName = $CurrentHostPool.GetFSLogixStorageAccountName()
            if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentHostPoolStorageAccountName).NameAvailable) {
                Write-Error -Message "The '$CurrentHostPoolStorageAccountName' Storage Account Name is NOT available"
                $result = $false
            }
            else {
                Write-Verbose -Message "The '$CurrentHostPoolStorageAccountName' Storage Account Name is available"
            }
        }
    }
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    return $result
}

function Test-AzAvdKeyVaultNameAvailability {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [HostPool[]] $HostPool
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    $result = $true
    foreach ($CurrentHostPool in $HostPool) {
        $CurrentHostPoolKeyVaultName = $CurrentHostPool.GetKeyVaultName()
        if (-not(Test-AzKeyVaultNameAvailability -Name $CurrentHostPoolKeyVaultName).NameAvailable) {
            Write-Error -Message "The '$CurrentHostPoolKeyVaultName' Key Vault Name is NOT available"
            $result = $false
        }
        else {
            Write-Verbose -Message "The '$CurrentHostPoolKeyVaultName' Key Vault Account Name is available"
        }
    }
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    return $result
}

function New-AzHostPoolSessionHostCredentialKeyVault {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $false)]
        [string] $Location = "EastUs",
        [Parameter(Mandatory = $false)]
        [PSCredential] $LocalAdminCredential,
        [Parameter(Mandatory = $false)]
        [PSCredential] $ADJoinCredential
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"


    Write-Host -Object "Azure Key Vault Setup"
    $StartTime = Get-Date
    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $AzLocationShortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion
    
    $Index = 0
    Do {
        $Index++
        $KeyVaultName = "kvavdhpcred{0}{1:D3}" -f $AzLocationShortNameHT[$Location].shortName, $Index
        $KeyVaultName = $KeyVaultName.ToLower()
        if ($Index -gt 999) {
            Stop-Transcript
            Write-Error "No name available for HostPool Credential Keyvault" -ErrorAction Stop
        }
    } While (-not(Test-AzKeyVaultNameAvailability -Name $KeyVaultName).NameAvailable)
    Write-Host -Object "Azure Key Vault Name for Credentials: $KeyVaultName"
    $ResourceGroupName = "rg-avd-kv-poc-{0}-{1:D3}" -f $AzLocationShortNameHT[$Location].shortName, $Index

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
    Write-Verbose -Message "Creating a secret in $KeyVaultName called '$SecretUserName'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretUserName -SecretValue $SecureUserName

    $SecretPassword = "LocalAdminPassword"
    Write-Verbose -Message "Creating a secret in $KeyVaultName called '$SecretPassword'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretPassword -SecretValue $SecurePassword
    #endregion

    #region Defining ad join credential(s)
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
    Write-Verbose -Message "Creating a secret in $KeyVaultName called '$SecretUserName'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretUserName -SecretValue $SecureUserName

    $SecretPassword = "ADJoinPassword"
    Write-Verbose -Message "Creating a secret in $KeyVaultName called '$SecretPassword'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretPassword -SecretValue $SecurePassword
    #endregion

    $ThisDomainController = Get-AzVMCompute | Get-AzVM
    # Get the VM's network interface
    $ThisDomainControllerNetworkInterfaceId = $ThisDomainController.NetworkProfile.NetworkInterfaces[0].Id
    $ThisDomainControllerNetworkInterface = Get-AzNetworkInterface -ResourceId $ThisDomainControllerNetworkInterfaceId
    # Get the subnet ID
    $ThisDomainControllerSubnetId = $ThisDomainControllerNetworkInterface.IpConfigurations[0].Subnet.Id
    $ThisDomainControllerSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $ThisDomainControllerSubnetId
    $split = $ThisDomainControllerSubnetId.split('/')
    # Get the vnet ID
    $ThisDomainControllerVirtualNetworkId = $split[0..($split.Count - 3)] -join "/"
    $ThisDomainControllerVirtualNetwork = Get-AzResource -ResourceId $ThisDomainControllerVirtualNetworkId | Get-AzVirtualNetwork
    
    #region Private endpoint for Key Vault Setup
    #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
    #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
    ## Create the private endpoint connection. ## 
    $PrivateEndpointName = "pep{0}" -f $($KeyVaultName -replace "\W")
    $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $KeyVault.ResourceId).GroupId
    $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $KeyVault.ResourceId -GroupId $GroupId
    Write-Verbose -Message "Creating the Private Endpoint for the Key Vault '$KeyVaultName' (in the '$ResourceGroupName' Resource Group)"
    $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $ResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -Subnet $ThisDomainControllerSubnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

    ## Create the private DNS zone. ##
    $PrivateDnsZoneName = 'privatelink.vaultcore.azure.net'
    $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
    if ($null -eq $PrivateDnsZone) {
        Write-Verbose -Message "Creating the Private DNS Zone for the Key Vault '$KeyVaultName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
        $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
    }

    $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
    $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
    if ($null -eq $PrivateDnsVirtualNetworkLink) {
        $ThisDomainControllerVirtualNetworkId = [string]::Join("/", $split[0..($split.Count - 3)])
        ## Create a DNS network link. ##
        Write-Verbose -Message "Creating the Private DNS VNet Link for the Key Vault '$KeyVaultName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
        $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
    }

    ## Configure the DNS zone. ##
    Write-Verbose -Message "Creating the DNS Zone Configuration of the Private Dns Zone Group for Key Vault '$KeyVaultName'"
    $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

    ## Create the DNS zone group. ##
    Write-Verbose -Message "Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$ResourceGroupName' Resource Group)"
    $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $ResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force

    #Key Vault - Disabling Public Access
    Write-Verbose -Message "Disabling the Public Access for the Key Vault'$KeyVaultName' (in the '$ResourceGroupName' Resource Group)"
    $null = Update-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName -PublicNetworkAccess "Disabled" 
    #endregion

    $EndTime = Get-Date
    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host -Object "Azure Key Vault Setup Processing Time: $($TimeSpan.ToString())"

    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    return $KeyVault
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

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    Add-Type -AssemblyName 'System.Web'
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    $RandomPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
    Write-Host "The password is : $RandomPassword"
    if ($ClipBoard) {
        Write-Verbose -Message "The password has beeen copied into the clipboard (Use Win+V)"
        $RandomPassword | Set-Clipboard
    }
    if ($AsSecureString) {
        ConvertTo-SecureString -String $RandomPassword -AsPlainText -Force
    }
    else {
        $RandomPassword
    }
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

#Was coded as an alterative to Test-AzKeyVaultNameAvailability (for testing purpose - no more used in this script)
function Get-AzKeyVaultNameAvailability {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [Alias('Name')]
        [string]$VaultName
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

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
        $Response = Invoke-RestMethod -Method POST -Headers $authHeader -Body $($Body | ConvertTo-Json -Depth 100) -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
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
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    return $Response
}

#Was coded as an alterative to Expand-AzWvdMsixImage (for testing purpose - no more used in this script)
function Expand-AzAvdMSIXImage {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -match "^\\\\.*\.vhdx?$" })]
        [string]$Uri
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

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
        $Response = Invoke-RestMethod -Method POST -Headers $authHeader -Body $($Body | ConvertTo-Json -Depth 100) -ContentType "application/json" -Uri $expandMsixImageURI -ErrorVariable ResponseError
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
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    return $Response
}

function Grant-ADJoinPermission {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,
        [Parameter(Mandatory = $true)]
        [Alias('OU')]
        [string]$OrganizationalUnit
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    # Import the Active Directory module
    Import-Module ActiveDirectory

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
    $ADUser = Get-ADUser -Filter "SamAccountName -eq '$($Credential.UserName)'"
    #If the user doesn't exist, we create it
    if (-not($ADUser)) {
        Write-Verbose -Message "Creating '$($Credential.UserName)' AD User (for adding Azure VM to ADDS)"
        #$DomainName = (Get-ADDomain).DNSRoot
        $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        #$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Forest.Name
        $ADUser = New-ADUser -Name $Credential.UserName -AccountPassword $Credential.Password -PasswordNeverExpires $true -Enabled $true -Description "Created by PowerShell Script for ADDS-joined AVD Session Hosts" -UserPrincipalName $("{0}@{1}" -f $Credential.UserName, $DomainName) -PassThru
    }

    # Define the security SamAccountName (user or group) to which you want to grant the permission
    $IdentityReference = [System.Security.Principal.IdentityReference] $ADUser.SID
    Import-Module -Name ActiveDirectory
    $Permission = Get-Acl -Path "AD:$OrganizationalUnit"

    Write-Verbose -Message "Applying required privileges to '$($Credential.UserName)' AD User (for adding Azure VM to ADDS)"
    foreach ($CurrentADRight in $ADRights) {
        $AccessRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($IdentityReference, $CurrentADRight.ActiveDirectoryRights, $CurrentADRight.AccessControlType, $CurrentADRight.ObjectType, $CurrentADRight.InheritanceType, $CurrentADRight.InheritedObjectType)
        $Permission.AddAccessRule($AccessRule)
    }

    # Apply the permission recursively to the OU and its descendants
    Get-ADOrganizationalUnit -Filter "DistinguishedName -like '$OrganizationalUnit'" -SearchBase $OrganizationalUnit -SearchScope Subtree | ForEach-Object {
        Write-Verbose -Message "Applying those required privileges to '$_'"
        Import-Module -Name ActiveDirectory
        Set-Acl -path "AD:$_" $Permission
    }

    Write-Verbose -Message "Permissions granted successfully."
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

#From https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD
function New-AzureComputeGallery {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [string]$Location = "EastUS",
        [Parameter(Mandatory = $false)]
        [string[]]$targetRegions = @($Location, "EastUS2"),
        [Parameter(Mandatory = $false)]
        [int]$ReplicaCount = 1
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    $StartTime = Get-Date
    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $AzLocationShortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
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
    $LocationShortName = $AzLocationShortNameHT[$Location].shortName
    Write-Verbose -Message "`$LocationShortName: $LocationShortName"
    if ($Location -notin $targetRegions) {
        $targetRegions += $Location
    }
    Write-Verbose -Message "`$targetRegions: $($targetRegions -join ', ')"
    [array] $targetRegionSettings = foreach ($CurrentTargetRegion in $targetRegions) {
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
        Write-Verbose -Message "Removing '$ResourceGroupName' Resource Group Name"
        Remove-AzResourceGroup -Name $ResourceGroupName -Force
    }
    Write-Verbose -Message "Creating '$ResourceGroupName' Resource Group Name"
    $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $location -Force

    #region Permissions, user identity, and role
    # setup role def names, these need to be unique
    $imageRoleDefName = "Azure Image Builder Image Def - $timeInt"
    $identityName = "aibIdentity-$timeInt"
    Write-Verbose -Message "`$imageRoleDefName: $imageRoleDefName"
    Write-Verbose -Message "`$identityName: $identityName"


    # Create the identity
    Write-Verbose -Message "Creating User Assigned Identity '$identityName'"
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
    Invoke-WebRequest -Uri $aibRoleImageCreationUrl -UseBasicParsing -OutFile $aibRoleImageCreationPath

    ((Get-Content -path $aibRoleImageCreationPath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $aibRoleImageCreationPath
    ((Get-Content -path $aibRoleImageCreationPath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $aibRoleImageCreationPath
    ((Get-Content -path $aibRoleImageCreationPath -Raw) -replace 'Azure Image Builder Service Image Creation Role', $imageRoleDefName) | Set-Content -Path $aibRoleImageCreationPath

    # Create a role definition
    Write-Verbose -Message "Creating '$imageRoleDefName' Role Definition"
    $RoleDefinition = New-AzRoleDefinition -InputFile $aibRoleImageCreationPath

    # Grant the role definition to the VM Image Builder service principal
    Write-Verbose -Message "Assigning '$($RoleDefinition.Name)' Role to '$($AssignedIdentity.Name)'"
    Do {
        Write-Verbose -Message "Sleeping 10 seconds"
        Start-Sleep -Seconds 10
        $RoleAssignment = New-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $ResourceGroup.ResourceId -ErrorAction Ignore #-Debug
    } While ($null -eq $RoleAssignment)
  
    #endregion

    #region Create an Azure Compute Gallery
    $GalleryName = "{0}_{1}_{2}_{3}" -f $AzureComputeGalleryPrefix, $Project, $LocationShortName, $timeInt
    Write-Verbose -Message "`$GalleryName: $GalleryName"

    # Create the gallery
    Write-Verbose -Message "Creating Azure Compute Gallery '$GalleryName'"
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
    Write-Verbose -Message "`$templateFilePath: $templateFilePath "

    Invoke-WebRequest -Uri $templateUrl -UseBasicParsing -OutFile $templateFilePath

    ((Get-Content -path $templateFilePath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $templateFilePath
    ((Get-Content -path $templateFilePath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $templateFilePath
    #((Get-Content -path $templateFilePath -Raw) -replace '<region>',$location) | Set-Content -Path $templateFilePath
    ((Get-Content -path $templateFilePath -Raw) -replace '<runOutputName>', $runOutputName01) | Set-Content -Path $templateFilePath

    ((Get-Content -path $templateFilePath -Raw) -replace '<imageDefName>', $imageDefName01) | Set-Content -Path $templateFilePath
    ((Get-Content -path $templateFilePath -Raw) -replace '<sharedImageGalName>', $GalleryName) | Set-Content -Path $templateFilePath
    ((Get-Content -path $templateFilePath -Raw) -replace '<targetRegions>', $($targetRegionSettings | ConvertTo-Json)) | Set-Content -Path $templateFilePath
    ((Get-Content -path $templateFilePath -Raw) -replace '<imgBuilderId>', $AssignedIdentity.Id) | Set-Content -Path $templateFilePath
    ((Get-Content -path $templateFilePath -Raw) -replace '<version>', $version) | Set-Content -Path $templateFilePath
    #endregion

    #region Submit the template
    Write-Verbose -Message "Starting Resource Group Deployment from '$templateFilePath'"
    $ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $templateFilePath -TemplateParameterObject @{"api-Version" = "2022-07-01"; "imageTemplateName" = $imageTemplateName01; "svclocation" = $location }

    #region Build the image
    Write-Verbose -Message "Starting Image Builder Template from '$imageTemplateName01' (As Job)"
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
    Write-Verbose -Message "Creating Azure Image Builder Template Source Object "
    $srcPlatform = New-AzImageBuilderTemplateSourceObject @SrcObjParams

    $disObjParams = @{
        SharedImageDistributor = $true
        GalleryImageId         = "$($GalleryImageDefinition02.Id)/versions/$version"
        ArtifactTag            = @{source = 'avd-win11'; baseosimg = 'windows11' }

        # 1. Uncomment following line for a single region deployment.
        #ReplicationRegion = $location

        # 2. Uncomment following line if the custom image should be replicated to another region(s).
        TargetRegion           = $targetRegionSettings

        RunOutputName          = $runOutputName02
        ExcludeFromLatest      = $false
    }
    Write-Verbose -Message "Creating Azure Image Builder Template Distributor Object "
    $disSharedImg = New-AzImageBuilderTemplateDistributorObject @disObjParams

    $ImgTimeZoneRedirectionPowerShellCustomizerParams = @{  
        PowerShellCustomizer = $true  
        Name                 = 'Timezone Redirection'  
        RunElevated          = $true  
        runAsSystem          = $true  
        ScriptUri            = 'https://raw.githubusercontent.com/Azure/RDS-Templates/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2023-07-31/TimezoneRedirection.ps1'
    }

    Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgTimeZoneRedirectionPowerShellCustomizerParams.Name)'"
    $TimeZoneRedirectionCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgTimeZoneRedirectionPowerShellCustomizerParams 

    $ImgVSCodePowerShellCustomizerParams = @{  
        PowerShellCustomizer = $true  
        Name                 = 'Install Visual Studio Code'  
        RunElevated          = $true  
        runAsSystem          = $true  
        ScriptUri            = 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/Install-VSCode.ps1'
    }

    Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgVSCodePowerShellCustomizerParams.Name)'"
    $VSCodeCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgVSCodePowerShellCustomizerParams 

    Write-Verbose -Message "Creating Azure Image Builder Template WindowsUpdate Customizer Object"
    $WindowsUpdateCustomizer = New-AzImageBuilderTemplateCustomizerObject -WindowsUpdateCustomizer -Name 'WindowsUpdate' -Filter @('exclude:$_.Title -like ''*Preview*''', 'include:$true') -SearchCriterion "IsInstalled=0" -UpdateLimit 40

    $ImgDisableAutoUpdatesPowerShellCustomizerParams = @{  
        PowerShellCustomizer = $true  
        Name                 = 'Disable AutoUpdates'  
        RunElevated          = $true  
        runAsSystem          = $true  
        ScriptUri            = 'https://raw.githubusercontent.com/Azure/RDS-Templates/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2023-07-31/TimezoneRedirection.ps1'
    }

    Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgDisableAutoUpdatesPowerShellCustomizerParams.Name)'"
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
    Write-Verbose -Message "Creating Azure Image Builder Template from '$imageTemplateName02' Image Template Name"
    $ImageBuilderTemplate = New-AzImageBuilderTemplate @ImgTemplateParams

    #region Build the image
    #Start the image building process using Start-AzImageBuilderTemplate cmdlet:
    Write-Verbose -Message "Starting Image Builder Template from '$imageTemplateName02' (As Job)"
    $Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName02 -AsJob
    #endregion

    Write-Verbose -Message "Waiting for jobs to complete"
    $Jobs | Wait-Job | Out-Null

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
    Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateName01'"
    #$Jobs += $getStatus01 | Remove-AzImageBuilderTemplate -AsJob
    $getStatus01 | Remove-AzImageBuilderTemplate -NoWait
    Write-Verbose -Message "Removing '$aibRoleImageCreationPath'"
    Write-Verbose -Message "Removing '$templateFilePath'"
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
    #endregion

    Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateName02'"
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
    Write-Verbose -Message "Removing jobs"
    $Jobs | Remove-Job -Force

    $EndTime = Get-Date
    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host -Object "Overall Azure Compute Gallery Setup Processing Time: $($TimeSpan.ToString())"

    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    return $Gallery
}

#Get The Azure VM Compute Object for the VM executing this function
function Get-AzVMCompute {
    [CmdletBinding()]
    Param(
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    $uri = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers @{"Metadata" = "true" } -Method GET -TimeoutSec 5
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
        return $response.compute
    }
    catch {
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
}

function New-AzAvdSessionHost {
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
        [hashtable] $Tag,
        [switch]$IsMicrosoftEntraIdJoined, 
        [switch] $Spot,
        [switch] $HibernationEnabled,
        [switch] $Intune
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    $OSDiskSize = "127"
    $OSDiskType = "Premium_LRS"

    Import-Module -Name Az.Compute
    $ThisDomainController = Get-AzVMCompute | Get-AzVM
    # Get the VM's network interface
    $ThisDomainControllerNetworkInterfaceId = $ThisDomainController.NetworkProfile.NetworkInterfaces[0].Id
    $ThisDomainControllerNetworkInterface = Get-AzNetworkInterface -ResourceId $ThisDomainControllerNetworkInterfaceId
    # Get the subnet ID
    $ThisDomainControllerSubnetId = $ThisDomainControllerNetworkInterface.IpConfigurations[0].Subnet.Id
    $ThisDomainControllerSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $ThisDomainControllerSubnetId
    $split = $ThisDomainControllerSubnetId.split('/')
    # Get the vnet ID
    $ThisDomainControllerVirtualNetworkId = $split[0..($split.Count - 3)] -join "/"
    $ThisDomainControllerVirtualNetwork = Get-AzResource -ResourceId $ThisDomainControllerVirtualNetworkId | Get-AzVirtualNetwork

    if ($null -eq (Get-AZVMSize -Location $ThisDomainControllerVirtualNetwork.Location | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
        Stop-Transcript
        Write-Error "The '$VMSize' is not available in the '$($ThisDomainControllerVirtualNetwork.Location)' location" -ErrorAction Stop
    }

    Write-Verbose -Message "`$HostPoolId: $HostPoolId"
    $HostPool = Get-AzResource -ResourceId $HostPoolId
    Write-Verbose -Message "Creating the '$VMName' Session Host into the '$($HostPool.Name)' Host Pool (in the '$($HostPool.ResourceGroupName)' Resource Group)"

    $NICName = "nic-$VMName"
    $OSDiskName = '{0}_OSDisk' -f $VMName
    #$DataDiskName = "$VMName-DataDisk01"

    #Create Network Interface Card 
    $NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -SubnetId $ThisDomainControllerSubnet.Id -Force

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

    $LocalAdminUserName = $KeyVault | Get-AzKeyVaultSecret -Name LocalAdminUserName -AsPlainText
    $LocalAdminPassword = ($KeyVault | Get-AzKeyVaultSecret -Name LocalAdminPassword).SecretValue
    $LocalAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($LocalAdminUserName, $LocalAdminPassword)

    #Set VM operating system parameters
    $null = Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $VMName -Credential $LocalAdminCredential -ProvisionVMAgent

    #Set boot diagnostic to managed storage account
    $null = Set-AzVMBootDiagnostic -VM $VMConfig -Enable 

    #Set virtual machine source image
    if (-not([string]::IsNullOrEmpty($VMSourceImageId))) {
        Write-Verbose -Message "Building Azure VM via `$VMSourceImageId:$VMSourceImageId"
        $null = Set-AzVMSourceImage -VM $VMConfig -Id $VMSourceImageId
    }
    else {
        Write-Verbose -Message "Building Azure VM via `$ImagePublisherName:$ImagePublisherName/`$ImageOffer:$ImageOffer/`$ImageSku:$ImageSku"
        $null = Set-AzVMSourceImage -VM $VMConfig -PublisherName $ImagePublisherName -Offer $ImageOffer -Skus $ImageSku -Version 'latest'
    }
    #Set OsDisk configuration
    #From https://learn.microsoft.com/en-us/azure/virtual-machines/ephemeral-os-disks-deploy#powershell
    if ($DiffDiskPlacement -eq [DiffDiskPlacement]::None)
    {
        $null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage
        Write-Verbose -Message "No Ephemeral OS disk for '$VMName' Azure VM"
    } 
    elseif ($DiffDiskPlacement -eq [DiffDiskPlacement]::CacheDisk) {
        $null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -CreateOption fromImage -DiffDiskSetting Local -DiffDiskPlacement CacheDisk -Caching ReadOnly
        Write-Verbose -Message "Ephemeral OS disk for '$VMName' Azure VM set to 'CacheDisk'"
    }
    else { 
        $null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -CreateOption fromImage -DiffDiskSetting Local -DiffDiskPlacement ResourceDisk -Caching ReadOnly
        Write-Verbose -Message "Ephemeral OS disk for '$VMName' Azure VM set to 'ResourceDisk'"
    }
    try {
        $null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -VM $VMConfig -Tag $Tag -DisableBginfoExtension -ErrorAction Stop
    } 
    #Maybe: Ephemeral OS disk is not supported for specified VM size.
    catch #[ComputeCloudException]
    {
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "Message: $($_.Exception.Message)"
        Write-Verbose -Message "Disabling Ephemeral OS disk for '$VMName' Azure VM"
        $null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage
        $null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -VM $VMConfig -Tag $Tag -DisableBginfoExtension
    }
    $VM = Get-AzVM -ResourceGroup $ResourceGroupName -Name $VMName
    $null = Start-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName

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
        Write-Verbose -Message "The '$VMName' VM will be Microsoft Entra ID joined"
        $aadJoin = [boolean]::TrueString
    }
    else {
        $ExtensionName = "joindomain$("{0:yyyyMMddHHmmss}" -f (Get-Date))"
        Write-Verbose -Message "Adding '$VMName' VM to '$DomainName' AD domain"

        $AdJoinUserName = $KeyVault | Get-AzKeyVaultSecret -Name AdJoinUserName -AsPlainText
        $AdJoinPassword = ($KeyVault | Get-AzKeyVaultSecret -Name AdJoinPassword).SecretValue

        $ADDomainJoinUser = Get-ADUser -Identity $AdJoinUserName -Properties UserPrincipalName
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
    #Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$VMName /user:$($LocalAdminCredential.UserName) /pass:$($LocalAdminCredential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait


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
        location           = $ThisDomainControllerVirtualNetwork.Location
    }
    
    Write-Verbose -Message "Adding '$VMName' to '$($HostPool.Name)' Host Pool"
    $result = Set-AzVMExtension @avdDscSettings
    Write-Verbose -Message "Result: `r`n$($result | Out-String)"
    #>

    $avdModuleLocation = "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration_1.0.02599.267.zip"
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
    Write-Verbose -Message "Adding '$VMName' to '$($HostPool.Name)' Host Pool"
    $result = Set-AzVMExtension -VMName $VMName -ResourceGroupName $ResourceGroupName -Location  $ThisDomainControllerVirtualNetwork.Location -TypeHandlerVersion $avdExtensionVersion -Publisher $avdExtensionPublisher -ExtensionType $avdExtensionName -Name $avdExtensionName -Settings $avdExtensionSetting
    Write-Verbose -Message "Result: `r`n$($result | Out-String)"

    if ($IsMicrosoftEntraIdJoined) {
        #region Installing the AADLoginForWindows extension
        $PreviouslyExistingAzureADDevice = Get-MgBetaDevice -Filter "displayName eq '$VMName'" -ConsistencyLevel eventual -All
        if ($null -ne $PreviouslyExistingAzureADDevice) {
            Write-Verbose -Message "Removing previously existing '$VMName' as a device into 'Microsoft Entra ID'"
            #The pipeline has been stopped ==> $PreviouslyExistingAzureADDevice | Remove-MgBetaDevice
            $PreviouslyExistingAzureADDevice | ForEach-Object -Process { 
                Write-Verbose -Message "Removing Microsoft Entra ID Device : $($_.DisplayName)"
                Remove-MgBetaDevice -DeviceId $_.Id 
            }
        }
        if ($Intune) {
            #From https://rozemuller.com/how-to-join-azure-ad-automated/
            #From https://virtuallyflatfeet.com/category/intune/
            Write-Verbose -Message "Adding '$VMName' as a device into 'Microsoft Entra ID' and enrolled with Intune"
            $domainJoinSettings  = @{
                mdmId = "0000000a-0000-0000-c000-000000000000"
            }

            $result = Set-AzVMExtension -Publisher "Microsoft.Azure.ActiveDirectory" -Name AADLoginForWindows -ResourceGroupName  $VM.ResourceGroupName -VMName $VM.Name -Settings $domainJoinSettings -ExtensionType "AADLoginForWindows" -TypeHandlerVersion 2.0
            Write-Verbose -Message "Result: `r`n$($result | Out-String)"
        }
        else {
            Write-Verbose -Message "Adding '$VMName' as a device into 'Microsoft Entra ID'"
            $result = Set-AzVMExtension -Publisher Microsoft.Azure.ActiveDirectory -Name AADLoginForWindows -ResourceGroupName $VM.ResourceGroupName -VMName $VM.Name -ExtensionType AADLoginForWindows -TypeHandlerVersion 2.0
            Write-Verbose -Message "Result: `r`n$($result | Out-String)"
        }
        #endregion
        <#
        #>
    }
    <#
    Write-Verbose -Message "Restarting '$VMName'"
    Restart-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName -Confirm:$false
    #>
    Write-Verbose -Message "Leaving funct<ion '$($MyInvocation.MyCommand)'"
}

function Add-AzAvdSessionHost {
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
        [Microsoft.Azure.Commands.KeyVault.Models.PSKeyVault]$KeyVault,
        [Parameter(Mandatory = $true)]
        [String]$RegistrationInfoToken,
        [Parameter(Mandatory = $true)]
        [String]$OUPath,
        [Parameter(Mandatory = $true)]
        [String]$DomainName,
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

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #HibernationEnabled can't be used with Spot VMs
    if ($Spot) {
        $HibernationEnabled = $false
    }

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
    Write-Verbose -Message "Adding $VMNumberOfInstances Session Hosts to the '$($HostPool.Name)' Host Pool (in the '$($HostPool.ResourceGroupName)' Resource Group)"
    $Jobs = foreach ($Index in $Start..$End) {
        $CurrentVMName = '{0}-{1}' -f $NamePrefix, $Index
        if (-not([string]::IsNullOrEmpty($VMSourceImageId))) {
            $Params = @{
                HostPoolId               = $HostPoolId 
                VMName                   = $CurrentVMName
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
                #Verbose                  = $true
            }
        }
        else {
            $Params = @{
                HostPoolId               = $HostPoolId 
                VMName                   = $CurrentVMName
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
                #Verbose                  = $true
            }
        }
        #$AsJob = $false
        if ($AsJob) {
            #From https://stackoverflow.com/questions/7162090/how-do-i-start-a-job-of-a-function-i-just-defined
            #From https://stackoverflow.com/questions/76844912/how-to-call-a-class-object-in-powershell-jobs
            $ExportedFunctions = [scriptblock]::Create(@"
            Function New-AzAvdSessionHost { ${Function:New-AzAvdSessionHost} }          
            Function Get-AzVMCompute { ${Function:Get-AzVMCompute} }
            Function Get-CallerPreference { ${Function:Get-CallerPreference} }
"@)
            Write-Verbose -Message "Starting background job for '$CurrentVMName' SessionHost Creation (via New-AzAvdSessionHost) ... "
            try {
                #Getting the Log Directory if ran from a Start-ThreadJob
                $LocalLogDir = $using:LogDir
                Write-Verbose -Message "We are in the context of a 'Start-ThreadJob'"
            }
            catch {
                #Getting the Log Directory if NOT ran from a Start-ThreadJob
                $LocalLogDir = $LogDir
                Write-Verbose -Message "We are NOT in the context of a 'Start-ThreadJob'"
            }
            Write-Verbose -Message "`$LocalLogDir: $LocalLogDir"
            Start-ThreadJob -ScriptBlock { param($LogDir) New-AzAvdSessionHost @using:Params *>&1 | Out-File -FilePath $("{0}\New-AzAvdSessionHost_{1}_{2}.txt" -f $LogDir, $using:CurrentVMName, (Get-Date -Format 'yyyyMMddHHmmss')) } -InitializationScript $ExportedFunctions -ArgumentList $LocalLogDir #-StreamingHost $Host
        }
        else {
            New-AzAvdSessionHost @Params
        }
    }
    if ($AsJob) {
        $Jobs | Receive-Job -Wait -AutoRemoveJob
    }
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function Copy-MSIXDemoAppAttachPackage {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )   

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    $URI = "https://api.github.com/repos/lavanack/laurentvanacker.com/contents/Azure/Azure%20Virtual%20Desktop/MSIX/MSIX"
    $Response = Invoke-WebRequest -Uri $URI -UseBasicParsing
    $Objects = $Response.Content | ConvertFrom-Json
    $Files = $Objects | Where-Object -FilterScript { $_.type -eq "file" } | Select-Object -ExpandProperty download_url
    $VHDFileURIs = $Files -match "\.vhd$"

    Write-Verbose -Message "VHD File Source URIs: $($VHDFileURIs -join ',')" 
    #Copying the VHD package for MSIX to the MSIX file share    
    Start-BitsTransfer -Source $VHDFileURIs -Destination $Destination
    $MSIXDemoPackage = $VHDFileURIs | ForEach-Object -Process { Join-Path -Path $Destination -ChildPath $($_ -replace ".*/") }
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    return $MSIXDemoPackage
}

function Copy-MSIXDemoPFXFile {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [string[]]$ComputerName,
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()] 
        [System.Security.SecureString]$SecurePassword = $(ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force)
    )   

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    $URI = "https://api.github.com/repos/lavanack/laurentvanacker.com/contents/Azure/Azure%20Virtual%20Desktop/MSIX/MSIX"
    $Response = Invoke-WebRequest -Uri $URI -UseBasicParsing
    $Objects = $Response.Content | ConvertFrom-Json
    $Files = $Objects | Where-Object -FilterScript { $_.type -eq "file" } | Select-Object -ExpandProperty download_url
    $PFXFileURIs = $Files -match "\.pfx$"

    #Copying the PFX files for MSIX to a temp local folder
    $TempFolder = New-Item -Path $(Join-Path -Path $env:TEMP -ChildPath $("{0:yyyyMMddHHmmss}" -f (Get-Date))) -ItemType Directory -Force
    #Copying the Self-Signed certificate to the MSIX file share
    Start-BitsTransfer -Source $PFXFileURIs -Destination $TempFolder
    $DownloadedPFXFiles = Get-ChildItem -Path $TempFolder -Filter *.pfx -File


    #$Session = New-PSSession -ComputerName $ComputerName -ErrorAction Ignore
    $Session = Wait-PSSession -ComputerName $SessionHostNames -PassThru

    #Copying the PFX to all session hosts
    $Session | ForEach-Object -Process { Copy-Item -Path $DownloadedPFXFiles.FullName -Destination C:\ -ToSession $_ -Force }

    Invoke-command -Session $Session -ScriptBlock {
        $using:DownloadedPFXFiles | ForEach-Object -Process { 
            $LocalFile = $(Join-Path -Path C: -ChildPath $_.Name)
            #Adding the self-signed certificate to the Trusted Root Certification Authorities (To validate this certificate)
            $ImportPfxCertificates = Import-PfxCertificate $LocalFile -CertStoreLocation Cert:\LocalMachine\TrustedPeople\ -Password $using:SecurePassword 
            Write-Verbose -Message $($ImportPfxCertificates | Out-String)
            #Removing the PFX file (useless now)
            Remove-Item -Path $LocalFile -Force
            Write-Verbose -Message "Updating GPO"
            gpupdate /force /wait:-1 /target:computer | Out-Null
        }
    }
    $Session | Remove-PSSession
    #Removing the Temp folder (useless now)
    Remove-Item -Path $TempFolder -Recurse -Force
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function Wait-PSSession {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [string[]]$ComputerName,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()] 
        [int]$Seconds = 30,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()] 
        [int]$Attempts = 10,
        [switch]$PassThru
	)

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #Any negative value means infinite loop. 
    if ($Attempts -lt 0) {
        $Attempts = [int]::MaxValue
    }
    $Loop = 0
    Write-Verbose -Message "Computer Names (Nb: $($ComputerName.Count)): $($ComputerName -join ', ')"  
    Do {
        $Loop ++  
        Write-Verbose -Message "Loop #$($Loop)"  
        $Session = New-PSSession -ComputerName $ComputerName -ErrorAction Ignore
        if ($Session.Count -lt $ComputerName.Count) {
            Write-Verbose -Message "Sleeping $Seconds Seconds"
            Start-Sleep -Seconds $Seconds
            $result = $false
        }
        else {
            $result = $true
        }
        if (-not($PassThru)) {
            $Session | Remove-PSSession
        }
        Write-Verbose -Message "Result: $result"  
    } While ((-not($Result)) -and ($Loop -lt $Attempts))
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    if (-not($PassThru)) {   
        return $result
    } 
    else {
        return $Session
    }
}

function Wait-AzVMPowerShell {
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

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    #Any negative value means infinite loop. 
    if ($Attempts -lt 0) {
        $Attempts = [int]::MaxValue
        Write-Verbose -Message "Infinite Loop Mode Enabled"  
    }
    $Loop = 0
    $SessionHosts = Get-AzWvdSessionHost -HostpoolName $HostPoolName -ResourceGroupName $ResourceGroupName
    #Write-Verbose -Message "Session Hosts (Nb: $($SessionHosts.Count)): $($SessionHosts.Name -replace "^.*/" -join ', ')"
    Write-Verbose -Message "Session Hosts (Nb: $($SessionHosts.Count)): $($SessionHosts.Name -replace "^.*/" -replace "\..*$" -join ', ')"
    Do {
        $Loop ++  
        Write-Verbose -Message "Loop #$($Loop)"  
        $Jobs = foreach ($CurrentSessionHost in $SessionHosts) {
            $CurrentSessionHostVM = $CurrentSessionHost.ResourceId | Get-AzVM
            Write-Verbose -Message "Processing '$($CurrentSessionHostVM.Name)'"
            Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $CurrentSessionHostVM.Name -CommandId 'RunPowerShellScript' -ScriptString 'return $true' -AsJob
        }
        $Jobs | Wait-Job | Out-Null
        #Write-Host "Job State: $($Jobs.State -join ', ')" 
        Write-Verbose -Message "Job State:`r`n$($Jobs | Group-Object State -NoElement | Out-String)"  
        if ($Jobs.State -ne "Completed") {
            Write-Verbose -Message "Sleeping $Seconds Seconds"
            Start-Sleep -Seconds $Seconds
            $result = $false
        }
        else {
            $result = $true
        }
        $Jobs | Remove-Job -Force
        Write-Verbose -Message "Result: $result"  
    } While ((-not($Result)) -and ($Loop -lt $Attempts))
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    return $result
}

function Start-MicrosoftEntraIDConnectSync {
    [CmdletBinding()]
    Param()

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    if (Get-Service -Name ADSync -ErrorAction Ignore) {
        Start-Service -Name ADSync
        Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"
        $ADSyncConnectorRunStatus = Get-ADSyncConnectorRunStatus
        Write-Verbose -Message "`$ADSyncConnectorRunStatus: $($ADSyncConnectorRunStatus | Out-String)"
        if (-not((Get-ADSyncScheduler).SyncCycleInProgress)) {
            Write-Verbose -Message "Running a sync with Microsoft Entra ID"
            try {
                $null = Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
            }
            catch {
                Write-Verbose -Message "Microsoft Entra ID Sync already in progress"
            }
            Do {
                Write-Verbose -Message "Sleeping 5 seconds"
                Start-Sleep -Seconds 5
                $ADSyncConnectorRunStatus = Get-ADSyncConnectorRunStatus
                Write-Verbose -Message "`$ADSyncConnectorRunStatus: $($ADSyncConnectorRunStatus | Out-String)"
            } While ((Get-ADSyncScheduler).SyncCycleInProgress)

        }
        else {
            Write-Verbose -Message "Microsoft Entra ID Sync already in progress"
        }
    }
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function Remove-AzAvdHostPoolSetup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'HostPool')]
        [Alias('Name')]
        [HostPool[]]$HostPool,
        [Parameter(Mandatory = $true, ParameterSetName = 'FullName')]
        [ValidateScript({ (Test-Path -Path $_ -PathType Leaf) -and ($_ -match "\.json$") })]
        [Alias('Path')]
        [string[]]$FullName
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    Write-Host -Object "HostPool Removal"
    $StartTime = Get-Date
    if ($FullName) {
        $HostPools = foreach ($CurrentFullName in $FullName) {
            $CurrentFullName = (Resolve-Path -Path $CurrentFullName).Path
            Write-Verbose -Message "Using the '$CurrentFullName' JSON file"
            #Split Arrays to items 
            Get-Content -Path $CurrentFullName -Raw | ConvertFrom-Json | ForEach-Object -Process { $_ }
        }
        #Remove duplicated items (by name)
        $HostPools = $HostPools | Sort-Object -Property Name -Unique
    }
    else {
        $HostPools = $HostPool | Select-Object -Property *, @{Name="ResourceGroupName"; Expression = {$_.GetResourceGroupName()}} -ExcludeProperty "KeyVault"
    }
    $HostPools = $HostPools | Where-Object -FilterScript { $_.Name }
    Write-Verbose -Message "Cleaning up the '$($HostPools.Name -join ', ')' Host Pools"
    #region Cleanup of the previously existing resources
    #region DNS Cleanup
    $OUDistinguishedNames = (Get-ADOrganizationalUnit -Filter * | Where-Object -FilterScript { $_.Name -in $($HostPools.Name) }).DistinguishedName 
    if (-not([string]::IsNullOrEmpty($OUDistinguishedNames))) {
        $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        $OUDistinguishedNames | ForEach-Object -Process {
            Write-Verbose -Message "Processing OU: '$_'"
            (Get-ADComputer -Filter 'DNSHostName -like "*"' -SearchBase $_).Name } | ForEach-Object -Process { 
            try {
                if (-not([string]::IsNullOrEmpty($_))) {
                    Write-Verbose -Message "Removing DNS Record: '$_'"
                    #$DomainName = (Get-ADDomain).DNSRoot
                    Remove-DnsServerResourceRecord -ZoneName $DomainName -RRType "A" -Name "$_" -Force -ErrorAction Ignore
                }
            } 
            catch {} 
        }
    }
    #endregion

    #region AD OU/GPO Cleanup
    $OrganizationalUnits = Get-ADOrganizationalUnit -Filter * | Where-Object -FilterScript { $_.Name -in $($HostPools.Name) } 
    Write-Verbose -Message "Removing OUs: $($OrganizationalUnits.Name -join ', ')"
    $OrganizationalUnits | Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -PassThru -ErrorAction Ignore | Remove-ADOrganizationalUnit -Recursive -Confirm:$false #-WhatIf
    $GPOs = Get-GPO -All | Where-Object -FilterScript { $_.DisplayName -match $($HostPools.Name -join "|") } 
    Write-Verbose -Message "Removing GPOs: $($GPOs.DisplayName -join ', ')"
    $GPOs | Remove-GPO 
    #endregion

    #region Azure AD/Microsoft Entra ID cleanup
    $MicrosoftEntraIDHostPools = $HostPools | Where-Object -FilterScript { $_.IdentityProvider -eq [IdentityProvider]::MicrosoftEntraID }
    #Getting all session hosts starting with the Name Prefixes
    $RegExp = ($MicrosoftEntraIDHostPools.NamePrefix -replace '(^[^\n]*$)', '^$1-') -join '|'
    Write-Verbose -Message "`$RegExp : $RegExp"
    Get-MgBetaDevice -All | Where-Object -FilterScript { $_.DisplayName -match $RegExp }| ForEach-Object -Process { 
        Write-Verbose -Message "Removing Microsoft Entra ID Device : $($_.DisplayName)"
        Remove-MgBetaDevice -DeviceId $_.Id 
    }
    #Removing the other Azure AD groups (created for Entra ID / Intune for instance)
    #Risky command :Get-AzADGroup | Where-Object -FilterScript { $_.DisplayName -match "^($($HostPools.Name -join '|'))" } | Remove-AzADGroup -WhatIf
    foreach ($CurrentHostPoolName in $HostPools.Name) {
        Write-Verbose -Message "Removing Microsoft Entra ID Group : $CurrentHostPoolName"
        Get-AzADGroup -DisplayNameStartsWith $CurrentHostPoolName | Remove-AzADGroup
    }
    #endregion

    #region Intune Cleanup
    #From https://therandomadmin.com/2024/03/04/get-intune-devices-with-powershell-2/
    $IntuneHostPools = $HostPools | Where-Object -FilterScript { $_.Intune }
    if ($IntuneHostPools) {
        Remove-IntuneItemViaCmdlet -HostPool $IntuneHostPools
    }
    #endregion


    #region Azure Cleanup
    <#
    $HostPools = (Get-AzWvdHostPool | Where-Object -FilterScript {$_.Name -in $($HostPools.Name)})
    Write-Verbose -Message "Getting HostPool(s): $($HostPools.Name -join, ', ')"
    $ResourceGroup = $HostPools | ForEach-Object { Get-AzResourceGroup $_.Id.split('/')[4]}
    #Alternative to get the Resource Group(s)
    #$ResourceGroup = Get-AzResourceGroup | Where-Object -FilterScript {($_.ResourceGroupName -match $($HostPools.Name -join "|"))
    #>
    $ResourceGroupName = $HostPools.ResourceGroupName
    Write-Verbose -Message "ResourceGroup Name(s): $($ResourceGroupName -join, ', ')"
    $ResourceGroup = Get-AzResourceGroup | Where-Object -FilterScript { ($_.ResourceGroupName -in $ResourceGroupName) }

    Write-Verbose -Message "Removing Azure Delete Lock (if any) on Resource Group(s): $($ResourceGroup.ResourceGroupName -join, ', ')"
    $ResourceGroup | Foreach-Object -Process { Get-AzResourceLock -ResourceGroupName $_.ResourceGroupName -AtScope | Where-Object -FilterScript { $_.Properties.level -eq 'CanNotDelete' } } | Remove-AzResourceLock -Force -ErrorAction Ignore

    #region Windows Credential Manager Cleanup
    Write-Verbose -Message "Removing Credentials from Windows Credential Manager"
    $StorageAccountName = ($ResourceGroup | Get-AzStorageAccount).StorageAccountName
    $Pattern = $StorageAccountName -join "|"
    $StorageAccountCredentials = cmdkey /list | Select-string -Pattern "(?<Target>Target: (?<Domain>Domain:target=(?<FQDN>(?<Pattern>$Pattern)\.file\.core\.windows\.net)))" -AllMatches
    if ($StorageAccountCredentials.Matches) {
        $StorageAccountCredentials.Matches | ForEach-Object -Process { 
            $FQDN = $_.Groups['FQDN']
            $Domain = $_.Groups['Domain']
            Write-Verbose -Message "'$FQDN' credentials will be removed from the Windows Credential Manager"
            Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /delete:$Domain" -Wait
        }
    }
    #endregion

    Write-Verbose -Message "Removing Resource Group(s) (As a Job): $($ResourceGroupName -join, ', ')"
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
    Write-Verbose -Message "Removing Dedicated HostPool Key Vault in removed state (As a Job)"
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
    #endregion

    #region Run a sync with Azure AD
    Start-MicrosoftEntraIDConnectSync
    #endregion
    $EndTime = Get-Date
    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host -Object "HostPool Removal Processing Time: $($TimeSpan.ToString())"
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function New-AzAvdPersonalHostPoolSetup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Name')]
        [object[]]$HostPool,

        [Parameter(Mandatory = $true)]
        [Alias('OU')]
        [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]$ADOrganizationalUnit,

        [Parameter(Mandatory = $false)]
        [string]$LogDir = ".",

        [switch] $AsJob
    )

    begin {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

        $StartTime = Get-Date
        $AzContext = Get-AzContext

        #region Variables
        $SKUName = "Standard_LRS"
        $CurrentHostPoolStorageAccountNameMaxLength = 24
        $CurrentHostPoolKeyVaultNameMaxLength = 24

        $ThisDomainController = Get-AzVMCompute | Get-AzVM
        # Get the VM's network interface
        $ThisDomainControllerNetworkInterfaceId = $ThisDomainController.NetworkProfile.NetworkInterfaces[0].Id
        $ThisDomainControllerNetworkInterface = Get-AzNetworkInterface -ResourceId $ThisDomainControllerNetworkInterfaceId
        # Get the subnet ID
        $ThisDomainControllerSubnetId = $ThisDomainControllerNetworkInterface.IpConfigurations[0].Subnet.Id
        $ThisDomainControllerSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $ThisDomainControllerSubnetId
        $split = $ThisDomainControllerSubnetId.split('/')
        # Get the vnet ID
        $ThisDomainControllerVirtualNetworkId = $split[0..($split.Count - 3)] -join "/"
        $ThisDomainControllerVirtualNetwork = Get-AzResource -ResourceId $ThisDomainControllerVirtualNetworkId | Get-AzVirtualNetwork

        #$DomainName = (Get-ADDomain).DNSRoot
        $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        #endregion 

    }
    process {
        Foreach ($CurrentHostPool in $HostPool) {
            Write-Host -Object "Starting '$($CurrentHostPool.Name)' Setup"
            $CurrentHostPoolStartTime = Get-Date
            $Status = @{ $true = "Enabled"; $false = "Disabled" }
            $Tag = @{HostPoolName = $CurrentHostPool.Name; HostPoolType = [HostPoolType]::Personal; Intune = $Status[$CurrentHostPool.Intune]; CreationTime = [datetime]::Now; CreatedBy = (Get-AzContext).Account.Id; EphemeralODisk = $CurrentHostPool.DiffDiskPlacement}
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

            #region Creating an <Azure Location> OU 
            $LocationOU = Get-ADOrganizationalUnit -Filter "Name -eq '$($CurrentHostPool.Location)'" -SearchBase $ADOrganizationalUnit.DistinguishedName
            if (-not($LocationOU)) {
                $LocationOU = New-ADOrganizationalUnit -Name $CurrentHostPool.Location -Path $ADOrganizationalUnit.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "Creating '$($LocationOU.DistinguishedName)' OU (under '$($ADOrganizationalUnit.DistinguishedName)')"
            }
            #endregion

            #region Creating an PersonalDesktops OU 
            $PersonalDesktopsOU = Get-ADOrganizationalUnit -Filter 'Name -eq "PersonalDesktops"' -SearchBase $LocationOU.DistinguishedName
            if (-not($PersonalDesktopsOU)) {
                $PersonalDesktopsOU = New-ADOrganizationalUnit -Name "PersonalDesktops" -Path $LocationOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "Creating '$($PersonalDesktopsOU.DistinguishedName)' OU (under '$($LocationOU.DistinguishedName)')"
            }
            #endregion

            #region General AD Management
            #region Host Pool Management: Dedicated AD OU Setup (1 OU per HostPool)
            $CurrentHostPoolOU = Get-ADOrganizationalUnit -Filter "Name -eq '$($CurrentHostPool.Name)'" -SearchBase $PersonalDesktopsOU.DistinguishedName
            if (-not($CurrentHostPoolOU)) {
                $CurrentHostPoolOU = New-ADOrganizationalUnit -Name "$($CurrentHostPool.Name)" -Path $PersonalDesktopsOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "Creating '$($CurrentHostPoolOU.DistinguishedName)' OU (under '$($PersonalDesktopsOU.DistinguishedName)')"
            }
            #endregion

            #region Host Pool Management: Dedicated AD users group
            $CurrentHostPoolDAGUsersAzADGroupName = "$($CurrentHostPool.Name) - Desktop Application Group Users"
            $CurrentHostPoolDAGUsersADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolDAGUsersAzADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
            if (-not($CurrentHostPoolDAGUsersADGroup)) {
                Write-Verbose -Message "Creating '$CurrentHostPoolDAGUsersAzADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
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
                Write-Verbose -Message "Creating '$CurrentHostPoolResourceGroupName' Resource Group"
                $CurrentHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Force
            }
            #endregion

            #region Identity Provider Management
            if ($CurrentHostPool.IsActiveDirectoryJoined()) {
                $AdJoinUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name AdJoinUserName -AsPlainText
                $AdJoinPassword = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name AdJoinPassword).SecretValue
                $AdJoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($AdJoinUserName, $AdJoinPassword)
                Grant-ADJoinPermission -Credential $AdJoinCredential -OrganizationalUnit $CurrentHostPoolOU.DistinguishedName
                $Tag['IdentityProvider'] = "Active Directory Directory Services"
            }
            else {
                $Tag['IdentityProvider'] = "Microsoft Entra ID"
                #region Assign Virtual Machine Administrator Login' RBAC role to the Resource Group
                # Get the object ID of the user group you want to assign to the application group
                Do {
                    Start-MicrosoftEntraIDConnectSync
                    Write-Verbose -Message "Sleeping 30 seconds"
                    Start-Sleep -Seconds 30
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolDAGUsersAzADGroupName
                } While (-not($AzADGroup.Id))

                # Assign users to the application group
                $parameters = @{
                    ObjectId           = $AzADGroup.Id
                    ResourceGroupName  = $CurrentHostPoolResourceGroupName
                    RoleDefinitionName = 'Virtual Machine Administrator Login'
                    #Verbose            = $true
                }

                Write-Verbose -Message "Assigning the 'Virtual Machine Administrator Login' RBAC role to '$CurrentHostPoolDAGUsersAzADGroupName' AD Group on the '$CurrentHostPoolResourceGroupName' Resource Group"
                $null = New-AzRoleAssignment @parameters
                #endregion 

            }
            #endregion 

            #region Key Vault
            #region Key Vault Name Setup
            $CurrentHostPoolKeyVaultName = $CurrentHostPool.GetKeyVaultName()
            $CurrentHostPoolKeyVaultName = $CurrentHostPoolKeyVaultName.Substring(0, [system.math]::min($CurrentHostPoolKeyVaultNameMaxLength, $CurrentHostPoolKeyVaultName.Length)).ToLower()
            $CurrentHostPoolKeyVaultName = $CurrentHostPoolKeyVaultName.ToLower()
            #endregion 

            #region Dedicated Key Vault Setup
            $CurrentHostPoolKeyVault = Get-AzKeyVault -VaultName $CurrentHostPoolKeyVaultName -ErrorAction Ignore
            if (-not($CurrentHostPoolKeyVault)) {
                if (-not(Test-AzKeyVaultNameAvailability -Name $CurrentHostPoolKeyVaultName).NameAvailable) {
                    Stop-Transcript
                    Write-Error "The key vault name '$CurrentHostPoolKeyVaultName' is not available !" -ErrorAction Stop
                }
                Write-Verbose -Message "Creating '$CurrentHostPoolKeyVaultName' Key Vault (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                $CurrentHostPoolKeyVault = New-AzKeyVault -ResourceGroupName $CurrentHostPoolResourceGroupName -VaultName $CurrentHostPoolKeyVaultName -Location $ThisDomainControllerVirtualNetwork.Location -EnabledForDiskEncryption -SoftDeleteRetentionInDays 7 -DisableRbacAuthorization
            }
            #endregion

            #region Private endpoint for Key Vault Setup
            #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
            #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
            ## Create the private endpoint connection. ## 

            $PrivateEndpointName = "pep{0}" -f $($CurrentHostPoolKeyVaultName -replace "\W")
            $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $CurrentHostPoolKeyVault.ResourceId).GroupId
            $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $CurrentHostPoolKeyVault.ResourceId -GroupId $GroupId
            Write-Verbose -Message "Creating the Private Endpoint for the Key Vault '$CurrentHostPoolKeyVaultName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -Subnet $ThisDomainControllerSubnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

            ## Create the private DNS zone. ##
            $PrivateDnsZoneName = 'privatelink.vaultcore.azure.net'
            $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
            if ($null -eq $PrivateDnsZone) {
                Write-Verbose -Message "Creating the Private DNS Zone for the Key Vault '$CurrentHostPoolKeyVaultName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
            }

            $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
            $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
            if ($null -eq $PrivateDnsVirtualNetworkLink) {
                $ThisDomainControllerVirtualNetworkId = [string]::Join("/", $split[0..($split.Count - 3)])
                ## Create a DNS network link. ##
                Write-Verbose -Message "Creating the Private DNS VNet Link for the Key Vault '$CurrentHostPoolKeyVaultName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
            }


            ## Configure the DNS zone. ##
            Write-Verbose -Message "Creating the DNS Zone Configuration of the Private Dns Zone Group for Key Vault '$CurrentHostPoolKeyVaultName'"
            $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

            ## Create the DNS zone group. ##
            Write-Verbose -Message "Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $CurrentHostPoolResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force

            #Key Vault - Disabling Public Access
            Write-Verbose -Message "Disabling the Public Access for the Key Vault'$CurrentHostPoolKeyVaultName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $null = Update-AzKeyVault -VaultName $CurrentHostPoolKeyVaultName -ResourceGroupName $CurrentHostPoolResourceGroupName -PublicNetworkAccess "Disabled" 
            #endregion

            #endregion

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
                LoadBalancerType              = 'Persistent'
                PreferredAppGroupType         = 'Desktop'
                Location                      = $CurrentHostPool.Location
                StartVMOnConnect              = $true
                ExpirationTime                = $RegistrationInfoExpirationTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
                CustomRdpProperty             = $CustomRdpProperty
                Tag                           = $Tag
                #Verbose                       = $true
            }

            Write-Verbose -Message "Creating the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $CurrentAzWvdHostPool = New-AzWvdHostPool @parameters
            Write-Verbose -Message "Creating Registration Token (Expiration: '$RegistrationInfoExpirationTime') for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
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
                ResourceGroupName    = $CurrentHostPoolResourceGroupName
                Location             = $CurrentHostPool.Location
                HostPoolArmPath      = $CurrentAzWvdHostPool.Id
                ApplicationGroupType = 'Desktop'
                ShowInFeed           = $true
                #Verbose              = $true
            }

            Write-Verbose -Message "Creating the Desktop Application Group for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $CurrentAzDesktopApplicationGroup = New-AzWvdApplicationGroup @parameters

            Write-Verbose -Message "Updating the friendly name of the Desktop for the Desktop Application Group of the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) to 'Full Desktop'"
            $parameters = @{
                ApplicationGroupName = $CurrentAzDesktopApplicationGroup.Name
                ResourceGroupName    = $CurrentHostPoolResourceGroupName
            }
            $null = Get-AzWvdDesktop @parameters | Update-AzWvdDesktop -FriendlyName "Full Desktop"

            #region Assign 'Desktop Virtualization User RBAC role to application groups
            # Get the object ID of the user group you want to assign to the application group
            Do {
                Start-MicrosoftEntraIDConnectSync
                Write-Verbose -Message "Sleeping 30 seconds"
                Start-Sleep -Seconds 30
                $AzADGroup = $null
                $AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolDAGUsersAzADGroupName
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

            Write-Verbose -Message "Assigning the 'Desktop Virtualization User' RBAC role to '$CurrentHostPoolDAGUsersAzADGroupName' AD Group on the Desktop Application Group (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $null = New-AzRoleAssignment @parameters
            #endregion 

            #endregion

            #region Workspace Setup
            $Options = $CurrentHostPool.Type, $CurrentHostPool.IdentityProvider
            if ($CurrentHostPool.VMSourceImageId) {
                $Options += 'Azure Compte Gallery'
            }
            else {
                $Options += 'Market Place'
            }
            if ($CurrentHostPool.Intune) {
                $Options += 'Intune'
            }
            if ($CurrentHostPool.DiffDiskPlacement -eq [DiffDiskPlacement]::CacheDisk) {
                $Options += 'Ephemeral OS Disk: CacheDisk'
            }
            elseif ($CurrentHostPool.DiffDiskPlacement -eq [DiffDiskPlacement]::ResourceDisk) {
                $Options += 'Ephemeral OS Disk: ResourceDisk'
            } 
            $FriendlyName = "{0} ({1})" -f $CurrentHostPool.GetAzAvdWorkSpaceName(), $($Options -join ', ')
            $parameters = @{
                Name                      = $CurrentHostPool.GetAzAvdWorkSpaceName()
                FriendlyName              = $FriendlyName
                ResourceGroupName         = $CurrentHostPoolResourceGroupName
                ApplicationGroupReference = $CurrentAzDesktopApplicationGroup.Id
                Location                  = $CurrentHostPool.Location
                #Verbose                   = $true
            }

            Write-Verbose -Message "Creating the WorkSpace for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $CurrentAzWvdWorkspace = New-AzWvdWorkspace @parameters
            #endregion

            #region Adding Session Hosts to the Host Pool
            if (-not([String]::IsNullOrEmpty($CurrentHostPool.VMSourceImageId))) {
                #We propagate the AsJob context to the child function
                Add-AzAvdSessionHost -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentHostPool.NamePrefix -VMNumberOfInstances $CurrentHostPool.VMNumberOfInstances -KeyVault $CurrentHostPool.KeyVault -RegistrationInfoToken $RegistrationInfoToken.Token -DomainName $DomainName -OUPath $CurrentHostPoolOU.DistinguishedName -VMSize $CurrentHostPool.VMSize -VMSourceImageId $CurrentHostPool.VMSourceImageId -DiffDiskPlacement $CurrentHostPool.DiffDiskPlacement -Tag $Tag -IsMicrosoftEntraIdJoined:$CurrentHostPool.IsMicrosoftEntraIdJoined() -Spot:$CurrentHostPool.Spot -HibernationEnabled:$CurrentHostPool.HibernationEnabled -Intune:$CurrentHostPool.Intune -LogDir $LogDir -AsJob #:$AsJob
            }
            else {
                #We propagate the AsJob context to the child function
                Add-AzAvdSessionHost -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentHostPool.NamePrefix -VMNumberOfInstances $CurrentHostPool.VMNumberOfInstances -KeyVault $CurrentHostPool.KeyVault -RegistrationInfoToken $RegistrationInfoToken.Token -DomainName $DomainName -OUPath $CurrentHostPoolOU.DistinguishedName -VMSize $CurrentHostPool.VMSize -DiffDiskPlacement $CurrentHostPool.DiffDiskPlacement -ImagePublisherName $CurrentHostPool.ImagePublisherName -ImageOffer $CurrentHostPool.ImageOffer -ImageSku $CurrentHostPool.ImageSku -Tag $Tag -IsMicrosoftEntraIdJoined:$CurrentHostPool.IsMicrosoftEntraIdJoined() -Spot:$CurrentHostPool.Spot -HibernationEnabled:$CurrentHostPool.HibernationEnabled -Intune:$CurrentHostPool.Intune -LogDir $LogDir -AsJob #:$AsJob
            }
            $SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            $SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
            #endregion 

            if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
                    #region Creating a dynamic device group for our AVD hosts
                    $DisplayName = "{0} - Devices" -f $CurrentHostPool.Name
                    $Description = "Dynamic device group for our AVD hosts for the {0} HostPool." -f $CurrentHostPool.Name
                    $MailNickname = $($DisplayName -replace "\s").ToLower()
                    $MembershipRule = "(device.displayName -startsWith ""$($CurrentHostPool.NamePrefix)-"")"
                    $AzADDeviceDynamicGroup = New-AzADGroup -DisplayName $DisplayName -Description $Description -MembershipRule $MembershipRule -MembershipRuleProcessingState "On" -GroupType "DynamicMembership" -MailNickname $MailNickname -SecurityEnabled
                    #endregion
            }

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
            Write-Verbose -Message "Creating the Log Analytics WorkSpace '$($LogAnalyticsWorkSpaceName)' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $LogAnalyticsWorkSpace = New-AzOperationalInsightsWorkspace -Location $CurrentHostPool.Location -Name $LogAnalyticsWorkSpaceName -Sku pergb2018 -ResourceGroupName $CurrentHostPoolResourceGroupName -Force
            Do {
                Write-Verbose -Message "Sleeping 10 seconds"
                Start-Sleep -Seconds 10
                $LogAnalyticsWorkSpace = $null
                $LogAnalyticsWorkSpace = Get-AzOperationalInsightsWorkspace -Name $LogAnalyticsWorkSpaceName -ResourceGroupName $CurrentHostPoolResourceGroupName
            } While ($null -eq $LogAnalyticsWorkSpace)
            Write-Verbose -Message "Sleeping 30 seconds"
            Start-Sleep -Seconds 30
            #region Enabling Diagnostics Setting for the HostPool
            Write-Verbose -Message "Enabling Diagnostics Setting for the '$($CurrentAzWvdHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $Categories = "Checkpoint", "Error", "Management", "Connection", "HostRegistration", "AgentHealthStatus"
            $Log = $Categories | ForEach-Object {
                New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category $_ 
            }
            $HostPoolDiagnosticSetting = New-AzDiagnosticSetting -Name $CurrentAzWvdHostPool.Name -ResourceId $CurrentAzWvdHostPool.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Log $Log
            #endregion

            #region Enabling Diagnostics Setting for the WorkSpace
            Write-Verbose -Message "Enabling Diagnostics Setting for the  '$($CurrentAzWvdWorkspace.Name)' Work Space"
            <#
            $Categories = "Checkpoint", "Error", "Management", "Feed"
            $Log = $Categories | ForEach-Object {
                New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category $_ 
            }
            #>
            $Log = New-AzDiagnosticSettingLogSettingsObject -Enabled $true -CategoryGroup allLogs 
            $WorkSpaceDiagnosticSetting = New-AzDiagnosticSetting -Name $CurrentAzWvdWorkspace.Name -ResourceId $CurrentAzWvdWorkspace.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Log $Log
            #endregion
            #endregion

            #region Installing Azure Monitor Windows Agent on Virtual Machine(s)
            #$SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            if (-not([string]::IsNullOrEmpty($SessionHosts.ResourceId))) {
                $SessionHostVMs = $SessionHosts.ResourceId | Get-AzVM
                $Jobs = foreach ($CurrentSessionHostVM in $SessionHostVMs) {
                    Write-Verbose -Message "Installing AzureMonitorWindowsAgent on the '$($CurrentSessionHostVM.Name)' Virtual Machine (in the '$CurrentHostPoolResourceGroupName' Resource Group) (As A Job)"
                    $ExtensionName = "AzureMonitorWindowsAgent_$("{0:yyyyMMddHHmmss}" -f (Get-Date))"
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
                Write-Verbose -Message "Waiting all jobs completes"
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
                    Write-Verbose -Message "Installing Log Analytics Agent on the '$($CurrentSessionHostVM.Name)' Virtual Machine (in the '$CurrentHostPoolResourceGroupName' Resource Group) (As A Job)"
                    Set-AzVMExtension -ExtensionName "MicrosoftMonitoringAgent" -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostVM.Name -Publisher "Microsoft.EnterpriseCloud.Monitoring" -ExtensionType "MicrosoftMonitoringAgent" -Settings $PublicSettings -TypeHandlerVersion "1.0" -ProtectedSettings $ProtectedSettings -Location $CurrentHostPool.Location -AsJob
<                }
                Write-Verbose -Message "Waiting all jobs completes"
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
                [PSCustomObject] @{EventLogName = 'Application'; Levels = 1,2,3 }
                [PSCustomObject] @{EventLogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Levels = 1,2,3 }
                [PSCustomObject] @{EventLogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin'; Levels = 1,2,3 }
                [PSCustomObject] @{EventLogName = 'System'; Levels = 2,3 }
                [PSCustomObject] @{EventLogName = 'Microsoft-FSLogix-Apps/Operational' ; Levels = 1,2,3 }
                [PSCustomObject] @{EventLogName = 'Microsoft-FSLogix-Apps/Admin' ; Levels = 1,2,3 }
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

            $PerformanceCounters = foreach ($CurrentKey in $PerformanceCountersHT.Keys)
            {
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
            $DataCollectionRuleName = "dcr-{0}" -f $LogAnalyticsWorkSpace.Name
            $DataFlow = New-AzDataFlowObject -Stream Microsoft-Perf, Microsoft-Event -Destination $LogAnalyticsWorkSpace.Name
            $DestinationLogAnalytic = New-AzLogAnalyticsDestinationObject -Name $LogAnalyticsWorkSpace.Name -WorkspaceResourceId $LogAnalyticsWorkSpace.ResourceId
            $DataCollectionRule = New-AzDataCollectionRule -Name $DataCollectionRuleName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Dataflow $DataFlow -DataSourcePerformanceCounter $PerformanceCounters -DataSourceWindowsEventLog $WindowsEventLogs -DestinationLogAnalytic $DestinationLogAnalytic #-DataCollectionEndpointId $DataCollectionEndpoint.Id
            #endregion

            #region Adding Data Collection Rule Association for every Session Host
            #$DataCollectionRule = Get-AzDataCollectionRule -ResourceGroupName $CurrentHostPoolResourceGroupName -RuleName $DataCollectionRuleName
            $DataCollectionRuleAssociations = foreach ($CurrentSessionHost in $SessionHosts) {
                <#
                $AssociationName = 'configurationAccessEndpoint'
                Write-Verbose -Message "Associating the '$($DataCollectionEndpoint.Name)' Data Collection Endpoint with the '$($CurrentSessionHost.Name)' Session Host "
                Write-Verbose -Message "`$AssociationName: $AssociationName"
                New-AzDataCollectionRuleAssociation -ResourceUri $CurrentSessionHost.ResourceId -AssociationName $AssociationName #-DataCollectionEndpointId $DataCollectionEndpoint.Id
                #>
                $AssociationName = "dcr-{0}" -f $($CurrentSessionHost.ResourceId -replace ".*/").ToLower()
                Write-Verbose -Message "Associating the '$($DataCollectionRule.Name)' Data Collection Rule with the '$($CurrentSessionHost.Name)' Session Host "
                Write-Verbose -Message "`$AssociationName: $AssociationName"
                New-AzDataCollectionRuleAssociation -ResourceUri $CurrentSessionHost.ResourceId -AssociationName $AssociationName -DataCollectionRuleId $DataCollectionRule.Id
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
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    }
}

function New-AzAvdPooledHostPoolSetup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Name')]
        [object[]]$HostPool,

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
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

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
        $CurrentHostPoolStorageAccountNameMaxLength = 24
        $CurrentHostPoolKeyVaultNameMaxLength = 24

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

        $ThisDomainController = Get-AzVMCompute | Get-AzVM
        # Get the VM's network interface
        $ThisDomainControllerNetworkInterfaceId = $ThisDomainController.NetworkProfile.NetworkInterfaces[0].Id
        $ThisDomainControllerNetworkInterface = Get-AzNetworkInterface -ResourceId $ThisDomainControllerNetworkInterfaceId
        # Get the subnet ID
        $ThisDomainControllerSubnetId = $ThisDomainControllerNetworkInterface.IpConfigurations[0].Subnet.Id
        $ThisDomainControllerSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $ThisDomainControllerSubnetId
        $split = $ThisDomainControllerSubnetId.split('/')
        # Get the vnet ID
        $ThisDomainControllerVirtualNetworkId = $split[0..($split.Count - 3)] -join "/"
        $ThisDomainControllerVirtualNetwork = Get-AzResource -ResourceId $ThisDomainControllerVirtualNetworkId | Get-AzVirtualNetwork

        #$DomainName = (Get-ADDomain).DNSRoot
        #$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        $DomainInformation = Get-ADDomain
        $DomainGuid = $DomainInformation.ObjectGUID.ToString()
        $DomainName = $DomainInformation.DnsRoot
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

            $Status = @{ $true = "Enabled"; $false = "Disabled" }
            $Tag = @{MSIX = $Status[$CurrentHostPool.MSIX]; FSLogix = $Status[$CurrentHostPool.FSLogix]; Intune = $Status[$CurrentHostPool.Intune]; HostPoolName = $CurrentHostPool.Name; HostPoolType = [HostPoolType]::Pooled; CreationTime = [datetime]::Now; CreatedBy = (Get-AzContext).Account.Id; EphemeralODisk = $CurrentHostPool.DiffDiskPlacement }
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

            #region Creating an <Azure Location> OU 
            $LocationOU = Get-ADOrganizationalUnit -Filter "Name -eq '$($CurrentHostPool.Location)'" -SearchBase $ADOrganizationalUnit.DistinguishedName
            if (-not($LocationOU)) {
                $LocationOU = New-ADOrganizationalUnit -Name $CurrentHostPool.Location -Path $ADOrganizationalUnit.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "Creating '$($LocationOU.DistinguishedName)' OU (under '$($ADOrganizationalUnit.DistinguishedName)')"
            }
            #endregion

            #region Creating a PooledDesktops OU 
            $PooledDesktopsOU = Get-ADOrganizationalUnit -Filter 'Name -eq "PooledDesktops"' -SearchBase $LocationOU.DistinguishedName
            if (-not($PooledDesktopsOU)) {
                $PooledDesktopsOU = New-ADOrganizationalUnit -Name "PooledDesktops" -Path $LocationOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "Creating '$($PooledDesktopsOU.DistinguishedName)' OU (under '$($LocationOU.DistinguishedName)')"
            }
            #endregion

            #region General AD Management
            #region Host Pool Management: Dedicated AD OU Setup (1 OU per HostPool)
            $CurrentHostPoolOU = Get-ADOrganizationalUnit -Filter "Name -eq '$($CurrentHostPool.Name)'" -SearchBase $PooledDesktopsOU.DistinguishedName
            if (-not($CurrentHostPoolOU)) {
                $CurrentHostPoolOU = New-ADOrganizationalUnit -Name "$($CurrentHostPool.Name)" -Path $PooledDesktopsOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "Creating '$($CurrentHostPoolOU.DistinguishedName)' OU (under '$($PooledDesktopsOU.DistinguishedName)')"
            }
            #endregion

            #region Host Pool Management: Dedicated AD users group
            $CurrentHostPoolDAGUsersAzADGroupName = "$($CurrentHostPool.Name) - Desktop Application Group Users"
            $CurrentHostPoolDAGUsersADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolDAGUsersAzADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
            if (-not($CurrentHostPoolDAGUsersADGroup)) {
                Write-Verbose -Message "Creating '$CurrentHostPoolDAGUsersAzADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                $CurrentHostPoolDAGUsersADGroup = New-ADGroup -Name $CurrentHostPoolDAGUsersAzADGroupName -SamAccountName $CurrentHostPoolDAGUsersAzADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolDAGUsersAzADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
            }

            $CurrentHostPoolRAGUsersADGroupName = "$($CurrentHostPool.Name) - Remote Application Group Users"
            $CurrentHostPoolRAGUsersADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolRAGUsersADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
            if (-not($CurrentHostPoolRAGUsersADGroup)) {
                Write-Verbose -Message "Creating '$CurrentHostPoolRAGUsersADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
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
                    Write-Verbose -Message "Creating '$($CurrentHostPoolFSLogixContributorADGroup.Name)' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                }
                Write-Verbose -Message "Adding the '$CurrentHostPoolDAGUsersAzADGroupName' AD group to the '$CurrentHostPoolFSLogixContributorADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                $CurrentHostPoolFSLogixContributorADGroup | Add-ADGroupMember -Members $CurrentHostPoolDAGUsersAzADGroupName

                $CurrentHostPoolFSLogixElevatedContributorADGroupName = "$($CurrentHostPool.Name) - $FSLogixElevatedContributor"
                $CurrentHostPoolFSLogixElevatedContributorADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolFSLogixElevatedContributorADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolFSLogixElevatedContributorADGroup)) {
                    $CurrentHostPoolFSLogixElevatedContributorADGroup = New-ADGroup -Name $CurrentHostPoolFSLogixElevatedContributorADGroupName -SamAccountName $CurrentHostPoolFSLogixElevatedContributorADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolFSLogixElevatedContributorADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                    Write-Verbose -Message "Creating '$($CurrentHostPoolFSLogixElevatedContributorADGroup.Name)' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                }

                $CurrentHostPoolFSLogixReaderADGroupName = "$($CurrentHostPool.Name) - $FSLogixReader"
                $CurrentHostPoolFSLogixReaderADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolFSLogixReaderADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolFSLogixReaderADGroup)) {
                    $CurrentHostPoolFSLogixReaderADGroup = New-ADGroup -Name $CurrentHostPoolFSLogixReaderADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolFSLogixReaderADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                    Write-Verbose -Message "Creating '$($CurrentHostPoolFSLogixReaderADGroup.Name)' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
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
                $CurrentHostPoolStorageAccountName = $CurrentHostPoolStorageAccountName.Substring(0, [system.math]::min($CurrentHostPoolStorageAccountNameMaxLength, $CurrentHostPoolStorageAccountName.Length)).ToLower()
                #endregion 

                #region Dedicated Host Pool AD GPO Management (1 GPO per Host Pool for setting up the dedicated VHDLocations/CCDLocations value)
                if ($CurrentHostPool.IsActiveDirectoryJoined()) {
                    $CurrentHostPoolFSLogixGPO = Get-GPO -Name "$($CurrentHostPool.Name) - FSLogix Settings" -ErrorAction Ignore
                    if (-not($CurrentHostPoolFSLogixGPO)) {
                        $CurrentHostPoolFSLogixGPO = New-GPO -Name "$($CurrentHostPool.Name) - FSLogix Settings"
                        Write-Verbose -Message "Creating '$($CurrentHostPoolFSLogixGPO.DisplayName)' GPO (linked to '($($CurrentHostPoolOU.DistinguishedName))'"
                    }
                    $null = $CurrentHostPoolFSLogixGPO | New-GPLink -Target $CurrentHostPoolOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore

                    #region FSLogix GPO Management: Dedicated GPO settings for FSLogix profiles for this HostPool 
                    #From https://learn.microsoft.com/en-us/fslogix/tutorial-configure-profile-containers#profile-container-configuration
                    Write-Verbose -Message "Setting some 'FSLogix' related registry values for '$($CurrentHostPoolFSLogixGPO.DisplayName)' GPO (linked to '$($PooledDesktopsOU.DistinguishedName)' OU)"
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "DeleteLocalProfileWhenVHDShouldApply" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "FlipFlopProfileDirectoryName" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LockedRetryCount" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 3
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LockedRetryInterval" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 15
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ProfileType" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ReAttachIntervalSeconds" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 15
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ReAttachRetryCount" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 3
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "SizeInMBs" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 30000

                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "PreventLoginWithFailure" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "PreventLoginWithTempProfile" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "VolumeType" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "VHDX"
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LogFileKeepingPeriod" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 10
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "IsDynamic" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1

                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "VHDLocations" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"
                    #Use Redirections.xml. Be careful : https://twitter.com/JimMoyle/status/1247843511413755904w
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "RedirXMLSourceFolder" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"

                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-automatic-updates
                    #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.WindowsUpdate::AutoUpdateCfg
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName "NoAutoUpdate" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#set-up-time-zone-redirection
                    #From https://admx.help/?Category=VMware_Horizon&Policy=VMware.Policies.Cascadia::CASCADIA_TIME_ZONE
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fEnableTimeZoneRedirection" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-storage-sense
                    #$null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -ValueName "01" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
                    #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.StorageSense::SS_AllowStorageSenseGlobal
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\StorageSense' -ValueName "AllowStorageSenseGlobal" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0

                    #region GPO Debug log file
                    #From https://blog.piservices.fr/post/2017/12/21/active-directory-debug-avance-de-l-application-des-gpos
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics' -ValueName "GPSvcDebugLevel" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0x30002
                    #endregion

                    #region Microsoft Defender Endpoint A/V General Exclusions (the *.VHD and *.VHDX exclusions applies to FSLogix and MSIX) 
                    #From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
                    Write-Verbose -Message "Setting some 'Microsoft Defender Endpoint A/V Exclusions for this HostPool' related registry values for '$($CurrentHostPoolFSLogixGPO.DisplayName)' GPO (linked to '$($CurrentHostPoolOU.DistinguishedName)' OU)"
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -ValueName "Exclusions_Paths" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%TEMP%\*\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%TEMP%\*\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%Windir%\TEMP\*\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%Windir%\TEMP\*\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramData%\FSLogix\Cache\*" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramData%\FSLogix\Proxy\*" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramFiles%\FSLogix\Apps\frxdrv.sys" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramFiles%\FSLogix\Apps\frxdrvvt.sys" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramFiles%\FSLogix\Apps\frxccd.sys" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0

                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.lock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.meta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.metadata" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.lock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.meta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.metadata" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.CIM" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0

                    #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.WindowsDefender::Exclusions_Processesget-job
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -ValueName "Exclusions_Processes" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -ValueName "%ProgramFiles%\FSLogix\Apps\frxccd.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -ValueName "%ProgramFiles%\FSLogix\Apps\frxccds.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -ValueName "%ProgramFiles%\FSLogix\Apps\frxsvc.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -ValueName "%ProgramFiles%\FSLogix\Apps\frxrobocopy.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    #endregion
                    <#
                    Write-Verbose -Message "Setting some 'FSLogix' related registry values for '$($CurrentHostPoolFSLogixGPO.DisplayName)' GPO (linked to '$($CurrentHostPoolOU.DistinguishedName)' OU)"
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "VHDLocations" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"
                    #Use Redirections.xml. Be careful : https://twitter.com/JimMoyle/status/1247843511413755904w
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "RedirXMLSourceFolder" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"
                    #>
                    #endregion 

                    #region GPO "Local Users and Groups" Management via groups.xml
                    #From https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/37722b69-41dd-4813-8bcd-7a1b4d44a13d
                    #From https://jans.cloud/2019/08/microsoft-fslogix-profile-container/
                    $GroupXMLGPOFilePath = "\\{0}\SYSVOL\{0}\Policies\{{{1}}}\Machine\Preferences\Groups\Groups.xml" -f $DomainName, $($CurrentHostPoolFSLogixGPO.Id)
                    Write-Verbose -Message "Creating '$GroupXMLGPOFilePath'"
                    #Generating an UTC time stamp
                    $Changed = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
                    #$ADGroupToExcludeFromFSLogix = @('Domain Admins', 'Enterprise Admins')
                    $ADGroupToExcludeFromFSLogix = @('Domain Admins')
                    $Members = foreach ($CurrentADGroupToExcludeFromFSLogix in $ADGroupToExcludeFromFSLogix) {
                        $CurrentADGroupToExcludeFromFSLogixSID = (Get-ADGroup -Filter "Name -eq '$CurrentADGroupToExcludeFromFSLogix'").SID.Value
                        if (-not([string]::IsNullOrEmpty($CurrentADGroupToExcludeFromFSLogixSID))) {
                            Write-Verbose -Message "Excluding '$CurrentADGroupToExcludeFromFSLogix' from '$GroupXMLGPOFilePath'"
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
                    Write-Verbose -Message "Processing '$GPTINIGPOFilePath'"
                    $result = Select-string -Pattern "(Version)=(\d+)" -AllMatches -Path $GPTINIGPOFilePath
                    #Getting current version
                    [int]$VersionNumber = $result.Matches.Groups[-1].Value
                    Write-Verbose -Message "Version Number: $VersionNumber"
                    #Increasing current version
                    $VersionNumber += 2
                    Write-Verbose -Message "New Version Number: $VersionNumber"
                    #Updating file
                    (Get-Content $GPTINIGPOFilePath -Encoding UTF8) -replace "(Version)=(\d+)", "`$1=$VersionNumber" | Set-Content $GPTINIGPOFilePath -Encoding UTF8
                    Write-Verbose -Message $(Get-Content $GPTINIGPOFilePath -Encoding UTF8 | Out-String)
                    #endregion 

                    #region gPCmachineExtensionNames Management
                    #From https://www.infrastructureheroes.org/microsoft-infrastructure/microsoft-windows/guid-list-of-group-policy-client-extensions/
                    #[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]
                    #[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]
                    Write-Verbose -Message "Processing gPCmachineExtensionNames Management"
                    $gPCmachineExtensionNamesToAdd = "[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]"
                    $RegExPattern = $gPCmachineExtensionNamesToAdd -replace "(\W)" , '\$1'
                    $GPOADObject = Get-ADObject -LDAPFilter "CN={$($CurrentHostPoolFSLogixGPO.Id.Guid)}" -Properties gPCmachineExtensionNames
                    #if (-not($GPOADObject.gPCmachineExtensionNames.StartsWith($gPCmachineExtensionNamesToAdd)))
                    if ($GPOADObject.gPCmachineExtensionNames -notmatch $RegExPattern) {
                        $GPOADObject | Set-ADObject -Replace @{gPCmachineExtensionNames = $($gPCmachineExtensionNamesToAdd + $GPOADObject.gPCmachineExtensionNames) }
                        #Get-ADObject -LDAPFilter "CN={$($CurrentHostPoolFSLogixGPO.Id.Guid)}" -Properties gPCmachineExtensionNames
                    }
                    #endregion
                }
                #endregion 

                #region Dedicated Resource Group Management (1 per HostPool)
                $CurrentHostPoolResourceGroupName = $CurrentHostPool.GetResourceGroupName()

                $CurrentHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -ErrorAction Ignore
                if (-not($CurrentHostPoolResourceGroup)) {
                    $CurrentHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Force
                    Write-Verbose -Message "Creating '$($CurrentHostPoolResourceGroup.ResourceGroupName)' Resource Group"
                }
                #endregion

                #region Dedicated Storage Account Setup
                $CurrentHostPoolStorageAccount = Get-AzStorageAccount -Name $CurrentHostPoolStorageAccountName -ResourceGroupName $CurrentHostPoolResourceGroupName -ErrorAction Ignore
                if (-not($CurrentHostPoolStorageAccount)) {
                    if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentHostPoolStorageAccountName).NameAvailable) {
                        Stop-Transcript
                        Write-Error "The storage account name '$CurrentHostPoolStorageAccountName' is not available !" -ErrorAction Stop
                    }
                    $CurrentHostPoolStorageAccount = New-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName -Location $ThisDomainControllerVirtualNetwork.Location -SkuName $SKUName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true
                    Write-Verbose -Message "Creating '$($CurrentHostPoolStorageAccount.StorageAccountName)' Storage Account (in the '$($CurrentHostPoolStorageAccount.ResourceGroupName)' Resource Group)"
                }
                #Registering the Storage Account with your active directory environment under the target
                if ($CurrentHostPool.IsActiveDirectoryJoined()) {
                    if (-not(Get-ADComputer -Filter "Name -eq '$CurrentHostPoolStorageAccountName'" -SearchBase $CurrentHostPoolOU.DistinguishedName)) {
                        if (-not(Get-Module -Name AzFilesHybrid -ListAvailable)) {
                            $AzFilesHybridZipName = 'AzFilesHybrid.zip'
                            $OutFile = Join-Path -Path $env:TEMP -ChildPath $AzFilesHybridZipName
                            Start-BitsTransfer https://github.com/Azure-Samples/azure-files-samples/releases/latest/download/AzFilesHybrid.zip -destination $OutFile
                            Expand-Archive -Path $OutFile -DestinationPath $env:TEMP\AzFilesHybrid -Force
                            Push-Location -Path $env:TEMP\AzFilesHybrid
                            .\CopyToPSPath.ps1
                            Pop-Location
                        }
                        Write-Verbose -Message "Registering the Storage Account '$CurrentHostPoolStorageAccountName' with your AD environment (under '$($CurrentHostPoolOU.DistinguishedName)') OU"
                        Import-Module AzFilesHybrid
                        $null = New-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -KeyName "kerb1"
                        $null = Join-AzStorageAccountForAuth -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -DomainAccountType "ComputerAccount" -OrganizationUnitDistinguishedName $CurrentHostPoolOU.DistinguishedName -Confirm:$false
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
                        $ServicePrincipal = Get-AzADServicePrincipal -Filter "DisplayName eq '[Storage Account] $CurrentHostPoolStorageAccountName.file.core.windows.net'"
                    } While ($null -eq $ServicePrincipal)

                    # Grant admin consent to the service principal for the app role
                    Set-AdminConsent -context $AzContext -applicationId $ServicePrincipal.AppId
                    #endregion

                    #region Disable multi-factor authentication on the storage account
                    #From https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-portal#disable-multi-factor-authentication-on-the-storage-account
                    $NoMFAEntraIDGroup = Get-AzADGroup -SearchString $NoMFAEntraIDGroupName
                    if (-not($NoMFAEntraIDGroup))
                    {
                        Write-Warning -Message "'$NoMFAEntraIDGroupName' Entra ID group not found for disabling the MFA for the '$($ServicePrincipal.DisplayName)' Service Principal."
                        #Creating the No MFA Entra ID Group
                        $NoMFAEntraIDGroup = New-NoMFAUserEntraIDGroup -NoMFAEntraIDGroupName $NoMFAEntraIDGroupName
                    }
                    Write-Verbose -Message "Adding the '$($ServicePrincipal.DisplayName)' Service Principal as member of the '$($NoMFAEntraIDGroup.DisplayName)' Microsoft Entra ID Group"
                    $null = Add-AzADGroupMember -TargetGroupObjectId $NoMFAEntraIDGroup.Id -MemberObjectId $ServicePrincipal.Id
                    #Creating the MFA Conditional Access Policy and excluding the No MFA Entra ID Group
                    $MFAForAllUsersConditionalAccessPolicy = New-MFAForAllUsersConditionalAccessPolicy -ExcludeGroupName $NoMFAEntraIDGroup.DisplayName
                    <#
                    Start-Process -FilePath "https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-portal#disable-multi-factor-authentication-on-the-storage-account"
                    Do {
                        $Response = Read-Host -Prompt "Did you disable multi-factor authentication on the storage account ? (Y/N)"

                    } While ($Response -ne "Y")
                    #>
                    #endregion

                    #region Configure the clients to retrieve Kerberos tickets
                    #From https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-portal#configure-the-clients-to-retrieve-kerberos-tickets
                    #endregion
                }

                $CurrentHostPoolStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }

                # Save the password so the drive 
                Write-Verbose -Message "Saving the credentials for accessing to the Storage Account '$CurrentHostPoolStorageAccountName' in the Windows Credential Manager"
                Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "cmdkey /add:`"$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix`" /user:`"localhost\$CurrentHostPoolStorageAccountName`" /pass:`"$($CurrentHostPoolStorageAccountKey.Value)`""

                #region Private endpoint for Storage Setup
                #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
                #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
                #From https://ystatit.medium.com/azure-key-vault-with-azure-service-endpoints-and-private-link-part-1-bcc84b4c5fbc
                ## Create the private endpoint connection. ## 

                Write-Verbose -Message "Creating the Private Endpoint for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                $PrivateEndpointName = "pep{0}" -f $($CurrentHostPoolStorageAccountName -replace "\W")
                $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $CurrentHostPoolStorageAccount.Id).GroupId | Where-Object -FilterScript { $_ -match "file" }
                $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $CurrentHostPoolStorageAccount.Id -GroupId $GroupId
                $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -Subnet $ThisDomainControllerSubnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

                ## Create the private DNS zone. ##
                Write-Verbose -Message "Creating the Private DNS Zone for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                $PrivateDnsZoneName = "privatelink.$GroupId.$StorageEndpointSuffix"
                $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
                if ($null -eq $PrivateDnsZone) {
                    Write-Verbose -Message "Creating the Private DNS Zone for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                    $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
                }

                $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
                $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
                if ($null -eq $PrivateDnsVirtualNetworkLink) {
                    $ThisDomainControllerVirtualNetworkId = [string]::Join("/", $split[0..($split.Count - 3)])
                    ## Create a DNS network link. ##
                    Write-Verbose -Message "Creating the Private DNS VNet Link for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                    $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
                }


                ## Configure the DNS zone. ##
                Write-Verbose -Message "Creating the DNS Zone Configuration of the Private Dns Zone Group for the Storage Account '$CurrentHostPoolStorageAccountName'"
                $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

                ## Create the DNS zone group. ##
                Write-Verbose -Message "Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $CurrentHostPoolResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force

                #Storage Account - Disabling Public Access
                #From https://www.jorgebernhardt.com/azure-storage-public-access/
                #From https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-powershell#change-the-default-network-access-rule
                #From https://github.com/adstuart/azure-privatelink-dns-microhack
                Write-Verbose -Message "Disabling the Public Access for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                $null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -PublicNetworkAccess Disabled
                #(Get-AzStorageAccount -Name $CurrentHostPoolResourceGroupName -ResourceGroupName $CurrentHostPoolStorageAccountName ).AllowBlobPublicAccess
                #endregion
                #endregion
                Start-Sleep -Seconds 60
                #region Dedicated Share Management
                $FSLogixShareName | ForEach-Object -Process { 
                    $CurrentHostPoolShareName = $_
                    Write-Verbose -Message "Creating the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                    #Create a share for FSLogix
                    #$CurrentHostPoolStorageAccountShare = New-AzRmStorageShare -ResourceGroupName $CurrentHostPoolResourceGroupName -StorageAccountName $CurrentHostPoolStorageAccountName -Name $CurrentHostPoolShareName -AccessTier Hot -QuotaGiB 200
                    $CurrentHostPoolStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }
                    $storageContext = New-AzStorageContext -StorageAccountName $CurrentHostPoolStorageAccountName -StorageAccountKey $CurrentHostPoolStorageAccountKey.Value
                    $CurrentHostPoolStorageAccountShare = New-AzStorageShare -Name $CurrentHostPoolShareName -Context $storageContext

                    # Mount the share
                    $null = New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\$CurrentHostPoolShareName"

                    #region NTFS permissions for FSLogix
                    #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
                    #region Sample NTFS permissions for FSLogix
                    Write-Verbose -Message "Setting the ACL for the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) "
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
                        Write-Verbose -Message "Creating the 'redirections.xml' file for the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                        $null = New-Item -Path Z: -Name "redirections.xml" -ItemType "file" -Value $RedirectionsXMLFileContent -Force
                        Write-Verbose -Message "Setting the ACL for the 'redirections.xml' file in the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
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
                    #endregion

                    #region Run a sync with Azure AD
                    Start-MicrosoftEntraIDConnectSync
                    #endregion 

                    #region RBAC Management
                    #Constrain the scope to the target file share
                    $SubscriptionId = $AzContext.Subscription.Id
                    $Scope = "/subscriptions/$SubscriptionId/resourceGroups/$CurrentHostPoolResourceGroupName/providers/Microsoft.Storage/storageAccounts/$CurrentHostPoolStorageAccountName/fileServices/default/fileshares/$CurrentHostPoolShareName"

                    #region Setting up the file share with right RBAC: FSLogix Contributor = "Storage File Data SMB Share Contributor"
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "Sleeping 30 seconds"
                        Start-Sleep -Seconds 30
                        $AzADGroup = $null
                        $AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolFSLogixContributorADGroupName
                    } While (-not($AzADGroup.Id))
                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolFSLogixContributorADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) "
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #region Setting up the file share with right RBAC: FSLogix Elevated Contributor = "Storage File Data SMB Share Elevated Contributor"
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "Sleeping 30 seconds"
                        Start-Sleep -Seconds 30
                        $AzADGroup = $null
                        $AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolFSLogixElevatedContributorADGroupName
                    } While (-not($AzADGroup.Id))

                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolFSLogixElevatedContributorADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) "
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #region Setting up the file share with right RBAC: FSLogix Reader = "Storage File Data SMB Share Reader"
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Reader"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "Sleeping 30 seconds"
                        Start-Sleep -Seconds 30
                        $AzADGroup = $null
                        $AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolFSLogixReaderADGroupName
                    } While (-not($AzADGroup.Id))
                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolFSLogixReaderADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) "
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #endregion
                }
                #endregion
                #endregion
            }
            else {
                Write-Verbose -Message "FSLogix NOT enabled for '$($CurrentHostPool.Name)' HostPool"
            }
            #endregion

            #region MSIX
            #No EntraID and MSIX : https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-overview?pivots=msix-app-attach#identity-providers
            if (($CurrentHostPool.IsActiveDirectoryJoined()) -and ($CurrentHostPool.MSIX)) {
                #region MSIX AD Management
                #region Dedicated HostPool AD group

                #region Dedicated HostPool AD MSIX groups
                $CurrentHostPoolMSIXHostsADGroupName = "$($CurrentHostPool.Name) - $MSIXHosts"
                $CurrentHostPoolMSIXHostsADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolMSIXHostsADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolMSIXHostsADGroup)) {
                    Write-Verbose -Message "Creating '$CurrentHostPoolMSIXHostsADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                    $CurrentHostPoolMSIXHostsADGroup = New-ADGroup -Name $CurrentHostPoolMSIXHostsADGroupName -SamAccountName $CurrentHostPoolMSIXHostsADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolMSIXHostsADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                }

                $CurrentHostPoolMSIXShareAdminsADGroupName = "$($CurrentHostPool.Name) - $MSIXShareAdmins"
                $CurrentHostPoolMSIXShareAdminsADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolMSIXShareAdminsADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolMSIXShareAdminsADGroup)) {
                    Write-Verbose -Message "Creating '$CurrentHostPoolMSIXShareAdminsADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                    $CurrentHostPoolMSIXShareAdminsADGroup = New-ADGroup -Name $CurrentHostPoolMSIXShareAdminsADGroupName -SamAccountName $CurrentHostPoolMSIXShareAdminsADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolMSIXShareAdminsADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                }

                $CurrentHostPoolMSIXUsersADGroupName = "$($CurrentHostPool.Name) - $MSIXUsers"
                $CurrentHostPoolMSIXUsersADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolMSIXUsersADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolMSIXUsersADGroup)) {
                    Write-Verbose -Message "Creating '$CurrentHostPoolMSIXUsersADGroup' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
                    $CurrentHostPoolMSIXUsersADGroup = New-ADGroup -Name $CurrentHostPoolMSIXUsersADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolMSIXUsersADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                }
                Write-Verbose -Message "Adding the '$CurrentHostPoolDAGUsersAzADGroupName' AD group to the '$CurrentHostPoolMSIXUsersADGroup' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)')"
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
                $CurrentHostPoolStorageAccountName = $CurrentHostPoolStorageAccountName.Substring(0, [system.math]::min($CurrentHostPoolStorageAccountNameMaxLength, $CurrentHostPoolStorageAccountName.Length)).ToLower()
                #endregion 

                #region Dedicated Host Pool AD GPO Management (1 GPO per Host Pool for setting up the dedicated VHDLocations/CCDLocations value)
                $CurrentHostPoolMSIXGPO = Get-GPO -Name "$($CurrentHostPool.Name) - MSIX Settings" -ErrorAction Ignore
                if (-not($CurrentHostPoolMSIXGPO)) {
                    $CurrentHostPoolMSIXGPO = New-GPO -Name "$($CurrentHostPool.Name) - MSIX Settings"
                    Write-Verbose -Message "Creating '$($CurrentHostPoolMSIXGPO.DisplayName)' GPO (linked to '($($CurrentHostPoolOU.DistinguishedName))'"
                }
                $null = $CurrentHostPoolMSIXGPO | New-GPLink -Target $CurrentHostPoolOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore

                #region Turning off automatic updates for MSIX app attach applications
                #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-azure-portal#turn-off-automatic-updates-for-msix-app-attach-applications
                Write-Verbose -Message "Turning off automatic updates for MSIX app attach applications for '$($CurrentHostPoolMSIXGPO.DisplayName)' GPO (linked to '$($PooledDesktopsOU.DistinguishedName)' OU)"
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\WindowsStore' -ValueName "AutoDownload" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -ValueName "PreInstalledAppsEnabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Debug' -ValueName "ContentDeliveryAllowedOverride" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
                #Look for Disable-ScheduledTask ... in the code for the next step(s)
                #endregion

                #region Microsoft Defender Endpoint A/V Exclusions for this HostPool 
                #From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
                Write-Verbose -Message "Setting some 'Microsoft Defender Endpoint A/V Exclusions for this HostPool' related registry values for '$($CurrentHostPoolMSIXGPO.DisplayName)' GPO (linked to '$($CurrentHostPoolOU.DistinguishedName)' OU)"
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.lock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.meta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.metadata" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.lock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.meta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.metadata" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.CIM" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                #endregion

                #region Dedicated Resource Group Management (1 per HostPool)
                $CurrentHostPoolResourceGroupName = $CurrentHostPool.GetResourceGroupName()

                $CurrentHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -ErrorAction Ignore
                if (-not($CurrentHostPoolResourceGroup)) {
                    Write-Verbose -Message "Creating '$CurrentHostPoolResourceGroupName' Resource Group"
                    $CurrentHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Force
                }
                #endregion


                #region Dedicated Storage Account Setup
                $CurrentHostPoolStorageAccount = Get-AzStorageAccount -Name $CurrentHostPoolStorageAccountName -ResourceGroupName $CurrentHostPoolResourceGroupName -ErrorAction Ignore
                if (-not($CurrentHostPoolStorageAccount)) {
                    if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentHostPoolStorageAccountName).NameAvailable) {
                        Stop-Transcript
                        Write-Error "The storage account name '$CurrentHostPoolStorageAccountName' is not available !" -ErrorAction Stop
                    }
                    $CurrentHostPoolStorageAccount = New-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName -Location $ThisDomainControllerVirtualNetwork.Location -SkuName $SKUName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true
                    Write-Verbose -Message "Creating '$($CurrentHostPoolStorageAccount.StorageAccountName)' Storage Account (in the '$($CurrentHostPoolStorageAccount.ResourceGroupName)' Resource Group)"
                }
                #Registering the Storage Account with your active directory environment under the target
                if (-not(Get-ADComputer -Filter "Name -eq '$CurrentHostPoolStorageAccountName'" -SearchBase $CurrentHostPoolOU.DistinguishedName)) {
                    if (-not(Get-Module -Name AzFilesHybrid -ListAvailable)) {
                        $AzFilesHybridZipName = 'AzFilesHybrid.zip'
                        $OutFile = Join-Path -Path $env:TEMP -ChildPath $AzFilesHybridZipName
                        Start-BitsTransfer https://github.com/Azure-Samples/azure-files-samples/releases/latest/download/AzFilesHybrid.zip -destination $OutFile
                        Expand-Archive -Path $OutFile -DestinationPath $env:TEMP\AzFilesHybrid -Force
                        Push-Location -Path $env:TEMP\AzFilesHybrid
                        .\CopyToPSPath.ps1
                        Pop-Location
                    }
                    Write-Verbose -Message "Registering the Storage Account '$CurrentHostPoolStorageAccountName' with your AD environment (under '$($CurrentHostPoolOU.DistinguishedName)') OU"
                    Import-Module AzFilesHybrid
                    $null = New-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -KeyName "kerb1"
                    $null = Join-AzStorageAccountForAuth -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -DomainAccountType "ComputerAccount" -OrganizationUnitDistinguishedName $CurrentHostPoolOU.DistinguishedName -Confirm:$false
                    #$KerbKeys = Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -ListKerbKey 
                }

                # Get the target storage account
                #$storageaccount = Get-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName

                # List the directory service of the selected service account
                #$CurrentHostPoolStorageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceOptions

                # List the directory domain information if the storage account has enabled AD authentication for file shares
                #$CurrentHostPoolStorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties

                $CurrentHostPoolStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }

                # Save the password so the drive 
                Write-Verbose -Message "Saving the credentials for accessing to the Storage Account '$CurrentHostPoolStorageAccountName' in the Windows Credential Manager"
                Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "cmdkey /add:`"$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix`" /user:`"localhost\$CurrentHostPoolStorageAccountName`" /pass:`"$($CurrentHostPoolStorageAccountKey.Value)`""

                #region Private endpoint for Storage Setup
                #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
                #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
                #From https://ystatit.medium.com/azure-key-vault-with-azure-service-endpoints-and-private-link-part-1-bcc84b4c5fbc
                ## Create the private endpoint connection. ## 

                Write-Verbose -Message "Creating the Private Endpoint for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                $PrivateEndpointName = "pep{0}" -f $($CurrentHostPoolStorageAccountName -replace "\W")
                $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $CurrentHostPoolStorageAccount.Id).GroupId | Where-Object -FilterScript { $_ -match "file" }
                $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $CurrentHostPoolStorageAccount.Id -GroupId $GroupId
                $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -Subnet $ThisDomainControllerSubnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

                ## Create the private DNS zone. ##
                Write-Verbose -Message "Creating the Private DNS Zone for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                $PrivateDnsZoneName = "privatelink.$GroupId.$StorageEndpointSuffix"
                $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
                if ($null -eq $PrivateDnsZone) {
                    Write-Verbose -Message "Creating the Private DNS Zone for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                    $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
                }

                $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
                $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
                if ($null -eq $PrivateDnsVirtualNetworkLink) {
                    $ThisDomainControllerVirtualNetworkId = [string]::Join("/", $split[0..($split.Count - 3)])
                    ## Create a DNS network link. ##
                    Write-Verbose -Message "Creating the Private DNS VNet Link for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                    $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
                }


                ## Configure the DNS zone. ##
                Write-Verbose -Message "Creating the DNS Zone Configuration of the Private Dns Zone Group for the Storage Account '$CurrentHostPoolStorageAccountName'"
                $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

                ## Create the DNS zone group. ##
                Write-Verbose -Message "Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $CurrentHostPoolResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force

                #Storage Account - Disabling Public Access
                #From https://www.jorgebernhardt.com/azure-storage-public-access/
                #From https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-powershell#change-the-default-network-access-rule
                #From https://github.com/adstuart/azure-privatelink-dns-microhack
                Write-Verbose -Message "Disabling the Public Access for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                $null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -PublicNetworkAccess Disabled
                #(Get-AzStorageAccount -Name $CurrentHostPoolResourceGroupName -ResourceGroupName $CurrentHostPoolStorageAccountName ).AllowBlobPublicAccess
                #endregion
                #endregion
                Start-Sleep -Seconds 60
                $MSIXDemoPackages = $null
                #region Dedicated Share Management
                $MSIXShareName | ForEach-Object -Process { 
                    $CurrentHostPoolShareName = $_
                    #Create a share for MSIX
                    Write-Verbose -Message "Creating the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                    #$CurrentHostPoolStorageShare = New-AzRmStorageShare -ResourceGroupName $CurrentHostPoolResourceGroupName -StorageAccountName $CurrentHostPoolStorageAccountName -Name $CurrentHostPoolShareName -AccessTier Hot -QuotaGiB 200
                    $CurrentHostPoolStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }
                    $storageContext = New-AzStorageContext -StorageAccountName $CurrentHostPoolStorageAccountName -StorageAccountKey $CurrentHostPoolStorageAccountKey.Value
                    $CurrentHostPoolStorageAccountShare = New-AzStorageShare -Name $CurrentHostPoolShareName -Context $storageContext

                    # Copying the  Demo MSIX Packages from my dedicated GitHub repository
                    $MSIXDemoPackages = Copy-MSIXDemoAppAttachPackage -Destination "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\$CurrentHostPoolShareName"

                    # Mount the share
                    $null = New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\$CurrentHostPoolShareName"

                    #region NTFS permissions for MSIX
                    #From https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach-file-share#how-to-set-up-the-file-share
                    #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
                    Write-Verbose -Message "Setting the ACL on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
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

                    #region RBAC Management
                    #Constrain the scope to the target file share
                    $SubscriptionId = $AzContext.Subscription.Id
                    $Scope = "/subscriptions/$SubscriptionId/resourceGroups/$CurrentHostPoolResourceGroupName/providers/Microsoft.Storage/storageAccounts/$CurrentHostPoolStorageAccountName/fileServices/default/fileshares/$CurrentHostPoolShareName"

                    #region Setting up the file share with right RBAC: MSIX Hosts & MSIX Users = "Storage File Data SMB Share Contributor" + MSIX Share Admins = Storage File Data SMB Share Elevated Contributor
                    #https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach-file-share#how-to-set-up-the-file-share
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "Sleeping 30 seconds"
                        Start-Sleep -Seconds 30
                        $AzADGroup = $null
                        $AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolMSIXHostsADGroupName
                    } While (-not($AzADGroup.Id))

                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolMSIXHostsADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }

                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "Sleeping 30 seconds"
                        Start-Sleep -Seconds 30
                        $AzADGroup = $null
                        $AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolMSIXUsersADGroupName
                    } While (-not($AzADGroup.Id))
                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to 'CurrentPooledHostPoolMSIXUsersADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName'  (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #region Setting up the file share with right RBAC
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "Sleeping 30 seconds"
                        Start-Sleep -Seconds 30
                        $AzADGroup = $null
                        $AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolMSIXShareAdminsADGroupName
                    } While (-not($AzADGroup.Id))
                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolMSIXShareAdminsADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #endregion
                }
                #endregion
                #endregion
            
                #endregion

            }
            else {
                Write-Verbose -Message "MSIX NOT enabled for '$($CurrentHostPool.Name)' HostPool"
            }
            #endregion

            #region Dedicated Resource Group Management (1 per HostPool)
            $CurrentHostPoolResourceGroupName = $CurrentHostPool.GetResourceGroupName()

            $CurrentHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -ErrorAction Ignore
            if (-not($CurrentHostPoolResourceGroup)) {
                Write-Verbose -Message "Creating '$CurrentHostPoolResourceGroupName' Resource Group"
                $CurrentHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Force
            }
            #endregion

            #region Identity Provider Management
            if ($CurrentHostPool.IsActiveDirectoryJoined()) {
                $AdJoinUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name AdJoinUserName -AsPlainText
                $AdJoinPassword = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name AdJoinPassword).SecretValue
                $AdJoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($AdJoinUserName, $AdJoinPassword)
                Grant-ADJoinPermission -Credential $AdJoinCredential -OrganizationalUnit $CurrentHostPoolOU.DistinguishedName
                $Tag['IdentityProvider'] = "Active Directory Directory Services"
            }
            else {
                $Tag['IdentityProvider'] = "Microsoft Entra ID"
                #region Assign Virtual Machine User Login' RBAC role to the Resource Group
                # Get the object ID of the user group you want to assign to the application group
                Do {
                    Start-MicrosoftEntraIDConnectSync
                    Write-Verbose -Message "Sleeping 30 seconds"
                    Start-Sleep -Seconds 30
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolDAGUsersAzADGroupName
                } While (-not($AzADGroup.Id))

                # Assign users to the application group
                $parameters = @{
                    ObjectId           = $AzADGroup.Id
                    ResourceGroupName  = $CurrentHostPoolResourceGroupName
                    RoleDefinitionName = 'Virtual Machine User Login'
                    #Verbose            = $true
                }

                Write-Verbose -Message "Assigning the '$($parameters.RoleDefinitionName)' RBAC role to '$CurrentHostPoolDAGUsersAzADGroupName' AD Group on the '$CurrentHostPoolResourceGroupName' Resource Group"
                $null = New-AzRoleAssignment @parameters
                #endregion 
            }
            #endregion 

            #region Key Vault
            #region Key Vault Name Setup
            $CurrentHostPoolKeyVaultName = $CurrentHostPool.GetKeyVaultName()
            $CurrentHostPoolKeyVaultName = $CurrentHostPoolKeyVaultName.Substring(0, [system.math]::min($CurrentHostPoolKeyVaultNameMaxLength, $CurrentHostPoolKeyVaultName.Length)).ToLower()
            $CurrentHostPoolKeyVaultName = $CurrentHostPoolKeyVaultName.ToLower()
            #endregion 

            #region Dedicated Key Vault Setup
            $CurrentHostPoolKeyVault = Get-AzKeyVault -VaultName $CurrentHostPoolKeyVaultName -ErrorAction Ignore
            if (-not($CurrentHostPoolKeyVault)) {
                if (-not(Test-AzKeyVaultNameAvailability -Name $CurrentHostPoolKeyVaultName).NameAvailable) {
                    Stop-Transcript
                    Write-Error "The key vault name '$CurrentHostPoolKeyVaultName' is not available !" -ErrorAction Stop
                }
                Write-Verbose -Message "Creating '$CurrentHostPoolKeyVaultName' Key Vault (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
                $CurrentHostPoolKeyVault = New-AzKeyVault -ResourceGroupName $CurrentHostPoolResourceGroupName -VaultName $CurrentHostPoolKeyVaultName -Location $ThisDomainControllerVirtualNetwork.Location -EnabledForDiskEncryption -SoftDeleteRetentionInDays 7 -DisableRbacAuthorization
            }
            #endregion

            #region Private endpoint for Key Vault Setup
            #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
            #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
            ## Create the private endpoint connection. ## 

            $PrivateEndpointName = "pep{0}" -f $($CurrentHostPoolKeyVaultName -replace "\W")
            $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $CurrentHostPoolKeyVault.ResourceId).GroupId
            $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $CurrentHostPoolKeyVault.ResourceId -GroupId $GroupId
            Write-Verbose -Message "Creating the Private Endpoint for the Key Vault '$CurrentHostPoolKeyVaultName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -Subnet $ThisDomainControllerSubnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

            ## Create the private DNS zone. ##
            $PrivateDnsZoneName = 'privatelink.vaultcore.azure.net'
            $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
            if ($null -eq $PrivateDnsZone) {
                Write-Verbose -Message "Creating the Private DNS Zone for the Key Vault '$CurrentHostPoolKeyVaultName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
            }

            $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
            $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
            if ($null -eq $PrivateDnsVirtualNetworkLink) {
                $ThisDomainControllerVirtualNetworkId = [string]::Join("/", $split[0..($split.Count - 3)])
                ## Create a DNS network link. ##
                Write-Verbose -Message "Creating the Private DNS VNet Link for the Key Vault '$CurrentHostPoolKeyVaultName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group)"
                $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
            }


            ## Configure the DNS zone. ##
            Write-Verbose -Message "Creating the DNS Zone Configuration of the Private Dns Zone Group for Key Vault '$CurrentHostPoolKeyVaultName'"
            $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

            ## Create the DNS zone group. ##
            Write-Verbose -Message "Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $CurrentHostPoolResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force

            #Key Vault - Disabling Public Access
            Write-Verbose -Message "Disabling the Public Access for the Key Vault'$CurrentHostPoolKeyVaultName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $null = Update-AzKeyVault -VaultName $CurrentHostPoolKeyVaultName -ResourceGroupName $CurrentHostPoolResourceGroupName -PublicNetworkAccess "Disabled" 
            #endregion

            #endregion

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
                LoadBalancerType      = 'BreadthFirst'
                PreferredAppGroupType = 'Desktop'
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

            Write-Verbose -Message "Creating the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $CurrentAzWvdHostPool = New-AzWvdHostPool @parameters
            Write-Verbose -Message "Creating Registration Token (Expiration: '$RegistrationInfoExpirationTime') for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
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
                ResourceGroupName    = $CurrentHostPoolResourceGroupName
                Location             = $CurrentHostPool.Location
                HostPoolArmPath      = $CurrentAzWvdHostPool.Id
                ApplicationGroupType = 'Desktop'
                ShowInFeed           = $true
                #Verbose              = $true
            }

            Write-Verbose -Message "Creating the Desktop Application Group for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $CurrentAzDesktopApplicationGroup = New-AzWvdApplicationGroup @parameters

            Write-Verbose -Message "Updating the friendly name of the Desktop for the Desktop Application Group of the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) to 'Full Desktop'"
            $parameters = @{
                ApplicationGroupName = $CurrentAzDesktopApplicationGroup.Name
                ResourceGroupName    = $CurrentHostPoolResourceGroupName
            }
            $null = Get-AzWvdDesktop @parameters | Update-AzWvdDesktop -FriendlyName "Full Desktop"

            #region Assign 'Desktop Virtualization User' RBAC role to application groups
            # Get the object ID of the user group you want to assign to the application group
            Do {
                Start-MicrosoftEntraIDConnectSync
                Write-Verbose -Message "Sleeping 30 seconds"
                Start-Sleep -Seconds 30
                $AzADGroup = $null
                $AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolDAGUsersAzADGroupName
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

            Write-Verbose -Message "Assigning the '$($parameters.RoleDefinitionName)' RBAC role to '$CurrentHostPoolDAGUsersAzADGroupName' AD Group on the Desktop Application Group (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
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

            Write-Verbose -Message "Creating the Remote Application Group for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $CurrentAzRemoteApplicationGroup = New-AzWvdApplicationGroup @parameters

            #region Assign required RBAC role to application groups
            # Get the object ID of the user group you want to assign to the application group
            Do {
                Start-MicrosoftEntraIDConnectSync
                Write-Verbose -Message "Sleeping 30 seconds"
                Start-Sleep -Seconds 30
                $AzADGroup = $null
                $AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolRAGUsersADGroupName
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

            Write-Verbose -Message "Assigning the '$($parameters.RoleDefinitionName)' RBAC role to '$CurrentHostPoolRAGUsersADGroupName' AD Group on the Remote Application Group (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $null = New-AzRoleAssignment @parameters
            #endregion 

            #endregion

            #region Workspace Setup
            $ApplicationGroupReference = $CurrentAzRemoteApplicationGroup.Id, $CurrentAzDesktopApplicationGroup.Id

            $Options = $CurrentHostPool.Type, $CurrentHostPool.IdentityProvider
            if ($CurrentHostPool.VMSourceImageId) {
                $Options += 'Azure Compte Gallery'
            }
            else {
                $Options += 'Market Place'
            }
            if ($CurrentHostPool.FSLogix) {
                $Options += 'FSLogix'
            }
            if ($CurrentHostPool.MSIX) {
                $Options += 'MSIX'
            }
            if ($CurrentHostPool.Intune) {
                $Options += 'Intune'
            }
            if ($CurrentHostPool.DiffDiskPlacement -eq [DiffDiskPlacement]::CacheDisk) {
                $Options += 'Ephemeral OS Disk: CacheDisk'
            }
            elseif ($CurrentHostPool.DiffDiskPlacement -eq [DiffDiskPlacement]::ResourceDisk) {
                $Options += 'Ephemeral OS Disk: ResourceDisk'
            } 
            $FriendlyName = "{0} ({1})" -f $CurrentHostPool.GetAzAvdWorkSpaceName(), $($Options -join ', ')
            $parameters = @{
                Name                      = $CurrentHostPool.GetAzAvdWorkSpaceName()
                FriendlyName              = $FriendlyName
                ResourceGroupName         = $CurrentHostPoolResourceGroupName
                ApplicationGroupReference = $ApplicationGroupReference
                Location                  = $CurrentHostPool.Location
                #Verbose                   = $true
            }

            Write-Verbose -Message "Creating the WorkSpace for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $CurrentAzWvdWorkspace = New-AzWvdWorkspace @parameters
            #endregion

            #region Adding Session Hosts to the Host Pool
            $Status = @{ $true = "Enabled"; $false = "Disabled" }
            if (-not([String]::IsNullOrEmpty($CurrentHostPool.VMSourceImageId))) {
                #We propagate the AsJob context to the child function
                Add-AzAvdSessionHost -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentHostPool.NamePrefix -VMNumberOfInstances $CurrentHostPool.VMNumberOfInstances -KeyVault $CurrentHostPool.KeyVault -RegistrationInfoToken $RegistrationInfoToken.Token -DomainName $DomainName -OUPath $CurrentHostPoolOU.DistinguishedName -VMSize $CurrentHostPool.VMSize -VMSourceImageId $CurrentHostPool.VMSourceImageId -DiffDiskPlacement $CurrentHostPool.DiffDiskPlacement -Tag $Tag -IsMicrosoftEntraIdJoined:$CurrentHostPool.IsMicrosoftEntraIdJoined() -Spot:$CurrentHostPool.Spot -HibernationEnabled:$CurrentHostPool.HibernationEnabled -Intune:$CurrentHostPool.Intune -LogDir $LogDir -AsJob #:$AsJob
            }
            else {
                #We propagate the AsJob context to the child function
                Add-AzAvdSessionHost -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentHostPool.NamePrefix -VMNumberOfInstances $CurrentHostPool.VMNumberOfInstances -KeyVault $CurrentHostPool.KeyVault -RegistrationInfoToken $RegistrationInfoToken.Token -DomainName $DomainName -OUPath $CurrentHostPoolOU.DistinguishedName -VMSize $CurrentHostPool.VMSize -DiffDiskPlacement $CurrentHostPool.DiffDiskPlacement -ImagePublisherName $CurrentHostPool.ImagePublisherName -ImageOffer $CurrentHostPool.ImageOffer -ImageSku $CurrentHostPool.ImageSku -Tag $Tag -IsMicrosoftEntraIdJoined:$CurrentHostPool.IsMicrosoftEntraIdJoined() -Spot:$CurrentHostPool.Spot -HibernationEnabled:$CurrentHostPool.HibernationEnabled -Intune:$CurrentHostPool.Intune -LogDir $LogDir -AsJob #:$AsJob
            }
            $SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            $SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
            #endregion 

            if (($CurrentHostPool.IsMicrosoftEntraIdJoined()) -and ($CurrentHostPool.FSLogix)) {
                #region Creating a dynamic device group for our AVD hosts
                $DisplayName = "{0} - Devices" -f $CurrentHostPool.Name
                $Description = "Dynamic device group for our AVD hosts for the {0} HostPool." -f $CurrentHostPool.Name
                $MailNickname = $($DisplayName -replace "\s").ToLower()
                $MembershipRule = "(device.displayName -startsWith ""$($CurrentHostPool.NamePrefix)-"")"
                $AzADDeviceDynamicGroup = New-AzADGroup -DisplayName $DisplayName -Description $Description -MembershipRule $MembershipRule -MembershipRuleProcessingState "On" -GroupType "DynamicMembership" -MailNickname $MailNickname -SecurityEnabled
                #endregion

                #region Configure the session hosts

                #region Configure the clients to retrieve Kerberos tickets
                # From https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-powershell#configure-the-clients-to-retrieve-kerberos-tickets
                # From https://learn.microsoft.com/en-us/azure/virtual-desktop/create-profile-container-azure-ad#configure-the-session-hosts
                $LocalAdminUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminUserName -AsPlainText
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
                        $URI = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Setup/Set-AVDRegistryItemProperty.ps1"
                        $ScriptPath = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $URI -Leaf)
                        Invoke-WebRequest -Uri $URI -UseBasicParsing -OutFile $ScriptPath
                        $Result = Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptPath $ScriptPath
                        Write-Verbose -Message $("{0}:`r`n{1}" -f $ScriptPath, ($Result | Out-String))
                        Remove-Item -Path $ScriptPath -Force
                        #endregion
                        #endregion

                        #region Configure FSLogix
                        #region Configure FSLogix - Registry
                        # Run PowerShell script on the VM
                        $URI = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Setup/Set-FSLogixRegistryItemProperty.ps1"
                        $ScriptPath = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $URI -Leaf)
                        Invoke-WebRequest -Uri $URI -UseBasicParsing -OutFile $ScriptPath
                        $Result = Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptPath $ScriptPath -Parameter @{CurrentHostPoolStorageAccountName = $CurrentHostPoolStorageAccountName }
                        Write-Verbose -Message $("{0}:`r`n{1}" -f $ScriptPath, ($Result | Out-String))
                        Remove-Item -Path $ScriptPath -Force
                        #endregion
                        #endregion

                        <#
                        #region Configure the clients to disable FSLogix
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

                    <#
                    #region Intune Configuration Profile - Administrative Templates

                    #region AVD Global Settings FSLogix - Intune Configuration Profile - Administrative Templates
                    #region AVD Global Settings FSLogix - ADMX/ADML
                    foreach ($CurrentSessionHostName in $SessionHostNames) {
                        $ScriptBlock = [scriptblock]::Create("Function Get-CallerPreference { ${Function:Get-CallerPreference} }; Function Install-AVDGPOSettings { ${Function:Install-AVDGPOSettings} }; Install-AVDGPOSettings -Force")
                        $null = Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptString $ScriptBlock
                    }
                    #endregion
                    
                    New-AzAvdIntuneAdministrativeTemplateConfigurationPolicyViaCmdlet -HostPoolName $CurrentHostPool.Name
                    #endregion

                    #region Configure FSLogix - Intune Configuration Profile - Administrative Templates
                    #region Configure FSLogix - ADMX/ADML
                    foreach ($CurrentSessionHostName in $SessionHostNames) {
                        $ScriptBlock = [scriptblock]::Create("Function Get-CallerPreference { ${Function:Get-CallerPreference} }; Function Install-FSLogixGPOSettings { ${Function:Install-FSLogixGPOSettings} }; Install-FSLogixGPOSettings -Force")
                        $null = Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptString $ScriptBlock
                    }
                    #endregion

                    New-FSLogixIntuneAdministrativeTemplateConfigurationPolicyViaCmdlet -CurrentHostPoolStorageAccountName $CurrentHostPool.GetFSLogixStorageAccountName() -HostPoolName $CurrentHostPool.Name
                    #endregion

                    #endregion
                    #>

                    #region Intune Configuration Profile - Settings Catalog
                    #region AVD Global Settings FSLogix - Intune Configuration Profile - Settings Catalog
                    New-AVDIntuneSettingsCatalogConfigurationPolicyViaGraphAPI -HostPoolStorageAccountName $CurrentHostPool.GetFSLogixStorageAccountName() -HostPoolName $CurrentHostPool.Name
                    #endregion

                    #region Configure FSLogix - Intune Configuration Profile - Settings Catalog
                    New-FSLogixIntuneSettingsCatalogConfigurationPolicyViaGraphAPI -HostPoolStorageAccountName $CurrentHostPool.GetFSLogixStorageAccountName() -HostPoolName $CurrentHostPool.Name
                    #endregion
                    #endregion

                    #Enabling New Performance Counters
                    New-IntunePowerShellScriptViaCmdlet -ScriptURI 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Setup/Enable-NewPerformanceCounter.ps1' -HostPoolName $CurrentHostPool.Name
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
            if (($CurrentHostPool.IsActiveDirectoryJoined()) -and ($CurrentHostPool.MSIX)) {
                #Adding the Session Hosts to the dedicated ADGroup for MSIX 
                #$SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
                #$SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
                #Adding Session Hosts to the dedicated AD MSIX Host group
                Write-Verbose -Message "Adding the Session Hosts Session Hosts to the '$($CurrentHostPoolMSIXHostsADGroup.Name)' AD Group"
                $CurrentHostPoolMSIXHostsADGroup | Add-ADGroupMember -Members $($SessionHostNames | Get-ADComputer).DistinguishedName
                Start-MicrosoftEntraIDConnectSync
    
                #Copying, Installing the MSIX Demo PFX File(s) (for signing MSIX Packages) on Session Host(s)
                Write-Verbose -Message "`$CurrentHostPool : $($CurrentHostPool.Name)"
                Write-Verbose -Message "`$SessionHostNames : $($SessionHostNames -join ',')"
                #$result = Wait-PSSession -ComputerName $SessionHostNames
                #Write-Verbose -Message "`$result: $result"
                Copy-MSIXDemoPFXFile -ComputerName $SessionHostNames

                #region Disabling the "\Microsoft\Windows\WindowsUpdate\Scheduled Start" Scheduled Task on Session Host(s)
                #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-azure-portal#turn-off-automatic-updates-for-msix-app-attach-applications
                $null = Disable-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsUpdate\" -TaskName "Scheduled Start" -CimSession $SessionHostNames
                #endregion 

                #region Restarting the Session Hosts
                $Jobs = foreach ($CurrentSessionHostName in $SessionHostNames) {
                    Restart-AzVM -Name $CurrentSessionHostName -ResourceGroupName $CurrentHostPoolResourceGroupName -Confirm:$false -AsJob
                }
                $Jobs | Wait-Job | Out-Null
                $Jobs | Remove-Job -Force
                #endregion 

                #region Adding the MSIX package(s) to the Host Pool
                #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-powershell
                foreach ($CurrentMSIXDemoPackage in $MSIXDemoPackages) {
                    $obj = $null
                    While ($null -eq $obj) {
                        Write-Verbose -Message "Expanding MSIX Image '$CurrentMSIXDemoPackage'"
                        $MyError = $null
                        #$obj = Expand-AzAvdMSIXImage -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName -Uri $CurrentMSIXDemoPackage
                        $obj = Expand-AzWvdMsixImage -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName -Uri $CurrentMSIXDemoPackage -ErrorAction Ignore -ErrorVariable MyError
                        if (($null -eq $obj)) {
                            Write-Verbose -Message "Error Message: $($MyError.Exception.Message)"
                            Write-Verbose -Message "Sleeping 30 seconds"
                            Start-Sleep -Seconds 30
                        }
                    }

                    $DisplayName = "{0} v{1}" -f $obj.PackageApplication.FriendlyName, $obj.Version
                    Write-Verbose -Message "Adding MSIX Image '$CurrentMSIXDemoPackage' as '$DisplayName'..."
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
            #endregion

            #region Adding Some Remote Apps
            #$RemoteApps = "Edge","Excel"
            #$SelectedAzWvdStartMenuItem = (Get-AzWvdStartMenuItem -ApplicationGroupName $CurrentAzRemoteApplicationGroup.Name -ResourceGroupName $CurrentHostPoolResourceGroupName | Where-Object -FilterScript {$_.Name -match $($RemoteApps -join '|')} | Select-Object -Property *)
            
            #2 Random Applications
            $result = Wait-AzVMPowerShell -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            $SelectedAzWvdStartMenuItem = Get-AzWvdStartMenuItem -ApplicationGroupName $CurrentAzRemoteApplicationGroup.Name -ResourceGroupName $CurrentHostPoolResourceGroupName | Get-Random -Count 2

            $AzWvdApplications = foreach ($CurrentAzWvdStartMenuItem in $SelectedAzWvdStartMenuItem) {
                #$Name = $CurrentAzWvdStartMenuItem.Name -replace "(.*)/"
                $Name = $CurrentAzWvdStartMenuItem.Name -replace "$($CurrentAzRemoteApplicationGroup.Name)/"
                try {
                    New-AzWvdApplication -AppAlias $CurrentAzWvdStartMenuItem.appAlias -GroupName $CurrentAzRemoteApplicationGroup.Name -Name $Name -ResourceGroupName $CurrentHostPoolResourceGroupName -CommandLineSetting DoNotAllow
                }
                catch {
                    Write-Warning -Message "Unable to add '$($CurrentAzWvdStartMenuItem.appAlias)' application as Remoteapp in the '$($CurrentAzRemoteApplicationGroup.Name)' Application Group"
                }
            }
            #endregion

            #region Log Analytics WorkSpace Setup : Monitor and manage performance and health
            #From https://learn.microsoft.com/en-us/training/modules/monitor-manage-performance-health/3-log-analytics-workspace-for-azure-monitor
            #From https://www.rozemuller.com/deploy-azure-monitor-for-windows-virtual-desktop-automated/#update-25-03-2021
            $LogAnalyticsWorkSpaceName = $CurrentHostPool.GetLogAnalyticsWorkSpaceName()
            Write-Verbose -Message "Creating the Log Analytics WorkSpace '$($LogAnalyticsWorkSpaceName)' (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            $LogAnalyticsWorkSpace = New-AzOperationalInsightsWorkspace -Location $CurrentHostPool.Location -Name $LogAnalyticsWorkSpaceName -Sku pergb2018 -ResourceGroupName $CurrentHostPoolResourceGroupName -Force


            #region Enabling Diagnostics Setting for the HostPool
            Write-Verbose -Message "Enabling Diagnostics Setting for the '$($CurrentAzWvdHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group)"
            #$HostPoolDiagnosticSetting = Set-AzDiagnosticSetting -Name $CurrentAzWvdHostPool.Name -ResourceId $CurrentAzWvdHostPool.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Enabled $true -Category "Checkpoint", "Error", "Management", "Connection", "HostRegistration", "AgentHealthStatus"
            $Categories = "Checkpoint", "Error", "Management", "Connection", "HostRegistration", "AgentHealthStatus"
            $Log = $Categories | ForEach-Object {
                New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category $_ 
            }
            $HostPoolDiagnosticSetting = New-AzDiagnosticSetting -Name $CurrentAzWvdHostPool.Name -ResourceId $CurrentAzWvdHostPool.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Log $Log
            #endregion

            #region Enabling Diagnostics Setting for the WorkSpace
            Write-Verbose -Message "Enabling Diagnostics Setting for the  '$($CurrentAzWvdWorkspace.Name)' Work Space"
            #$WorkSpaceDiagnosticSetting = Set-AzDiagnosticSetting -Name $CurrentAzWvdWorkspace.Name -ResourceId $CurrentAzWvdWorkspace.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Enabled $true -Category "Checkpoint", "Error", "Management", "Feed"
            $Categories = "Checkpoint", "Error", "Management", "Feed"
            $Log = $Categories | ForEach-Object {
                New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category $_ 
            }
            $WorkSpaceDiagnosticSetting = New-AzDiagnosticSetting -Name $CurrentAzWvdWorkspace.Name -ResourceId $CurrentAzWvdWorkspace.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Log $Log
            #endregion
            #endregion

            #region Installing Azure Monitor Windows Agent on Virtual Machine(s)
            #$SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            if (-not([string]::IsNullOrEmpty($SessionHosts.ResourceId))) {
                $SessionHostVMs = $SessionHosts.ResourceId | Get-AzVM
                $Jobs = foreach ($CurrentSessionHostVM in $SessionHostVMs) {
                    Write-Verbose -Message "Installing AzureMonitorWindowsAgent on the '$($CurrentSessionHostVM.Name)' Virtual Machine (in the '$CurrentHostPoolResourceGroupName' Resource Group) (As A Job)"
                    $ExtensionName = "AzureMonitorWindowsAgent_$("{0:yyyyMMddHHmmss}" -f (Get-Date))"
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
                Write-Verbose -Message "Waiting all jobs completes"
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
                    Write-Verbose -Message "Installing Log Analytics Agent on the '$($CurrentSessionHostVM.Name )' Virtual Machine (in the '$CurrentHostPoolResourceGroupName' Resource Group) (As A Job)"
                    Set-AzVMExtension -ExtensionName "MicrosoftMonitoringAgent" -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostVM.Name -Publisher "Microsoft.EnterpriseCloud.Monitoring" -ExtensionType "MicrosoftMonitoringAgent" -Settings $PublicSettings -TypeHandlerVersion "1.0" -ProtectedSettings $ProtectedSettings -Location $ThisDomainControllerVirtualNetwork.Location -AsJob
                }
                Write-Verbose -Message "Waiting all jobs completes"
                $Jobs | Wait-Job | Out-Null
                $Jobs | Remove-Job -Force
            }
            #endregion
            #>

            #region Data Collection Rules
            #region Event Logs
            #Levels : 1 = Critical, 2 = Error, 3 = Warning
            $EventLogs = @(
                @{EventLogName = 'Application'; Levels = 1,2,3 }
                @{EventLogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Levels = 1,2,3 }
                @{EventLogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin'; Levels = 1,2,3 }
                @{EventLogName = 'System'; Levels = 2,3 }
                @{EventLogName = 'Microsoft-FSLogix-Apps/Operational' ; Levels = 1,2,3 }
                @{EventLogName = 'Microsoft-FSLogix-Apps/Admin' ; Levels = 1,2,3 }
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

            $PerformanceCounters = foreach ($CurrentKey in $PerformanceCountersHT.Keys)
            {
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
            $DataCollectionRuleName = "dcr-{0}" -f $LogAnalyticsWorkSpace.Name
            $DataFlow = New-AzDataFlowObject -Stream Microsoft-Perf, Microsoft-Event -Destination $LogAnalyticsWorkSpace.Name
            $DestinationLogAnalytic = New-AzLogAnalyticsDestinationObject -Name $LogAnalyticsWorkSpace.Name -WorkspaceResourceId $LogAnalyticsWorkSpace.ResourceId
            $DataCollectionRule = New-AzDataCollectionRule -Name $DataCollectionRuleName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Dataflow $DataFlow -DataSourcePerformanceCounter $PerformanceCounters -DataSourceWindowsEventLog $WindowsEventLogs -DestinationLogAnalytic $DestinationLogAnalytic #-DataCollectionEndpointId $DataCollectionEndpoint.Id
            #endregion

            #region Adding Data Collection Rule Association for every Session Host
            #$DataCollectionRule = Get-AzDataCollectionRule -ResourceGroupName $CurrentHostPoolResourceGroupName -RuleName $DataCollectionRuleName
            $DataCollectionRuleAssociations = foreach ($CurrentSessionHost in $SessionHosts) {
                <#
                $AssociationName = 'configurationAccessEndpoint'
                Write-Verbose -Message "Associating the '$($DataCollectionEndpoint.Name)' Data Collection Endpoint with the '$($CurrentSessionHost.Name)' Session Host "
                Write-Verbose -Message "`$AssociationName: $AssociationName"
                New-AzDataCollectionRuleAssociation -ResourceUri $CurrentSessionHost.ResourceId -AssociationName $AssociationName -DataCollectionEndpointId $DataCollectionEndpoint.Id
                #>
                $AssociationName = "dcr-{0}" -f $($CurrentSessionHost.ResourceId -replace ".*/").ToLower()
                Write-Verbose -Message "Associating the '$($DataCollectionRule.Name)' Data Collection Rule with the '$($CurrentSessionHost.Name)' Session Host "
                Write-Verbose -Message "`$AssociationName: $AssociationName"
                New-AzDataCollectionRuleAssociation -ResourceUri $CurrentSessionHost.ResourceId -AssociationName $AssociationName -DataCollectionRuleId $DataCollectionRule.Id
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
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    }
}

function New-AzAvdHostPoolSetup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [Alias('Name')]
        [HostPool[]]$HostPool,

        [Parameter(Mandatory = $false)]
        [string]$NoMFAEntraIDGroupName = "No-MFA Users",

        [Parameter(Mandatory = $false)]
        [string]$LogDir = ".",

        [switch] $AsJob
    )

    begin {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

        $StartTime = Get-Date
        $AzContext = Get-AzContext
        <#
        $StorageEndpointSuffix = $AzContext | Select-Object -ExpandProperty Environment | Select-Object -ExpandProperty StorageEndpointSuffix
        $AzureKeyVaultDnsSuffix = $AzContext | Select-Object -ExpandProperty Environment | Select-Object -ExpandProperty AzureKeyVaultDnsSuffix
        $AzureKeyVaultDnsSuffix2 = "vaultcore.azure.net"
        $DnsServerConditionalForwarderZones = $StorageEndpointSuffix, $AzureKeyVaultDnsSuffix, $AzureKeyVaultDnsSuffix2
        #>
        Import-Module -Name DnsServer
        $DnsServerConditionalForwarderZones = "file.core.windows.net", "vaultcore.azure.net", "vault.azure.net"
        #region DNS Conditional Forwarders
        foreach ($CurrentDnsServerConditionalForwarderZone in $DnsServerConditionalForwarderZones) {
            if ($null -eq (Get-DnsServerZone -Name $CurrentDnsServerConditionalForwarderZone -ErrorAction Ignore)) {
                #Adding Dns Server Conditional Forwarder Zone
                Write-Verbose -Message "Adding Dns Server Conditional Forwarder Zone for '$CurrentDnsServerConditionalForwarderZone'"
                #From https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16
                Add-DnsServerConditionalForwarderZone -Name $CurrentDnsServerConditionalForwarderZone -MasterServers "168.63.129.16"
            }
        }
        #endregion


        #region Get the vnet and subnet where this DC is connected to
        # Get the VM networking data
        $ThisDomainController = Get-AzVMCompute | Get-AzVM
        # Get the VM's network interface
        $ThisDomainControllerNetworkInterfaceId = $ThisDomainController.NetworkProfile.NetworkInterfaces[0].Id
        $ThisDomainControllerNetworkInterface = Get-AzNetworkInterface -ResourceId $ThisDomainControllerNetworkInterfaceId

        # Get the subnet ID
        $ThisDomainControllerSubnetId = $ThisDomainControllerNetworkInterface.IpConfigurations[0].Subnet.Id
        $split = $ThisDomainControllerSubnetId.split('/')
        # Get the vnet ID
        $ThisDomainControllerVirtualNetworkId = $split[0..($split.Count - 3)] -join "/"
        $ThisDomainControllerVirtualNetwork = Get-AzResource -ResourceId $ThisDomainControllerVirtualNetworkId | Get-AzVirtualNetwork

        # Get the subnet details
        $ThisDomainControllerSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $ThisDomainControllerSubnetId
        #endregion

        #region AVD OU Management

        $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext
        #$DomainName = (Get-ADDomain).DNSRoot
        $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

        $AVDRootOU = Get-ADOrganizationalUnit -Filter 'Name -eq "AVD"' -SearchBase $DefaultNamingContext
        if (-not($AVDRootOU)) {
            $AVDRootOU = New-ADOrganizationalUnit -Name "AVD" -Path $DefaultNamingContext -ProtectedFromAccidentalDeletion $true -PassThru
            Write-Verbose -Message "Creating '$($AVDRootOU.DistinguishedName)' OU (under '$DefaultNamingContext')"
        }
        #Blocking Inheritance
        $null = $AVDRootOU | Set-GPInheritance -IsBlocked Yes
        #endregion

        #region AVD GPO Management
        $AVDGPO = Get-GPO -Name "AVD - Global Settings" -ErrorAction Ignore
        if (-not($AVDGPO)) {
            $AVDGPO = New-GPO -Name "AVD - Global Settings" -ErrorAction Ignore
            Write-Verbose -Message "Creating '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU)"
        }
        $null = $AVDGPO | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore

        Write-Verbose -Message "Setting GPO Setting for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU)"
        #region Network Settings
        #From https://learn.microsoft.com/en-us/training/modules/configure-user-experience-settings/4-configure-user-settings-through-group-policies
        Write-Verbose -Message "Setting some 'Network Settings' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU)"
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.BITS::BITS_DisableBranchCache
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\BITS' -ValueName "DisableBranchCache" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.PoliciesContentWindowsBranchCache::EnableWindowsBranchCache
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\PeerDist\Service' -ValueName "Enable" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.HotspotAuthentication::HotspotAuth_Enable
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\HotspotAuthentication' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.PlugandPlay::P2P_Disabled
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\policies\Microsoft\Peernet' -ValueName "Disabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.OfflineFiles::Pol_Enabled
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\NetCache' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #endregion

        #region Session Time Settings
        #From https://learn.microsoft.com/en-us/training/modules/configure-user-experience-settings/6-configure-session-timeout-properties
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Idle_Limit_1
        Write-Verbose -Message "Setting some 'Session Time Settings' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU)"
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxIdleTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 900000
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Disconnected_Timeout_1
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxDisconnectionTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 900000
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Limits_2
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxConnectionTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_Session_End_On_Limit_2
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fResetBroken" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #endregion

        #region Enable Screen Capture Protection
        #From https://learn.microsoft.com/en-us/training/modules/manage-access/5-configure-screen-capture-protection-for-azure-virtual-desktop
        #Value 2 is for blocking screen capture on client and server.
        #Write-Verbose -Message "Setting some 'Enable Screen Capture Protection' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU)"
        #$null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fEnableScreenCaptureProtection" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #endregion

        #region Enable Watermarking
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/watermarking#enable-watermarking
        Write-Verbose -Message "Setting some 'Enable Watermarking' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU)"
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fEnableWatermarking" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1

        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "WatermarkingHeightFactor" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 180
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "WatermarkingOpacity" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2000
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "WatermarkingQrScale" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 4
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "WatermarkingWidthFactor" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 320
        #endregion

        #region Enabling and using the new performance counters
        #From https://learn.microsoft.com/en-us/training/modules/install-configure-apps-session-host/10-troubleshoot-application-issues-user-input-delay
        Write-Verbose -Message "Setting some 'Performance Counters' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU)"
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\System\CurrentControlSet\Control\Terminal Server' -ValueName "EnableLagCounter" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #endregion 

        #region Starter GPOs Management
        Write-Verbose -Message "Starter GPOs Management"
        try {
            $null = Get-GPStarterGPO -Name "Group Policy Reporting Firewall Ports" -ErrorAction Stop
        }
        catch {
            <#
            Write-Warning "The required starter GPOs are not installed. Please click on the 'Create Starter GPOs Folder' under Group Policy Management / Forest / Domains / $DomainName / Starter GPOs before continuing"
            Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "gpmc.msc" -Wait
            #>
            $OutFile = Join-Path -Path $env:Temp -ChildPath StarterGPOs.zip
            Invoke-WebRequest -Uri https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Setup/StarterGPOs.zip -UseBasicParsing -OutFile $OutFile
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
            Write-Verbose -Message "Creating '$($GPO.DisplayName)' Starter GPO"
        }
        $GPLink = $GPO | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore
        Write-Verbose -Message "Linking '$($GPO.DisplayName)' Starter GPO to '$($AVDRootOU.DistinguishedName)' OU"

        $GPO = Get-GPO -Name "Group Policy Remote Update Firewall Ports" -ErrorAction Ignore
        if (-not($GPO)) {
            $GPO = Get-GPStarterGPO -Name "Group Policy Remote Update Firewall Ports" | New-GPO -Name "Group Policy Remote Update Firewall Ports"
            Write-Verbose -Message "Creating '$($GPO.DisplayName)' Starter GPO"
        }
        $GPLink = $GPO | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore
        Write-Verbose -Message "Linking '$($GPO.DisplayName)' Starter GPO to '$($AVDRootOU.DistinguishedName)' OU"
        #endregion
        #endregion
        #endregion

        #region Assigning the Desktop Virtualization Power On Off Contributor
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/start-virtual-machine-connect?tabs=azure-portal#assign-the-desktop-virtualization-power-on-contributor-role-with-the-azure-portal
        #$objId = (Get-AzADServicePrincipal -AppId "9cdead84-a844-4324-93f2-b2e6bb768d07").Id
        $objId = (Get-AzADServicePrincipal -DisplayName "Azure Virtual Desktop").Id
        $SubscriptionId = $AzContext.Subscription.Id
        $Scope = "/subscriptions/$SubscriptionId"
        if (-not(Get-AzRoleAssignment -ObjectId $objId -RoleDefinitionName "Desktop Virtualization Power On Off Contributor" -Scope $Scope)) {
            Write-Verbose -Message "Assigning the 'Desktop Virtualization Power On Off Contributor' RBAC role to Service Principal '$objId' on the Subscription '$SubscriptionId'"
            $null = New-AzRoleAssignment -ObjectId $objId -RoleDefinitionName "Desktop Virtualization Power On Off Contributor" -Scope $Scope
        }
        #endregion
    }
    process {
        #No pipeline input and No -AsJob switch specified
        $PooledHostPools = $HostPool | Where-Object -FilterScript { $_.Type -eq [HostPoolType]::Pooled }
        $PersonalHostPools = $HostPool | Where-Object -FilterScript { $_.Type -eq [HostPoolType]::Personal }

        #From https://stackoverflow.com/questions/7162090/how-do-i-start-a-job-of-a-function-i-just-defined
        #From https://stackoverflow.com/questions/76844912/how-to-call-a-class-object-in-powershell-jobs
        if ($AsJob) {
            #Setting the ThrottleLimit to the total number of host pool VM instances + 1
            $ThrottleLimit = $($HostPool.VMNumberOfInstances | Measure-Object -Sum).Sum + $HostPool.Count + 1
            Write-Verbose -Message "`$ThrottleLimit: $ThrottleLimit"
            $null = Start-ThreadJob -ScriptBlock { $null } -ThrottleLimit $ThrottleLimit

            $ExportedFunctions = [scriptblock]::Create(@"
                Function Wait-AzVMPowerShell  { ${Function:Wait-AzVMPowerShell } }
                Function New-AzAvdPooledHostPoolSetup { ${Function:New-AzAvdPooledHostPoolSetup} }
                Function New-AzAvdPersonalHostPoolSetup { ${Function:New-AzAvdPersonalHostPoolSetup} }
                Function Grant-ADJoinPermission { ${Function:Grant-ADJoinPermission} }
                Function Start-MicrosoftEntraIDConnectSync { ${Function:Start-MicrosoftEntraIDConnectSync} }
                Function Get-AzVMCompute { ${Function:Get-AzVMCompute} }
                Function Wait-PSSession { ${Function:Wait-PSSession} }
                function Set-AdminConsent { ${Function:Set-AdminConsent} }
                Function Copy-MSIXDemoAppAttachPackage { ${Function:Copy-MSIXDemoAppAttachPackage} }
                Function Copy-MSIXDemoPFXFile { ${Function:Copy-MSIXDemoPFXFile} }
                Function Get-AzKeyVaultNameAvailability { ${Function:Get-AzKeyVaultNameAvailability} }
                Function Add-AzAvdSessionHost { ${Function:Add-AzAvdSessionHost} }                       
                Function New-AzAvdSessionHost { ${Function:New-AzAvdSessionHost} }
                Function Add-CategoryFullPath { ${Function:Add-CategoryFullPath} }                
                Function New-FSLogixIntuneSettingsCatalogConfigurationPolicyViaGraphAPI { ${Function:New-FSLogixIntuneSettingsCatalogConfigurationPolicyViaGraphAPI} }  
                Function New-AVDIntuneSettingsCatalogConfigurationPolicyViaGraphAPI { ${Function:New-AVDIntuneSettingsCatalogConfigurationPolicyViaGraphAPI} }  
                Function New-IntunePowerShellScriptViaCmdlet { ${Function:New-IntunePowerShellScriptViaCmdlet} }  
                Function Set-GroupPolicyDefinitionSettingViaCmdlet { ${Function:New-GroupPolicyDefinitionSettingViaCmdlet} } 
                Function Get-GroupPolicyDefinitionPresentationViaCmdlet { ${Get-GroupPolicyDefinitionPresentationViaCmdlet} } 
                Function Get-CallerPreference { ${Function:Get-CallerPreference} }
                Function New-MFAForAllUsersConditionalAccessPolicy { ${Function:New-MFAForAllUsersConditionalAccessPolicy} }
                Function Get-MgGraphObject { ${Function:Get-MgGraphObject} }
                Function New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI { ${Function:New-IntuneSettingsCatalogConfigurationPolicySettingsViaGraphAPI} }   
"@)
            $Jobs = @()
            $Jobs += foreach ($CurrentPooledHostPool in $PooledHostPools) {
                Write-Verbose -Message "Starting background job for '$($CurrentPooledHostPool.Name)' Pooled HostPool Creation (via New-AzAvdPooledHostPoolSetup) ... "
                Start-ThreadJob -ScriptBlock { New-AzAvdPooledHostPoolSetup -HostPool $using:CurrentPooledHostPool -ADOrganizationalUnit $using:AVDRootOU -NoMFAEntraIDGroupName $using:NoMFAEntraIDGroupName -LogDir $LogDir -AsJob *>&1 | Out-File -FilePath $("{0}\New-AzAvdPooledHostPoolSetup_{1}_{2}.txt" -f $using:LogDir, $($using:CurrentPooledHostPool).Name, (Get-Date -Format 'yyyyMMddHHmmss')) } -InitializationScript $ExportedFunctions #-StreamingHost $Host
            }

            $Jobs += foreach ($CurrentPersonalHostPool in $PersonalHostPools) {
                Write-Verbose -Message "Starting background job for '$($CurrentPersonalHostPool.Name)' Personal HostPool Creation (via New-AzAvdPersonalHostPoolSetup)"
                Start-ThreadJob -ScriptBlock { New-AzAvdPersonalHostPoolSetup -HostPool $using:CurrentPersonalHostPool -ADOrganizationalUnit $using:AVDRootOU -LogDir $LogDir -AsJob *>&1 | Out-File -FilePath $("{0}\New-AzAvdPersonalHostPoolSetup_{1}_{2}.txt" -f $using:LogDir, $($using:CurrentPersonalHostPool).Name, (Get-Date -Format 'yyyyMMddHHmmss')) } -InitializationScript $ExportedFunctions #-StreamingHost $Host
            }

            Write-Verbose -Message "Waiting the background jobs complete"
            $Jobs | Receive-Job -Wait -AutoRemoveJob
            #Write-Verbose -Message "Removing the background jobs"
            #$Jobs | Remove-Job -Force
        }
        else {
            if ($null -ne $PooledHostPools) {
                #$PooledHostPools | New-AzAvdPooledHostPoolSetup -ADOrganizationalUnit $AVDRootOU -NoMFAEntraIDGroupName $NoMFAEntraIDGroupName -LogDir $LogDir 
                New-AzAvdPooledHostPoolSetup -HostPool $PooledHostPools -ADOrganizationalUnit $AVDRootOU -NoMFAEntraIDGroupName $NoMFAEntraIDGroupName -LogDir $LogDir 
                <#
                foreach ($CurrentPooledHostPool in $PooledHostPools) {
                    New-AzAvdPooledHostPoolSetup -HostPool $CurrentPooledHostPool -ADOrganizationalUnit $AVDRootOU -NoMFAEntraIDGroupName $NoMFAEntraIDGroupName -LogDir $LogDir
                }
                #>
            }
            if ($null -ne $PersonalHostPools) {
                #$PersonalHostPools | New-AzAvdPersonalHostPoolSetup -ADOrganizationalUnit $AVDRootOU -LogDir $LogDir
                New-AzAvdPersonalHostPoolSetup -HostPool $PersonalHostPools -ADOrganizationalUnit $AVDRootOU -LogDir $LogDir
                <#
                foreach ($CurrentPersonalHostPool in $PersonalHostPools) {
                    New-AzAvdPersonalHostPoolSetup -HostPool $CurrentPersonalHostPool -ADOrganizationalUnit $AVDRootOU -LogDir $LogDir
                }
                #>  
            }
        }
    }
    end {
        $IntuneHostPools = $HostPool | Where-Object -FilterScript { $_.Intune }
        if ($IntuneHostPools) {
            Sync-IntuneSessionHostViaCmdlet -HostPool $IntuneHostPools
        }
        $EndTime = Get-Date
        $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
        Write-Host -Object "Overall HostPool Setup Processing Time: $($TimeSpan.ToString())"
        Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    }
}

function Restart-AzAvdSessionHost {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [HostPool[]]$HostPool,
        [switch] $Wait
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    $SessionHostNames = foreach ($CurrentHostPool in $HostPool) { (Get-AzWvdSessionHost -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPool.GetResourceGroupName() -ErrorAction Ignore).ResourceId -replace ".*/" | Where-Object -FilterScript { -not([string]::IsNullOrEmpty($_)) } }

    $Jobs = foreach ($CurrentSessionHostName in $SessionHostNames) {
        Write-Host -Object "Restarting '$CurrentSessionHostName' Azure VM"
        Get-AzVM -Name $CurrentSessionHostName | Restart-AzVM -AsJob
    }
    if ($Wait)
    {
        Write-Host -Object "Waiting for all restarts"
        $Jobs | Wait-Job | Out-Null
        $Jobs | Remove-Job -Force
    }
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

function New-AzAvdHostPoolBackup {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [HostPool[]]$HostPool,
        [Parameter(Mandatory = $false)]
        [Alias('BackupDir')]
        [string]$Directory = [Environment]::GetFolderPath("MyDocuments")
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    $null = New-Item -Path $Directory -ItemType Directory -Force
    $JSONFilePath = Join-Path -Path $Directory -ChildPath $("HostPool_{0:yyyyMMddHHmmss}.json" -f (Get-Date))
    Write-Verbose -Message "Backing up Host Pool Configuration into '$JSONFilePath'"
    $HostPool.GetPropertyForJSON() | ConvertTo-Json -Depth 1 | Out-File -FilePath $JSONFilePath -Force
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
    return $(Get-Item -Path $JSONFilePath)
}

#Use the AD OU for generating the RDG file. Had to be called after the AD Object creation (at the end of the processing)
function New-AzAvdRdcMan {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        #[string]$FullName = $(Join-Path -Path $([Environment]::GetFolderPath("Desktop")) -ChildPath "$((Get-ADDomain).DNSRoot).rdg"),
        [string]$FullName = $(Join-Path -Path $([Environment]::GetFolderPath("Desktop")) -ChildPath "$([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name).rdg"),
        [Parameter(Mandatory = $true)]
        [HostPool[]]$HostPool,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,
        [switch] $Open,
        [switch] $Install,
        [switch] $Update
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

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
        Write-Verbose -Message "Creating '$FullName' file"
        Set-Content -Value $RDGFileContentTemplate -Path $FullName
    }

    $AVDRDGFileContent = [xml](Get-Content -Path $FullName)
    $AVDFileElement = $AVDRDGFileContent.RDCMan.file
    $AVDGroupElement = $AVDFileElement.group | Where-Object -FilterScript {
        $_.ChildNodes.Name -eq $RootAVDOUName
    }

    foreach ($CurrentHostPool in $HostPool) {
        Write-Verbose -Message "Processing '$($CurrentHostPool.Name)' HostPool"
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
            
            Write-Verbose -Message "Processing '$ParentCurrentOU'"
            $ParentElement = $groupElement.group | Where-Object -FilterScript { $_.ChildNodes.Name -eq $ParentCurrentOU }
            if ($ParentElement) {
                Write-Verbose -Message "'$ParentCurrentOU' found under '$($groupElement.FirstChild.name)'"
            } 
            else {
                $ParentElement = $groupElement.AppendChild($AVDRDGFileContent.CreateElement('group'))
                $propertiesElement = $ParentElement.AppendChild($AVDRDGFileContent.CreateElement('properties'))
                $nameElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('name'))
                Write-Verbose -Message "Creating '$ParentCurrentOU' level"
                $nameTextNode = $nameElement.AppendChild($AVDRDGFileContent.CreateTextNode($ParentCurrentOU))
                $expandedElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('expanded'))
                $expandedTextNode = $expandedElement.AppendChild($AVDRDGFileContent.CreateTextNode('True'))
            }
            $groupElement = $ParentElement
        }

        if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
            if ($null -ne $CurrentHostPool.KeyVault) {
                $LocalAdminUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminUserName -AsPlainText
                $LocalAdminPassword = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminPassword).SecretValue
                $LocalAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($LocalAdminUserName, $LocalAdminPassword)
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
            $SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $ResourceGroupName
            if ($null -ne $SessionHosts) {
                $SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
                $Machines = foreach ($CurrentSessionHostName in $SessionHostNames) {
                    Write-Verbose -Message "Processing '$CurrentSessionHostName' Session Host"
                    $VM = Get-AzVM -Name $CurrentSessionHostName -ResourceGroupName $resourceGroupName
                    $NIC = Get-AzNetworkInterface -Name $($VM.NetworkProfile.NetworkInterfaces.Id -replace ".*/")
                    $PrivateIpAddress = $NIC.IpConfigurations.PrivateIPAddress
                    [pscustomobject]@{DisplayName = $CurrentSessionHostName; Name = $PrivateIpAddress }
                }
            }
        }
        foreach ($CurrentMachine in $Machines) {
            Write-Verbose -Message "Processing '$($CurrentMachine.Name)' Machine"
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
        Write-Verbose -Message "Downloading the latest RDCMan version form SysInternals"
        $Response = Invoke-WebRequest -Uri "https://download.sysinternals.com/files/RDCMan.zip" -UseBasicParsing -OutFile $OutFile -PassThru
        Write-Verbose -Message "Extracting the downloaded archive file to system32"
        $System32 = $(Join-Path -Path $env:windir -ChildPath "system32")
        $RDCManProcess = (Get-Process -Name rdcman -ErrorAction Ignore)
        #If RDCMan is running for system32 folder
        if (($null -ne $RDCManProcess) -and ((Split-Path -Path $RDCManProcess.Path -Parent) -eq $System32)) {
            Write-Warning "RDCMan is running. Unable to update the update the executable in the '$System32' folder."
        }
        else { 
            Expand-Archive -Path $OutFile -DestinationPath $System32 -Force
        }
        Write-Verbose -Message "Removing the downloaded archive file to system32"
        Remove-Item -Path $OutFile -Force
        if ($Open) {
            Write-Verbose -Message "Opening RDC Manager"
            #Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "rdcman ""$FullName"""
            Start-Process -FilePath "rdcman" -ArgumentList """$FullName"""
        }
    }
    elseif ($Open) {
        & $FullName
    }
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

#Use the HostPool properties for generating the RDG file. Doesn't required to be called after the AD Object creation. Can be called at the start of the processing.
function New-AzAvdRdcManV2 {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        #[string]$FullName = $(Join-Path -Path $([Environment]::GetFolderPath("Desktop")) -ChildPath "$((Get-ADDomain).DNSRoot).rdg"),
        [string]$FullName = $(Join-Path -Path $([Environment]::GetFolderPath("Desktop")) -ChildPath "$([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name).rdg"),
        [Parameter(Mandatory = $true)]
        [HostPool[]]$HostPool,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,
        [switch] $Open,
        [switch] $Install,
        [switch] $Update
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

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
        Write-Verbose -Message "Creating '$FullName' file"
        Set-Content -Value $RDGFileContentTemplate -Path $FullName
    }

    $AVDRDGFileContent = [xml](Get-Content -Path $FullName)
    $AVDFileElement = $AVDRDGFileContent.RDCMan.file
    $AVDGroupElement = $AVDFileElement.group | Where-Object -FilterScript {
        $_.ChildNodes.Name -eq $RootAVDOUName
    }

    foreach ($CurrentHostPool in $HostPool) {
        Write-Verbose -Message "Processing '$($CurrentHostPool.Name)' HostPool"
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
            
            Write-Verbose -Message "Processing '$ParentLevel'"
            $ParentElement = $groupElement.group | Where-Object -FilterScript { $_.ChildNodes.Name -eq $ParentLevel }
            if ($ParentElement) {
                Write-Verbose -Message "'$ParentLevel' found under '$($groupElement.FirstChild.name)'"
            } 
            else {
                $ParentElement = $groupElement.AppendChild($AVDRDGFileContent.CreateElement('group'))
                $propertiesElement = $ParentElement.AppendChild($AVDRDGFileContent.CreateElement('properties'))
                $nameElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('name'))
                Write-Verbose -Message "Creating '$ParentLevel' level"
                $nameTextNode = $nameElement.AppendChild($AVDRDGFileContent.CreateTextNode($ParentLevel))
                $expandedElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('expanded'))
                $expandedTextNode = $expandedElement.AppendChild($AVDRDGFileContent.CreateTextNode('True'))
            }
            $groupElement = $ParentElement
        }

        if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
            if ($null -ne $CurrentHostPool.KeyVault) {
                $LocalAdminUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminUserName -AsPlainText
                $LocalAdminPassword = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminPassword).SecretValue
                $LocalAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($LocalAdminUserName, $LocalAdminPassword)
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
            $SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $ResourceGroupName
            if ($null -ne $SessionHosts) {
                $SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
                $Machines = foreach ($CurrentSessionHostName in $SessionHostNames) {
                    Write-Verbose -Message "Processing '$CurrentSessionHostName' Session Host"
                    $VM = Get-AzVM -Name $CurrentSessionHostName -ResourceGroupName $resourceGroupName
                    $NIC = Get-AzNetworkInterface -Name $($VM.NetworkProfile.NetworkInterfaces.Id -replace ".*/")
                    $PrivateIpAddress = $NIC.IpConfigurations.PrivateIPAddress
                    [pscustomobject]@{DisplayName = $CurrentSessionHostName; Name = $PrivateIpAddress }
                }
            }
        }
        foreach ($CurrentMachine in $Machines) {
            Write-Verbose -Message "Processing '$($CurrentMachine)' Machine"
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
        Write-Verbose -Message "Downloading the latest RDCMan version form SysInternals"
        $Response = Invoke-WebRequest -Uri "https://download.sysinternals.com/files/RDCMan.zip" -UseBasicParsing -OutFile $OutFile -PassThru
        Write-Verbose -Message "Extracting the downloaded archive file to system32"
        $System32 = $(Join-Path -Path $env:windir -ChildPath "system32")
        $RDCManProcess = (Get-Process -Name rdcman -ErrorAction Ignore)
        #If RDCMan is running for system32 folder
        if (($null -ne $RDCManProcess) -and ((Split-Path -Path $RDCManProcess.Path -Parent) -eq $System32)) {
            Write-Warning "RDCMan is running. Unable to update the update the executable in the '$System32' folder."
        }
        else { 
            Expand-Archive -Path $OutFile -DestinationPath $System32 -Force
        }
        Write-Verbose -Message "Removing the downloaded archive file to system32"
        Remove-Item -Path $OutFile -Force
        if ($Open) {
            Write-Verbose -Message "Opening RDC Manager"
            #Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "rdcman ""$FullName"""
            Start-Process -FilePath "rdcman" -ArgumentList """$FullName"""
        }
    }
    elseif ($Open) {
        & $FullName
    }
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

#From https://learn.microsoft.com/en-us/azure/virtual-desktop/autoscale-scaling-plan?tabs=powershell
function New-AzAvdScalingPlan {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [HostPool[]] $HostPool
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    foreach ($CurrentHostPool in $HostPool) {
        #region Sclaing Plan
        $AzWvdHostPool = (Get-AzWvdHostPool | Where-Object -FilterScript { $_.Name -eq $($CurrentHostPool.Name) })
        $ResourceGroupName = $CurrentHostPool.GetResourceGroupName()
        $ScalingPlanName = $CurrentHostPool.GetAzAvdScalingPlanName()
        Write-Host -Object "Setting up a Scaling Plan for the '$CurrentHostPool.Name' HostPool"
        $scalingPlanParams = @{
            ResourceGroupName = $ResourceGroupName
            Name              = $ScalingPlanName
            Location          = $CurrentHostPool.Location
            Description       = $CurrentHostPool.Name
            FriendlyName      = $CurrentHostPool.Name
            HostPoolType      = $CurrentHostPool.Type
            TimeZone          = (Get-TimeZone).Id
            HostPoolReference = @(@{'hostPoolArmPath' = $AzWvdHostPool.Id; 'scalingPlanEnabled' = $CurrentHostPool.ScalingPlan })
        }
        $scalingPlan = New-AzWvdScalingPlan @scalingPlanParams
        #endregion

        if ($CurrentHostPool.Type -eq [HostPoolType]::Pooled) {
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
            if ($CurrentHostPool.HibernationEnabled) {
                $PeakActionOnDisconnect = 'Hibernate'
                $RampDownActionOnLogoff = 'Hibernate'
            }
            else {
                $PeakActionOnDisconnect = 'Deallocate '
                $RampDownActionOnLogoff = 'Deallocate '
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
                RampUpActionOnDisconnect          = 'Deallocate'
                RampUpMinutesToWaitOnLogoff       = '3'
                RampUpActionOnLogoff              = 'Deallocate'
                PeakStartTimeHour                 = '9'
                PeakStartTimeMinute               = '0'
                PeakStartVMOnConnect              = 'Enable'
                PeakMinutesToWaitOnDisconnect     = '10'
                PeakActionOnDisconnect            = $PeakActionOnDisconnect
                PeakMinutesToWaitOnLogoff         = '15'
                PeakActionOnLogoff                = 'Deallocate'
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
                OffPeakActionOnDisconnect         = 'Deallocate'
                OffPeakMinutesToWaitOnLogoff      = '15'
                OffPeakActionOnLogoff             = 'Deallocate'
                #Verbose                           = $true
            }

            $scalingPlanPersonalSchedule = New-AzWvdScalingPlanPersonalSchedule @scalingPlanPersonalScheduleParams
        }
    }
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}

#endregion

Export-ModuleMember -Function Connect-Azure, Install-AVDGPOSettings, Install-FSLogixGPOSettings, Install-RequiredModule, Invoke-AzAvdOperationalInsightsQuery, New-AzAvdHostPoolBackup, New-AzAvdHostPoolSetup, New-AzAvdRdcMan, New-AzAvdScalingPlan, New-AzHostPoolSessionHostCredentialKeyVault, New-AzureComputeGallery, Register-AzRequiredResourceProvider, Remove-AzAvdHostPoolSetup, Restart-AzAvdSessionHost, Set-MgBetaAVDUsersGroupLicense, Start-MicrosoftEntraIDConnectSync, Test-AzAvdKeyVaultNameAvailability, Test-AzAvdStorageAccountNameAvailability, Test-Domaincontroller, Update-MgBetaUserUsageLocation