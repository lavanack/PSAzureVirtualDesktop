#
# Module manifest for module 'PSAzureVirtualDesktop'
#
# Generated by: Laurent VAN ACKER
#
# Generated on: 07/07/2024
#

@{
   
    # Script module or binary module file associated with this manifest.
    RootModule             = 'PSAzureVirtualDesktop.psm1'

    # Version number of this module.
    ModuleVersion          = '1.0.8'

    # Supported PSEditions
    CompatiblePSEditions   = 'Desktop'

    # ID used to uniquely identify this module
    GUID                   = '7ff087aa-a00a-4939-b929-57a9d168e7a0'

    # Author of this module
    Author                 = 'Laurent VAN ACKER'

    # Company or vendor of this module
    CompanyName            = 'Unknown'

    # Copyright statement for this module
    Copyright              = '2024'

    # Description of the functionality provided by this module
    Description            = 'Build Azure AVD POCs'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion      = '5.1'

    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    DotNetFrameworkVersion = '4.0'

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    CLRVersion             = '4.0'

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules        = @(
        'Az.Accounts', 
        'Az.ApplicationInsights', 
        'Az.Compute'
        'Az.DesktopVirtualization'
        'Az.ImageBuilder', 
        'Az.ManagedServiceIdentity', 
        'Az.KeyVault', 
        'Az.Monitor', 
        'Az.Network', 
        'Az.OperationalInsights', 
        'Az.PrivateDns', 
        'Az.RecoveryServices',
        'Az.Resources', 
        'Az.Storage',
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Beta.Applications',
        'Microsoft.Graph.Beta.DeviceManagement',
        'Microsoft.Graph.Beta.DeviceManagement.Actions',
        'Microsoft.Graph.Beta.DeviceManagement.Administration',
        'Microsoft.Graph.Beta.Groups',
        'Microsoft.Graph.Beta.Identity.DirectoryManagement',
        'Microsoft.Graph.Beta.Identity.SignIns',
        'Microsoft.Graph.Beta.Users',
        'Microsoft.Graph.Beta.Users.Actions',
        'Pester',
        'ThreadJob'
    )

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()
    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    #ScriptsToProcess       = '.\ScriptsToProcess\Test-NewerAvailableModule.ps1', '.\ScriptsToProcess\Update-AzDesktopVirtualizationModule.ps1'
    ScriptsToProcess       = '.\ScriptsToProcess\Test-NewerAvailableModule.ps1'

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport      = 'Connect-PsAvdAzure', 'Get-AzurePairedRegion', 'Get-AzVMCompute', 'Get-AzVMSubnet', 'Get-AzVMVirtualNetwork', 'Get-PsAvdAzGalleryImageDefinition', 'Get-PsAvdFSLogixProfileShare', 'Get-PsAvdLatestOperationalInsightsData', 'Get-PsAvdMSIXProfileShare', 'Import-PsAvdWorkbook', 'Install-PsAvdAvdGpoSettings', 'Install-PsAvdFSLogixGpoSettings', 'Invoke-PsAvdErrorLogFilePester', 'New-AzureComputeGallery', 'New-PsAvdAzureSiteRecoveryPolicyAssignment', 'New-PsAvdHostPoolBackup', 'New-PsAvdHostPoolSessionHostCredentialKeyVault', 'New-PsAvdHostPoolSetup', 'New-PsAvdPrivateDnsZoneSetup', 'New-PsAvdPrivateEndpointSetup', 'New-PsAvdRdcMan', 'New-PsAvdScalingPlan', 'New-PsAvdAzureMonitorBaselineAlertsDeployment', 'Register-PsAvdRequiredResourceProvider', 'Remove-PsAvdHostPoolSetup', 'Restart-PsAvdSessionHost', 'Set-PsAvdMgBetaUsersGroupLicense', 'Start-MicrosoftEntraIDConnectSync', 'Test-Domaincontroller', 'Test-PsAvdKeyVaultNameAvailability', 'Test-PsAvdStorageAccountNameAvailability', 'Update-PsAvdMgBetaUserUsageLocation'

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport        = '*'

    # Variables to export from this module
    VariablesToExport      = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport        = '*'

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData            = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags                       = 'Azure', 'AVD', 'POC'

            # A URL to the license for this module.
            # LicenseUri = ''

            # A URL to the main website for this project.
            ProjectUri                 = 'https://github.com/lavanack/PSAzureVirtualDesktop'

            # Dependent modules managed externally
            ExternalModuleDependencies = "DnsServer", "ActiveDirectory"

            # A URL to an icon representing this module.
            # IconUri = ''

            # Prerelease string of this module
            # Prerelease = 'preview'

            # ReleaseNotes of this module
            # ReleaseNotes = ''

        } # End of PSData hashtable

    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

}

