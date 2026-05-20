#region function definitions
function Install-AzDesktopVirtualizationModule {
    [CmdletBinding(PositionalBinding=$false)]
    Param (
    )
    $ModuleName = "Az.DesktopVirtualization"
    $RequiredVersion = "5.4.6"
    $InstalledVersions = Get-Module -Name $ModuleName -ListAvailable | Sort-Object -Property Version -Descending
    if ($RequiredVersion -notin $InstalledVersions.Version) {
        #Installing Module if not installed
        Install-Module -Name $ModuleName -RequiredVersion "$RequiredVersion-preview" -AllowPrerelease -AllowClobber -AcceptLicense -Force
    }
    #Unloading Module from Memory
    Remove-Module -Name $ModuleName -Force -ErrorAction Ignore
    Import-Module -Name $ModuleName -RequiredVersion $RequiredVersion -Force
}
#endregion

Install-AzDesktopVirtualizationModule #-Verbose