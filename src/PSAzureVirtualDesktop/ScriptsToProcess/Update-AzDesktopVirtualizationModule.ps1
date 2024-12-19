#region function definitions
function Update-AzDesktopVirtualizationModule {
    [CmdletBinding()]
    Param (
        [string] $MaximumVersion = "5.3.0"
    )
    
    $HighestInstalledVersion = Get-Module -Name Az.DesktopVirtualization -ListAvailable | Sort-Object -Property Version -Descending | Select-Object -First 1
    Write-Verbose "`$HighestInstalledVersion:`r`n$($HighestInstalledVersion | Out-String)"
    if ($HighestInstalledVersion.Version -lt [system.version]::parse($MaximumVersion)) {
        $InstalledModule = Install-Module -Name Az.DesktopVirtualization -Force -MaximumVersion $MaximumVersion -AllowPrerelease -PassThru
        Write-Verbose "Installed Version:`r`n$($InstalledModule | Out-String)"
    }
}
#endregion

Update-AzDesktopVirtualizationModule #-Verbose