#region function definitions
function Update-AzDesktopVirtualizationModule {
    [CmdletBinding()]
    Param (
        [string] $MinimumVersion = "5.2.1"
    )
    
    $HighestInstalledVersion = Get-Module -Name Az.DesktopVirtualization -ListAvailable | Sort-Object -Property Version -Descending | Select-Object -First 1
    Write-Verbose "`$HighestInstalledVersion:`r`n$($HighestInstalledVersion | Out-String)"
    if ($HighestInstalledVersion.Version -lt [system.version]::parse($MinimumVersion)) {
        $InstalledModule = Install-Module -Name Az.DesktopVirtualization -Force -MinimumVersion $MinimumVersion -AllowPrerelease -PassThru
        Write-Verbose "Installed Version:`r`n$($InstalledModule | Out-String)"
    }
}
#endregion

Update-AzDesktopVirtualizationModule #-Verbose