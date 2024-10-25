#region function definitions
Function Test-NewerAvailableModule {
    [CmdletBinding()]
    Param (
    ) 
    Write-Verbose -Message "Entering function '$($MyInvocation.MyCommand)'"

    $ModuleName = "PSAzureVirtualDesktop"
    #We have to parse the version to get the correct sorting. Without this "1.11.0" -gt "1.2.0" returns $false
    $GreatestInstalledModuleVersion = (Get-Module $ModuleName -ListAvailable | Select-Object -Property *, @{Name = "ParsedVersion"; Expression = { [version]::Parse($_.Version) } } | Sort-Object -Property ParsedVersion | Select-Object -Last 1).ParsedVersion
    $FoundModule = Find-Module -Name $ModuleName -ErrorAction Ignore
    if (-not([string]::IsNullOrEmpty($FoundModule))) {
        $LatestAvailableModuleVersion = [version]::Parse((Find-Module -Name $ModuleName -ErrorAction Ignore).Version)
        if ($GreatestInstalledModuleVersion -lt $LatestAvailableModuleVersion) {
            Write-Warning -Message "A newer version of the '$ModuleName' module is available: $LatestAvailableModuleVersion. Consider updating it ! (You're using $GreatestInstalledModuleVersion)"
            #Update-Module -Name $ModuleName -Force
        }
        else {
            Write-Verbose -Message "You're using the latest version ($GreatestInstalledModuleVersion) of the '$ModuleName' module"
        }
    }
    else {
        Write-Warning -Message "No module found in the registered repositories: $((Get-PSRepository).Name -join ', ')"
    }
    Write-Verbose -Message "Leaving function '$($MyInvocation.MyCommand)'"
}
#endregion

Test-NewerAvailableModule #-Verbose