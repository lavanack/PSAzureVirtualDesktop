param (
    #[Parameter(Mandatory)]
    [HostPool[]] $HostPool,
    [int] $MinutesAgo = 30
)

BeforeDiscovery {
    [string[]] $Queries = @("Heartbeat | order by TimeGenerated desc | limit 1", "Perf | order by TimeGenerated desc | limit 1", "Event | order by TimeGenerated desc | limit 1")
    [string[]] $PerComputerQueries = @("Heartbeat | summarize arg_max(TimeGenerated, *) by Computer", "Perf | summarize arg_max(TimeGenerated, *) by Computer", "Event | summarize arg_max(TimeGenerated, *) by Computer")
    $AzOperationalInsightsQuery = @{}
    foreach ($CurrentHostPool in $HostPool) {
        $LogAnalyticsWorkspaceName = $CurrentHostPool.GetLogAnalyticsWorkSpaceName()
        $LogAnalyticsWorkspace = Get-AzOperationalInsightsWorkspace -Name $LogAnalyticsWorkspaceName -ResourceGroupName $CurrentHostPool.GetResourceGroupName()
        $Results = foreach ($CurrentPerComputerQuery in $PerComputerQueries) {
            $Result = Invoke-AzOperationalInsightsQuery -WorkspaceId $LogAnalyticsWorkspace.CustomerId -Query $CurrentPerComputerQuery
            $Result.Results | Select-Object -Property @{Name = "Resource"; Expression = { $_.Computer -replace "\..*" } }, @{Name = "HostPool"; Expression = { $CurrentHostPool } }, Type, TimeGenerated, @{Name = "Query"; Expression = { $CurrentPerComputerQuery } }
        }
        #$Results.Results | Select-Object -Property Computer, Type, TimeGenerated
        $AzOperationalInsightsQuery.Add($CurrentHostPool.Name, $Results)
    }
}


Describe "<_.Name> HostPool - LogAnalytics Workspaces" -ForEach $HostPool {
    BeforeEach {
        $LogAnalyticsWorkspaceName = $_.GetLogAnalyticsWorkSpaceName()
    }
    Context '<_.Name>' {
        It  '<_.Name> HostPool has a valid LogAnalytics Workspace' {
            $LogAnalyticsWorkspaceName | Should -Be $_.GetLogAnalyticsWorkSpaceName() #-ErrorAction Stop
        }
        <#
        It  "<_.Name> HostPool session hosts sent data less than $MinutesAgo minutes ago" -ForEach $Queries {
            $Result = Invoke-AzOperationalInsightsQuery -WorkspaceId $LogAnalyticsWorkspace.CustomerId -Query $_
            Get-Date ($Result.Results.TimeGenerated) | Should -BeGreaterThan (Get-Date).AddMinutes(-$MinutesAgo) #-ErrorAction Stop
        }
        #>
    }
    <#
    Context '<_>' -ForEach $Queries {
        It  "'$($CurrentHostPool.Name)' HostPool Session Hosts sent data less than $MinutesAgo minutes ago for '<_>'" {
            $Result = Invoke-AzOperationalInsightsQuery -WorkspaceId $LogAnalyticsWorkspace.CustomerId -Query $_
            Get-Date ($Result.Results.TimeGenerated) | Should -BeGreaterThan (Get-Date).AddMinutes(-$MinutesAgo) #-ErrorAction Stop
        }
    }
    #>
}

Describe "<_.Name> HostPool Session Hosts - LogAnalytics Workspaces" -ForEach $HostPool {
    Context "'<_.Resource>' HostPool Session Hosts" -ForEach $AzOperationalInsightsQuery[$_.Name] {
        It  "'<_.Resource>' Session Host (HostPool: '<_.HostPool.Name>') sent data less than $MinutesAgo minutes ago for '<_.Query>'" {
            Get-Date ($_.TimeGenerated) | Should -BeGreaterThan (Get-Date).AddMinutes(-$MinutesAgo) #-ErrorAction Stop
        }
    }
}
