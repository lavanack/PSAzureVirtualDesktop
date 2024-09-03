param (
    #[Parameter(Mandatory)]
    [HostPool[]] $HostPool
)

BeforeDiscovery {
    $ScalingPlanHostPools = $HostPool | Where-Object -FilterScript {$_.ScalingPlan} 
}

Describe "<_.Name> HostPool - ScalingPlans" -ForEach $ScalingPlanHostPools {
        BeforeEach {
            $ScalingPlan = Get-AzWvdScalingPlan -HostPoolName $_.Name -ResourceGroupName $_.GetResourceGroupName() -ErrorAction Ignore
        }
        Context '<_.Name>' {
            It  '<_.Name> HostPool has the right ScalingPlan' {
                $ScalingPlan.Name | Should -Be $_.GetAzAvdScalingPlanName() #-ErrorAction Stop
        }
    }
}
