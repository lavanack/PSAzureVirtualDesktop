param (
    #[Parameter(Mandatory)]
    [HostPool[]] $HostPool
)

BeforeAll {
    $AzLocation = (Get-AzLocation).Location
}

Describe "<_.Name> HostPool - Class Instantiation" -ForEach $HostPool {
    Context '<_.Name>' {
        It  '<_.Name> is an HostPool' {
            $_ | Should -BeOfType -ExpectedType HostPool #-ErrorAction Stop
        }

        It '<_.Name> has a valid Azure location' {
            $_.Location | Should -BeIn $AzLocation #-ErrorAction Stop
        }


    }
}