param (
    #[Parameter(Mandatory)]
    [string] $LogDir
)

BeforeDiscovery {
    $LogFiles = Get-ChildItem -Path $LogDir -Filter *.txt -File 
}

Describe "Log Files" {
    Context '<_.FullName>' -ForEach $LogFiles {
        It  '<_.FullName> has no error' {
            #$_ | Select-String -Pattern "~~~" -Quiet | Should -BeFalse
            ($_ | Select-String -Pattern "~~~").Count  | Should -Be 0 -Because 'No errors should occur'
        }
    }
}