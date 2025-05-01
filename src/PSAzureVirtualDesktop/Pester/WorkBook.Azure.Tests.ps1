param (
    [Parameter(Mandatory)]
    [string[]] $WorkBookName
)

Describe "Azure Virtual Desktop Workbooks"{
    Context "'<_>' Workbook" -ForEach $WorkBookName {
        It  "'<_>' Workbook exists" {
            $DisplayName = $_
            $(Get-AzApplicationInsightsWorkbook -Category workbook | Where-Object -FilterScript { $_.DisplayName -eq $DisplayName}) | Should -Not -BeNullOrEmpty #-ErrorAction Stop
        }
    }
}
