param (
    #[Parameter(Mandatory)]
    [hashtable] $WorkBook
)

Describe "Azure Virtual Desktop Workbooks"{
    Context "'<_>' Workbook" -ForEach $WorkBook.Keys {
        It  "'<_>' Workbook exists" {
            $DisplayName = $_
            $(Get-AzApplicationInsightsWorkbook -Category workbook | Where-Object -FilterScript { $_.DisplayName -eq $DisplayName}) | Should -Not -BeNullOrEmpty #-ErrorAction Stop
        }
    }
}
