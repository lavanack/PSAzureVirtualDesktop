# Change log for PSAzureVirtualDesktop

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

- [Change log for PSAzureVirtualDesktop](#change-log-for-psazurevirtualdesktop)
  - [\[Unreleased\]](#unreleased)
    - [Changed](#changed)
  - [\[1.0.4\] - 2024-11-11](#104---2024-11-11)
    - [Changed](#changed-1)
  - [\[1.0.3\] - 2024-10-24](#103---2024-10-24)
    - [Changed](#changed-2)
  - [\[1.0.2\] - 2024-09-27](#102---2024-09-27)
    - [Changed](#changed-3)
  - [\[1.0.1\] - 2024-09-06](#101---2024-09-06)
    - [Changed](#changed-4)
  - [\[1.0.0\] - 2024-09-05](#100---2024-09-05)
    - [Changed](#changed-5)

  
## [Unreleased]

### Changed

- 2024-11-11 - Updated CHANGELOG.md
- 2024-09-27 - Updated CHANGELOG.md
- 2024-09-05 - Created CHANGELOG.md

## [1.0.4] - 2024-11-11

### Changed

- Updating Pester Tests
- Setting the Sign-in frequency duration to 1 Hour for the '[AVD] Require multifactor authentication for all users' Conditional Access Policy
- Installing VM Insights via https://learn.microsoft.com/en-us/azure/azure-monitor/vm/vminsights-enable?tabs=powershell#enable-vm-insights-1
- Renaming the Data Collection Rules to be compliant with AVD Configuration Workbook and AVD Insights (cf. https://www.reddit.com/r/AZURE/comments/1ddac0z/avd_insights_dcr_does_not_appear/?tl=fr and https://learn.microsoft.com/en-us/azure/azure-monitor/vm/vminsights-enable?tabs=powershell#enable-vm-insights-using-arm-templates)
- Adding Diagnostics Settings for the Desktop and RemoteApp Applictaion Groups
- - Changing the Diagnostics Settings to AllLogs

  
## [1.0.3] - 2024-10-24

### Changed

- Changing credential management by adding [Get-LocalAdminCredential](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/Get-LocalAdminCredential) and [Get-AdjoinCredential](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/Get-AdjoinCredential) functions
- Minor fixes
  
## [1.0.2] - 2024-09-27

### Changed

- Adding the UseKeyVaultForStorageAccountKey() static method and UseKeyVaultForStorageAccountKey_ static property on the [HostPool](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/HostPool-PowerShell-Classes#hostpool-powershell-class-base-class) PowerShell class to store the Storage Account (for MSIX and FSLogix) Key in an Azure Key Vault to be compliant with the Secure Future Initiative (SFI) (Only required for MSFTees)
- Code Cleanup (Part 1): Removing useless and non-used functions and code
- Disabling PositionalBinding for all functions
- Reformating code
- Code optimizations
   
## [1.0.1] - 2024-09-06

### Changed

- Minor update
  
## [1.0.0] - 2024-09-05

### Changed

- Initial release
