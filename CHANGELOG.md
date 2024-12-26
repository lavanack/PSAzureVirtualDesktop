# Change log for PSAzureVirtualDesktop

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

- [Change log for PSAzureVirtualDesktop](#change-log-for-psazurevirtualdesktop)
  - [\[Unreleased\]](#unreleased)
    - [Changed](#changed)
  - [\[1.0.6\] - 2024-12-26](#106---2024-12-26)
    - [Changed](#changed-1)
  - [\[1.0.5\] - 2024-12-26](#105---2024-12-26)
    - [Changed](#changed-2)
  - [\[1.0.4\] - 2024-12-26](#104---2024-12-26)
    - [Changed](#changed-3)
  - [\[1.0.3\] - 2024-10-24](#103---2024-10-24)
    - [Changed](#changed-4)
  - [\[1.0.2\] - 2024-09-27](#102---2024-09-27)
    - [Changed](#changed-5)
  - [\[1.0.1\] - 2024-09-06](#101---2024-09-06)
    - [Changed](#changed-6)
  - [\[1.0.0\] - 2024-09-05](#100---2024-09-05)
    - [Changed](#changed-7)

## [Unreleased]

### Changed

- 2024-12-26 - Updated CHANGELOG.md
- 2024-11-11 - Updated CHANGELOG.md
- 2024-09-27 - Updated CHANGELOG.md
- 2024-09-05 - Created CHANGELOG.md

## [1.0.6] - 2024-12-26

### Changed

- Fixing bug for the Security eventlog (for collecting failures)

## [1.0.5] - 2024-12-26

### Changed

- Published by mistake

## [1.0.4] - 2024-12-26

### Changed

- Removing the UseKeyVaultForStorageAccountKey() static method and UseKeyVaultForStorageAccountKey_ static property on the [HostPool](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/HostPool-PowerShell-Classes#hostpool-powershell-class-base-class) PowerShell class
- Updating Pester Tests
- Setting the Sign-in frequency duration to 1 Hour for the '[AVD] Require multifactor authentication for all users' Conditional Access Policy
- Installing VM Insights via <https://learn.microsoft.com/en-us/azure/azure-monitor/vm/vminsights-enable?tabs=powershell#enable-vm-insights-1>
- Renaming the Data Collection Rules to be compliant with AVD Configuration Workbook and AVD Insights (cf. <https://www.reddit.com/r/AZURE/comments/1ddac0z/avd_insights_dcr_does_not_appear/?tl=fr> and <https://learn.microsoft.com/en-us/azure/azure-monitor/vm/vminsights-enable?tabs=powershell#enable-vm-insights-using-arm-templates>)
- Adding Diagnostics Settings for the Desktop and RemoteApp Application Groups
- Changing the Diagnostics Settings to AllLogs
- Dedicated Subnet(s) can be used for the AVD Session Hosts
- Private Endpoints for MSIX AppAttach, Azure AppAttach and FSLogix file shares can be used on multiple virtual networks
- FSLogix Cloud Cache Container is now available as option for Pooled Host Pools. We will use the [Azure Paired Regions](https://learn.microsoft.com/en-us/azure/reliability/cross-region-replication-azure#azure-paired-regions).
- Azure Site Recovery (ASR) is now available as option for all Host Pools. We will use the [Azure Paired Regions](https://learn.microsoft.com/en-us/azure/reliability/cross-region-replication-azure#azure-paired-regions).
- Fixing bug for the Security eventlog (for collecting failures)
- The following switches are now available for the [New-PsAvdHostPoolSetup](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/New-PsAvdHostPoolSetup) function
  - AMBA: For installing the [Azure Monitor Baseline Alerts for Azure Virtual Desktop](https://azure.github.io/azure-monitor-baseline-alerts/patterns/specialized/avd/)  after the setup. The [New-PsAvdAzureMonitorBaselineAlertsDeployment](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/New-PsAvdAzureMonitorBaselineAlertsDeployment) function is used for this purpose
  - WorkBook: For installing some AVD Configuration Workbook after the setup. The [Import-PsAvdWorkbook](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/Import-PsAvdWorkbook) function is used for this purpose
  - Restart: For restarting the Session Hosts after the setup. The [Restart-PsAvdSessionHost](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/Restart-PsAvdSessionHost) function is used for this purpose
  - RDCMan: For creating a RDCMan file after the setup. The [New-PsAvdRdcMan](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/New-PsAvdRdcMan) function is used for this purpose

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
