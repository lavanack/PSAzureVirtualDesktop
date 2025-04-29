# Changelog for PSAzureVirtualDesktop

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

- [Changelog for PSAzureVirtualDesktop](#changelog-for-psazurevirtualdesktop)
  - [\[Unreleased\]](#unreleased)
    - [Changed](#changed)
  - [\[1.0.12\] - 2025-04-29](#1012---2025-04-29)
  - [\[1.0.11\] - 2025-04-16](#1011---2025-04-16)
  - [\[1.0.10\] - 2025-04-14](#1010---2025-04-14)
  - [\[1.0.9\] - 2025-04-04](#109---2025-04-04)
  - [\[1.0.8\] - 2025-02-12](#108---2025-02-12)
  - [\[1.0.7\] - 2024-12-26](#107---2024-12-26)
  - [\[1.0.6\] - 2024-12-26](#106---2024-12-26)
  - [\[1.0.5\] - 2024-12-26](#105---2024-12-26)
  - [\[1.0.4\] - 2024-12-26](#104---2024-12-26)
  - [\[1.0.3\] - 2024-10-24](#103---2024-10-24)
  - [\[1.0.2\] - 2024-09-27](#102---2024-09-27)
  - [\[1.0.1\] - 2024-09-06](#101---2024-09-06)
  - [\[1.0.0\] - 2024-09-05](#100---2024-09-05)

## [Unreleased]

### Changed

- 2025-04-29 - Updated `CHANGELOG.md`
- 2025-04-16 - Updated `CHANGELOG.md`
- 2024-12-26 - Updated `CHANGELOG.md`
- 2024-11-11 - Updated `CHANGELOG.md`
- 2024-09-27 - Updated `CHANGELOG.md`
- 2024-09-05 - Created `CHANGELOG.md`

## [1.0.12] - 2025-04-29

- Updating OS from Windows 11 23H2 to Windows 11 24H2 for the AVD Session Hosts
  
## [1.0.11] - 2025-04-16

- Renamed the `Get-PsAvdMSIXProfileShare` function to [`Get-PsAvdAppAttachProfileShare`](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/Get-PsAvdAppAttachProfileShare)
  
## [1.0.10] - 2025-04-14

- Changed the naming convention for [MSIX AppAttach](https://learn.microsoft.com/azure/virtual-desktop/app-attach-overview?pivots=msix-app-attach) and [Azure AppAttach](https://learn.microsoft.com/azure/virtual-desktop/app-attach-overview?pivots=app-attach) Storage Accounts from `msix*` to `apat*`
- Changed the name of the file share for [MSIX AppAttach](https://learn.microsoft.com/azure/virtual-desktop/app-attach-overview?pivots=msix-app-attach) and [Azure AppAttach](https://learn.microsoft.com/azure/virtual-desktop/app-attach-overview?pivots=app-attach) from `msix` to `appattach`
- Updated the content of the `redirections.xml` files for the FSLogix Profile Containers and Office Containers
- Disabled the retention policy for the Storage Accounts used for [MSIX AppAttach](https://learn.microsoft.com/azure/virtual-desktop/app-attach-overview?pivots=msix-app-attach) and [Azure AppAttach](https://learn.microsoft.com/azure/virtual-desktop/app-attach-overview?pivots=app-attach)
- Updated code for managing licenses as a workaround for [this issue](https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3201)

## [1.0.9] - 2025-04-04

- Removed dedicated RDP ShortPath functions (enabled by default)  

## [1.0.8] - 2025-02-12

- Changed VM Security Type from `Standard` to `TrustedLaunch` for the AVD Session Hosts
- Moved from Access Policy to RBAC for managing Key Vaults and assigned the "Key Vault Administrator" role to the logged-in user.

## [1.0.7] - 2024-12-26

- Moved back Pester test files to the `Pester` folder

## [1.0.6] - 2024-12-26

- Fixed bug for the Security event log (for collecting failures)
- Moved Pester test files to the `tools\Pester` folder

## [1.0.5] - 2024-12-26

- Published by mistake

## [1.0.4] - 2024-12-26

- Removed the `UseKeyVaultForStorageAccountKey()` static method and `UseKeyVaultForStorageAccountKey_` static property on the [HostPool](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/HostPool-PowerShell-Classes#hostpool-powershell-class-base-class) PowerShell class
- Updated Pester Tests
- Set the Sign-in frequency duration to 1 Hour for the '[AVD] Require multifactor authentication for all users' Conditional Access Policy
- Installed VM Insights via [this guide](https://learn.microsoft.com/en-us/azure/azure-monitor/vm/vminsights-enable?tabs=powershell#enable-vm-insights-1)
- Renamed the Data Collection Rules to be compliant with AVD Configuration Workbook and AVD Insights (cf. [Reddit discussion](https://www.reddit.com/r/AZURE/comments/1ddac0z/avd_insights_dcr_does_not_appear/?tl=fr) and [Microsoft documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/vm/vminsights-enable?tabs=powershell#enable-vm-insights-using-arm-templates))
- Added Diagnostics Settings for the Desktop and RemoteApp Application Groups
- Changed the Diagnostics Settings to `AllLogs`
- Dedicated Subnet(s) can be used for the AVD Session Hosts
- Private Endpoints for MSIX AppAttach, Azure AppAttach, and FSLogix file shares can be used on multiple virtual networks
- FSLogix Cloud Cache Container is now available as an option for Pooled Host Pools. We will use the [Azure Paired Regions](https://learn.microsoft.com/en-us/azure/reliability/cross-region-replication-azure#azure-paired-regions).
- Azure Site Recovery (ASR) is now available as an option for all Host Pools. We will use the [Azure Paired Regions](https://learn.microsoft.com/en-us/azure/reliability/cross-region-replication-azure#azure-paired-regions).
- Fixed bug for the Security event log (for collecting failures)
- The following switches are now available for the [`New-PsAvdHostPoolSetup`](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/New-PsAvdHostPoolSetup) function:
  - `AMBA`: For installing the [Azure Monitor Baseline Alerts for Azure Virtual Desktop](https://azure.github.io/azure-monitor-baseline-alerts/patterns/specialized/avd/) after the setup. The [`New-PsAvdAzureMonitorBaselineAlertsDeployment`](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/New-PsAvdAzureMonitorBaselineAlertsDeployment) function is used for this purpose
  - `WorkBook`: For installing some AVD Configuration Workbook after the setup. The [`Import-PsAvdWorkbook`](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/Import-PsAvdWorkbook) function is used for this purpose
  - `Restart`: For restarting the Session Hosts after the setup. The [`Restart-PsAvdSessionHost`](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/Restart-PsAvdSessionHost) function is used for this purpose
  - `RDCMan`: For creating an RDCMan file after the setup. The [`New-PsAvdRdcMan`](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/New-PsAvdRdcMan) function is used for this purpose

## [1.0.3] - 2024-10-24

- Changed credential management by adding [`Get-LocalAdminCredential`](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/Get-LocalAdminCredential) and [`Get-AdjoinCredential`](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/Get-AdjoinCredential) functions
- Minor fixes
  
## [1.0.2] - 2024-09-27

- Added the `UseKeyVaultForStorageAccountKey()` static method and `UseKeyVaultForStorageAccountKey_` static property on the [HostPool](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/HostPool-PowerShell-Classes#hostpool-powershell-class-base-class) PowerShell class to store the Storage Account (for MSIX and FSLogix) Key in an Azure Key Vault to be compliant with the Secure Future Initiative (SFI) (Only required for MSFTees)
- Code Cleanup (Part 1): Removed useless and non-used functions and code
- Disabled `PositionalBinding` for all functions
- Reformatted code
- Code optimizations

## [1.0.1] - 2024-09-06

- Minor update
  
## [1.0.0] - 2024-09-05

- Initial release
