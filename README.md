# PSAzureVirtualDesktop

- [PSAzureVirtualDesktop](#psazurevirtualdesktop)
  - [Release Notes](#release-notes)
  - [Change log](#change-log)
  - [What's Next](#whats-next)
  - [Introduction](#introduction)
  - [Requirements](#requirements)
    - [PowerShell Modules](#powershell-modules)
    - [Domain Controller](#domain-controller)
  - [Installation](#installation)
  - [Documentation and Examples](#documentation-and-examples)

## Release Notes

- [1.0.15]
  - Switching from Standard_D2s_v6 to Standard_D2s_v5 for the AVD Session Hosts (because v6 is not available in every Azure region)
  - Enabling [Azure Private Link with Azure Virtual Desktop](https://learn.microsoft.com/fr-fr/azure/virtual-desktop/private-link-overview)
  - Pester Tests are now optional (via -Pester switch on some functions)
  - RBAC role management improvement
  - Bug fixes
- [1.0.14]
  - [Configuring the session lock behavior for Azure Virtual Desktop](https://learn.microsoft.com/en-us/azure/virtual-desktop/configure-session-lock-behavior?tabs=group-policy)
  - OneDrive management for redirection of the known folders (Desktop, Documents, Pictures) 
- [1.0.13]
  - Enabling SSO
  - Switching from Standard_D2s_v4 to Standard_D2s_v6 for the AVD Session Hosts
  - Adding the more scopes for Graph
  - Updating the '[AVD] Require multifactor authentication for all users' Conditional Access Policy
  - Adding a Toast notification when a user logs in to have information about the FSLogix Profile space used.
  - Adding some code to start VMs in case of eviction due to Spot Instance VM settings.
  - Adding a workbook instance from the [https://blog.itprocloud.de/AVD-Azure-Virtual-Desktop-Error-Drill-Down-Workbook/](https://blog.itprocloud.de/AVD-Azure-Virtual-Desktop-Error-Drill-Down-Workbook/) Azure Workbook Template for every Hostpool.
  - The[AMBA] (http://aka.ms/amba) alerts are now enabled by default
  - Updating Pester Tests
- [1.0.12]
  - Updating OS from Windows 11 23H2 to Windows 11 24H2 for the AVD Session Hosts
- [1.0.11]
  - Renaming the Get-PsAvdMSIXProfileShare function to [Get-PsAvdAppAttachProfileShare](https://github.com/lavanack/PSAzureVirtualDesktop/wiki/Get-PsAvdAppAttachProfileShare)
- 1.0.10
  - Modifications for Storage Account names and file share names for MSIX [MSIX AppAttach](https://learn.microsoft.com/azure/virtual-desktop/app-attach-overview?pivots=msix-app-attach) and [Azure AppAttach](https://learn.microsoft.com/azure/virtual-desktop/app-attach-overview?pivots=app-attach)
- 1.0.9
  - Removing dedicated RDP ShortPath functions (enabled by default)  
- 1.0.8
  - RBAC for managing Key Vaults
  - VM Security Type set to TrustedLaunch
- 1.0.7
  - Minor update
- 1.0.6
  - Fixing bug for the Security eventlog (for collecting failures)
- 1.0.5
  - Published by mistake
- 1.0.4
  - Adding AVD dedicated Virtual network support
  - Bug fixes
- 1.0.3
  - Adding functions for credential management
  - Bug fixes
- 1.0.2
  - Code cleanup and optimizations
- 1.0.1
  - Minor update
- 1.0.0
  - First stable release

## Change log

A full list of changes in each version can be found in the [change log](CHANGELOG.md).

## What's Next

A list of potential changes or evolutions can be found in the [What's next log](Whatsnext.md).

## Introduction

This GitHub repository is the home of the PowerShell module [PSAzureVirtualDesktop](https://www.powershellgallery.com/packages/PSAzureVirtualDesktop). This module is a collection of PowerShell classes and functions that can be used to quickly deploy Azure Virtual Desktop (AVD) Proof-Of-Concepts. FSLogix, MSIX, AppAttach (With AD only for the moment in this project), Intune, ADDS or Entra joined VMs, Scaling Plan, Hibernation, OS Ephemeral Disks are some of the supported options available.

> [!IMPORTANT]
The module is designed to be used in a lab environment and is not intended for production use. The module is provided as-is and is not supported by Microsoft. **For a Microsoft-supported version deployment, I suggest using the Azure Virtual Desktop (AVD) Landing Zone Accelerator (LZA), which is available [here](https://github.com/Azure/avdaccelerator). Please note that this only covers the Azure component where the module [PSAzureVirtualDesktop](https://www.powershellgallery.com/packages/PSAzureVirtualDesktop) encompasses both OnPrem and Azure configurations.**

## Requirements

### PowerShell Modules

The following Powershell modules will be installed as part of the installation of the PSAzureVirtualDesktop module:

- [Az.Accounts](https://www.powershellgallery.com/packages/Az.Accounts)
- [Az.ApplicationInsights](https://www.powershellgallery.com/packages/Az.ApplicationInsights)
- [Az.Compute](https://www.powershellgallery.com/packages/Az.Compute)
- [Az.DesktopVirtualization](https://www.powershellgallery.com/packages/Az.DesktopVirtualization)
- [Az.ImageBuilder](https://www.powershellgallery.com/packages/Az.ImageBuilder)
- [Az.ManagedServiceIdentity](https://www.powershellgallery.com/packages/Az.ManagedServiceIdentity)
- [Az.KeyVault](https://www.powershellgallery.com/packages/Az.KeyVault)
- [Az.Monitor](https://www.powershellgallery.com/packages/Az.Monitor)
- [Az.Network](https://www.powershellgallery.com/packages/Az.Network)
- [Az.OperationalInsights](https://www.powershellgallery.com/packages/Az.OperationalInsights)
- [Az.PrivateDns](https://www.powershellgallery.com/packages/Az.PrivateDns)
- [Az.Resources](https://www.powershellgallery.com/packages/Az.Resources)
- [Az.Storage](https://www.powershellgallery.com/packages/Az.Storage)
- [Microsoft.Graph.Authentication](https://www.powershellgallery.com/packages/Microsoft.Graph.Authentication)
- [Microsoft.Graph.Beta.Applications](https://www.powershellgallery.com/packages/Microsoft.Graph.Beta.Applications)
- [Microsoft.Graph.Beta.DeviceManagement](https://www.powershellgallery.com/packages/Microsoft.Graph.Beta.DeviceManagement)
- [Microsoft.Graph.Beta.DeviceManagement.Actions](https://www.powershellgallery.com/packages/Microsoft.Graph.Beta.DeviceManagement.Actions)
- [Microsoft.Graph.Beta.DeviceManagement.Administration](https://www.powershellgallery.com/packages/Microsoft.Graph.Beta.DeviceManagement.Administration)
- [Microsoft.Graph.Beta.Groups](https://www.powershellgallery.com/packages/Microsoft.Graph.Beta.Groups)
- [Microsoft.Graph.Beta.DirectoryManagement](https://www.powershellgallery.com/packages/Microsoft.Graph.Beta.Identity.DirectoryManagement)
- [Microsoft.Graph.Beta.Identity.SignIns](https://www.powershellgallery.com/packages/Microsoft.Graph.Beta.Identity.SignIns)
- [Microsoft.Graph.Beta.Users](https://www.powershellgallery.com/packages/Microsoft.Graph.Beta.Users)
- [Microsoft.Graph.Beta.Users.Actions](https://www.powershellgallery.com/packages/Microsoft.Graph.Beta.Users.Actions)
- [Pester](https://www.powershellgallery.com/packages/Pester)
- [ThreadJob](https://www.powershellgallery.com/packages/ThreadJob)

The following PowerShell modules are also required to be installed on the machine where the module is being used (cf. [Domain Controller](#domain-controller)):

- [DnsServer](https://learn.microsoft.com/en-us/powershell/module/dnsserver)
- [ActiveDirectory](https://learn.microsoft.com/en-us/powershell/module/activedirectory)

### Domain Controller

Before proceeding, ensure that a Domain Controller is present in your Azure Tenant. This requires a Windows Server with the Active Directory Directory Services role installed and configured. If this is not already set up, you can use the following links to quicky create these resources. The options are listed from least to most preferred:

- [https://aka.ms/m365avdws](https://aka.ms/m365avdws)
- [https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab](https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab)
- [https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab%20-%20PowerShell](https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab%20-%20PowerShell) (Only the New-AAD-Hybrid-Lab.ps1: Step-by-step guide is needed - the rest is optional)

For some configurations (Entra joined VMs/Session Hosts without FSLogix for instance), this Domain Controller is not really required, but we used the ActiveDirectory for managing the user accounts what will be used and synchronized with EntraID via Azure AD Connect.

## Installation

To install from the PowerShell gallery using PowerShellGet (in PowerShell 5.0) run the following command from your Domain Controller:

```powershell
Find-Module -Name PSAzureVirtualDesktop -Repository PSGallery | Install-Module
```

To confirm installation, run the below command:

```powershell
Get-Module PSAzureVirtualDesktop -ListAvailable
```

## Documentation and Examples

For a full list of functions in PSAzureVirtualDesktop and examples on their use, check out the [PSAzureVirtualDesktop wiki](https://github.com/lavanack/PSAzureVirtualDesktop/wiki).
