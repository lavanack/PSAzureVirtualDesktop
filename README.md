# PSAzureVirtualDesktop

- [PSAzureVirtualDesktop](#psazurevirtualdesktop)
  - [Release Notes](#release-notes)
  - [Change log](#change-log)
  - [Introduction](#introduction)
  - [Requirements](#requirements)
    - [PowerShell Modules](#powershell-modules)
    - [Domain Controller](#domain-controller)
  - [Installation](#installation)
  - [Documentation and Examples](#documentation-and-examples)

## Release Notes

- 1.0.0
  - First stable release

## Change log

A full list of changes in each version can be found in the [change log](CHANGELOG.md).

## Introduction

This GitHub repository is the home of the PowerShell module [PSAzureVirtualDesktop](https://www.powershellgallery.com/packages/PSAzureVirtualDesktop). This module is a collection of PowerShell classes and functions that can be used to quickly deploy Azure Virtual Desktop (AVD) Proof-Of-Concepts. FSLogix, MSIX, Intune, ADDS or Entra join VMs, Scaling Plan, Hibernation, OS Ephemeral Disks are some of the supported options available.

> [!IMPORTANT]
The module is designed to be used in a lab environment and is not intended for production use. The module is provided as-is and is not supported by Microsoft. <b>For a Microsoft-supported version deployment, I suggest using the Azure Virtual Desktop (AVD) Landing Zone Accelerator (LZA), which is available [here](https://github.com/Azure/avdaccelerator). Please note that this only covers the Azure component where the module [PSAzureVirtualDesktop](https://www.powershellgallery.com/packages/PSAzureVirtualDesktop) encompasses both OnPrem and Azure configurations.</b>

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
Install-Module -Name PSAzureVirtualDesktop
```
To confirm installation, run the below command:

```powershell
Get-Module PSAzureVirtualDesktop -ListAvailable
```

## Documentation and Examples

For a full list of functions in PSAzureVirtualDesktop and examples on their use, check out the [PSAzureVirtualDesktop wiki](https://github.com/lavanack/PSAzureVirtualDesktop/wiki).
