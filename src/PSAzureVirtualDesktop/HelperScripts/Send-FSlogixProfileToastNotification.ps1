<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free
right to use and modify the Sample Code and to reproduce and distribute
the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software
product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is
embedded; and (iii) to indemnify, hold harmless, and defend Us and
Our suppliers from and against any claims or lawsuits, including
attorneys' fees, that arise or result from the use or distribution
of the Sample Code.
#>
#requires -Version 5

[CmdletBinding(PositionalBinding = $false)]
Param (
)

#region Function definitions
function Send-FSlogixProfileToastNotification {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [string] $FileSystemLabel = "*Profile-$ENV:USERNAME*",
        [int] $TimeoutInMs = 5000
    )
    # Get the relevant informations from the FSLogix profile
    $FSLogixProfileVolume = Get-Volume -FileSystemLabel $FileSystemLabel | Where-Object -FilterScript { $_.DriveType -eq 'Fixed' }

    # Execute only if FSLogix profile is available
    if ($FSLogixProfileVolume -ne $null) {
        # Calculate the free space in percent
        $PercentFree = [Math]::round((($FSLogixProfileVolume.SizeRemaining / $FSLogixProfileVolume.Size) * 100))
        $SizeRemainingInGB = "{0:N0}" -f $($FSLogixProfileVolume.SizeRemaining / 1GB)


        Add-Type -AssemblyName System.Windows.Forms
        $global:BalMsg = New-Object System.Windows.Forms.NotifyIcon

        $bodyText = "($PercentFree% free - $SizeRemainingInGB GB remaining)."
        # If free space is less then 10 % show message
        if ($PercentFree -le 10) {
            $HeadlineText = 'Your profile contingent is almost exhausted. Please inform the IT service!'
            $BalMsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Error
        }
        elseif ($PercentFree -le 20) {
            $HeadlineText = "Your profile contingent is very busy. Please inform the IT service!"
            $BalMsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
        }
        else {
            $HeadlineText = "Your profile contingent has enough space storage."
            $BalMsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        }

        $Path = (Get-Process -id $PID).Path
        $BalMsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($Path)
        $BalMsg.BalloonTipTitle = $HeadlineText
        $BalMsg.BalloonTipText = $bodyText
        $BalMsg.Visible = $true
        $BalMsg.ShowBalloonTip($TimeoutInMs)
    }
}
#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

# Wait 10 sec. till showing the message
Start-Sleep -Seconds 10

#Send-FSlogixProfileToastNotification -FileSystemLabel $env:USERNAME -TimeoutInMs 10000 -Verbose
Send-FSlogixProfileToastNotification -Verbose
#endregion