<#
.SYNOPSIS
Creates a mail-enabled security group, a shared mailbox, and an application access policy in Exchange Online.

.DESCRIPTION
This script connects to Exchange Online, creates a mail-enabled security group, a shared mailbox, and an application access policy with specified parameters. It hides the mail-enabled security group from the address list and restricts access for the app to the group members.

.PARAMETER GroupName
The name of the mail-enabled security group to be created.

.PARAMETER GroupAlias
The alias for the mail-enabled security group.

.PARAMETER GroupEmail
The email address for the mail-enabled security group.

.PARAMETER SharedMailboxName
The email address for the shared mailbox.

.PARAMETER SharedMailboxDisplayName
The display name for the shared mailbox.

.PARAMETER SharedMailboxAlias
The alias for the shared mailbox.

.PARAMETER ClientId
The Application (Client) ID of the Entra ID app registration.

.EXAMPLE
.\RestrictServicePrincipalEmail.ps1 `
    -GroupName "SMTP Graph" `
    -GroupAlias "smtp-graph" `
    -GroupEmail "smtp-graph@contoso.com" `
    -SharedMailboxName "privroles@contoso.com" `
    -SharedMailboxDisplayName "Privileged Roles Monitoring" `
    -SharedMailboxAlias "privroles" `
    -ClientId "12345678-abcd-efgh-ijkl-9876543210ab" `

.NOTES
Author: Sebastian Flæng Markdanner
Website: https://chanceofsecurity.com
Version: 1.0

- Requires the ExchangeOnlineManagement PowerShell module.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$GroupName,

    [Parameter(Mandatory = $true)]
    [string]$GroupAlias,

    [Parameter(Mandatory = $true)]
    [string]$GroupEmail,

    [Parameter(Mandatory = $true)]
    [string]$SharedMailboxName,

    [Parameter(Mandatory = $true)]
    [string]$SharedMailboxDisplayName,

    [Parameter(Mandatory = $true)]
    [string]$SharedMailboxAlias,

    [Parameter(Mandatory = $true)]
    [string]$ClientId
)

# Connect to Exchange Online
Connect-ExchangeOnline

# Creates a new mail-enabled security group
New-DistributionGroup -Name $GroupName -Alias $GroupAlias -Type Security

# Set email address and hide the mail-enabled security group from the address list
Set-DistributionGroup -Identity $GroupName -EmailAddresses SMTP:$GroupEmail -HiddenFromAddressListsEnabled $true

# Creates a new shared mailbox
New-Mailbox -Shared -Name $SharedMailboxName -DisplayName $SharedMailboxDisplayName -Alias $SharedMailboxAlias

# Add the shared mailbox to the mail-enabled security group
Add-DistributionGroupMember -Identity $GroupName -Member $SharedMailboxName

# Create the application access policy
New-ApplicationAccessPolicy -AppId $ClientId -PolicyScopeGroupId $GroupEmail -AccessRight RestrictAccess -Description "Restrict this app to send mails only to members of the group $GroupName"

# Output confirmation
Write-Output "Resources created successfully: mail-enabled security group '$GroupName' and Shared Mailbox '$SharedMailboxName'. Application Access Policy applied."
