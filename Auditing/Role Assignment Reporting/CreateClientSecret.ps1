<#
.SYNOPSIS
Creates a client secret for an Entra ID app registration.

.DESCRIPTION
This script creates a client secret for an Entra ID app registration using the application's Client ID (ClientId).
It calculates the secret's expiration date based on the specified duration, generates the secret, and copies the secret value to the clipboard.

.PARAMETER ClientId
The Application (Client) ID of the Entra ID app registration.

.PARAMETER Description
A custom description or identifier for the client secret.

.PARAMETER Duration
The number of years the client secret will remain valid. Default is 99 years.

.EXAMPLE
.\Create-ClientSecret.ps1 -ClientId "12345678-90ab-cdef-1234-567890abcdef" -Description "MyAppSecret" -Duration 99
Creates a client secret for the specified app with a validity period of 99 years and copies the secret value to the clipboard.

.NOTES
Author:     Sebastian Flæng Markdanner
Website:    https://chanceofsecurity.com
Version:    1.0

- Requires the Az PowerShell module.
- User must be authenticated to Azure with sufficient permissions to manage app registrations.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [string]$Description,
    
    [Parameter(Mandatory = $true)]
    [int]$Duration = 99
)

# Authenticate to Azure
Connect-AzAccount

# Calculate start and end dates
$StartDate = Get-Date
$EndDate = $StartDate.AddYears($Duration)

# Encode the description to Base64
$EncodedDescription = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Description))

# Create client secret
$ClientSecret = Get-AzADApplication -ApplicationId $ClientId | New-AzADAppCredential -StartDate $StartDate -EndDate $EndDate -CustomKeyIdentifier $EncodedDescription

# Copy secret to clipboard
$ClientSecret.SecretText | Set-Clipboard

# Notify user and wait
Write-Output "Client secret created and copied to clipboard. Script will end in 10 seconds."
Start-Sleep -Seconds 10