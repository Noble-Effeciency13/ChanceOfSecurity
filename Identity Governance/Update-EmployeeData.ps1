<#
.SYNOPSIS
    Updates an employee's hire and leave dates in Microsoft Graph using their User Principal Name.

.DESCRIPTION
    This script connects to Microsoft Graph and updates the specified user's hire and leave dates. 
    It performs basic date format validation and updates the user's profile.

.PARAMETER UserPrincipalName
    The User Principal Name (UPN) of the employee whose dates are being updated.
    Required parameter. Example: john.doe@contoso.com

.PARAMETER HireDateInput
    The employee's hire date in 'yyyy-MM-dd' format.
    Required parameter. Example: 2024-01-15

.PARAMETER LeaveDateInput
    The employee's planned leave date in 'yyyy-MM-dd' format.
    Required parameter. Example: 2024-12-31

.EXAMPLE
    .\Update-EmployeeData.ps1 -UserPrincipalName john.doe@contoso.com -HireDateInput 2024-01-15
    
    Updates John Doe's hire date in Microsoft Entra via Microsoft Graph.

.EXAMPLE
    .\Update-EmployeeData.ps1 -UserPrincipalName john.doe@contoso.com -LeaveDateInput 2024-12-31
    
    Updates John Doe's leave dates in Microsoft Entra via Microsoft Graph.

.NOTES
    Prerequisites:
    - Microsoft Graph PowerShell SDK must be installed
    - Requires administrative permissions with following scopes:
      * User.ReadWrite.All
      * User-LifeCycleInfo.ReadWrite.All

    Author: Sebastian Flæng Markdanner
    Website: https://chanceofsecurity.com
    Version: 1.4
    Last Updated: 2024-12-15

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.users/update-mguser
#>

param (
    [Parameter(Mandatory = $true, 
               HelpMessage = "Enter the user's full User Principal Name (UPN)")]
    [ValidateNotNullOrEmpty()]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false, 
               HelpMessage = "Enter hire date in yyyy-MM-dd format")]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$HireDateInput,

    [Parameter(Mandatory = $false, 
               HelpMessage = "Enter leave date in yyyy-MM-dd format")]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$LeaveDateInput
)

# Check if at least one date parameter is provided
if (-not $HireDateInput -and -not $LeaveDateInput) {
    throw "At least one of the parameters 'HireDateInput' or 'LeaveDateInput' must be provided."
}

# Function to validate and format dates
function Format-DateToISO8601 {
    param (
        [string]$DateInput,
        [string]$TimeSuffix
    )
    try {
        # Validate date format
        if (-not ($DateInput -match "^\d{4}-\d{2}-\d{2}$")) {
            throw "Invalid date format: $DateInput. Please use 'yyyy-MM-dd'."
        }
        # Return date in ISO 8601 format
        return "$DateInput$TimeSuffix"
    } catch {
        throw "Error processing date input: $_"
    }
}

# Main script execution block
try {
    # Format the dates if provided
    $EmployeeHireDate = if ($HireDateInput) {
        Format-DateToISO8601 -DateInput $HireDateInput -TimeSuffix "T00:00:00Z"
    } else { $null }

    $EmployeeLeaveDateTime = if ($LeaveDateInput) {
        Format-DateToISO8601 -DateInput $LeaveDateInput -TimeSuffix "T23:59:59Z"
    } else { $null }

    # Verbose connection status
    Write-Verbose "Connecting to Microsoft Graph with required scopes..."
    
    # Connect to Microsoft Graph with specified scopes
    Connect-MgGraph -Scopes "User.ReadWrite.All", "User-LifeCycleInfo.ReadWrite.All" | Out-Null

    # Update user lifecycle dates if provided
    $UpdateParams = @{
        UserId = $UserPrincipalName
    }
    if ($EmployeeHireDate) { $UpdateParams.EmployeeHireDate = $EmployeeHireDate }
    if ($EmployeeLeaveDateTime) { $UpdateParams.EmployeeLeaveDateTime = $EmployeeLeaveDateTime }

    Update-MgUser @UpdateParams

    # Confirm update and retrieve updated user details
    $UpdatedUser = Get-MgUser -UserId $UserPrincipalName -Property EmployeeHireDate,EmployeeLeaveDateTime

    # Output results
    Write-Host "Successfully updated lifecycle dates for $($UserPrincipalName):" -ForegroundColor Green
    if ($EmployeeHireDate) {
        Write-Host "Hire Date: $($UpdatedUser.EmployeeHireDate)" -ForegroundColor Cyan
    }
    if ($EmployeeLeaveDateTime) {
        Write-Host "Leave Date: $($UpdatedUser.EmployeeLeaveDateTime)" -ForegroundColor Cyan
    }
} 
catch {
    # Robust error handling with detailed error message
    Write-Error "Operation failed: $_"
    throw
} 
finally {
    # Always attempt to disconnect, suppressing any disconnection errors
    try { 
        if ((Get-MgContext).AuthType -ne 'None') {
            Disconnect-MgGraph | Out-Null 
        }
    } catch {}
}