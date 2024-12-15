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
    .\Update-UserLifecycleDates.ps1 -UserPrincipalName john.doe@contoso.com -HireDateInput 2024-01-15 -LeaveDateInput 2024-12-31
    
    Updates John Doe's hire and leave dates in Microsoft Graph.

.NOTES
    Prerequisites:
    - Microsoft Graph PowerShell SDK must be installed
    - Requires administrative permissions with following scopes:
      * User.ReadWrite.All
      * User-LifeCycleInfo.ReadWrite.All

    Author: Sebastian Flæng Markdanner
    Website: https://chanceofsecurity.com
    Version: 1.3
    Last Updated: 2024-12-15

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.users/update-mguser
#>

param (
    [Parameter(Mandatory = $true, 
               HelpMessage = "Enter the user's full User Principal Name (UPN)")]
    [ValidateNotNullOrEmpty()]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $true, 
               HelpMessage = "Enter hire date in yyyy-MM-dd format")]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$HireDateInput,

    [Parameter(Mandatory = $true, 
               HelpMessage = "Enter leave date in yyyy-MM-dd format")]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$LeaveDateInput
)

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
    # Format the dates
    $EmployeeHireDate = Format-DateToISO8601 -DateInput $HireDateInput -TimeSuffix "T00:00:00Z"
    $EmployeeLeaveDateTime = Format-DateToISO8601 -DateInput $LeaveDateInput -TimeSuffix "T23:59:59Z"

    # Verbose connection status
    Write-Verbose "Connecting to Microsoft Graph with required scopes..."
    
    # Connect to Microsoft Graph with specified scopes
    Connect-MgGraph -Scopes "User.ReadWrite.All", "User-LifeCycleInfo.ReadWrite.All" | Out-Null

    # Update user lifecycle dates
    Update-MgUser -UserId $UserPrincipalName `
                  -EmployeeHireDate $EmployeeHireDate `
                  -EmployeeLeaveDateTime $EmployeeLeaveDateTime

    # Confirm update and retrieve updated user details
    $UpdatedUser = Get-MgUser -UserId $UserPrincipalName -Property EmployeeHireDate,EmployeeLeaveDateTime

    # Output results
    Write-Host "Successfully updated lifecycle dates for $($UserPrincipalName):" -ForegroundColor Green
    Write-Host "Hire Date: $($UpdatedUser.EmployeeHireDate)" -ForegroundColor Cyan
    Write-Host "Leave Date: $($UpdatedUser.EmployeeLeaveDateTime)" -ForegroundColor Cyan
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