<#
.SYNOPSIS
    Removes Microsoft Entra Elevated Access (User Access Administrator role) from a specified user or the current user.

.DESCRIPTION
    This script automates the removal of Elevated Access in Entra by removing the User Access Administrator
    role assignment at the root scope ("/"). It uses Azure REST APIs to handle the role management operations.
    
    The script includes a confirmation prompt before removing access, which can be bypassed using the -Force parameter.
    All operations are timestamped for better tracking and auditing.

.PARAMETER UserId
    Optional. The Object ID of the user whose elevated access should be removed.
    If not provided, the script will use the currently authenticated user's ID.
    The script automatically converts User Principal Names (email addresses) to Object IDs.

.PARAMETER Force
    Optional. Switch parameter to bypass the confirmation prompt.

.EXAMPLE
    .\Remove-ElevatedAccess.ps1
    Removes elevated access for the currently authenticated user after confirmation.

.EXAMPLE
    .\Remove-ElevatedAccess.ps1 -UserId "12345678-1234-1234-1234-123456789012"
    Removes elevated access for the specified user ID after confirmation.

.EXAMPLE
    .\Remove-ElevatedAccess.ps1 -UserId "user@domain.com"
    Removes elevated access for the specified user (automatically converts email to Object ID) after confirmation.

.EXAMPLE
    .\Remove-ElevatedAccess.ps1 -Force
    Removes elevated access for the current user without confirmation prompt.

.NOTES
    Author: Sebastian Flæng Markdanner
    Website: https://chanceofsecurity.com
    Version: 1.1
    Last Updated: 2025-02-16
    
    Requirements:
    - Azure PowerShell Module (Az)
    - Active Entra ID Global Administrator Role
#>

[CmdletBinding()]
param(
    [string]$UserId,    # User Object ID for whom to remove elevated access
    [switch]$Force      # Skip confirmation prompt
)

# Add timestamp function
function Get-Timestamp {
    return "[{0:yyyy-MM-dd HH:mm:ss}]" -f (Get-Date)
}

# Ensure Az module is installed
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Write-Host "📦 Installing Az PowerShell module..." -ForegroundColor Yellow
    Install-Module -Name Az -Scope CurrentUser -Force -AllowClobber
}

# Connect to Azure (if not already authenticated)
if (-not (Get-AzContext)) {
    Write-Host "🔑 No active Azure session found. Initiating login..." -ForegroundColor Yellow
    Connect-AzAccount
}

# Define API URLs and versions
$managementApi = "https://management.azure.com"
$apiVersion = "2022-04-01"
$roleDefinitionApi = "$managementApi/providers/Microsoft.Authorization/roleDefinitions?api-version=$apiVersion&`$filter=roleName+eq+'User Access Administrator'"

# Get access token for Azure Management API
$accessTokenARM = (Get-AzAccessToken -ResourceUrl $managementApi).Token

# Set request headers for Azure ARM API calls
$headersARM = @{
    "Authorization" = "Bearer $accessTokenARM"
    "Content-Type"  = "application/json"
}

# Step 1: Get User Access Administrator Role Definition ID
Write-Host "🔍 Retrieving User Access Administrator role definition..." -ForegroundColor Yellow
$roleResponse = Invoke-RestMethod -Uri $roleDefinitionApi -Method Get -Headers $headersARM
$roleDefinitionId = $roleResponse.value[0].id

if (-not $roleDefinitionId) {
    Write-Host "❌ Failed to retrieve User Access Administrator Role Definition ID." -ForegroundColor Red
    Write-Host "   Please ensure you have sufficient permissions to view role definitions." -ForegroundColor Red
    exit
}

Write-Host "✅ Retrieved User Access Administrator Role ID: $roleDefinitionId" -ForegroundColor Green

# Step 2: Determine the User Object ID
if (-not $UserId) {
    Write-Host "👤 No User ID provided, using currently authenticated user..." -ForegroundColor Yellow
    $currentUser = (Get-AzContext).Account.Id
    
    # Convert UPN to Object ID if the current user is identified by email/UPN
    if ($currentUser -notmatch '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {
        Write-Host "🔄 Converting user principal name to Object ID..." -ForegroundColor Yellow
        try {
            $UserId = (Get-AzADUser -UserPrincipalName $currentUser).Id
            if (-not $UserId) {
                throw "Unable to find Object ID for user $currentUser"
            }
        }
        catch {
            Write-Host "❌ Failed to retrieve Object ID for user $currentUser" -ForegroundColor Red
            Write-Host "   Error: $_" -ForegroundColor Red
            exit
        }
    }
    else {
        $UserId = $currentUser
    }
}

if (-not $UserId) {
    Write-Host "❌ Failed to retrieve the user's Object ID. Please provide one manually using the -UserId parameter." -ForegroundColor Red
    exit
}

Write-Host "🔍 Using User Object ID: $UserId" -ForegroundColor Yellow

# Step 3: Get Role Assignments for User at Root Scope using ARM API
Write-Host "🔍 Searching for elevated access role assignments..." -ForegroundColor Yellow
$roleAssignmentsApi = "$managementApi/providers/Microsoft.Authorization/roleAssignments?api-version=$apiVersion&`$filter=principalId+eq+'$UserId'"
$roleAssignmentsResponse = Invoke-RestMethod -Uri $roleAssignmentsApi -Method Get -Headers $headersARM

# Find role assignment for User Access Administrator at "/" scope
$roleAssignment = $roleAssignmentsResponse.value | Where-Object {
    $_.properties.roleDefinitionId -eq $roleDefinitionId -and $_.properties.scope -eq "/"
}

if (-not $roleAssignment) {
    Write-Host "❌ No elevated access role assignments found for removal." -ForegroundColor Red
    Write-Host "   The user either doesn't have elevated access or it was already removed." -ForegroundColor Yellow
    exit
}

$roleAssignmentId = $roleAssignment.name

Write-Host "✅ Found Elevated Access Role Assignment ID: $roleAssignmentId" -ForegroundColor Green

# Step 4: Remove Elevated Access
$removeRoleApi = "$managementApi/providers/Microsoft.Authorization/roleAssignments/$($roleAssignmentId)?api-version=$apiVersion"

Write-Host "🔗 Attempting to remove Elevated Access using URL: $removeRoleApi" -ForegroundColor Cyan

# Add confirmation unless -Force is used
if (-not $Force) {
    $confirmation = Read-Host "Are you sure you want to remove Elevated Access for user $UserId? (Y/N)"
    if ($confirmation -ne 'Y') {
        Write-Host "Operation cancelled by user." -ForegroundColor Yellow
        exit
    }
}

try {
    Invoke-RestMethod -Uri $removeRoleApi -Method Delete -Headers $headersARM | Out-Null
    Write-Host "✅ $(Get-Timestamp) Successfully removed Elevated Access for user: $UserId" -ForegroundColor Green
    Write-Host "   The user no longer has User Access Administrator privileges at the root scope." -ForegroundColor Green
} catch {
    Write-Host "❌ $(Get-Timestamp) Failed to remove Elevated Access for user: $UserId" -ForegroundColor Red
    Write-Host "   Error: $_" -ForegroundColor Red
    Write-Host "   Please ensure you have sufficient permissions to remove role assignments." -ForegroundColor Red
}