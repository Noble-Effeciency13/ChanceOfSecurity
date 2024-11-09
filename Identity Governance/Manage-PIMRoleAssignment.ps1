<#
.SYNOPSIS
   Manage Privileged Identity Management (PIM) eligible roles in Microsoft Entra ID, Azure RBAC, and Group Membership.

.NOTES
    Author: Sebastian Flæng Markdanner
    Website: https://chanceofsecurity.com
    Email: Sebastian.Markdanner@chanceofsecurity.com
    Version: 3.1
    Date: 09-11-2024

.DESCRIPTION
   This script allows administrators to create and manage PIM-eligible roles across:
     - Microsoft Entra ID (directory roles)
     - Azure RBAC roles within subscriptions, management groups, resource groups, or resources
     - Group membership eligibility for specified groups in Entra ID

.PARAMETER ScopeType
   Specifies the scope of the role assignment. Valid values are:
      - "EntraID" for Entra ID directory roles
      - "Azure" for Azure RBAC roles
      - "GroupMembership" for PIM-enabled group memberships

    NOTE:
      - Nested groups are NOT supported if the targeted group have Microsoft Entra Role assignments enabled.

.PARAMETER PrincipalIdentifiers
   Array of identifiers for the principals (UPNs for users, display names for groups or applications).

.PARAMETER RoleDefinitionId
   The ID of the role to assign. This parameter is mandatory for Entra ID and Azure RBAC roles.

.PARAMETER GroupAccessId
   Specifies the access level for group membership when ScopeType is "GroupMembership".
   Valid values are:
      - "Owner" for group ownership
      - "Member" for group membership

.PARAMETER GroupDisplayName
   The display name of the group when ScopeType is set to "GroupMembership". This parameter is mandatory for group membership assignments.

.PARAMETER DirectoryScopeId
   The scope of the assignment. Use "/" for tenant-wide scope in Entra ID.

.PARAMETER Scope
   The Azure scope for RBAC role assignments. Can specify:
      - Root scope for the entire tenant (`/`).
      - Management group (`/providers/Microsoft.Management/managementGroups/<ManagementGroupId>`).
      - Subscription (`/subscriptions/<SubscriptionId>`).
      - Resource group (`/subscriptions/<SubscriptionId>/resourceGroups/<ResourceGroupName>`).
      - Specific resource (`/subscriptions/<SubscriptionId>/resourceGroups/<ResourceGroupName>/providers/<ResourceProviderNamespace>/<ResourceType>/<ResourceName>`).
   If not provided, the script defaults to the current subscription in the logged-in context.

.PARAMETER ActionType
   Specifies the type of action to perform. Valid values are:
      - "Active" for assigning an active role
      - "Eligible" for assigning an eligible role
      - "Remove" for removing an existing role assignment.

    NOTE:
      - Eligible Roles are NOT supported for Service principals

.PARAMETER Justification
   A brief description or justification for the role assignment or removal.

.PARAMETER StartDateTime
   The date and time at which the role assignment should begin. Defaults to the current date and time if not specified.

.PARAMETER Duration
   The duration for the role assignment in ISO 8601 format (e.g., "PT10H" for 10 hours). This is applicable to both eligible and active role assignments.

.EXAMPLE
   ./Manage-PIMRoleAssignment.ps1 -ScopeType "GroupMembership" -PrincipalIdentifiers "user1@domain.com", "group2" -ActionType "Eligible" -GroupDisplayName "Engineering" -GroupAccessId "Member" -Justification "Project access"

   Creates an eligible assignment for multiple principals: user "user1@domain.com" and group "group2" as "Members" of the "Engineering" group.

.EXAMPLE
   ./Manage-PIMRoleAssignment.ps1 -ScopeType "EntraID" -PrincipalIdentifiers "group1", "sp1", "user2@domain.com" -RoleDefinitionId "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" -ActionType "Active" -Justification "Directory Reader role assignment for group1" -StartDateTime ([datetime]"2024-12-24T10:00:00Z") -Duration "PT8H"

   Creates an active assignment for the group "group1", the Service Principal "sp1" and the user "user2@domain.com" in Microsoft Entra ID with an 8-hour duration for the Directory Reader role. The assignment starts on December 24, 2024, at 10:00 AM UTC.

.EXAMPLE
   ./Manage-PIMRoleAssignment.ps1 -ScopeType "Azure" -PrincipalIdentifiers "group1", "user3@domain.com" -RoleDefinitionId "acdd72a7-3385-48ef-bd42-f606fba81ae7" -Scope "/subscriptions/<SubscriptionID>" -ActionType "Eligible" -Justification "Read-only access"

   Assigns an eligible role to the group "group1" & user "user3@domain.com" for the reader role in the specified Azure subscription.

.EXAMPLE
   ./Manage-PIMRoleAssignment.ps1 -ScopeType "Azure" -PrincipalIdentifiers "user4@domain.com" -RoleDefinitionId "b24988ac-6180-42a0-ab88-20f7382dd24c" -Scope "/providers/Microsoft.Management/managementGroups/<ManagementGroupId>" -ActionType "Eligible" -Justification "Management group assignment" -Duration ""

   Assigns an eligible Contributor role assignment for the user "user4@domain.com" to the specified Management Group within Azure without an expiration.

.EXAMPLE
   ./Manage-PIMRoleAssignment.ps1 -ScopeType "Azure" -PrincipalIdentifiers "user5@domain.com", "group1" -RoleDefinitionId "b24988ac-6180-42a0-ab88-20f7382dd24c" -Scope "/subscriptions/<SubscriptionId>/resourceGroups/<ResourceGroupName>" -ActionType "Active" -Justification "Resource group access for user5"

   Assigns an active Contributor role assignment for the user "user5@domain.com" and the group "group1" to a specific resource group in Azure with the default 8-hour duration.

.INPUTS
   None. This script does not accept piped input.

.OUTPUTS
   None. This script does not produce output directly.
#>

param (
    [Parameter(Mandatory=$true)][ValidateSet("EntraID", "Azure", "GroupMembership")][string]$ScopeType,
    [Parameter(Mandatory=$true)][string[]]$PrincipalIdentifiers,
    [string]$RoleDefinitionId,
    [ValidateSet("Owner", "Member")][string]$GroupAccessId,
    [string]$GroupDisplayName,
    [string]$DirectoryScopeId = "/",
    [string]$Scope,
    [ValidateSet("Active", "Eligible", "Remove")][string]$ActionType = "Eligible",
    [string]$Justification,
    [datetime]$StartDateTime = (Get-Date),
    [string]$Duration = "PT8H"  # ISO 8601 duration format
)

# Track Graph connection status
$Global:IsGraphConnected = $false

# Custom logging function to provide clear, color-coded output with timestamps
function Write-ScriptLog {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")][string]$Type = "Info",
        [switch]$NoNewline,
        [string]$VerboseMessage
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $colors = @{
        "Info"    = "Cyan"
        "Warning" = "Yellow"
        "Error"   = "Red"
        "Success" = "Green"
    }
    
    $prefix = switch($Type) {
        "Info"    { "INFO" }
        "Warning" { "WARN" }
        "Error"   { "ERROR" }
        "Success" { "SUCCESS" }
    }
    
    # Format and display the main message
    $formatMessage = "[$timestamp] $prefix : $Message"
    if ($NoNewline) {
        Write-Host $formatMessage -ForegroundColor $colors[$Type] -NoNewline
    } else {
        Write-Host $formatMessage -ForegroundColor $colors[$Type]
    }

    # Write verbose message if provided and -Verbose is used
    if ($VerboseMessage -and $Verbose) {
        Write-Host "[$timestamp] VERBOSE : $VerboseMessage" -ForegroundColor "Gray"
    }
}

# Manages Microsoft Graph connection state
# Ensures necessary scopes are available for operations
function Ensure-GraphConnection {
    param (
        # Default scopes required for PIM operations
        [string[]]$Scopes = @(
            "User.Read.All",
            "Group.Read.All", 
            "Application.Read.All",
            "GroupMember.ReadWrite.All",
            "Directory.AccessAsUser.All",
            "RoleManagement.Read.All"
        )
    )
    
    if (-not $Global:IsGraphConnected) {
        try {
            Write-ScriptLog "Connecting to Microsoft Graph..." -Type "Info"
            Connect-MgGraph -Scopes $Scopes -ErrorAction Stop
            $Global:IsGraphConnected = $true
            Write-ScriptLog "Successfully connected to Microsoft Graph." -Type "Success"
        } catch {
            Write-ScriptLog "Failed to connect to Microsoft Graph: $_" -Type "Error"
        }
    } else {
        Write-ScriptLog "Microsoft Graph is already connected." -Type "Info"
    }
}

# Safely disconnects from Microsoft Graph when operations are complete
function Disconnect-GraphIfNeeded {
    if ($Global:IsGraphConnected) {
        try {
            Write-ScriptLog "Disconnecting from Microsoft Graph..." -Type "Info"
            Disconnect-MgGraph
            $Global:IsGraphConnected = $false
            Write-ScriptLog "Successfully disconnected from Microsoft Graph." -Type "Success"
        } catch {
            Write-ScriptLog "Error disconnecting from Microsoft Graph: $_" -Type "Error"
        }
    }
}

# Ensures required PowerShell modules are available and loaded
# Handles version conflicts by importing latest available version
function Ensure-Modules {
    param(
        [string[]]$Modules  # Array of required module names
    )

    foreach ($module in $Modules) {
        # Get latest installed version
        $latestModule = Get-Module -ListAvailable -Name $module | 
            Sort-Object Version -Descending | 
            Select-Object -First 1

        # Remove current version to prevent conflicts
        if (Get-Module -Name $module) {
            Remove-Module -Name $module -Force -ErrorAction SilentlyContinue
        }

        # Import latest version
        if ($latestModule) {
            Write-ScriptLog "Importing latest version of module $module (Version: $($latestModule.Version))" -Type "Info"
            Import-Module -Name $latestModule.Path -ErrorAction Stop
        } else {
            Write-ScriptLog "Module $module is not installed. Please install it before running this script." -Type "Error"
        }
    }
}

# Retrieves group ID using display name with pagination support
# Handles large directories by processing results in chunks
function Get-GroupId {
    param (
        [string]$GroupDisplayName  # Display name of the target group
    )
    
    Ensure-GraphConnection -Scopes "Group.Read.All"
    $nextPage = "https://graph.microsoft.com/v1.0/groups?`$top=100"
    
    do {
        $groupRequest = Invoke-MgGraphRequest -Uri $nextPage -Method Get
        $groups = $groupRequest.Value
        $nextPage = $groupRequest.'@odata.nextLink'
        $group = $groups | Where-Object { $_.displayName -eq $GroupDisplayName }
    } until ($group -or -not $nextPage)
    
    if ($null -eq $group) { 
        throw "Group with display name '$GroupDisplayName' not found." 
    }
    return $group.Id
}

# Checks for existing role assignments to prevent duplicates
# Returns existing assignment if found, null otherwise
function Get-ExistingRoleAssignment {
    param (
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$DirectoryScopeId = "/"
    )

    Ensure-GraphConnection

    try {
        Write-ScriptLog "Checking for existing role assignment" -Type "Info"
        Write-ScriptLog "PrincipalId: $PrincipalId" -Type "Info"
        Write-ScriptLog "Scope: $DirectoryScopeId" -Type "Info"
        Write-ScriptLog "RoleDefinitionId: $RoleDefinitionId" -Type "Info"

        $query = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
        $assignments = Invoke-MgGraphRequest -Uri $query -Method Get

        # Filter assignments based on all criteria
        $existingAssignment = $assignments.Value | Where-Object {
            $_.principalId -eq $PrincipalId -and 
            $_.roleDefinitionId -eq $RoleDefinitionId -and 
            $_.directoryScopeId -eq $DirectoryScopeId
        }

        if ($existingAssignment) {
            Write-ScriptLog "Existing role assignment found for PrincipalId: $PrincipalId" -Type "Success"
            return $existingAssignment
        } else {
            Write-ScriptLog "No existing role assignment found for PrincipalId: $PrincipalId" -Type "Info"
            return $null
        }

    } catch {
        Write-ScriptLog "Error checking for existing role assignment: $_" -Type "Error"
    }
}

# Retrieves data for each principal (user, group, or service principal)
# Supports multiple principal types and handles pagination
function Get-PrincipalsData {
    param (
        [string[]]$PrincipalIdentifiers,  # Array of principal identifiers
        [string]$ScopeType               # Type of scope being processed
    )

    Write-ScriptLog "Starting principal data retrieval process..." -Type "Info"
    
    # Ensure required modules and Graph connection
    Ensure-Modules -Modules @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Groups",
        "Microsoft.Graph.Applications",
        "Microsoft.Graph.Identity.Governance"
    )
    Ensure-GraphConnection

    $principalsData = @()

    # Helper function for paginated API queries
    function Perform-PaginatedLookup {
        param (
            [string]$baseUrl,
            [string]$filterKey,
            [string]$filterValue
        )
        $nextPage = "$baseUrl`?`$top=100"
        do {
            $request = Invoke-MgGraphRequest -Uri $nextPage -Method Get
            $items = $request.Value
            $nextPage = $request.'@odata.nextLink'
            $result = $items | Where-Object { $_.$filterKey -eq $filterValue }
        } until ($result -or -not $nextPage)
        return $result
    }

    # Process each principal identifier
    foreach ($PrincipalIdentifier in $PrincipalIdentifiers) {
        Write-ScriptLog "Processing principal: $PrincipalIdentifier" -Type "Info"

        $principalInfo = @{
            Identifier = $PrincipalIdentifier
            Id = $null
            Type = $null
        }

        # Try to find principal as user
        try {
            Write-ScriptLog "Looking up user: $PrincipalIdentifier" -Type "Info"
            $user = Perform-PaginatedLookup -baseUrl "https://graph.microsoft.com/v1.0/users" -filterKey "userPrincipalName" -filterValue $PrincipalIdentifier
            if ($user) {
                $principalInfo.Id = $user.Id
                $principalInfo.Type = "User"
                Write-ScriptLog "Found user with ID: $($user.Id)" -Type "Success"
            }
        } catch {
            Write-ScriptLog "User lookup failed: $_" -Type "Warning"
        }

        # If not found as user, try as group
        if (-not $principalInfo.Id) {
            try {
                Write-ScriptLog "Looking up group: $PrincipalIdentifier" -Type "Info"
                $group = Perform-PaginatedLookup -baseUrl "https://graph.microsoft.com/v1.0/groups" -filterKey "displayName" -filterValue $PrincipalIdentifier
                if ($group) {
                    $principalInfo.Id = $group.Id
                    $principalInfo.Type = "Group"
                    Write-ScriptLog "Found group with ID: $($group.Id)" -Type "Success"
                }
            } catch {
                Write-ScriptLog "Group lookup failed: $_" -Type "Warning"
            }
        }

        # If not found as user or group, try as service principal
        if (-not $principalInfo.Id) {
            try {
                Write-ScriptLog "Looking up service principal: $PrincipalIdentifier" -Type "Info"
                $sp = Perform-PaginatedLookup -baseUrl "https://graph.microsoft.com/v1.0/servicePrincipals" -filterKey "displayName" -filterValue $PrincipalIdentifier
                if ($sp) {
                    $principalInfo.Id = $sp.Id
                    $principalInfo.Type = "ServicePrincipal"
                    Write-ScriptLog "Found service principal with ID: $($sp.Id)" -Type "Success"
                }
            } catch {
                Write-ScriptLog "Service principal lookup failed: $_" -Type "Warning"
            }
        }

        if ($principalInfo.Id -and $principalInfo.Type) {
            $principalsData += $principalInfo
        } else {
            Write-ScriptLog "No matching principal found for: $PrincipalIdentifier" -Type "Warning"
        }
    }

    Write-ScriptLog "Principal data retrieval complete." -Type "Success"
    return $principalsData
}

# Removes a Service Principal from a specified Microsoft Entra ID group
# Handles direct removal without using PIM schedules
function Remove-ServicePrincipalFromGroup {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DirectoryObjectId
    )

    try {
        Write-ScriptLog "Ensuring Graph connection with necessary permissions..." -Type "Info"
        Ensure-GraphConnection -Scopes @(
            "GroupMember.ReadWrite.All",
            "Directory.AccessAsUser.All"
        )

        Write-ScriptLog "Attempting to remove Service Principal from group..." -Type "Info"
        
        Remove-MgGroupMemberDirectoryObjectByRef `
            -GroupId $GroupId `
            -DirectoryObjectId $DirectoryObjectId `
            -ErrorAction Stop

        Write-ScriptLog "Successfully removed Service Principal from group" -Type "Success"
    }
    catch {
        $simplifiedError = switch -Wildcard ($_.Exception.Message) {
            "*401*Unauthorized*" { "Authorization failed. Please check permissions and admin consent." }
            "*404*" { "Group or Service Principal not found." }
            "*403*" { "Access forbidden. Insufficient permissions." }
            default { "Failed to remove Service Principal from group." }
        }
        
        Write-ScriptLog $simplifiedError -Type "Error" -VerboseMessage $_.Exception.Message
        throw $simplifiedError
    }
}

# Main function to process Graph assignments
# Handles different assignment types and scopes
function Process-GraphAssignments {
    param (
        [array]$principalsData
    )

    Write-ScriptLog "Starting Graph assignments processing..." -Type "Info"

    $scheduleInfo = @{
        startDateTime = $StartDateTime
        expiration    = @{ 
            type     = "AfterDuration"
            duration = $Duration 
        }
    }

    if ($ScopeType -eq "GroupMembership" -and $GroupDisplayName) {
        try {
            $GroupId = Get-GroupId -GroupDisplayName $GroupDisplayName
            Write-ScriptLog "Successfully resolved Group ID: $GroupId" -Type "Success"
        }
        catch {
            Write-ScriptLog "Failed to find group: $GroupDisplayName" -Type "Error" -VerboseMessage $_.Exception.Message
            return
        }
    }

    foreach ($principalInfo in $principalsData) {
        if (-not $principalInfo.Id) {
            Write-ScriptLog "Invalid principal: $($principalInfo.Identifier)" -Type "Warning"
            continue
        }

        try {
            Write-ScriptLog "Processing $ScopeType assignment for principal: $($principalInfo.Identifier)" -Type "Info"

            switch ($ScopeType) {
                "EntraID" {
                    # Special handling for Service Principals in Entra ID
                    if ($principalInfo.Type -eq "ServicePrincipal") {
                        Write-ScriptLog "Processing Service Principal in Entra ID context" -Type "Info"
                        
                        # Check for existing role assignments to prevent duplicates
                        $existingAssignment = Get-ExistingRoleAssignment `
                            -PrincipalId $principalInfo.Id `
                            -RoleDefinitionId $RoleDefinitionId `
                            -DirectoryScopeId $DirectoryScopeId

                        if ($ActionType -eq "Remove") {
                            if ($existingAssignment) {
                                Write-ScriptLog "Removing existing role assignment" -Type "Info"
                                Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $existingAssignment.Id -ErrorAction Stop
                                Write-ScriptLog "Successfully removed role assignment" -Type "Success"
                            }
                            else {
                                Write-ScriptLog "No existing assignment found to remove" -Type "Info"
                            }
                        }
                        elseif ($ActionType -eq "Active") {
                            if ($existingAssignment) {
                                Write-ScriptLog "Active role assignment already exists, skipping creation" -Type "Info"
                            }
                            else {
                                Write-ScriptLog "Creating new active role assignment" -Type "Info"
                                $params = @{
                                    principalId      = $principalInfo.Id
                                    RoleDefinitionId = $RoleDefinitionId
                                    DirectoryScopeId = $DirectoryScopeId
                                    justification    = $Justification
                                    scheduleInfo     = $scheduleInfo
                                }
                                New-MgRoleManagementDirectoryRoleAssignment -BodyParameter $params -ErrorAction Stop
                                Write-ScriptLog "Successfully created active role assignment" -Type "Success"
                            }
                        }
                        elseif ($ActionType -eq "Eligible") {
                            Write-ScriptLog "Eligible assignments aren't supported for Service Principals - skipping." -Type "Warning"
                        }
                    }
                    else {
                        # Handle non-Service Principal assignments through eligibility schedule
                        Write-ScriptLog "Processing eligibility schedule request for non-Service Principal" -Type "Info"
                        $params = @{
                            principalId      = $principalInfo.Id
                            RoleDefinitionId = $RoleDefinitionId
                            DirectoryScopeId = $DirectoryScopeId
                            action           = if ($ActionType -eq "Remove") { "AdminRemove" } else { "AdminAssign" }
                            justification    = $Justification
                            scheduleInfo     = $scheduleInfo
                        }
                        New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params
                        Write-ScriptLog "Successfully processed eligibility schedule request" -Type "Success"
                    }
                }

                "GroupMembership" {
                    Write-ScriptLog "Processing group membership assignment" -Type "Info"
                    # Handle Service Principal direct removal from groups
                    if ($ActionType -eq "Remove" -and $principalInfo.Type -eq "ServicePrincipal") {
                        Write-ScriptLog "Removing Service Principal from group" -Type "Info"
                        Remove-ServicePrincipalFromGroup -GroupId $GroupId -DirectoryObjectId $principalInfo.Id
                    }
                    else {
                        # Process group membership assignments for other principal types
                        $params = @{
                            accessId      = $GroupAccessId
                            principalId   = $principalInfo.Id
                            groupId       = $GroupId
                            action        = if ($ActionType -eq "Remove") { "AdminRemove" } else { "AdminAssign" }
                            justification = $Justification
                            scheduleInfo  = $scheduleInfo
                        }
                        New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop
                        Write-ScriptLog "Successfully processed group membership request" -Type "Success"
                    }
                }

                "Azure" {
                    Write-ScriptLog "Processing Azure RBAC assignment" -Type "Info"
                    # Generate unique identifier for the assignment
                    $guid = [guid]::NewGuid().ToString()
                    
                    # Determine the scope for role assignment
                    if (-not $Scope) {
                        $subscriptionId = (Get-AzContext).Subscription.Id
                        $fullyQualifiedRoleDefinitionId = "/subscriptions/$subscriptionId/providers/Microsoft.Authorization/roleDefinitions/$RoleDefinitionId"
                        Write-ScriptLog "Using current subscription scope: $subscriptionId" -Type "Info"
                    }
                    else {
                        $fullyQualifiedRoleDefinitionId = "$Scope/providers/Microsoft.Authorization/roleDefinitions/$RoleDefinitionId"
                        Write-ScriptLog "Using provided scope for role assignment" -Type "Info"
                    }

                    # Prepare common parameters for Azure role assignments
                    $basicRequestParams = @{
                        Name                      = $guid
                        Scope                     = $Scope
                        PrincipalId               = $principalInfo.Id
                        RoleDefinitionId          = $fullyQualifiedRoleDefinitionId
                        Justification             = $Justification
                        ScheduleInfoStartDateTime = $StartDateTime.ToString("o")
                        ExpirationDuration        = $Duration
                        ExpirationType            = "AfterDuration"
                    }

                    # Process based on action type
                    switch ($ActionType) {
                        "Eligible" {
                            Write-ScriptLog "Creating eligible Azure role assignment" -Type "Info"
                            New-AzRoleEligibilityScheduleRequest @basicRequestParams -RequestType "AdminAssign" -ErrorAction Stop
                        }
                        "Active" {
                            Write-ScriptLog "Creating active Azure role assignment" -Type "Info"
                            New-AzRoleAssignmentScheduleRequest @basicRequestParams -RequestType "AdminAssign" -ErrorAction Stop
                        }
                        "Remove" {
                            # Attempt to remove both eligible and active assignments
                            Write-ScriptLog "Attempting to remove Azure role assignments" -Type "Info"
                            try {
                                New-AzRoleEligibilityScheduleRequest @basicRequestParams -RequestType "AdminRemove" -ErrorAction Stop
                                Write-ScriptLog "Successfully removed eligible assignment" -Type "Success"
                            }
                            catch {
                                Write-ScriptLog "No eligible assignment found or removal failed: $_" -Type "Warning"
                            }
                            try {
                                New-AzRoleAssignmentScheduleRequest @basicRequestParams -RequestType "AdminRemove" -ErrorAction Stop
                                Write-ScriptLog "Successfully removed active assignment" -Type "Success"
                            }
                            catch {
                                Write-ScriptLog "No active assignment found or removal failed: $_" -Type "Warning"
                            }
                        }
                    }
                }
            }
            
            Write-ScriptLog "Successfully completed processing for $($principalInfo.Identifier)" -Type "Success"
        }
        catch {
            $simplifiedError = switch -Wildcard ($_.Exception.Message) {
                "*ResourceNotFound*" { "Resource not found." }
                "*RoleAssignmentDoesNotExist*" { "Role assignment not found." }
                "*Unauthorized*" { "Authorization failed." }
                "*Forbidden*" { "Access forbidden." }
                default { "Failed to process role assignment." }
            }
            
            Write-ScriptLog "Error for $($principalInfo.Identifier): $simplifiedError" -Type "Error" -VerboseMessage $_.Exception.Message
        }
    }
}

# Script entry point
Write-ScriptLog "Starting PIM role assignment management script..." -Type "Info"
$principalsData = Get-PrincipalsData -PrincipalIdentifiers $PrincipalIdentifiers -ScopeType $ScopeType
Process-GraphAssignments -principalsData $principalsData
Disconnect-GraphIfNeeded
Write-ScriptLog "Script execution complete." -Type "Success"