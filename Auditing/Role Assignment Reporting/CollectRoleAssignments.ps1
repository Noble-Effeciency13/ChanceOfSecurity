<#
.SYNOPSIS
Collects and exports Azure RBAC roles and Microsoft 365 Administrator roles to CSV and Excel files.

.DESCRIPTION
This script retrieves role assignments (active and eligible) from Azure subscriptions and Microsoft Entra using Azure RBAC and Microsoft Graph APIs. 
It processes the data, generates reports, and optionally emails the results. 
The script ensures that required modules are installed or updated, and it can be run locally or in an automated pipeline.

.PARAMETER TenantId
The Tenant ID (GUID) of the Entra ID tenant.

.PARAMETER ClientId
The Client ID of the service principal.

.PARAMETER Client_secret
The client secret associated with the registered application.

.PARAMETER SaveFiles
Indicates whether to save the output files locally. Default is `$true`.

.PARAMETER outDir
The directory where output files will be saved. Default is `C:\Temp`.

.PARAMETER localRun
Indicates whether the script is run locally. Default is `$true`.

.PARAMETER mailFrom
The email address from which the results will be sent. Optional.

.PARAMETER mailTo
The recipient's email address for sending the results. Mandatory if `mailFrom` is specified.

.PARAMETER mailSubject
The subject of the email. Default is "Admin Roles overview".

.PARAMETER excelFileName
The prefix for the name of the final excel file. Default is "Entra And RBAC Admin Roles".

.EXAMPLE
# Run the script locally and save output files:
.\CollectRoleAssignments.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -Client_secret "your-client-secret" -localRun $true -SaveFiles $true

.EXAMPLE
# Run the script locally and email the results:
.\CollectRoleAssignments.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -Client_secret "your-client-secret" -localRun $true -mailFrom "noreply@yourdomain.com" -mailTo "admin@yourdomain.com"

.EXAMPLE
# Run the script in a pipeline and save files to a temporary directory:
.\CollectRoleAssignments.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -Client_secret "your-client-secret" -localRun $false

.NOTES
Author:     Sebastian Flæng Markdanner
Website:    https://chanceofsecurity.com
Version:    1.7

- Entra ID Service Principal with:
  - Azure RBAC Reader role at Subscription, Management Group OR Root level.
  - Entra ID Directory Reader Role

- Microsoft Graph API permissions:
  - Application.Read.All
  - AuditLog.Read.All
  - Directory.Read.All
  - PrivilegedAccess.Read.AzureAD
  - RoleManagement.Read.All
  - User.Read.All
  - Mail.Send (if emailing results).

- Required PowerShell modules:
  - Az.Accounts
  - Az.Resources
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Users
  - Microsoft.Graph.Identity.DirectoryManagement
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Reports
  - Microsoft.Graph.Identity.Governance
  - ImportExcel

.OUTPUTS
- Excel file: Combined report of Azure RBAC and Entra roles.
#>

#Region Script Parameters
param (
    [Parameter(Mandatory=$true)][string]$TenantId,
    [Parameter(Mandatory=$true)][string]$ClientId,
    [Parameter(Mandatory=$true)][string]$Client_secret,
    [Parameter(Mandatory=$true)][bool]$localRun = $true,
    [bool]$SaveFiles = $true,
    [string]$outDir = ("C:\Temp"),
    [string]$mailFrom = $null,
    [string]$mailTo,
    [string]$mailSubject = ("Admin Roles Overview"),
    [string]$excelFileName = ("Entra And RBAC Admin Roles")
)
#EndRegion

#Region Script Configuration
$WarningPreference = "SilentlyContinue"

# Setup output directory
if ($localRun -ne $true) { 
    $tempDir = [System.IO.Path]::GetTempPath()
    $outDir = Join-Path -Path $tempDir -ChildPath "AzureReports" 
}
if (-not (Test-Path -Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}
$excelFilePath = Join-Path $outDir "$($excelFileName)_$((Get-Date).ToString('HH.mm_dd-MM-yyyy')).xlsx"

# Required modules
$requiredModules = @(
    "Az.Accounts",
    "Az.Resources",
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Identity.Governance",
    "ImportExcel"
)
#EndRegion

#Region Helper Functions
function Get-GraphData {
    param($uri, $authHeader)
    
    $data = @()
    do {
        try {
            $result = Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Get
            if ($null -eq $result) { return $null }
            
            if ($result.value) {
                $data += $result.value
            }
            
            $uri = $result.'@odata.nextLink'
            if ($uri) {
                Start-Sleep -Milliseconds 500
            }
        }
        catch {
            Write-Error "Failed to get data from Graph API: $_"
            throw
        }
    } while ($uri)
    
    return $data
}

function SafeRemoveModule { 
    param([string]$moduleName) 
    if (Get-Module $moduleName -ErrorAction SilentlyContinue) { 
        Remove-Module $moduleName -Force -ErrorAction SilentlyContinue 
    } 
}

function Test-Admin { 
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 
}

function Sanitize-TableName { 
    param([string]$name) 
    return $name -replace '[^a-zA-Z0-9_]', '_' 
}

function Get-AzAccessToken {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret
    )
    $body = @{
        grant_type = "client_credentials"
        client_id = $ClientId
        client_secret = $ClientSecret
        resource = "https://management.azure.com/"
    }
    $url = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    $response = Invoke-RestMethod -Method Post -Uri $url -ContentType "application/x-www-form-urlencoded" -Body $body
    return $response.access_token
}

function Install-OrUpdateModule {
    param([string]$moduleName)
    if (!(Get-Module -Name $moduleName -ListAvailable)) {
        Install-Module -Name $moduleName -Force -AllowClobber -Scope CurrentUser
    }
    Import-Module -Name $moduleName -Force
}
#EndRegion

#Region Initialize Environment
# Install/Update required modules if running locally
if ($localRun) {
    $totalSteps = $requiredModules.Count
    $currentStep = 0
    Write-Progress -Id 0 -Activity "Managing required modules" -Status "Starting" -PercentComplete 0

    foreach ($module in $requiredModules) {
        $currentStep++
        $overallProgress = ($currentStep / $totalSteps) * 100
        Write-Progress -Id 0 -Activity "Managing required modules" -Status "Processing $module" -PercentComplete $overallProgress
        Install-OrUpdateModule -moduleName $module
        Write-Progress -Id 1 -Activity "Imported $module" -Status "Complete" -Completed
    }

    Write-Progress -Id 0 -Activity "Managing required modules" -Status "Complete" -Completed
    Install-Module -Name PowerShellGet -Force -AllowClobber -Scope CurrentUser -WarningAction Ignore
}
#EndRegion

#Region Authentication
# Set up credentials and tokens
Write-Verbose "Setting up authentication..."

# Function to get Graph API token
function Get-GraphToken {
    param (
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret
    )
    
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    
    $params = @{
        Uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        Method = 'Post'
        Body = $body
        ContentType = 'application/x-www-form-urlencoded'
        UseBasicParsing = $true
    }
    
    try {
        $response = Invoke-RestMethod @params
        return $response.access_token
    }
    catch {
        Write-Error "Failed to acquire Graph token: $_"
        throw
    }
}

try {
    # Get Graph API token
    Write-Verbose "Acquiring Graph API token..."
    $graphToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $Client_secret
    $authHeader = @{
        'Authorization' = "Bearer $graphToken"
        'Content-Type' = 'application/json'
    }
    
    # Connect to Azure
    Write-Verbose "Connecting to Azure..."
    $secureSecret = ConvertTo-SecureString -String $Client_secret -AsPlainText -Force
    $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientId, $secureSecret
    
    $null = Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant $TenantId -WarningAction SilentlyContinue
    
    Write-Verbose "Authentication completed successfully"
}
catch {
    Write-Error "Authentication failed: $_"
    throw
}
#EndRegion

#Region Check Entra P2 Service Plan
$servicePlanId = "eec0eb4f-6444-4f95-aba0-50c24d67f998"
$subscriptionsResponse = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/subscribedSkus" -Headers $authHeader
$servicePlanEnabled = $subscriptionsResponse.value | Where-Object {
    $_.ServicePlans | Where-Object { $_.ServicePlanId -eq $servicePlanId -and $_.ProvisioningStatus -eq "Success" }
}# | ForEach-Object { $true }

$foreground = if ($servicePlanEnabled) { "Green" } else { "DarkMagenta" }
Write-Host "The service plan Azure AD Premium P2 is $(if ($servicePlanEnabled) { "enabled" } else { "not enabled" }) for the tenant." -ForegroundColor $foreground
#EndRegion

#Region Data Collection
# Collect EntraID data
Write-Verbose "Collecting all users, groups, and service principals from EntraID"
try {
    $allUsers = Get-GraphData -uri 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,mail,displayName' -authHeader $authHeader
    Write-Verbose "Collected $($allUsers.Count) users"
    $allGroups = Get-GraphData -uri 'https://graph.microsoft.com/v1.0/groups?$select=id,displayName' -authHeader $authHeader
    Write-Verbose "Collected $($allGroups.Count) groups"
    $allServicePrincipals = Get-GraphData -uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName' -authHeader $authHeader
    Write-Verbose "Collected $($allServicePrincipals.Count) service principals"
    if ($allUsers.Count -eq 0 -and $allGroups.Count -eq 0 -and $allServicePrincipals.Count -eq 0) { throw "No data collected from EntraID" }
} catch {
    Write-Error "Error collecting data from EntraID: $_"
    return
}

# Process principals
$allPrincipals = @()
$allPrincipals += $allUsers | ForEach-Object { 
    [PSCustomObject]@{ 
        id = $_.id
        type = 'User'
        identifier = $_.userPrincipalName 
        principal  = $_
    } 
}
$allPrincipals += $allGroups | ForEach-Object { 
    [PSCustomObject]@{ 
        id = $_.id
        type = 'Group'
        identifier = $_.displayName 
        principal  = $_
    } 
}
$allPrincipals += $allServicePrincipals | ForEach-Object { 
    [PSCustomObject]@{ 
        id = $_.id
        type = 'ServicePrincipal'
        identifier = $_.appId 
        principal  = $_
    } 
}

# Collect Azure Subscriptions and RBAC Roles
Write-Verbose "Collecting Azure Subscriptions"
$subscriptions = Get-AzSubscription
$totalSubscriptions = $subscriptions.Count
Write-Verbose "$totalSubscriptions found"
$subCount = 0
$rbacRoles = @()

# Process each subscription for RBAC roles
foreach ($subscription in $subscriptions) {
    $null = Set-AzContext -SubscriptionId $subscription.SubscriptionId
    $subCount++
    Write-Progress -id 0 -Activity "Processing subscriptions" -Status "$subCount of $totalSubscriptions processed. Currently processing subscription: $($subscription.Name)." -PercentComplete ($subCount / $totalSubscriptions * 100)
    
    # Process active role assignments
    $roleAssignments = Get-AzRoleAssignment
    foreach ($roleAssignment in $roleAssignments) {
        $accountName = if ($roleAssignment.ObjectType -in @("Group", "ServicePrincipal", "Unknown")) {
            $roleAssignment.DisplayName
        } else {
            $roleAssignment.SignInName
        }

        $displayName = if ($roleAssignment.ObjectType -in @("Group", "ServicePrincipal", "Unknown")) {
            "$($roleAssignment.ObjectType): $($roleAssignment.DisplayName)"
        } else {
            if ($accountName -like "*#EXT#@*") {
                "External User: $($roleAssignment.DisplayName)"
            } else {
                "User: $($roleAssignment.DisplayName)"
            }
        }

        if ($accountName -like "*#EXT#@*") {
            $externalUser = $allUsers | Where-Object { $_.id -eq $roleAssignment.ObjectId }
            if ($externalUser -and $externalUser.mail) { 
                $accountName = $externalUser.mail 
            }
        }

        $rbacRoles += [PSCustomObject]@{
            AccountName = $accountName
            DisplayName = $displayName
            SubscriptionName = $subscription.Name
            RoleDefinitionName = $roleAssignment.RoleDefinitionName
            AssignmentType = "Active"
            LastSignIn = $null
            Scope = $roleAssignment.Scope
            ObjectType = $roleAssignment.ObjectType
        }
    }

    # Process eligible role assignments
    if ($servicePlanEnabled) {
        Write-Verbose "Collecting eligible Azure RBAC roles using ARM API for subscription $($subscription.SubscriptionId)"
        $armToken = Get-AzAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $Client_secret
        $armUri = "https://management.azure.com/subscriptions/$($subscription.SubscriptionId)/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01&`$expand=principal,roleDefinition"
    
        try {
            $response = Invoke-RestMethod -Uri $armUri -Method Get -Headers @{ Authorization = "Bearer $armToken" }
            if ($response.PSObject.Properties.Name -contains 'value' -and $response.value -is [array]) {
                foreach ($schedule in $response.value) {
                    Write-Verbose "Processing eligible role: $($schedule.properties.expandedProperties.roleDefinition.displayName) for principal: $($schedule.properties.expandedProperties.principal.displayName)"

                    $accountName = $schedule.properties.expandedProperties.principal.displayName
                    $displayName = $accountName

                    $entraUser = $allUsers | Where-Object { $_.displayName -eq $accountName } | Select-Object -First 1
                    if ($entraUser) {
                        $accountName = if ($entraUser.userPrincipalName -like "*#EXT#*") { 
                            $entraUser.mail 
                        } else { 
                            $entraUser.userPrincipalName 
                        }
                        $displayName = if ($entraUser.userPrincipalName -like "*#EXT#*") { 
                            "External User: $($entraUser.displayName)" 
                        } else { 
                            "User: $($entraUser.displayName)" 
                        }
                    } else {
                        $entraGroup = $allGroups | Where-Object { $_.displayName -eq $accountName } | Select-Object -First 1
                        if ($entraGroup) {
                            $accountName = $entraGroup.displayName
                            $displayName = "Group: $($entraGroup.displayName)"
                        } else {
                            $entraServicePrincipal = $allServicePrincipals | Where-Object { $_.displayName -eq $accountName } | Select-Object -First 1
                            if ($entraServicePrincipal) {
                                $accountName = $entraServicePrincipal.appId
                                $displayName = "ServicePrincipal: $($entraServicePrincipal.displayName)"
                            }
                        }
                    }

                    $rbacRoles += [PSCustomObject]@{
                        AccountName = $accountName
                        DisplayName = $displayName
                        SubscriptionName = $subscription.Name
                        RoleDefinitionName = $schedule.properties.expandedProperties.roleDefinition.displayName
                        AssignmentType = "Eligible"
                        LastSignIn = $null
                        Scope = $schedule.properties.expandedProperties.scope.id
                        ObjectType = $schedule.properties.expandedProperties.principal.type
                    }
                }
            }
        } catch {
        Write-Warning "Error processing eligible roles for subscription $($subscription.SubscriptionId): $_"
        }
    } else {
    Write-Verbose "Skipping eligible Azure RBAC roles as Entra P2 service plan is not enabled."
    }
}

# Collect Entra ID roles
Write-Verbose "Collecting Entra ID role assignments..."
$combinedEntraRoles = @()

# First, collect all regular directory roles
$roles = Get-GraphData -uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal' -authHeader $authHeader
$roles1 = Get-GraphData -uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=roleDefinition' -authHeader $authHeader

# Process regular directory roles
foreach ($role in $roles) {
    $roleDef = ($roles1 | Where-Object {$_.id -eq $role.id}).roleDefinition
    
    # Skip if this is an AU-scoped role - we'll handle those separately
    if ($role.directoryScopeId -like "/administrativeUnits/*") { continue }
    
    $combinedRole = $role | Select-Object *, @{Name='roleDefinitionNew'; Expression={ $roleDef }}
    $combinedRole | Add-Member -MemberType NoteProperty -Name "AssignmentType" -Value "Active"
    $combinedEntraRoles += $combinedRole
}

# Process eligible roles if P2 is enabled
if ($servicePlanEnabled) {
    $eligibleRoles = Get-GraphData -uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition' -authHeader $authHeader
    
    foreach ($role in $eligibleRoles) {
        # Skip if this is an AU-scoped role
        if ($role.directoryScopeId -like "/administrativeUnits/*") { continue }
        
        $combinedRole = $role | Select-Object *, @{Name='roleDefinitionNew'; Expression={ $role.roleDefinition }}
        $combinedRole | Add-Member -MemberType NoteProperty -Name "AssignmentType" -Value "Eligible"
        $combinedEntraRoles += $combinedRole
    }
}

# Process Administrative Unit roles
Write-Verbose "Processing Administrative Unit scoped role assignments..."

foreach ($au in $administrativeUnits) {
    Write-Verbose "Processing roles for AU: $($au.displayName)"
    
    # Get active role assignments for this AU using the updated endpoint
    $auRoles = Get-GraphData -uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$expand=principal&`$filter=directoryScopeId eq '/administrativeUnits/$($au.id)'" -authHeader $authHeader

    if ($auRoles) {
        foreach ($role in $auRoles) {
            $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/" + $role.roleDefinitionId
            $roleDefinitionDetails = Invoke-RestMethod -Method Get -uri $uri -Headers $authHeader -ErrorAction Stop
            $roleDefinitionDisplayName = $roleDefinitionDetails.displayName

            $combinedRole = [PSCustomObject]@{
                id                = $role.id
                principal         = $role.principal
                roleDefinitionNew = @{
                    displayName = "AU $($au.displayName): $roleDefinitionDisplayName"
                    isBuiltIn   = $true
                }
                AssignmentType    = "Active"
                directoryScopeId  = "/administrativeUnits/$($au.id)"
            }
            $combinedEntraRoles += $combinedRole
        }
    } else {
        Write-Warning "No active role assignments found for AU: $($au.displayName)"
    }
    
    # Get eligible role assignments if P2 is enabled
    if ($servicePlanEnabled) {
        try {
            $auEligibleRoles = Get-GraphData -uri "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules?`$expand=principal,roleDefinition&`$filter=directoryScopeId eq '/administrativeUnits/$($au.id)'" -authHeader $authHeader
            
            if ($auEligibleRoles) {
                foreach ($role in $auEligibleRoles) {
                    $combinedRole = [PSCustomObject]@{
                        id                = $role.id
                        principal         = $role.principal
                        roleDefinitionNew = @{
                            displayName = "AU $($au.displayName): $($role.roleDefinition.displayName)"
                            isBuiltIn   = $true
                        }
                        AssignmentType    = "Eligible"
                        directoryScopeId  = "/administrativeUnits/$($au.id)"
                    }
                    $combinedEntraRoles += $combinedRole
                }
            }
        } catch {
            Write-Warning "Error processing eligible roles for AU $($au.displayName): $_"
        }
    }
}
#EndRegion

#Region Data Processing
# Process RBAC Roles
$userSignIns = Get-GraphData -uri 'https://graph.microsoft.com/beta/users?$select=id,userPrincipalName,signInActivity' -authHeader $authHeader

# Remove duplicates from RBAC roles and group them
$rbacRoles = $rbacRoles | Group-Object -Property AccountName, RoleDefinitionName, Scope | ForEach-Object {
    $_.Group[0]
}

# Update RBAC roles with sign-in data
foreach ($role in $rbacRoles) {
    if ($role.ObjectType -eq "User") {
        $userSignIn = $userSignIns | Where-Object { $_.userPrincipalName -eq $role.AccountName }
        if ($userSignIn) {
            $role.LastSignIn = $userSignIn.signInActivity.lastSignInDateTime
        }
    }
}

# Sort RBAC roles by PrincipalType, AccountName, DisplayName, AssignmentType and Scope
$rbacRoles = $rbacRoles | Sort-Object -Property @{
    Expression = {
        switch ($_.ObjectType) {
            "User" { 
                if ($_.AccountName -like "*#EXT#*") { "2-External User" }
                else { "1-User" }
            }
            "Group" { "3-Group" }
            "ServicePrincipal" { "4-ServicePrincipal" }
            default { "5-$($_.ObjectType)" }
        }
    }
}, AccountName, DisplayName, AssignmentType, Scope


# Process Entra ID Roles
Write-Verbose "Processing Entra ID roles output..."
$entraReport = @()

# Modified grouping to preserve full objects
$groupedRoles = $combinedEntraRoles | Group-Object -Property { $_.principal.id }

foreach ($group in $groupedRoles) {
    $firstRole = $group.Group[0]
    
    # Skip if principal is null
    if ($null -eq $firstRole.principal) { continue }
    
    $reportLine = [ordered]@{
        "Principal" = switch ($firstRole.principal.'@odata.type') {
            '#microsoft.graph.user' {
                if ($firstRole.principal.userPrincipalName -like "*#EXT#*") {
                    $firstRole.principal.mail
                } else {
                    $firstRole.principal.userPrincipalName
                }
            }
            '#microsoft.graph.servicePrincipal' { $firstRole.principal.appId }
            '#microsoft.graph.group' { $firstRole.principal.displayName }
            Default { $firstRole.principal.userPrincipalName }
        }
        "PrincipalDisplayName" = switch ($firstRole.principal.'@odata.type') {
            '#microsoft.graph.user' { 
                if ($firstRole.principal.userPrincipalName -like "*#EXT#*") {
                    "External User: $($firstRole.principal.displayName)"
                } else {
                    "User: $($firstRole.principal.displayName)"
                }
            }
            '#microsoft.graph.servicePrincipal' { "ServicePrincipal: $($firstRole.principal.displayName)" }
            '#microsoft.graph.group' { "Group: $($firstRole.principal.displayName)" }
            Default { $firstRole.principal.displayName }
        }
        "PrincipalType" = if ($firstRole.principal.'@odata.type' -like "*user*" -and 
            $firstRole.principal.userPrincipalName -like "*#EXT#*") {
            "External User"
        } else {
            $firstRole.principal.'@odata.type'.Split(".")[-1]
        }
        "LastSignIn" = ""
    }

    # Process Active Roles
    $reportLine["ActiveRoles"] = ($group.Group | 
        Where-Object { $_.AssignmentType -eq "Active" } | 
        ForEach-Object { $_.roleDefinitionNew.displayName } | 
        Sort-Object) -join ", "

    # Process Eligible Roles
    $reportLine["EligibleRoles"] = ($group.Group | 
        Where-Object { $_.AssignmentType -eq "Eligible" } | 
        ForEach-Object { $_.roleDefinitionNew.displayName } | 
        Sort-Object) -join ", "

    $reportLine["IsBuiltIn"] = $firstRole.roleDefinitionNew.isBuiltIn

    # Add sign-in information if it's a user
    if ($reportLine.PrincipalType -in @("user", "External User")) {
        $userSignIn = $userSignIns | Where-Object { $_.userPrincipalName -eq $reportLine.Principal }
        if ($userSignIn) {
            $reportLine["LastSignIn"] = $userSignIn.signInActivity.lastSignInDateTime
        }
    }

    $entraReport += [PSCustomObject]$reportLine
}

# Sort Entra report by PrincipalType and then Principal
$entraReport = $entraReport | 
    Where-Object { $_.ActiveRoles -or $_.EligibleRoles } |
    Sort-Object -Property @{
        Expression = {
            switch ($_.PrincipalType) {
                "user" { "1-User" }
                "External User" { "2-External User" }
                "group" { "3-Group" }
                "servicePrincipal" { "4-ServicePrincipal" }
                default { "5-$($_.PrincipalType)" }
            }
        }
    }, Principal

# Export both reports to Excel
Write-Progress -Id 0 -Activity "Processing subscriptions" -Completed
$excelFilePath = Join-Path $outDir "Entra And RBAC Admin Roles_$((Get-Date).ToString('HH.mm_dd-MM-yyyy')).xlsx"

$rbacRoles | Export-Excel -Path $excelFilePath -WorksheetName "RBAC Roles" -AutoSize -TableStyle Medium2
$entraReport | Export-Excel -Path $excelFilePath -WorksheetName "Entra Roles" -AutoSize -TableStyle Medium2 -Append
#EndRegion

#Region Email Distribution
if ($mailFrom) {
    # Prepare email content
    $base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($excelFilePath))
    $URLsend = "https://graph.microsoft.com/v1.0/users/" + $mailFrom + "/sendMail"
    $FileName = (Get-Item -Path $excelFilePath).name

    # Configure email parameters
    $mailParams = @{
        message = @{
            subject = $mailSubject + " " + (Get-Date -Format "dddd dd/MM/yyyy")
            body = @{
                contentType = "Text"
                content = "Automatic mail with user roles attached"
            }
            toRecipients = @(
                @{
                    emailAddress = @{
                        address = $mailTo
                    }
                }
            )
            attachments = @(
                @{
                    "@odata.type" = "#microsoft.graph.fileAttachment"
                    name = $FileName
                    contentBytes = $base64string
                }
            )
        }
        saveToSentItems = "false"
    }

    # Send email using Graph API
    Invoke-RestMethod -Method POST -uri $URLsend -Headers $authHeader -Body ($mailParams | ConvertTo-Json -Depth 10)
    Write-Host "Email sent to $mailTo with results attached." -ForegroundColor DarkYellow

    # Clean up Excel file if not running locally or files shouldn't be saved
    if (-not $SaveFiles -or -not $localRun) { 
        Remove-Item -Path $excelFilePath -Force 
    }
} else {
    Write-Host "Results exported to $excelFilePath" -ForegroundColor Green
}
#EndRegion