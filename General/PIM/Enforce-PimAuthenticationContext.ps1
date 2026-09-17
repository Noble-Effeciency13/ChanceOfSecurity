#requires -Version 7.2

<#
.SYNOPSIS
Enforces Authentication Context for activation of Microsoft Entra roles onboarded into PIM.

.DESCRIPTION
Production Azure Automation runbook for a PowerShell 7.2+ runtime. It authenticates with the
Automation Account's system-assigned managed identity, discovers Microsoft Entra roles actually
onboarded into Privileged Identity Management (PIM), audits their activation Authentication
Context rule, remediates drift, writes structured JSON logs, and persists processed-role state.

Architecture:
    Azure Automation schedule -> this runbook -> managed identity -> Microsoft Graph v1.0

Discovery uses roleManagementPolicyAssignments scoped to '/' and DirectoryRole. This represents
roles onboarded into PIM, including newly onboarded built-in and custom roles. The runbook finds
the EndUser/Assignment unifiedRoleManagementPolicyAuthenticationContextRule and PATCHes only when
isEnabled or claimValue differs. Microsoft Graph has no supported POST for an individual PIM
policy rule, so a missing or duplicate built-in rule is logged as a policy-integrity error.

.NOTES
AZURE AUTOMATION SETUP
1. Create or select an Azure Automation Account with a PowerShell 7.2+ runtime.
2. Under Identity, enable the system-assigned managed identity and record its object ID.
3. No Az or Microsoft Graph runtime module is required. The runbook uses PowerShell's built-in
    REST/JSON commands and Azure Automation's native variable asset commands.
4. Grant the managed identity this Microsoft Graph application role and admin consent:
         RoleManagementPolicy.ReadWrite.Directory
         Application role ID: 31e08e0a-d3f7-4ca2-ac39-7343fb83e8ad
5. Import this file as a PowerShell runbook and publish it.
6. Create the Automation variables listed below.
7. In the Automation Account, create a recurring schedule and link it to this runbook. An hourly
     schedule is typical. Choose an interval longer than normal job duration to prevent overlap.

Managed identities do not have a normal API permissions blade. A Privileged Role Administrator
can assign the app role with Microsoft Graph PowerShell in a temporary bootstrap session:

    Connect-MgGraph -Scopes Application.Read.All,AppRoleAssignment.ReadWrite.All
    $managedIdentityObjectId = '<automation-account-managed-identity-object-id>'
    $graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -Property Id,AppRoles
    $role = $graph.AppRoles | Where-Object Value -eq 'RoleManagementPolicy.ReadWrite.Directory'
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentityObjectId `
        -PrincipalId $managedIdentityObjectId -ResourceId $graph.Id -AppRoleId $role.Id

RUNTIME PERMISSIONS
The Graph application role above is the only runtime permission required. No Azure subscription
RBAC assignment or Entra directory role is needed by this runbook. Do not grant Directory.ReadWrite.All,
RoleManagement.ReadWrite.Directory, Contributor, or Privileged Role Administrator to the runtime
identity; these are broader than this workflow needs. The bootstrap operator needs an Entra role
allowed to grant Graph app roles, normally Privileged Role Administrator.

PREREQUISITES
* Entra ID P2 or Entra ID Governance licensing and at least one role onboarded into PIM.
* Create/publish an Authentication Context (c1 through c99) under Conditional Access.
* Create and enable a Conditional Access policy targeting that same Authentication Context.
    Enabling the PIM rule alone does not provide the intended Conditional Access controls.
* Design and test emergency-access exclusions before production rollout.

AUTOMATION VARIABLES
* PimOperatingMode (String): NewRolesOnly or AuditAndRemediateAllRoles.
* PimAuthenticationContextId (String): default context, c1 through c99.
* PimSingleContextForAllRoles (Boolean): True uses the default for every role.
* PimRoleContextMappingsJson (String): JSON map used when the preceding value is False.
* PimProcessedRolesStateJson (String): {"schemaVersion":1,"roles":{}}
* PimDryRun (Boolean): initially True; set False after validating proposed changes.

NewRolesOnly skips a role after successful verification/remediation is recorded in state. Failed
roles and roles without mappings remain unprocessed and are retried. AuditAndRemediateAllRoles
checks every onboarded role every run and is recommended for continuous enforcement.

SINGLE CONTEXT EXAMPLE
    PimAuthenticationContextId=c1
    PimSingleContextForAllRoles=True
    PimRoleContextMappingsJson={}

ROLE-SPECIFIC EXAMPLE
Set PimSingleContextForAllRoles=False. Mapping keys are resolved in this order: role definition
GUID, exact role display name, then '*' fallback. GUID keys are preferred because names can change.

    {
        "62e90394-69f5-4237-9190-012177145e10": "c1",
        "Privileged Role Administrator": "c2",
        "*": "c3"
    }

Without a matching key or wildcard, RoleMappingMissing is logged, the role is unchanged, and it is
not marked processed.

PROCESSING AND RELIABILITY
The runbook validates configuration, authenticates app-only, pages through PIM policy assignments,
resolves the desired mapping, retrieves each policy's rules, compares exact desired state, and
PATCHes only drift. Successful role state is persisted after processing. Graph calls retry network
errors, 408/429, and 5xx with Retry-After or exponential backoff with jitter; 401 refreshes the
token. Any role failures are logged while remaining roles continue, then the job ends Failed so
Azure Monitor alerting can detect partial failure. Repeated compliant runs perform no writes.

VALIDATION CHECKLIST
1. Confirm the Authentication Context and matching Conditional Access policy are enabled.
2. Set PimDryRun=True and start the runbook manually.
3. Verify DiscoveryCompleted count and all PolicyChangeDetected/RoleMappingMissing records.
4. Set PimDryRun=False and run again; expect PolicyRemediated for drift.
5. Run once more; expect RoleCompliant with no PolicyRemediated records (idempotency).
6. Activate a non-emergency test role and verify Conditional Access controls are enforced.
7. Change the test role context, run AuditAndRemediateAllRoles, and verify repair.
8. Onboard a test role into PIM and verify discovery on the next run.
9. In NewRolesOnly, verify successful state and that the next run skips that role.

MONITORING AND SECURITY
Send Automation job logs to Log Analytics using diagnostic settings. Alert on failed jobs and JSON
events RunFailed, RoleProcessingFailed, and RoleMappingMissing. Retain Entra audit logs for an
independent change record. Restrict Automation Contributor and runbook/variable write access:
changing code or mappings can redirect tenant-wide activation controls. The runtime stores no
secret, certificate, user credential, or token. State contains only role/policy metadata. Azure
Automation variable writes are not transactional; avoid overlapping scheduled jobs.

TROUBLESHOOTING
* Authentication failure: enable system identity and confirm the job runs in Azure Automation.
* Graph 403: grant the application role ID above; allow several minutes for consent propagation.
* No roles: confirm roles are onboarded into PIM and the identity belongs to the expected tenant.
* RoleMappingMissing: add a GUID/name mapping or intentional '*' fallback.
* Invalid context: use an existing c1 through c99 value.
* Rule count 0 or >1: inspect the PIM policy or contact Microsoft support; do not synthesize rules.
* PATCH 400: confirm the context exists and inspect the Graph error/current rule payload.
* Compliant but activation is uncontrolled: correct the matching Conditional Access policy.
* NewRolesOnly skips an intentionally changed role: use audit mode or remove only its GUID from state.
* State loses recent metadata: scheduled jobs overlapped; increase the interval and run once.

REFERENCES
https://learn.microsoft.com/graph/api/unifiedrolemanagementpolicyrule-update?view=graph-rest-1.0
https://learn.microsoft.com/graph/identity-governance-pim-rules-overview
https://learn.microsoft.com/graph/permissions-reference#rolemanagementpolicyreadwrite-directory
https://learn.microsoft.com/azure/automation/enable-managed-identity-for-automation
https://learn.microsoft.com/azure/automation/shared-resources/variables
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:GraphBaseUri = 'https://graph.microsoft.com/v1.0'
$script:GraphToken = $null
$script:RunId = [guid]::NewGuid().ToString()

function Write-StructuredLog {
    param(
        [Parameter(Mandatory)][ValidateSet('Debug', 'Information', 'Warning', 'Error')][string]$Level,
        [Parameter(Mandatory)][string]$RecordType,
        [Parameter(Mandatory)][string]$Message,
        [System.Collections.IDictionary]$Data = @{}
    )

    $record = [ordered]@{
        timestamp = [DateTime]::UtcNow.ToString('o')
        level     = $Level
        event     = $RecordType
        message   = $Message
        runId     = $script:RunId
        data      = $Data
    }
    Write-Output ($record | ConvertTo-Json -Compress -Depth 10)
}

function Get-ManagedIdentityGraphToken {
    if ([string]::IsNullOrWhiteSpace($env:IDENTITY_ENDPOINT) -or [string]::IsNullOrWhiteSpace($env:IDENTITY_HEADER)) {
        throw 'Azure Automation managed identity endpoint variables are unavailable. Run this published runbook in an Automation Account with system-assigned identity enabled.'
    }

    $tokenUri = $env:IDENTITY_ENDPOINT + '?resource=https%3A%2F%2Fgraph.microsoft.com%2F'
    $tokenResponse = Invoke-RestMethod -Method Get -Uri $tokenUri -Headers @{
        'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER
        Metadata            = 'True'
    } -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace([string]$tokenResponse.access_token)) {
        throw 'The managed identity endpoint returned no Microsoft Graph access token.'
    }
    return [string]$tokenResponse.access_token
}

function Connect-GraphManagedIdentity {
    $script:GraphToken = Get-ManagedIdentityGraphToken
    Write-StructuredLog -Level Information -RecordType 'AuthenticationSucceeded' -Message 'Authenticated to Microsoft Graph with the Automation Account system-assigned managed identity.'
}

function Get-HttpStatusCode {
    param([Parameter(Mandatory)]$Exception)

    $responseProperty = $Exception.PSObject.Properties['Response']
    if ($null -ne $responseProperty -and $null -ne $responseProperty.Value -and $null -ne $responseProperty.Value.StatusCode) {
        return [int]$responseProperty.Value.StatusCode
    }
    return 0
}

function Invoke-GraphRequest {
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'PATCH')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Body,
        [int]$MaxAttempts = 5
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $headers = @{
                Authorization = "Bearer $script:GraphToken"
                Accept        = 'application/json'
            }
            $parameters = @{
                Method      = $Method
                Uri         = $Uri
                Headers     = $headers
                ErrorAction = 'Stop'
            }
            if ($PSBoundParameters.ContainsKey('Body')) {
                $parameters.ContentType = 'application/json'
                $parameters.Body = $Body | ConvertTo-Json -Depth 10 -Compress
            }
            return Invoke-RestMethod @parameters
        }
        catch {
            $statusCode = Get-HttpStatusCode -Exception $_.Exception
            if ($statusCode -eq 401 -and $attempt -lt $MaxAttempts) {
                $script:GraphToken = Get-ManagedIdentityGraphToken
                continue
            }

            $isTransient = $statusCode -in @(0, 408, 429, 500, 502, 503, 504)
            if (-not $isTransient -or $attempt -eq $MaxAttempts) {
                throw
            }

            $retryAfter = 0
            $responseProperty = $_.Exception.PSObject.Properties['Response']
            if ($null -ne $responseProperty -and $null -ne $responseProperty.Value -and $null -ne $responseProperty.Value.Headers) {
                $retryHeader = $responseProperty.Value.Headers.RetryAfter
                if ($null -ne $retryHeader -and $null -ne $retryHeader.Delta) {
                    $retryAfter = [int][Math]::Ceiling($retryHeader.Delta.TotalSeconds)
                }
            }
            $delaySeconds = if ($retryAfter -gt 0) { $retryAfter } else { [Math]::Min(60, [Math]::Pow(2, $attempt) + (Get-Random -Minimum 0 -Maximum 3)) }
            Write-StructuredLog -Level Warning -RecordType 'GraphRequestRetry' -Message 'A transient Microsoft Graph request failed; retrying.' -Data @{
                method = $Method; uri = $Uri; statusCode = $statusCode; attempt = $attempt; delaySeconds = $delaySeconds
            }
            Start-Sleep -Seconds $delaySeconds
        }
    }
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)

    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        $response = Invoke-GraphRequest -Method GET -Uri $nextUri
        foreach ($item in @($response.value)) {
            $items.Add($item)
        }
        $nextLinkProperty = $response.PSObject.Properties['@odata.nextLink']
        $nextUri = if ($null -eq $nextLinkProperty) { $null } else { [string]$nextLinkProperty.Value }
    }
    return $items.ToArray()
}

function Get-RequiredAutomationVariable {
    param([Parameter(Mandatory)][string]$Name)

    $value = Get-AutomationVariable -Name $Name
    if ($null -eq $value -or ($value -is [string] -and [string]::IsNullOrWhiteSpace($value))) {
        throw "Automation variable '$Name' is missing or empty."
    }
    return $value
}

function ConvertTo-Boolean {
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string]$Name)

    if ($Value -is [bool]) { return $Value }
    $parsed = $false
    if ([bool]::TryParse([string]$Value, [ref]$parsed)) { return $parsed }
    throw "Automation variable '$Name' must be True or False."
}

function Get-DesiredContextId {
    param(
        [Parameter(Mandatory)]$Assignment,
        [Parameter(Mandatory)][bool]$SingleContextForAllRoles,
        [Parameter(Mandatory)][string]$DefaultContextId,
        [Parameter(Mandatory)][hashtable]$RoleMappings
    )

    if ($SingleContextForAllRoles) { return $DefaultContextId }

    $roleDefinitionId = [string]$Assignment.roleDefinitionId
    $displayName = [string]$Assignment.roleDefinition.displayName
    foreach ($key in @($roleDefinitionId, $displayName, '*')) {
        if (-not [string]::IsNullOrWhiteSpace($key) -and $RoleMappings.ContainsKey($key)) {
            return [string]$RoleMappings[$key]
        }
    }
    return $null
}

function Test-ContextId {
    param([Parameter(Mandatory)][string]$ContextId)

    if ($ContextId -notmatch '^c([1-9]|[1-9][0-9])$') {
        throw "Authentication Context ID '$ContextId' is invalid. Expected c1 through c99."
    }
}

$summary = [ordered]@{ discovered = 0; considered = 0; compliant = 0; changed = 0; skipped = 0; failed = 0 }

try {
    $mode = [string](Get-RequiredAutomationVariable -Name 'PimOperatingMode')
    if ($mode -notin @('NewRolesOnly', 'AuditAndRemediateAllRoles')) {
        throw "PimOperatingMode must be 'NewRolesOnly' or 'AuditAndRemediateAllRoles'."
    }

    $defaultContextId = [string](Get-RequiredAutomationVariable -Name 'PimAuthenticationContextId')
    $singleContext = ConvertTo-Boolean -Value (Get-RequiredAutomationVariable -Name 'PimSingleContextForAllRoles') -Name 'PimSingleContextForAllRoles'
    $dryRun = ConvertTo-Boolean -Value (Get-RequiredAutomationVariable -Name 'PimDryRun') -Name 'PimDryRun'
    if ($singleContext) { Test-ContextId -ContextId $defaultContextId }

    $mappingJson = [string](Get-RequiredAutomationVariable -Name 'PimRoleContextMappingsJson')
    $roleMappings = @{}
    $mappingObject = $mappingJson | ConvertFrom-Json -AsHashtable
    foreach ($key in $mappingObject.Keys) {
        Test-ContextId -ContextId ([string]$mappingObject[$key])
        $roleMappings[[string]$key] = [string]$mappingObject[$key]
    }

    $stateJson = [string](Get-RequiredAutomationVariable -Name 'PimProcessedRolesStateJson')
    $state = $stateJson | ConvertFrom-Json -AsHashtable
    if (-not $state.ContainsKey('schemaVersion')) { $state.schemaVersion = 1 }
    if (-not $state.ContainsKey('roles')) { $state.roles = @{} }

    Connect-GraphManagedIdentity

    $assignmentUri = "$script:GraphBaseUri/policies/roleManagementPolicyAssignments?`$filter=scopeId%20eq%20'/'%20and%20scopeType%20eq%20'DirectoryRole'&`$expand=roleDefinition&`$top=100"
    $assignments = @(Get-GraphCollection -Uri $assignmentUri)
    $summary.discovered = $assignments.Count
    Write-StructuredLog -Level Information -RecordType 'DiscoveryCompleted' -Message 'Discovered role policies currently onboarded into PIM for Microsoft Entra roles.' -Data @{ count = $assignments.Count; mode = $mode; dryRun = $dryRun }

    foreach ($assignment in $assignments) {
        $roleDefinitionId = [string]$assignment.roleDefinitionId
        $roleName = if ([string]::IsNullOrWhiteSpace([string]$assignment.roleDefinition.displayName)) { $roleDefinitionId } else { [string]$assignment.roleDefinition.displayName }

        if ($mode -eq 'NewRolesOnly' -and $state.roles.ContainsKey($roleDefinitionId)) {
            $summary.skipped++
            Write-StructuredLog -Level Debug -RecordType 'PreviouslyProcessedRoleSkipped' -Message 'Skipped a role already recorded in state.' -Data @{ roleDefinitionId = $roleDefinitionId; roleName = $roleName }
            continue
        }

        $contextId = Get-DesiredContextId -Assignment $assignment -SingleContextForAllRoles $singleContext -DefaultContextId $defaultContextId -RoleMappings $roleMappings
        if ([string]::IsNullOrWhiteSpace($contextId)) {
            $summary.skipped++
            Write-StructuredLog -Level Warning -RecordType 'RoleMappingMissing' -Message 'No Authentication Context mapping exists for the role; it was left unprocessed and will be retried on a later run.' -Data @{ roleDefinitionId = $roleDefinitionId; roleName = $roleName }
            continue
        }
        Test-ContextId -ContextId $contextId
        $summary.considered++

        try {
            $encodedPolicyId = [uri]::EscapeDataString([string]$assignment.policyId)
            $rulesUri = "$script:GraphBaseUri/policies/roleManagementPolicies/$encodedPolicyId/rules"
            $rules = @(Get-GraphCollection -Uri $rulesUri)
            $contextRules = @($rules | Where-Object {
                $_.'@odata.type' -eq '#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule' -and
                $_.target.caller -eq 'EndUser' -and $_.target.level -eq 'Assignment'
            })
            if ($contextRules.Count -ne 1) {
                throw "Expected exactly one EndUser/Assignment Authentication Context rule but found $($contextRules.Count). PIM policy rules cannot be created with the supported Graph API."
            }

            $rule = $contextRules[0]
            $isCompliant = [bool]$rule.isEnabled -and ([string]$rule.claimValue -ceq $contextId)
            if ($isCompliant) {
                $summary.compliant++
                Write-StructuredLog -Level Information -RecordType 'RoleCompliant' -Message 'The role activation policy already has the required Authentication Context.' -Data @{ roleDefinitionId = $roleDefinitionId; roleName = $roleName; contextId = $contextId }
            }
            else {
                Write-StructuredLog -Level Information -RecordType 'PolicyChangeDetected' -Message 'The role activation policy requires remediation.' -Data @{
                    roleDefinitionId = $roleDefinitionId; roleName = $roleName; currentEnabled = [bool]$rule.isEnabled
                    currentContextId = [string]$rule.claimValue; desiredContextId = $contextId; dryRun = $dryRun
                }
                if (-not $dryRun) {
                    $encodedRuleId = [uri]::EscapeDataString([string]$rule.id)
                    $patchUri = "$script:GraphBaseUri/policies/roleManagementPolicies/$encodedPolicyId/rules/$encodedRuleId"
                    $body = @{
                        '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule'
                        id            = [string]$rule.id
                        isEnabled     = $true
                        claimValue    = $contextId
                    }
                    Invoke-GraphRequest -Method PATCH -Uri $patchUri -Body $body | Out-Null
                    Write-StructuredLog -Level Information -RecordType 'PolicyRemediated' -Message 'Enabled the required Authentication Context for role activation.' -Data @{ roleDefinitionId = $roleDefinitionId; roleName = $roleName; contextId = $contextId }
                }
                $summary.changed++
            }

            if (-not $dryRun) {
                $state.roles[$roleDefinitionId] = @{
                    displayName  = $roleName
                    contextId    = $contextId
                    policyId     = [string]$assignment.policyId
                    processedUtc = [DateTime]::UtcNow.ToString('o')
                }
            }
        }
        catch {
            $summary.failed++
            Write-StructuredLog -Level Error -RecordType 'RoleProcessingFailed' -Message $_.Exception.Message -Data @{ roleDefinitionId = $roleDefinitionId; roleName = $roleName; policyId = [string]$assignment.policyId }
        }
    }

    if (-not $dryRun) {
        $state.lastSuccessfulRunUtc = [DateTime]::UtcNow.ToString('o')
        Set-AutomationVariable -Name 'PimProcessedRolesStateJson' -Value ($state | ConvertTo-Json -Depth 10 -Compress)
    }

    Write-StructuredLog -Level Information -RecordType 'RunCompleted' -Message 'PIM Authentication Context enforcement run completed.' -Data $summary
    if ($summary.failed -gt 0) {
        throw "$($summary.failed) role policy operation(s) failed. Review RoleProcessingFailed records."
    }
}
catch {
    Write-StructuredLog -Level Error -RecordType 'RunFailed' -Message $_.Exception.Message -Data $summary
    throw
}
