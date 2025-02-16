<#
.SYNOPSIS
    Enables Microsoft Entra Elevated Access (User Access Administrator role) for the currently authenticated user.

.DESCRIPTION
    This script automates the process of enabling Elevated Access in Entra by calling the elevateAccess
    REST API endpoint. When successful, it grants the User Access Administrator role at the root scope ("/")
    to the currently authenticated user. This elevated access should be removed after use for security best practices.

.EXAMPLE
    .\Enable-ElevatedAccess.ps1
    Enables elevated access for the currently authenticated user.

.NOTES
    Author: Sebastian Flæng Markdanner
    Website: https://chanceofsecurity.com
    Version: 1.1
    Last Updated: 2025-02-16
    
    Requirements:
    - Azure PowerShell Module (Az)
    - User must be an Entra ID Global Administrator
#>

# Step 1: Ensure required modules are installed
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Write-Host "📦 Installing Az PowerShell module..." -ForegroundColor Yellow
    Install-Module -Name Az -Scope CurrentUser -Force -AllowClobber
}

# Step 2: Verify/establish Azure connection
if (-not (Get-AzContext)) {
    Write-Host "🔑 No active Azure session found. Initiating login..." -ForegroundColor Yellow
    Connect-AzAccount
}

# Step 3: Define API configuration
$apiVersion = "2016-07-01"
$managementApiUrl = "https://management.azure.com"
$apiUrl = "$managementApiUrl/providers/Microsoft.Authorization/elevateAccess?api-version=$apiVersion"

# Step 4: Obtain authentication token
Write-Host "🔒 Retrieving authentication token..." -ForegroundColor Yellow
$accessToken = (Get-AzAccessToken -ResourceUrl $managementApiUrl).Token

# Step 5: Prepare request headers
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

# Step 6: Enable elevated access
Write-Host "⚡ Enabling elevated access..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers
    Write-Host "✅ Elevated access successfully enabled!" -ForegroundColor Green
    Write-Host "   You now have User Access Administrator rights at the root scope." -ForegroundColor Green
    Write-Host "   ⚠️ Remember to remove elevated access when no longer needed!" -ForegroundColor Yellow
    
    # Display response for verification
    $response
}
catch {
    Write-Host "❌ Failed to elevate access: $_" -ForegroundColor Red
    Write-Host "   Common causes:" -ForegroundColor Yellow
    Write-Host "   - User is not an active Entra ID Global Administrator" -ForegroundColor Yellow
    Write-Host "   - Network connectivity issues" -ForegroundColor Yellow
}