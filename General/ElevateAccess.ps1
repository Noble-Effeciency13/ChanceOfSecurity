# Ensure Az module is installed
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Install-Module -Name Az -Scope CurrentUser -Force -AllowClobber
}

# Connect to Azure (if not already authenticated)
if (-not (Get-AzContext)) {
    Connect-AzAccount
}

# Define the API endpoint
$apiUrl = "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01"

# Get the access token for the current user
$accessToken = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token

# Set the request headers
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

# Make the POST request to elevate access
try {
    $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers
    Write-Host "✅ Elevated access successfully requested." -ForegroundColor Green
    $response
}
catch {
    Write-Host "❌ Failed to elevate access: $_" -ForegroundColor Red
}