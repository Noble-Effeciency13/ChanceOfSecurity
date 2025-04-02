<#
.SYNOPSIS
    Registers and validates an Microsoft Entra Password Protection Proxy server.

.DESCRIPTION
    This script automates the registration process for an Microsoft Entra Password Protection Proxy server
    and performs health checks before and after the registration. It handles both proxy and forest
    registration, with validation steps in between.

.PARAMETER AccountUpn
    The User Principal Name (UPN) of the account used for registration.
    Must be in email format (e.g., admin@contoso.com).
    The account must have Global Administrator privileges.

.NOTES
    File Name      : Register-EntraPasswordProtProxy.ps1
    Author         : Sebastian Flæng Markdanner
    Website        : https://chanceofsecurity.com
    Prerequisite   : Microsoft Entra Password Protection Proxy installed
    Version        : 1.0.1
    Creation Date  : 2024-03-31

.EXAMPLE
    .\Register-EntraPasswordProtProxy.ps1 -AccountUpn "admin@contoso.com"
    Registers the proxy server using the specified admin account.

#>

# Parameters
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$')]
    [string]$AccountUpn
)

# Module import with error handling
try {
    Import-Module AzureADPasswordProtection -ErrorAction Stop
    Write-Host "[INFO] Successfully imported AzureADPasswordProtection module." -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Unable to import AzureADPasswordProtection module. Please ensure it is installed." -ForegroundColor Red
    Write-Host "[ERROR] Exception: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Check if the Proxy service is running
try {
    $service = Get-Service AzureADPasswordProtectionProxy -ErrorAction Stop
    if ($service.Status -eq 'Running') {
        Write-Host "[INFO] AzureADPasswordProtectionProxy service is running. Proceeding with Proxy registration..." -ForegroundColor Green
        try {
            Register-AzureADPasswordProtectionProxy -AccountUpn $AccountUpn -ErrorAction Stop
            Write-Host "[INFO] Proxy registration successful." -ForegroundColor Green
        } catch {
            Write-Host "[ERROR] Failed to register proxy: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "[ERROR] AzureADPasswordProtectionProxy service is not running. Please start the service and try again." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "[ERROR] Failed to check service status: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Wait 2 seconds for the registration to take effect
Write-Host "[INFO] Waiting for registration to take effect..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

# Test Proxy Health and display errors if any
try {
    $healthResult = Test-AzureADPasswordProtectionProxyHealth -TestAll -ErrorAction Stop
    $failedTests = $healthResult | Where-Object { $_.Result -ne 'Passed' }
    if ($failedTests) {
        Write-Host "[ERROR] Proxy health check failed. Failed tests:" -ForegroundColor Red
        $failedTests | Format-Table
        exit 1
    } else {
        Write-Host "[INFO] All proxy health checks passed." -ForegroundColor Green
    }
} catch {
    Write-Host "[ERROR] Failed to run health checks: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# If Proxy health is good, register the forest
try {
    Register-AzureADPasswordProtectionForest -AccountUpn $AccountUpn -ErrorAction Stop
    Write-Host "[INFO] Forest registration initiated successfully." -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to register forest: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Wait 2 seconds for the forest registration to settle
Write-Host "[INFO] Waiting for forest registration to settle..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

# Final Proxy Health Test
try {
    $finalHealthResult = Test-AzureADPasswordProtectionProxyHealth -TestAll -ErrorAction Stop
    $failedFinalTests = $finalHealthResult | Where-Object { $_.Result -ne 'Passed' }
    if ($failedFinalTests) {
        Write-Host "[ERROR] Final health check failed. Failed tests:" -ForegroundColor Red
        $failedFinalTests | Format-Table
        exit 1
    } else {
        Write-Host "[SUCCESS] Final health check passed. Registration complete." -ForegroundColor Green
        exit 0
    }
} catch {
    Write-Host "[ERROR] Failed to run final health checks: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}