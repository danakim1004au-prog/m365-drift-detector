<#
.SYNOPSIS
    Azure Automation runbook variant of Invoke-DriftScan.
.DESCRIPTION
    Differences from the local driver:
      - Tenant config comes from an encrypted Automation variable
        ('DriftTenantConfig', JSON string) instead of a local file.
      - The auth certificate is uploaded to the Automation account and
        retrieved with Get-AutomationCertificate.
      - The HTML report is uploaded to a storage account (static website
        container) so the latest report is always at a stable URL.
    Schedule: link this runbook to a daily schedule in the Automation account.
    Modules: import Microsoft.Graph.Authentication and Az.Storage into the
    Automation account before first run.
#>
param(
    [string]$StorageAccountName = 'stmspdriftreports',
    [string]$ReportContainer = '$web'
)

$ErrorActionPreference = 'Stop'

# DriftDetector module is deployed alongside the runbook as an Automation module package.
Import-Module DriftDetector

$tenants = Get-AutomationVariable -Name 'DriftTenantConfig' | ConvertFrom-Json
$allFindings = [System.Collections.Generic.List[object]]::new()

foreach ($tenant in $tenants) {
    try {
        $cert = Get-AutomationCertificate -Name $tenant.certificateName
        Connect-MgGraph -TenantId $tenant.tenantId -ClientId $tenant.clientId -Certificate $cert -NoWelcome

        # Baselines ship inside the module package under baselines/.
        $baselinePath = Join-Path (Split-Path (Get-Module DriftDetector).Path) "baselines/$($tenant.tenantName.ToLower()).baseline.json"
        $allFindings.AddRange(@(Compare-DriftBaseline -Tenant $tenant.tenantName -BaselinePath $baselinePath))
    }
    catch {
        $allFindings.Add((New-DriftFinding $tenant.tenantName 'Scan' 'tenantScan' 'successful scan' "FAILED: $_" 'Error'))
    }
    finally {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}

$reportPath = Join-Path $env:TEMP 'drift-latest.html'
Export-DriftHtmlReport -Findings $allFindings -OutFile $reportPath

# Publish with the Automation account's managed identity.
Connect-AzAccount -Identity | Out-Null
$ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
Set-AzStorageBlobContent -File $reportPath -Container $ReportContainer -Blob 'drift-latest.html' `
    -Context $ctx -Properties @{ ContentType = 'text/html' } -Force | Out-Null

$critical = @($allFindings | Where-Object Severity -eq 'Critical').Count
Write-Output "Scan complete: $($allFindings.Count) checks, $critical critical."
if ($critical) { throw "$critical critical drift finding(s) — see drift-latest.html" }  # fails the job → alertable
