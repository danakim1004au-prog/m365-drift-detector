<#
.SYNOPSIS
    Scans every tenant in config/tenants.json for drift against its baseline.
.DESCRIPTION
    Certificate-based app-only auth per tenant, continue-on-error (one bad
    tenant becomes an Error finding, not a dead run). Produces an HTML report
    and a Power BI-ready CSV. Exit codes: 0 clean, 2 critical drift found,
    3 one or more tenants unscannable.
.EXAMPLE
    ./Invoke-DriftScan.ps1 -ConfigPath ../config/tenants.json -OutputPath ../reports
#>
#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot/../config/tenants.json",
    [string]$OutputPath = "$PSScriptRoot/../reports"
)

$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot/../DriftDetector" -Force

if (-not (Test-Path $ConfigPath)) {
    throw "Tenant config not found at $ConfigPath. Copy config/tenants.sample.json and fill in real values."
}
$tenants = Get-Content $ConfigPath -Raw | ConvertFrom-Json
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$allFindings = [System.Collections.Generic.List[object]]::new()

foreach ($tenant in $tenants) {
    Write-Host "── Scanning $($tenant.tenantName)" -ForegroundColor Cyan
    try {
        Connect-MgGraph -TenantId $tenant.tenantId -ClientId $tenant.clientId `
            -CertificateThumbprint $tenant.certificateThumbprint -NoWelcome

        $baselinePath = Join-Path "$PSScriptRoot/.." $tenant.baselinePath
        if (-not (Test-Path $baselinePath)) {
            Write-Warning "No baseline for $($tenant.tenantName) — capturing one now. Review and commit it."
            New-DriftBaseline -TenantName $tenant.tenantName -OutFile $baselinePath
            continue
        }

        $findings = Compare-DriftBaseline -Tenant $tenant.tenantName -BaselinePath $baselinePath
        $allFindings.AddRange(@($findings))

        $drift = @($findings | Where-Object Severity -in 'Critical', 'Warning')
        Write-Host "   $($findings.Count) checks, $($drift.Count) drifted" -ForegroundColor $(if ($drift) { 'Yellow' } else { 'Green' })
    }
    catch {
        Write-Warning "Scan failed for $($tenant.tenantName): $_"
        $allFindings.Add((New-DriftFinding $tenant.tenantName 'Scan' 'tenantScan' 'successful scan' "FAILED: $_" 'Error'))
    }
    finally {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
Export-DriftHtmlReport -Findings $allFindings -OutFile (Join-Path $OutputPath "drift-$stamp.html")
$allFindings | Export-Csv -Path (Join-Path $OutputPath "drift-$stamp.csv") -NoTypeInformation

Write-Host "`nReport: $OutputPath/drift-$stamp.html" -ForegroundColor Green

if ($allFindings | Where-Object Severity -eq 'Error')    { exit 3 }
if ($allFindings | Where-Object Severity -eq 'Critical') { exit 2 }
exit 0
