#Requires -Version 7.0
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

function Get-DriftObjectValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject[$Name]
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) {
        return $property.Value
    }

    return $null
}

function New-DriftFinding {
    param(
        [string]$Tenant,
        [string]$Area,
        [string]$Setting,
        [string]$Expected,
        [string]$Actual,
        [ValidateSet('Critical', 'Warning', 'Info', 'Error', 'Ok')]
        [string]$Severity
    )
    [pscustomobject]@{
        Tenant   = $Tenant
        Area     = $Area
        Setting  = $Setting
        Expected = $Expected
        Actual   = $Actual
        Severity = $Severity
        ScanTime = (Get-Date).ToString('s')
    }
}

# ---------------------------------------------------------------------------
# Snapshot collectors — each returns a plain object that serialises cleanly
# to JSON, so the same shapes are used for baselines and live state.
# ---------------------------------------------------------------------------

function Get-DriftCaPolicySnapshot {
    <#
    .SYNOPSIS
        Captures the Conditional Access posture of the connected tenant.
    .DESCRIPTION
        Returns one record per CA policy with the fields that matter for
        drift: state, included/excluded users and groups, grant controls.
        Requires Policy.Read.All (application).
    #>
    [CmdletBinding()]
    param()

    try {
        $response = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -ErrorAction Stop
        $policies = @(Get-DriftObjectValue $response 'value')
    }
    catch {
        # Free tenants can't host CA policies (requires Entra ID P1); return none.
        if ($_ -match '403|premium|NonPremium') {
            Write-Warning "Conditional Access requires Entra ID P1 — no policies captured (Free tenant)"
            return @()
        }
        throw
    }

    foreach ($p in $policies) {
        $conditions = Get-DriftObjectValue $p 'conditions'
        $users = Get-DriftObjectValue $conditions 'users'
        $grant = Get-DriftObjectValue $p 'grantControls'
        [pscustomobject]@{
            DisplayName    = Get-DriftObjectValue $p 'displayName'
            State          = Get-DriftObjectValue $p 'state' # enabled | disabled | enabledForReportingButNotEnforced
            IncludedUsers  = @(Get-DriftObjectValue $users 'includeUsers')
            ExcludedUsers  = @(Get-DriftObjectValue $users 'excludeUsers')
            ExcludedGroups = @(Get-DriftObjectValue $users 'excludeGroups')
            GrantControls  = @(Get-DriftObjectValue $grant 'builtInControls')
        }
    }
}

function Get-DriftMfaCoverage {
    <#
    .SYNOPSIS
        Returns the percentage of member users registered for MFA.
    .DESCRIPTION
        Uses the authentication-methods registration report. Requires
        Reports.Read.All / AuditLog.Read.All (application).
    #>
    [CmdletBinding()]
    param()

    $uri = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?`$top=999"
    $users = @()
    try {
        do {
            $page = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $users += @(Get-DriftObjectValue $page 'value')
            $uri = Get-DriftObjectValue $page '@odata.nextLink'
        } while ($uri)
    }
    catch {
        # 403: tenant lacks Azure AD Premium P1/P2 for this report API
        if ($_ -match '403|NonPremiumTenant|premium') {
            Write-Warning "MFA registration report requires Azure AD Premium P1/P2 — returning 0% (assign E5/P1 license to enable)"
            return [pscustomobject]@{
                MemberUserCount      = -1
                MfaRegisteredCount   = -1
                MfaRegisteredPercent = -1
                LicenseError         = $true
            }
        }
        throw
    }

    $members = @($users | Where-Object { (Get-DriftObjectValue $_ 'userType') -eq 'member' })
    $registered = @($members | Where-Object { Get-DriftObjectValue $_ 'isMfaRegistered' })

    [pscustomobject]@{
        MemberUserCount      = $members.Count
        MfaRegisteredCount   = $registered.Count
        MfaRegisteredPercent = if ($members.Count) { [math]::Round(100 * $registered.Count / $members.Count, 1) } else { 0 }
        LicenseError         = $false
    }
}

function Get-DriftSharingSettings {
    <#
    .SYNOPSIS
        Captures external-collaboration posture: Entra guest-invite policy
        and SharePoint tenant sharing capability.
    .DESCRIPTION
        Requires Policy.Read.All and SharePointTenantSettings.Read.All
        (application).
    #>
    [CmdletBinding()]
    param()

    # Entra guest-invite policy is available on every tenant tier.
    $authz = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'

    # SharePoint settings need a provisioned SharePoint Online (M365 licence);
    # a bare Entra-only tenant returns 404/403 here.
    $spoCapability = 'unavailable'
    $spoDomains = @()
    try {
        $spo = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings' -ErrorAction Stop
        $spoCapability = Get-DriftObjectValue $spo 'sharingCapability'
        $spoDomains = @(Get-DriftObjectValue $spo 'sharingAllowedDomainList')
    }
    catch {
        Write-Warning "SharePoint sharing settings unavailable (no SharePoint Online provisioned on this tenant)"
    }

    [pscustomobject]@{
        AllowInvitesFrom          = Get-DriftObjectValue $authz 'allowInvitesFrom'
        GuestUserRole             = Get-DriftObjectValue $authz 'guestUserRoleId'
        SharePointSharingCapability = $spoCapability
        SharingAllowedDomainList  = $spoDomains
    }
}

function Get-DriftSecureScore {
    <#
    .SYNOPSIS
        Returns the latest Microsoft Secure Score as a percentage.
    .DESCRIPTION
        Requires SecurityEvents.Read.All (application).
    #>
    [CmdletBinding()]
    param()

    # Secure Score is generated once a tenant has M365 security workloads;
    # a brand-new Entra-only tenant has no score document yet.
    try {
        $resp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/security/secureScores?`$top=1" -ErrorAction Stop
        $score = @(Get-DriftObjectValue $resp 'value') | Select-Object -First 1
    }
    catch {
        Write-Warning "Secure Score unavailable on this tenant"
        $score = $null
    }

    if (-not $score) {
        return [pscustomobject]@{
            CurrentScore = -1; MaxScore = -1; Percent = -1; CreatedDate = $null; Unavailable = $true
        }
    }

    $current = Get-DriftObjectValue $score 'currentScore'
    $max     = Get-DriftObjectValue $score 'maxScore'
    [pscustomobject]@{
        CurrentScore = $current
        MaxScore     = $max
        Percent      = if ($max) { [math]::Round(100 * $current / $max, 1) } else { 0 }
        CreatedDate  = Get-DriftObjectValue $score 'createdDateTime'
        Unavailable  = $false
    }
}

# ---------------------------------------------------------------------------
# Baseline capture & diff
# ---------------------------------------------------------------------------

function New-DriftBaseline {
    <#
    .SYNOPSIS
        Snapshots the connected tenant's current state into a baseline JSON.
    .DESCRIPTION
        Run this once against a known-good tenant configuration, review the
        JSON, commit it. From then on every scan diffs live state against
        this file. Tolerances (MFA floor, Secure Score floor) are seeded from
        the captured values and are meant to be hand-tuned in review.
    .EXAMPLE
        New-DriftBaseline -TenantName Contoso -OutFile baselines/contoso.baseline.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantName,
        [Parameter(Mandatory)][string]$OutFile
    )

    $mfa = Get-DriftMfaCoverage
    $score = Get-DriftSecureScore

    $mfaFloor = if ($mfa.LicenseError) {
        Write-Warning "MFA floor set to 0 (Premium license required — update baseline after assigning E5/P1)"
        0
    } else { [math]::Floor($mfa.MfaRegisteredPercent) }

    $scoreFloor = if ($score.Unavailable) {
        Write-Warning "Secure Score floor set to 0 (no score on this tenant yet)"
        0
    } else { [math]::Floor($score.Percent) }

    $baseline = [ordered]@{
        tenantName        = $TenantName
        capturedAt        = (Get-Date).ToString('s')
        conditionalAccess = @(Get-DriftCaPolicySnapshot)
        sharing           = Get-DriftSharingSettings
        mfaFloorPercent   = $mfaFloor
        secureScoreFloorPercent = $scoreFloor
    }

    $baseline | ConvertTo-Json -Depth 8 | Set-Content -Path $OutFile -Encoding utf8
    Write-Verbose "Baseline for $TenantName written to $OutFile"
}

function Compare-DriftBaseline {
    <#
    .SYNOPSIS
        Diffs live tenant state against a baseline and returns drift findings.
    .DESCRIPTION
        Emits one finding object per checked setting (including 'Ok' rows so
        the report shows coverage, not just failures). Severity model:
        CA regressions and sharing loosening are Critical; coverage/score
        floors are Warning.
    .EXAMPLE
        $findings = Compare-DriftBaseline -Tenant Contoso -BaselinePath baselines/contoso.baseline.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Tenant,
        [Parameter(Mandatory)][string]$BaselinePath
    )

    $baseline = Get-Content $BaselinePath -Raw | ConvertFrom-Json
    $findings = [System.Collections.Generic.List[object]]::new()

    # --- Conditional Access ------------------------------------------------
    $livePolicies = @(Get-DriftCaPolicySnapshot)
    # Collect baseline policy names up front: projecting .DisplayName over an
    # empty array throws under StrictMode, so guard with @(...).
    $baselinePolicies = @($baseline.conditionalAccess)
    $baselineNames = @($baselinePolicies | ForEach-Object { $_.DisplayName })
    foreach ($expected in $baselinePolicies) {
        $actual = $livePolicies | Where-Object DisplayName -eq $expected.DisplayName
        if (-not $actual) {
            $findings.Add((New-DriftFinding $Tenant 'ConditionalAccess' "$($expected.DisplayName) / exists" 'present' 'MISSING' 'Critical'))
            continue
        }
        $sev = if ($actual.State -eq $expected.State) { 'Ok' } else { 'Critical' }
        $findings.Add((New-DriftFinding $Tenant 'ConditionalAccess' "$($expected.DisplayName) / state" $expected.State $actual.State $sev))

        $newExclusions = @($actual.ExcludedUsers + $actual.ExcludedGroups |
            Where-Object { $_ -notin @($expected.ExcludedUsers + $expected.ExcludedGroups) })
        $sev = if ($newExclusions.Count -eq 0) { 'Ok' } else { 'Critical' }
        $findings.Add((New-DriftFinding $Tenant 'ConditionalAccess' "$($expected.DisplayName) / exclusions" 'no new exclusions' `
            $(if ($newExclusions) { "$($newExclusions.Count) new: $($newExclusions -join ', ')" } else { 'none' }) $sev))
    }
    foreach ($unexpected in ($livePolicies | Where-Object { $_.DisplayName -notin $baselineNames })) {
        $findings.Add((New-DriftFinding $Tenant 'ConditionalAccess' "$($unexpected.DisplayName) / exists" 'not in baseline' 'present (review & re-baseline)' 'Info'))
    }

    # --- Sharing -------------------------------------------------------------
    $sharing = Get-DriftSharingSettings
    # Ordered laxness scales: index above baseline = drifted looser.
    $inviteScale  = @('none', 'adminsAndGuestInviters', 'adminsGuestInvitersAndAllMembers', 'everyone')
    $sharingScale = @('disabled', 'existingExternalUserSharingOnly', 'externalUserSharingOnly', 'externalUserAndGuestSharing')

    foreach ($check in @(
        @{ Setting = 'allowInvitesFrom'; Expected = $baseline.sharing.AllowInvitesFrom; Actual = $sharing.AllowInvitesFrom; Scale = $inviteScale; Sev = 'Warning' }
        @{ Setting = 'sharePointSharingCapability'; Expected = $baseline.sharing.SharePointSharingCapability; Actual = $sharing.SharePointSharingCapability; Scale = $sharingScale; Sev = 'Critical' }
    )) {
        if ([string]$check.Actual -eq 'unavailable') {
            $findings.Add((New-DriftFinding $Tenant 'Sharing' $check.Setting $check.Expected 'unavailable on this tenant' 'Info'))
            continue
        }
        # Case-insensitive index lookup — Graph enum casing varies by tenant.
        $lowerScale = $check.Scale | ForEach-Object { $_.ToLower() }
        $drifted = $lowerScale.IndexOf([string]$check.Actual.ToLower()) -gt $lowerScale.IndexOf([string]$check.Expected.ToLower())
        $findings.Add((New-DriftFinding $Tenant 'Sharing' $check.Setting $check.Expected $check.Actual $(if ($drifted) { $check.Sev } else { 'Ok' })))
    }

    # --- MFA coverage --------------------------------------------------------
    $mfa = Get-DriftMfaCoverage
    if ($mfa.LicenseError) {
        $findings.Add((New-DriftFinding $Tenant 'MFA' 'mfaRegisteredPercent' ">= $($baseline.mfaFloorPercent)%" 'unavailable (Entra P1/P2 required)' 'Info'))
    } else {
        $sev = if ($mfa.MfaRegisteredPercent -ge $baseline.mfaFloorPercent) { 'Ok' } else { 'Warning' }
        $findings.Add((New-DriftFinding $Tenant 'MFA' 'mfaRegisteredPercent' ">= $($baseline.mfaFloorPercent)%" "$($mfa.MfaRegisteredPercent)%" $sev))
    }

    # --- Secure Score --------------------------------------------------------
    $score = Get-DriftSecureScore
    if ($score.Unavailable) {
        $findings.Add((New-DriftFinding $Tenant 'SecureScore' 'secureScorePercent' ">= $($baseline.secureScoreFloorPercent)%" 'unavailable on this tenant' 'Info'))
    } else {
        $sev = if ($score.Percent -ge $baseline.secureScoreFloorPercent) { 'Ok' } else { 'Warning' }
        $findings.Add((New-DriftFinding $Tenant 'SecureScore' 'secureScorePercent' ">= $($baseline.secureScoreFloorPercent)%" "$($score.Percent)%" $sev))
    }

    $findings
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

function Export-DriftHtmlReport {
    <#
    .SYNOPSIS
        Renders drift findings from all tenants into a single HTML report.
    .EXAMPLE
        Export-DriftHtmlReport -Findings $all -OutFile reports/drift-20260611.html
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)][string]$OutFile
    )

    $critical = @($Findings | Where-Object Severity -eq 'Critical').Count
    $warning  = @($Findings | Where-Object Severity -eq 'Warning').Count
    $errors   = @($Findings | Where-Object Severity -eq 'Error').Count

    $rows = foreach ($f in ($Findings | Sort-Object @{e = { @('Critical','Error','Warning','Info','Ok').IndexOf($_.Severity) }}, Tenant)) {
        $cls = $f.Severity.ToLower()
        "<tr class='$cls'><td>$($f.Tenant)</td><td>$($f.Area)</td><td>$([System.Web.HttpUtility]::HtmlEncode($f.Setting))</td>" +
        "<td>$([System.Web.HttpUtility]::HtmlEncode($f.Expected))</td><td>$([System.Web.HttpUtility]::HtmlEncode($f.Actual))</td><td>$($f.Severity)</td></tr>"
    }

    @"
<!DOCTYPE html><html><head><meta charset='utf-8'><title>M365 Drift Report</title><style>
body{font-family:Segoe UI,sans-serif;margin:2rem;color:#222}
.cards{display:flex;gap:1rem;margin-bottom:1.5rem}
.card{padding:1rem 1.5rem;border-radius:8px;color:#fff;min-width:8rem}
.card.crit{background:#c0392b}.card.warn{background:#e67e22}.card.err{background:#7f8c8d}
.card b{font-size:2rem;display:block}
table{border-collapse:collapse;width:100%}th,td{padding:.4rem .7rem;border:1px solid #ddd;text-align:left;font-size:.9rem}
th{background:#2c3e50;color:#fff}
tr.critical td{background:#fdecea}tr.error td{background:#eceff1}tr.warning td{background:#fef5e7}tr.ok td{color:#888}
</style></head><body>
<h1>M365 Multi-Tenant Drift Report</h1>
<p>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') · $(@($Findings | Select-Object -ExpandProperty Tenant -Unique).Count) tenants · $($Findings.Count) checks</p>
<div class='cards'>
  <div class='card crit'><b>$critical</b>Critical drift</div>
  <div class='card warn'><b>$warning</b>Warnings</div>
  <div class='card err'><b>$errors</b>Scan errors</div>
</div>
<table><tr><th>Tenant</th><th>Area</th><th>Setting</th><th>Expected</th><th>Actual</th><th>Severity</th></tr>
$($rows -join "`n")
</table></body></html>
"@ | Set-Content -Path $OutFile -Encoding utf8

    Write-Verbose "Report written to $OutFile"
}

Export-ModuleMember -Function Get-DriftCaPolicySnapshot, Get-DriftMfaCoverage, Get-DriftSharingSettings,
    Get-DriftSecureScore, New-DriftBaseline, Compare-DriftBaseline, Export-DriftHtmlReport, New-DriftFinding
