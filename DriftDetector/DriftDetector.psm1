#Requires -Version 7.0
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

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

    $policies = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' |
        Select-Object -ExpandProperty value

    foreach ($p in $policies) {
        [pscustomobject]@{
            DisplayName    = $p.displayName
            State          = $p.state                       # enabled | disabled | enabledForReportingButNotEnforced
            IncludedUsers  = @($p.conditions.users.includeUsers)
            ExcludedUsers  = @($p.conditions.users.excludeUsers)
            ExcludedGroups = @($p.conditions.users.excludeGroups)
            GrantControls  = @($p.grantControls.builtInControls)
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
    do {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri
        $users += $page.value
        $uri = $page.'@odata.nextLink'
    } while ($uri)

    $members = @($users | Where-Object { $_.userType -eq 'member' })
    $registered = @($members | Where-Object { $_.isMfaRegistered })

    [pscustomobject]@{
        MemberUserCount      = $members.Count
        MfaRegisteredCount   = $registered.Count
        MfaRegisteredPercent = if ($members.Count) { [math]::Round(100 * $registered.Count / $members.Count, 1) } else { 0 }
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

    $authz = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
    $spo = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings'

    [pscustomobject]@{
        AllowInvitesFrom          = $authz.allowInvitesFrom
        GuestUserRole             = $authz.guestUserRoleId
        SharePointSharingCapability = $spo.sharingCapability
        SharingAllowedDomainList  = @($spo.sharingAllowedDomainList)
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

    $score = (Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/security/secureScores?`$top=1").value | Select-Object -First 1

    [pscustomobject]@{
        CurrentScore = $score.currentScore
        MaxScore     = $score.maxScore
        Percent      = if ($score.maxScore) { [math]::Round(100 * $score.currentScore / $score.maxScore, 1) } else { 0 }
        CreatedDate  = $score.createdDateTime
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

    $baseline = [ordered]@{
        tenantName        = $TenantName
        capturedAt        = (Get-Date).ToString('s')
        conditionalAccess = @(Get-DriftCaPolicySnapshot)
        sharing           = Get-DriftSharingSettings
        mfaFloorPercent   = [math]::Floor($mfa.MfaRegisteredPercent)
        secureScoreFloorPercent = [math]::Floor($score.Percent)
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
    foreach ($expected in $baseline.conditionalAccess) {
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
    foreach ($unexpected in ($livePolicies | Where-Object DisplayName -notin $baseline.conditionalAccess.DisplayName)) {
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
        $drifted = $check.Scale.IndexOf([string]$check.Actual) -gt $check.Scale.IndexOf([string]$check.Expected)
        $findings.Add((New-DriftFinding $Tenant 'Sharing' $check.Setting $check.Expected $check.Actual $(if ($drifted) { $check.Sev } else { 'Ok' })))
    }

    # --- MFA coverage --------------------------------------------------------
    $mfa = Get-DriftMfaCoverage
    $sev = if ($mfa.MfaRegisteredPercent -ge $baseline.mfaFloorPercent) { 'Ok' } else { 'Warning' }
    $findings.Add((New-DriftFinding $Tenant 'MFA' 'mfaRegisteredPercent' ">= $($baseline.mfaFloorPercent)%" "$($mfa.MfaRegisteredPercent)%" $sev))

    # --- Secure Score --------------------------------------------------------
    $score = Get-DriftSecureScore
    $sev = if ($score.Percent -ge $baseline.secureScoreFloorPercent) { 'Ok' } else { 'Warning' }
    $findings.Add((New-DriftFinding $Tenant 'SecureScore' 'secureScorePercent' ">= $($baseline.secureScoreFloorPercent)%" "$($score.Percent)%" $sev))

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
