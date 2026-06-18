@{
    RootModule        = 'DriftDetector.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '7c1f2a9e-4b6d-4e8a-9c3f-2d5b8e1a6f04'
    Author            = 'Dana Kim'
    Description       = 'Multi-tenant M365 security-configuration drift detection: baseline-as-code diffing of Conditional Access, MFA coverage, external sharing and Secure Score via Microsoft Graph app-only auth.'
    PowerShellVersion = '7.0'
    RequiredModules   = @('Microsoft.Graph.Authentication')
    FunctionsToExport = @(
        'Get-DriftCaPolicySnapshot'
        'Get-DriftMfaCoverage'
        'Get-DriftSharingSettings'
        'Get-DriftSecureScore'
        'New-DriftBaseline'
        'Compare-DriftBaseline'
        'Export-DriftHtmlReport'
        'New-DriftFinding'
    )
    PrivateData       = @{
        PSData = @{
            Tags       = @('M365', 'Graph', 'MSP', 'ConditionalAccess', 'SecureScore', 'Drift', 'Governance')
            ProjectUri = 'https://github.com/danakim1004au-prog/m365-drift-detector'
        }
    }
}
