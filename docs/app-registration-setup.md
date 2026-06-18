# App registration setup (per tenant)

One app registration per customer tenant, certificate credential, read-only application permissions. Repeat for every tenant in `config/tenants.json`.

## 1. Create the certificate (once, on the scanning machine)

```powershell
$cert = New-SelfSignedCertificate -Subject 'CN=M365DriftDetector' `
    -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable `
    -KeySpec Signature -KeyLength 2048 -NotAfter (Get-Date).AddYears(1)
Export-Certificate -Cert $cert -FilePath driftdetector.cer   # public key only — this is what you upload
$cert.Thumbprint                                              # goes into tenants.json
```

For GitHub Actions, also export the PFX and store it base64-encoded as the `AUTH_CERT_PFX_B64` secret:

```powershell
Export-PfxCertificate -Cert $cert -FilePath driftdetector.pfx -Password (Read-Host -AsSecureString)
[Convert]::ToBase64String([IO.File]::ReadAllBytes('driftdetector.pfx')) | Set-Clipboard
```

## 2. Register the app in the customer tenant

Entra admin center → App registrations → **New registration**
- Name: `MSP Drift Detector`, single tenant, no redirect URI.

**Certificates & secrets** → Certificates → upload `driftdetector.cer`. (No client secrets — certs don't end up in command lines or logs.)

**API permissions** → Microsoft Graph → **Application permissions**:

| Permission | Used for |
|---|---|
| `Policy.Read.All` | Conditional Access policies, authorizationPolicy |
| `Reports.Read.All` | MFA registration report |
| `AuditLog.Read.All` | userRegistrationDetails requires it alongside Reports.Read.All |
| `SecurityEvents.Read.All` | Secure Score |
| `SharePointTenantSettings.Read.All` | SharePoint sharing settings |

Then **Grant admin consent**. All read-only — point this out in the customer security review; it shortens the conversation considerably.

## 3. Test the connection

```powershell
Connect-MgGraph -TenantId <tenantId> -ClientId <clientId> -CertificateThumbprint <thumbprint> -NoWelcome
Get-MgContext   # AuthType should be AppOnly
Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Method GET
```

## Multi-tenant note

The same `.cer` can be uploaded to every tenant's app registration, so one PFX on the runner covers the whole fleet. Rotate annually; the GitHub Actions workflow will start failing with a clear cert error when it expires — add a calendar reminder a month before `NotAfter`.
