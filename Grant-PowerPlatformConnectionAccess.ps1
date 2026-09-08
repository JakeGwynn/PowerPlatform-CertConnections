#Requires -Version 5.1
<#
.SYNOPSIS
    Shares an existing Power Platform connection with one or more principals, at one of the
    three connection access levels. The Caller identity that performs the call can be either a
    certificate-based Service Principal, or your own delegated (interactive) sign-in - see
    -CallerAuthMode.

.DESCRIPTION
    Standalone companion to New-PowerPlatformCertConnection.ps1 for re-sharing a connection that
    already exists, without re-running creation. Only one identity is involved - the Caller,
    which authenticates the call and (if sharing by UPN/email) resolves the recipient via
    Microsoft Graph. The Caller supports two auth modes (-CallerAuthMode): Certificate (default,
    client_credentials + a certificate JWT assertion) or Delegated (your own interactive sign-in
    via the `az` CLI - no -CallerClientId or certificate needed).

    Access levels map to Power Platform's connection permission roles:
      CanUse         -> roleName CanView          ("Can use")
      CanUseAndShare -> roleName CanViewWithShare  ("Can use and share")
      CanEdit        -> roleName CanEdit           ("Can edit")
    Confirmed against a HAR capture covering all three levels - roleName is the only thing that
    changes between them; capabilities stays an empty array.

.PARAMETER CallerAuthMode
    Certificate (default): the Caller authenticates as a Service Principal via
    -CallerClientId + a certificate source. Delegated: the Caller authenticates as whichever
    identity is (or becomes, via an interactive `az login` prompt) signed in to the Azure CLI -
    -CallerClientId and every Caller certificate parameter are ignored.

.PARAMETER PrincipalUpnsOrIds
    UPNs/emails (resolved via Graph - requires the Caller app to have Graph User.Read.All,
    admin-consented) or raw Entra object IDs (no extra permission needed).

.EXAMPLE
    .\Grant-PowerPlatformConnectionAccess.ps1 `
        -TenantId $tenantId -EnvironmentId $envId `
        -Connector 'shared_commondataserviceforapps' -ConnectionId $connectionId `
        -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
        -PrincipalUpnsOrIds 'alans@contoso.onmicrosoft.com', 'admin@contoso.onmicrosoft.com' -AccessLevel CanUse

.EXAMPLE
    # Caller uses delegated (interactive) auth instead of a certificate
    .\Grant-PowerPlatformConnectionAccess.ps1 `
        -TenantId $tenantId -EnvironmentId $envId `
        -Connector 'shared_commondataserviceforapps' -ConnectionId $connectionId `
        -CallerAuthMode Delegated `
        -PrincipalUpnsOrIds 'alans@contoso.onmicrosoft.com' -AccessLevel CanUse

.EXAMPLE
    # Share a PAD run-owner connection with another service principal (the only allowed recipient type)
    .\Grant-PowerPlatformConnectionAccess.ps1 `
        -TenantId $tenantId -EnvironmentId $envId `
        -Connector 'shared_uiflow' -ConnectionId $connectionId `
        -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
        -PrincipalUpnsOrIds $otherSpObjectId -AccessLevel CanUse -PrincipalType ServicePrincipal

.NOTES
    Supports -WhatIf/-Confirm - no permission changes are made when -WhatIf is passed.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$EnvironmentId,
    [Parameter(Mandatory)][string]$Connector,
    [Parameter(Mandatory)][string]$ConnectionId,

    # Caller identity - authenticates the call. -CallerAuthMode Certificate (default) needs
    # -CallerClientId + a certificate source below; Delegated needs neither (uses your own
    # interactive az CLI sign-in instead) and ignores the rest of this group.
    [ValidateSet('Certificate', 'Delegated')][string]$CallerAuthMode = 'Certificate',
    [string]$CallerClientId,
    [string]$CallerCertThumbprint,
    [ValidateSet('CurrentUser', 'LocalMachine')][string]$CallerCertStoreLocation = 'CurrentUser',
    [string]$CallerPfxPath,
    [Security.SecureString]$CallerPfxPassword,
    [string]$CallerKeyVaultName,
    [string]$CallerKeyVaultSecretName,
    [string]$CallerKeyVaultSecretVersion,
    [Security.SecureString]$CallerKeyVaultPfxPassword,

    [Parameter(Mandatory)][string[]]$PrincipalUpnsOrIds,
    [ValidateSet('CanUse', 'CanUseAndShare', 'CanEdit')][string]$AccessLevel = 'CanUse',
    [ValidateSet('User', 'ServicePrincipal')][string]$PrincipalType = 'User',
    [ValidateSet('Notify', 'DoNotNotify', 'NotSpecified')][string]$NotifyShareTargetOption = 'Notify',
    [switch]$InviteGuestToTenant,

    [string]$LoginAuthorityBaseUrl = 'https://login.microsoftonline.com',
    [string]$PowerPlatformApiResource = 'https://api.powerplatform.com/',
    [string]$EnvironmentApiDomainSuffix = 'environment.api.powerplatform.com',
    [string]$ApiVersion = '1',
    [int]$TimeoutSec = 100
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Modules\PowerPlatformCertConnection.Common.psm1') -Force
if ($CallerAuthMode -eq 'Certificate' -and -not $CallerClientId) {
    throw "-CallerClientId is required when -CallerAuthMode is 'Certificate' (the default). Pass -CallerAuthMode Delegated to sign in interactively instead."
}

# --- Authenticate as the Caller identity ---
$callerCert = $null
if ($CallerAuthMode -eq 'Certificate') {
    Write-Host "Loading Caller certificate..." -ForegroundColor Cyan
    $callerCert = Get-PPCertificateFromSource -Label 'Caller cert' -TenantId $TenantId `
        -Thumbprint $CallerCertThumbprint -StoreLocation $CallerCertStoreLocation `
        -PfxPath $CallerPfxPath -PfxPassword $CallerPfxPassword `
        -KeyVaultName $CallerKeyVaultName -KeyVaultSecretName $CallerKeyVaultSecretName `
        -KeyVaultSecretVersion $CallerKeyVaultSecretVersion -KeyVaultPfxPassword $CallerKeyVaultPfxPassword
}
else {
    Write-Host "Caller will sign in interactively (delegated, via az CLI) - no certificate needed." -ForegroundColor Cyan
}

$ppToken = Get-PPCallerToken -AuthMode $CallerAuthMode -Resource $PowerPlatformApiResource -TenantId $TenantId `
    -ClientId $CallerClientId -Certificate $callerCert -LoginAuthorityBaseUrl $LoginAuthorityBaseUrl -TimeoutSec $TimeoutSec
$envApiHost = Get-PPEnvironmentApiHost -EnvironmentId $EnvironmentId -DomainSuffix $EnvironmentApiDomainSuffix

# Only need a Graph token if at least one recipient was given as a UPN/email rather than a GUID
$graphToken = $null
$needsGraph = $PrincipalUpnsOrIds | Where-Object { $_ -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' }
if ($needsGraph) {
    $graphToken = Get-PPCallerToken -AuthMode $CallerAuthMode -Resource 'https://graph.microsoft.com' -TenantId $TenantId `
        -ClientId $CallerClientId -Certificate $callerCert -LoginAuthorityBaseUrl $LoginAuthorityBaseUrl -TimeoutSec $TimeoutSec
}

# --- Share with each principal ---
$results = foreach ($upnOrId in $PrincipalUpnsOrIds) {
    Write-Host "Sharing connection '$ConnectionId' with $upnOrId as $AccessLevel..." -ForegroundColor Cyan
    $principal = Resolve-PPPrincipal -UpnOrId $upnOrId -GraphToken $graphToken -TenantId $TenantId -PrincipalType $PrincipalType
    $shared = Grant-PPConnectionAccess -EnvironmentApiHost $envApiHost -Connector $Connector -ConnectionId $ConnectionId `
        -EnvironmentId $EnvironmentId -Principal $principal -AccessLevel $AccessLevel `
        -NotifyShareTargetOption $NotifyShareTargetOption -InviteGuestToTenant:$InviteGuestToTenant `
        -AccessToken $ppToken -ApiVersion $ApiVersion -TimeoutSec $TimeoutSec -WhatIf:$WhatIfPreference

    if ($shared) {
        Write-Host "Shared with $upnOrId as $AccessLevel" -ForegroundColor Green
        [PSCustomObject]@{ Principal = $upnOrId; PrincipalId = $principal.id; AccessLevel = $AccessLevel; Result = 'Shared' }
    }
    else {
        Write-Host "(WhatIf) Would have shared with $upnOrId as $AccessLevel." -ForegroundColor Yellow
        [PSCustomObject]@{ Principal = $upnOrId; PrincipalId = $principal.id; AccessLevel = $AccessLevel; Result = 'WhatIf' }
    }
}

Write-Host "`nDone." -ForegroundColor Cyan
$results | Format-Table -AutoSize
