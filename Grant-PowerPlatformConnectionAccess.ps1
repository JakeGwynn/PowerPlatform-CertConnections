#Requires -Version 5.1
<#
.SYNOPSIS
    Shares an existing Power Platform connection with one or more principals, at one of the
    three connection access levels, using app-only (client_credentials + certificate) auth.

.DESCRIPTION
    Standalone companion to New-PowerPlatformCertConnection.ps1 for re-sharing a connection that
    already exists, without re-running creation. Only one identity is involved - the Caller,
    which authenticates the call and (if sharing by UPN/email) resolves the recipient via
    Microsoft Graph.

    Access levels map to Power Platform's connection permission roles:
      CanUse         -> roleName CanView          ("Can use")
      CanUseAndShare -> roleName CanViewWithShare  ("Can use and share")
      CanEdit        -> roleName CanEdit           ("Can edit")
    Confirmed against a HAR capture covering all three levels - roleName is the only thing that
    changes between them; capabilities stays an empty array.

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

    # Caller identity - authenticates the call
    [Parameter(Mandatory)][string]$CallerClientId,
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

# --- Authenticate as the Caller identity ---
Write-Host "Loading Caller certificate..." -ForegroundColor Cyan
$callerCert = Get-PPCertificateFromSource -Label 'Caller cert' -TenantId $TenantId `
    -Thumbprint $CallerCertThumbprint -StoreLocation $CallerCertStoreLocation `
    -PfxPath $CallerPfxPath -PfxPassword $CallerPfxPassword `
    -KeyVaultName $CallerKeyVaultName -KeyVaultSecretName $CallerKeyVaultSecretName `
    -KeyVaultSecretVersion $CallerKeyVaultSecretVersion -KeyVaultPfxPassword $CallerKeyVaultPfxPassword

$ppToken = Get-PPCertClientCredentialsToken -TenantId $TenantId -ClientId $CallerClientId -Certificate $callerCert `
    -Scope (Get-PPScopeForResource $PowerPlatformApiResource) -LoginAuthorityBaseUrl $LoginAuthorityBaseUrl -TimeoutSec $TimeoutSec
$envApiHost = Get-PPEnvironmentApiHost -EnvironmentId $EnvironmentId -DomainSuffix $EnvironmentApiDomainSuffix

# Only need a Graph token if at least one recipient was given as a UPN/email rather than a GUID
$graphToken = $null
$needsGraph = $PrincipalUpnsOrIds | Where-Object { $_ -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' }
if ($needsGraph) {
    $graphToken = Get-PPCertClientCredentialsToken -TenantId $TenantId -ClientId $CallerClientId -Certificate $callerCert `
        -Scope 'https://graph.microsoft.com/.default' -LoginAuthorityBaseUrl $LoginAuthorityBaseUrl -TimeoutSec $TimeoutSec
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
