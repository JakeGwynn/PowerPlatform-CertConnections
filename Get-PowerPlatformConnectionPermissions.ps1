#Requires -Version 5.1
<#
.SYNOPSIS
    Lists who an existing Power Platform connection is currently shared with, and at what
    access level, using app-only (client_credentials + certificate) auth.

.DESCRIPTION
    Read-only companion to Grant-PowerPlatformConnectionAccess.ps1 - calls the GET counterpart
    of the modifyPermissions endpoint that script posts to, on the same connectivity host.
    Confirmed against a HAR capture (200 OK, matching the shape parsed below).

.EXAMPLE
    .\Get-PowerPlatformConnectionPermissions.ps1 `
        -TenantId $tenantId -EnvironmentId $envId `
        -Connector 'shared_commondataserviceforapps' -ConnectionId $connectionId `
        -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint

.EXAMPLE
    # Also save the raw response
    .\Get-PowerPlatformConnectionPermissions.ps1 `
        -TenantId $tenantId -EnvironmentId $envId `
        -Connector 'shared_keyvault' -ConnectionId $connectionId `
        -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint -AsRawJson
#>
[CmdletBinding()]
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

    [switch]$AsRawJson,
    [string]$OutputDirectory = "$PSScriptRoot\output",

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

# --- Fetch and print the current permissions ---
Write-Host "Listing permissions for connection '$ConnectionId'..." -ForegroundColor Cyan
$permissions = Get-PPConnectionPermissions -EnvironmentApiHost $envApiHost -Connector $Connector -ConnectionId $ConnectionId `
    -EnvironmentId $EnvironmentId -AccessToken $ppToken -ApiVersion $ApiVersion -TimeoutSec $TimeoutSec

if ($AsRawJson) {
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $rawPath = Join-Path $OutputDirectory "permissions_$ConnectionId.json"
    $permissions | ConvertTo-Json -Depth 10 | Set-Content $rawPath
    Write-Host "Raw JSON written to: $rawPath" -ForegroundColor DarkGray
}

if (-not $permissions -or $permissions.Count -eq 0) {
    Write-Host "No permission entries returned." -ForegroundColor Yellow
    return
}

$rows = foreach ($entry in $permissions) {
    [PSCustomObject]@{
        PrincipalDisplayName = $entry.properties.principal.displayName
        PrincipalEmail       = $entry.properties.principal.email
        PrincipalId          = $entry.properties.principal.id
        PrincipalType        = $entry.properties.principal.type
        AccessLevel          = ConvertTo-PPFriendlyAccessLevel -RoleName $entry.properties.roleName
        RoleName             = $entry.properties.roleName
    }
}

Write-Host "`nCurrent access on connection '$ConnectionId' ($Connector):" -ForegroundColor Cyan
$rows | Format-Table -AutoSize
