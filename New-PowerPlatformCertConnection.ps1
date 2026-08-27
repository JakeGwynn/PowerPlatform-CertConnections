#Requires -Version 5.1
<#
.SYNOPSIS
    Creates a certificate-authenticated Power Platform connection - Dataverse, Key Vault, or a
    Power Automate Desktop run-owner connection - using app-only (client_credentials + certificate)
    auth throughout. No delegated/interactive sign-in is used for any Dataverse/Power
    Platform/Graph call.

.DESCRIPTION
    Two identities are always involved: the Caller (authenticates every API call with its own
    certificate) and the Connection/RunOwner identity (never authenticates anything itself - its
    client id + certificate are just embedded in the connection for Power Platform to use at run
    time). The Connection/RunOwner app must already have whatever access the target service
    requires.

    Certificates for either identity can come from a local certificate store (by thumbprint), a
    local .pfx file, or Azure Key Vault (the az CLI's own signed-in session is used just to read
    the secret - see the *KeyVault* parameters below).

.PARAMETER ConnectionType
    Dataverse, KeyVault, or PadRunOwner. Each type needs a different set of parameters - see the
    examples below.

.PARAMETER RunOwnerCredentialMode
    KeyVaultPassword (default): username and password both come from Dataverse environment
    variables. KeyVaultCertificate / CyberArk: username comes from an environment variable,
    password is sent as the literal "none" - Microsoft documents these as the same request body;
    the CyberArk-vs-KeyVault difference is in how the Credential record itself is backed, not in
    this call. Direct: literal username/password, no Credential record needed.

.PARAMETER ShareAccessLevel
    CanUse, CanUseAndShare, or CanEdit - see Grant-PowerPlatformConnectionAccess.ps1.

.EXAMPLE
    .\New-PowerPlatformCertConnection.ps1 -ConnectionType Dataverse `
        -TenantId $tenantId -EnvironmentId $envId -DataverseUrl 'https://contoso.crm.dynamics.com' `
        -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
        -ConnectionClientId $connectionAppId -ConnectionCertThumbprint $connectionThumbprint `
        -ShareWithUpns 'admin@contoso.onmicrosoft.com' -ShareAccessLevel CanEdit

.EXAMPLE
    # Key Vault connection, connection cert pulled live from Key Vault via az cli
    .\New-PowerPlatformCertConnection.ps1 -ConnectionType KeyVault `
        -TenantId $tenantId -EnvironmentId $envId -VaultName 'ContosoKeyVault' `
        -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
        -ConnectionClientId $connectionAppId -ConnectionKeyVaultName 'CertsVault' -ConnectionKeyVaultSecretName 'connection-cert'

.EXAMPLE
    # PAD run-owner connection, Azure Key Vault password-based credential
    .\New-PowerPlatformCertConnection.ps1 -ConnectionType PadRunOwner `
        -TenantId $tenantId -EnvironmentId $envId `
        -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
        -RunOwnerAppId $runOwnerAppId -RunOwnerCertPfxPath .\runowner.pfx -RunOwnerCertPfxPassword (Read-Host -AsSecureString) `
        -RunOwnerCredentialMode KeyVaultPassword -CredentialId $credentialId `
        -UsernameEnvironmentVariable 'new_UserName1' -PasswordEnvironmentVariable 'new_Password1' `
        -MachineGroupId $machineGroupId

.NOTES
    Prerequisites (not created by this script): both app registrations and their certificates
    already exist, and the Connection/RunOwner app already has whatever access the target
    service requires. PadRunOwner also needs an existing Dataverse Credential record (unless
    -RunOwnerCredentialMode Direct) and a properly provisioned Machine Group.

    Supports -WhatIf/-Confirm. Certificate loading and token acquisition still happen (they're
    read-only), but nothing is created, and nothing is logged to -ConnectionLogPath.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('Dataverse', 'KeyVault', 'PadRunOwner')][string]$ConnectionType,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$EnvironmentId,

    # Dataverse / KeyVault
    [string]$DataverseUrl,
    [string]$VaultName,
    [hashtable]$ExtraParameters = @{},
    [string]$SecurityRoleName = 'System Administrator',

    # Caller identity - authenticates every call
    [Parameter(Mandatory)][string]$CallerClientId,
    [string]$CallerCertThumbprint,
    [ValidateSet('CurrentUser', 'LocalMachine')][string]$CallerCertStoreLocation = 'CurrentUser',
    [string]$CallerPfxPath,
    [Security.SecureString]$CallerPfxPassword,
    [string]$CallerKeyVaultName,
    [string]$CallerKeyVaultSecretName,
    [string]$CallerKeyVaultSecretVersion,
    [Security.SecureString]$CallerKeyVaultPfxPassword,

    # Connection identity - Dataverse/KeyVault only, embedded, never authenticates
    [string]$ConnectionClientId,
    [string]$ConnectionCertThumbprint,
    [ValidateSet('CurrentUser', 'LocalMachine')][string]$ConnectionCertStoreLocation = 'CurrentUser',
    [string]$ConnectionPfxPath,
    [Security.SecureString]$ConnectionPfxPassword,
    [string]$ConnectionKeyVaultName,
    [string]$ConnectionKeyVaultSecretName,
    [string]$ConnectionKeyVaultSecretVersion,
    [Security.SecureString]$ConnectionKeyVaultPfxPassword,

    # Run Owner identity - PadRunOwner only, embedded, never authenticates
    [string]$RunOwnerAppId,
    [string]$RunOwnerCertThumbprint,
    [ValidateSet('CurrentUser', 'LocalMachine')][string]$RunOwnerCertStoreLocation = 'CurrentUser',
    [string]$RunOwnerCertPfxPath,
    [Security.SecureString]$RunOwnerCertPfxPassword,
    [string]$RunOwnerKeyVaultName,
    [string]$RunOwnerKeyVaultSecretName,
    [string]$RunOwnerKeyVaultSecretVersion,
    [Security.SecureString]$RunOwnerKeyVaultPfxPassword,

    [ValidateSet('KeyVaultPassword', 'KeyVaultCertificate', 'CyberArk', 'Direct')][string]$RunOwnerCredentialMode = 'KeyVaultPassword',
    [string]$CredentialId,
    [string]$UsernameEnvironmentVariable,
    [string]$PasswordEnvironmentVariable,
    [string]$DirectUsername,
    [Security.SecureString]$DirectPassword,
    [string]$MachineGroupId,
    [string]$RunOwnerConnector = 'shared_uiflow',

    [string]$ConnectionDisplayName,
    [string]$ConnectionId = [guid]::NewGuid().ToString(),

    # Optional sharing
    [string[]]$ShareWithUpns = @(),
    [ValidateSet('CanUse', 'CanUseAndShare', 'CanEdit')][string]$ShareAccessLevel = 'CanUse',
    [ValidateSet('User', 'ServicePrincipal')][string]$SharePrincipalType = 'User',
    [ValidateSet('Notify', 'DoNotNotify', 'NotSpecified')][string]$NotifyShareTargetOption = 'Notify',
    [switch]$InviteGuestToTenant,

    # Cloud overrides (defaults = public commercial cloud)
    [string]$LoginAuthorityBaseUrl = 'https://login.microsoftonline.com',
    [string]$PowerPlatformApiResource = 'https://api.powerplatform.com/',
    [string]$EnvironmentApiDomainSuffix = 'environment.api.powerplatform.com',
    [string]$ApiVersion = '1',
    [int]$TimeoutSec = 100,

    [string]$OutputDirectory = "$PSScriptRoot\output",
    [string]$ConnectionLogPath
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Modules\PowerPlatformCertConnection.Common.psm1') -Force
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
if (-not $ConnectionLogPath) { $ConnectionLogPath = Join-Path $OutputDirectory 'CreatedConnections.log.txt' }

# --- Validate parameters for the selected connection type ---
switch ($ConnectionType) {
    'Dataverse' {
        if (-not $DataverseUrl) { throw "-DataverseUrl is required when -ConnectionType is 'Dataverse'." }
        if (-not $ConnectionClientId) { throw "-ConnectionClientId is required when -ConnectionType is 'Dataverse'." }
        $DataverseUrl = $DataverseUrl.TrimEnd('/')
    }
    'KeyVault' {
        if ($VaultName) { $ExtraParameters['vaultName'] = $VaultName }
        if (-not $ConnectionClientId) { throw "-ConnectionClientId is required when -ConnectionType is 'KeyVault'." }
    }
    'PadRunOwner' {
        if (-not $RunOwnerAppId) { throw "-RunOwnerAppId is required when -ConnectionType is 'PadRunOwner'." }
        if (-not $MachineGroupId) { throw "-MachineGroupId is required when -ConnectionType is 'PadRunOwner'." }
        if ($RunOwnerCredentialMode -ne 'Direct' -and -not $CredentialId) {
            throw "-CredentialId is required unless -RunOwnerCredentialMode is 'Direct'."
        }
    }
}
if (-not $ConnectionDisplayName) {
    $ConnectionDisplayName = switch ($ConnectionType) {
        'Dataverse' { 'DataverseCertAuth' }
        'KeyVault' { 'KeyVaultCertAuth' }
        'PadRunOwner' { 'PadRunOwnerConnection' }
    }
}

# --- Authenticate as the Caller identity ---
Write-Host "Loading Caller certificate..." -ForegroundColor Cyan
$callerCert = Get-PPCertificateFromSource -Label 'Caller cert' -TenantId $TenantId `
    -Thumbprint $CallerCertThumbprint -StoreLocation $CallerCertStoreLocation `
    -PfxPath $CallerPfxPath -PfxPassword $CallerPfxPassword `
    -KeyVaultName $CallerKeyVaultName -KeyVaultSecretName $CallerKeyVaultSecretName `
    -KeyVaultSecretVersion $CallerKeyVaultSecretVersion -KeyVaultPfxPassword $CallerKeyVaultPfxPassword

$connectorInfo = $null
if ($ConnectionType -in 'Dataverse', 'KeyVault') {
    $connectorInfo = (Get-PPConnectorRegistry)[$ConnectionType]
    foreach ($key in $connectorInfo.RequiredExtraParams) {
        if (-not $ExtraParameters.ContainsKey($key)) {
            throw "ConnectionType '$ConnectionType' requires a value for '$key' (e.g. -VaultName, or -ExtraParameters @{ $key = '...' })."
        }
    }

    if ($ConnectionType -eq 'Dataverse') {
        Write-Host "Validating certificate auth against Dataverse (WhoAmI)..." -ForegroundColor Cyan
        $dvToken = Get-PPCertClientCredentialsToken -TenantId $TenantId -ClientId $CallerClientId -Certificate $callerCert `
            -Scope (Get-PPScopeForResource $DataverseUrl) -LoginAuthorityBaseUrl $LoginAuthorityBaseUrl -TimeoutSec $TimeoutSec
        $who = Invoke-RestMethod -Uri "$DataverseUrl/api/data/v9.2/WhoAmI" -Headers @{ Authorization = "Bearer $dvToken" } -TimeoutSec $TimeoutSec
        Write-Host "WhoAmI succeeded. UserId=$($who.UserId)" -ForegroundColor Green

        Confirm-PPDataverseApplicationUser -DataverseUrl $DataverseUrl -TenantId $TenantId -AppClientId $ConnectionClientId `
            -CallerDataverseToken $dvToken -SecurityRoleName $SecurityRoleName -WhatIf:$WhatIfPreference | Out-Null
    }
    else {
        Write-Host "Make sure '$ConnectionClientId' already has access to the target Key Vault (e.g. Key Vault Secrets User)." -ForegroundColor Yellow
    }
}

# --- Build and create the connection ---
Write-Host "Creating the $ConnectionType connection..." -ForegroundColor Cyan
$ppToken = Get-PPCertClientCredentialsToken -TenantId $TenantId -ClientId $CallerClientId -Certificate $callerCert `
    -Scope (Get-PPScopeForResource $PowerPlatformApiResource) -LoginAuthorityBaseUrl $LoginAuthorityBaseUrl -TimeoutSec $TimeoutSec
$envApiHost = Get-PPEnvironmentApiHost -EnvironmentId $EnvironmentId -DomainSuffix $EnvironmentApiDomainSuffix

if ($ConnectionType -in 'Dataverse', 'KeyVault') {
    Write-Host "Loading Connection certificate..." -ForegroundColor Cyan
    $connectionCert = Get-PPCertificateFromSource -Label 'Connection cert' -TenantId $TenantId `
        -Thumbprint $ConnectionCertThumbprint -StoreLocation $ConnectionCertStoreLocation `
        -PfxPath $ConnectionPfxPath -PfxPassword $ConnectionPfxPassword `
        -KeyVaultName $ConnectionKeyVaultName -KeyVaultSecretName $ConnectionKeyVaultSecretName `
        -KeyVaultSecretVersion $ConnectionKeyVaultSecretVersion -KeyVaultPfxPassword $ConnectionKeyVaultPfxPassword
    $embed = Get-PPEmbeddablePfx -Certificate $connectionCert

    $connector = $connectorInfo.ConnectorName
    $values = New-PPCertOauthConnectionParameterValues -ConnectorInfo $connectorInfo -TenantId $TenantId `
        -ConnectionClientId $ConnectionClientId -PfxPassword $embed.Password -PfxBase64 $embed.Base64 -ExtraParameters $ExtraParameters
    $createBody = @{
        properties = @{
            environment             = @{ name = $EnvironmentId }
            connectionParametersSet = @{ name = 'CertOauth'; values = $values }
            displayName             = $ConnectionDisplayName
        }
    } | ConvertTo-Json -Depth 10
}
else {
    Write-Host "Loading Run Owner certificate..." -ForegroundColor Cyan
    $runOwnerCert = Get-PPCertificateFromSource -Label 'Run Owner cert' -TenantId $TenantId `
        -Thumbprint $RunOwnerCertThumbprint -StoreLocation $RunOwnerCertStoreLocation `
        -PfxPath $RunOwnerCertPfxPath -PfxPassword $RunOwnerCertPfxPassword `
        -KeyVaultName $RunOwnerKeyVaultName -KeyVaultSecretName $RunOwnerKeyVaultSecretName `
        -KeyVaultSecretVersion $RunOwnerKeyVaultSecretVersion -KeyVaultPfxPassword $RunOwnerKeyVaultPfxPassword
    $embed = Get-PPEmbeddablePfx -Certificate $runOwnerCert

    $connector = $RunOwnerConnector
    $values = New-PPRunOwnerConnectionParameterValues -CredentialMode $RunOwnerCredentialMode -MachineGroupId $MachineGroupId `
        -RunOwnerAppId $RunOwnerAppId -RunOwnerPfxBase64 $embed.Base64 -RunOwnerPfxPassword $embed.Password `
        -UsernameEnvironmentVariable $UsernameEnvironmentVariable -PasswordEnvironmentVariable $PasswordEnvironmentVariable `
        -DirectUsername $DirectUsername -DirectPassword (ConvertFrom-PPSecureStringPlain $DirectPassword)

    $properties = [ordered]@{
        environment = [ordered]@{ id = "/providers/Microsoft.PowerApps/environments/$EnvironmentId"; name = $EnvironmentId }
        displayName = $ConnectionDisplayName
    }
    # "Direct" mode has no Credential record, so Microsoft's "Connection without credentials" body
    # omits credentialId entirely - the other three modes all reference one.
    if ($RunOwnerCredentialMode -ne 'Direct') { $properties['credentialId'] = $CredentialId }
    $properties['connectionParametersSet'] = [ordered]@{ name = 'azureRelayRunOwner'; values = $values }
    $createBody = [ordered]@{ properties = $properties } | ConvertTo-Json -Depth 10
}

# --- Create the connection and record it ---
$connection = Invoke-PPCreateConnection -EnvironmentApiHost $envApiHost -Connector $connector -ConnectionId $ConnectionId `
    -AccessToken $ppToken -Body $createBody -ApiVersion $ApiVersion -TimeoutSec $TimeoutSec -WhatIf:$WhatIfPreference
if ($null -eq $connection) {
    Write-Host "(WhatIf) Connection was not actually created." -ForegroundColor Yellow
    return
}

$connection | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $OutputDirectory 'connection_result.json')
$status = $connection.properties.statuses[0].status
if ($status -ne 'Connected') {
    Write-Warning "Connection '$ConnectionId' was created but its status is '$status', not 'Connected'. See $OutputDirectory\connection_result.json."
}
Write-Host "Connection created: '$($connection.properties.displayName)' - status: $status - createdBy: $($connection.properties.createdBy.type)" -ForegroundColor Green
Write-Host "ConnectionId: $ConnectionId" -ForegroundColor Yellow

Add-PPConnectionLogEntry -LogPath $ConnectionLogPath -ConnectionType $ConnectionType -ConnectionId $ConnectionId `
    -DisplayName $ConnectionDisplayName -EnvironmentId $EnvironmentId -Connector $connector -Status $status `
    -CreatedByType $connection.properties.createdBy.type | Out-Null
Write-Host "Logged to: $ConnectionLogPath" -ForegroundColor DarkGray

# --- Optionally share the new connection ---
if ($ShareWithUpns.Count -gt 0) {
    if ($ConnectionType -eq 'PadRunOwner' -and $SharePrincipalType -eq 'User') {
        Write-Warning "PadRunOwner connections can only be shared with other Service Principals - pass -SharePrincipalType ServicePrincipal if these are app registrations, not human users."
    }

    $graphToken = $null
    $needsGraph = $ShareWithUpns | Where-Object { $_ -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' }
    if ($needsGraph) {
        $graphToken = Get-PPCertClientCredentialsToken -TenantId $TenantId -ClientId $CallerClientId -Certificate $callerCert `
            -Scope 'https://graph.microsoft.com/.default' -LoginAuthorityBaseUrl $LoginAuthorityBaseUrl -TimeoutSec $TimeoutSec
    }

    foreach ($upn in $ShareWithUpns) {
        Write-Host "Sharing with $upn as $ShareAccessLevel..." -ForegroundColor Cyan
        $principal = Resolve-PPPrincipal -UpnOrId $upn -GraphToken $graphToken -TenantId $TenantId -PrincipalType $SharePrincipalType
        $shared = Grant-PPConnectionAccess -EnvironmentApiHost $envApiHost -Connector $connector -ConnectionId $ConnectionId `
            -EnvironmentId $EnvironmentId -Principal $principal -AccessLevel $ShareAccessLevel `
            -NotifyShareTargetOption $NotifyShareTargetOption -InviteGuestToTenant:$InviteGuestToTenant `
            -AccessToken $ppToken -ApiVersion $ApiVersion -TimeoutSec $TimeoutSec -WhatIf:$WhatIfPreference
        if ($shared) { Write-Host "Shared with $upn as $ShareAccessLevel" -ForegroundColor Green }
        else { Write-Host "(WhatIf) Would have shared with $upn as $ShareAccessLevel." -ForegroundColor Yellow }
    }
}

Write-Host "`nDone." -ForegroundColor Cyan
[PSCustomObject]@{
    ConnectionType = $ConnectionType
    ConnectionId   = $ConnectionId
    DisplayName    = $ConnectionDisplayName
    Status         = $status
    CreatedByType  = $connection.properties.createdBy.type
    SharedWith     = ($ShareWithUpns -join ', ')
    ConnectionLog  = $ConnectionLogPath
} | Format-List
