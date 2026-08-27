#Requires -Version 5.1
<#
    Shared functions used by New-PowerPlatformCertConnection.ps1, Grant-PowerPlatformConnectionAccess.ps1
    and Get-PowerPlatformConnectionPermissions.ps1.

    Every call this module makes to Dataverse, the Power Platform connectivity API, or Microsoft
    Graph authenticates as a Service Principal using a certificate (client_credentials + a JWT
    assertion). The only delegated (interactive) sign-in anywhere is opt-in: if you choose a Key
    Vault certificate source, Get-PPKeyVaultSecretViaAzCli uses your own `az` CLI session to read
    the secret. That session is never used for anything else.

    Tested on both Windows PowerShell 5.1 and PowerShell 7+. A couple of things differ between
    those two runtimes and are handled explicitly below: RandomNumberGenerator.Fill() doesn't
    exist on .NET Framework, Invoke-WebRequest response headers are plain strings on 5.1 but
    string[] on 7+, and 5.1 doesn't always default to TLS 1.2.
#>

if ($PSVersionTable.PSVersion.Major -lt 6) {
    # Windows PowerShell / .NET Framework doesn't always default to TLS 1.2, which login.microsoftonline.com
    # and Graph require. PowerShell 7+ negotiates modern TLS on its own, so this is a no-op there.
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-Warning "Could not enable TLS 1.2: $($_.Exception.Message)"
    }
}

# --- Small utilities ---

function ConvertTo-PPBase64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-PPSecureStringPlain {
    # Only used right before a value has to go into a JSON body as plain text - there's no way
    # around that for the API calls that actually need the real value.
    param([Security.SecureString]$Secure)
    if (-not $Secure -or $Secure.Length -eq 0) { return '' }
    [System.Net.NetworkCredential]::new('', $Secure).Password
}

function ConvertTo-PPEmptySecureStringIfNull {
    param([Security.SecureString]$Secure)
    if ($null -eq $Secure) { return [Security.SecureString]::new() }
    return $Secure
}

function New-PPRandomPassword {
    param([int]$Length = 32)
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_='
    $bytes = New-Object byte[] $Length
    # RandomNumberGenerator.Fill() is .NET-only; Create()+GetBytes() works on both runtimes.
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

function ConvertTo-PPFormUrlEncoded {
    # Invoke-RestMethod's automatic Hashtable -> form-encoded body conversion has behaved
    # inconsistently across PowerShell versions, so we just build the string ourselves.
    param([Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Fields)
    ($Fields.GetEnumerator() | ForEach-Object {
        '{0}={1}' -f [Uri]::EscapeDataString([string]$_.Key), [Uri]::EscapeDataString([string]$_.Value)
    }) -join '&'
}

function Get-PPFirstHeaderValue {
    # Invoke-WebRequest's response Headers are plain strings on Windows PowerShell 5.1 but
    # string[] on PowerShell 7+. Indexing [0] on a plain string would return a single character
    # instead of throwing, so normalize both shapes here.
    param($HeaderValue)
    if ($null -eq $HeaderValue) { return $null }
    if ($HeaderValue -is [string]) { return $HeaderValue }
    return $HeaderValue[0]
}

# --- Certificate sources (store thumbprint / PFX file / Azure Key Vault via az cli) ---

function Get-PPAzureCliAccount {
    try {
        $raw = az account show --output json 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) { return $null }
        return $raw | ConvertFrom-Json
    }
    catch { return $null }
}

function Connect-PPAzureCli {
    param([string]$TenantId)
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw "The Azure CLI ('az') was not found on PATH. Install it to use a Key Vault certificate source."
    }
    $existing = Get-PPAzureCliAccount
    if ($existing -and (-not $TenantId -or $existing.tenantId -eq $TenantId)) { return }

    Write-Host "Signing in to Azure CLI for Key Vault access..." -ForegroundColor Cyan
    $loginArgs = @('login')
    if ($TenantId) { $loginArgs += @('--tenant', $TenantId) }
    az @loginArgs --output none
    if ($LASTEXITCODE -ne 0) { throw "az login failed (exit code $LASTEXITCODE)." }
}

function Get-PPKeyVaultSecretViaAzCli {
    # Works for a Key Vault "Certificate" object (its private key is exposed via the twin Secret
    # of the same name) and for a plain Secret holding a base64 PFX.
    param(
        [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$SecretName,
        [string]$SecretVersion,
        [string]$TenantId
    )
    Connect-PPAzureCli -TenantId $TenantId

    $showArgs = @('keyvault', 'secret', 'show', '--vault-name', $VaultName, '--name', $SecretName, '--output', 'json')
    if ($SecretVersion) { $showArgs += @('--version', $SecretVersion) }

    Write-Host "Retrieving '$SecretName' from Key Vault '$VaultName'..." -ForegroundColor Cyan
    $raw = az @showArgs 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $raw) {
        throw "az keyvault secret show failed for vault '$VaultName' secret '$SecretName'. Check the names and that you have a Get permission (e.g. Key Vault Secrets User) on it."
    }
    return $raw | ConvertFrom-Json
}

function Get-PPCertificateFromSource {
    # Loads a certificate from exactly one of three places. If more than one is supplied,
    # Key Vault wins, then a PFX file, then a store thumbprint.
    param(
        [string]$Thumbprint,
        [ValidateSet('CurrentUser', 'LocalMachine')][string]$StoreLocation = 'CurrentUser',

        [string]$PfxPath,
        [Security.SecureString]$PfxPassword,

        [string]$KeyVaultName,
        [string]$KeyVaultSecretName,
        [string]$KeyVaultSecretVersion,
        [Security.SecureString]$KeyVaultPfxPassword,

        [string]$TenantId,
        [Parameter(Mandatory)][string]$Label
    )
    $flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable

    if ($KeyVaultName -or $KeyVaultSecretName) {
        if (-not ($KeyVaultName -and $KeyVaultSecretName)) {
            throw "$Label : both -KeyVaultName and -KeyVaultSecretName are required."
        }
        $secret = Get-PPKeyVaultSecretViaAzCli -VaultName $KeyVaultName -SecretName $KeyVaultSecretName -SecretVersion $KeyVaultSecretVersion -TenantId $TenantId
        $bytes = [Convert]::FromBase64String($secret.value)
        $pwd = ConvertTo-PPEmptySecureStringIfNull $KeyVaultPfxPassword
        try {
            return [Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes, $pwd, $flags)
        }
        catch {
            throw "$Label : could not load '$KeyVaultSecretName' as a certificate (contentType '$($secret.contentType)'). If it's PEM rather than PKCS#12/PFX, re-export it as a PFX. $($_.Exception.Message)"
        }
    }
    if ($PfxPath) {
        if (-not (Test-Path -LiteralPath $PfxPath)) { throw "$Label : PFX file not found at '$PfxPath'." }
        $pwd = ConvertTo-PPEmptySecureStringIfNull $PfxPassword
        return [Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path -LiteralPath $PfxPath).Path, $pwd, $flags)
    }
    if ($Thumbprint) {
        $cert = Get-Item -LiteralPath "Cert:\$StoreLocation\My\$Thumbprint" -ErrorAction SilentlyContinue
        if (-not $cert) { throw "$Label : no certificate with thumbprint '$Thumbprint' found in $StoreLocation\My." }
        if (-not $cert.HasPrivateKey) { throw "$Label : certificate '$Thumbprint' has no private key." }
        return $cert
    }
    throw "$Label : specify a certificate source - Thumbprint, PfxPath+PfxPassword, or KeyVaultName+KeyVaultSecretName."
}

function Get-PPEmbeddablePfx {
    # Connections embed a raw PFX + password. We always re-export with a fresh random password
    # so the certificate's own unlock password is never sent anywhere.
    param([Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $password = New-PPRandomPassword
    $bytes = $Certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password)
    [PSCustomObject]@{
        Base64   = [Convert]::ToBase64String($bytes)
        Password = $password
    }
}

# --- Cert-based (client_credentials + JWT assertion) token acquisition ---

function New-PPClientAssertionJwt {
    param(
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$TokenEndpoint
    )
    $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = (ConvertTo-PPBase64Url $Certificate.GetCertHash()) } | ConvertTo-Json -Compress
    $now = [DateTimeOffset]::UtcNow
    $payload = @{
        aud = $TokenEndpoint; iss = $ClientId; sub = $ClientId; jti = [guid]::NewGuid().ToString()
        nbf = $now.ToUnixTimeSeconds(); exp = $now.AddMinutes(5).ToUnixTimeSeconds()
    } | ConvertTo-Json -Compress

    $unsigned = '{0}.{1}' -f (ConvertTo-PPBase64Url ([Text.Encoding]::UTF8.GetBytes($header))), (ConvertTo-PPBase64Url ([Text.Encoding]::UTF8.GetBytes($payload)))
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if (-not $rsa) { throw "Certificate '$($Certificate.Thumbprint)' has no usable RSA private key." }
    $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($unsigned), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)

    return '{0}.{1}' -f $unsigned, (ConvertTo-PPBase64Url $signature)
}

function Get-PPScopeForResource {
    param([Parameter(Mandatory)][string]$Resource)
    if ($Resource.EndsWith('/')) { return "$Resource.default" }
    return "$Resource/.default"
}

function Get-PPCertClientCredentialsToken {
    # App-only token via client_credentials + certificate assertion (RFC 7523). Pass whichever
    # -Scope you need (Dataverse, the Power Platform API, Graph, ...).
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)][string]$Scope,
        [string]$LoginAuthorityBaseUrl = 'https://login.microsoftonline.com',
        [int]$TimeoutSec = 100
    )
    $tokenEndpoint = '{0}/{1}/oauth2/v2.0/token' -f $LoginAuthorityBaseUrl.TrimEnd('/'), $TenantId
    $jwt = New-PPClientAssertionJwt -Certificate $Certificate -ClientId $ClientId -TokenEndpoint $tokenEndpoint

    $form = [ordered]@{
        client_id             = $ClientId
        scope                 = $Scope
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $jwt
        grant_type            = 'client_credentials'
    }
    $bodyString = ConvertTo-PPFormUrlEncoded -Fields $form
    $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $bodyString -ContentType 'application/x-www-form-urlencoded' -TimeoutSec $TimeoutSec
    return $response.access_token
}

# --- Environment host + principal resolution ---

function Get-PPEnvironmentApiHost {
    # 00aa00aa-bb11-cc22-dd33-44ee44ee44ee -> 00aa00aabb11cc22dd3344ee44ee44.ee.<suffix>
    param(
        [Parameter(Mandatory)][string]$EnvironmentId,
        [string]$DomainSuffix = 'environment.api.powerplatform.com'
    )
    $noDashes = $EnvironmentId -replace '-', ''
    if ($noDashes.Length -le 2) { throw "Environment ID '$EnvironmentId' is not a valid GUID." }
    $last2 = $noDashes.Substring($noDashes.Length - 2)
    $first = $noDashes.Substring(0, $noDashes.Length - 2)
    return '{0}.{1}.{2}' -f $first, $last2, $DomainSuffix
}

function Resolve-PPPrincipal {
    # Turns a UPN/email or a raw object ID into the principal object the sharing API expects.
    # A UPN/email is looked up via Graph so the share carries the same display name/email the
    # maker portal itself sends; a GUID is used as-is (no Graph permission needed for that case).
    param(
        [Parameter(Mandatory)][string]$UpnOrId,
        [string]$GraphToken,
        [string]$TenantId,
        [ValidateSet('User', 'ServicePrincipal')][string]$PrincipalType = 'User'
    )
    if ($UpnOrId -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        return [ordered]@{ id = $UpnOrId; type = $PrincipalType; tenantId = $TenantId }
    }
    if ($PrincipalType -ne 'User') {
        throw "'$UpnOrId' is not an object ID. For -PrincipalType ServicePrincipal, pass the service principal's object ID directly - Graph lookup by name isn't supported here."
    }
    if (-not $GraphToken) { throw "'$UpnOrId' is not a GUID and no Graph token was supplied to resolve it." }

    $user = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$([Uri]::EscapeDataString($UpnOrId))?`$select=id,displayName,mail,userPrincipalName" -Headers @{ Authorization = "Bearer $GraphToken" }
    return [ordered]@{
        id                = $user.id
        displayName       = $user.displayName
        email             = $user.mail
        type              = 'User'
        userType          = 'NotSpecified'
        tenantId          = $TenantId
        userPrincipalName = $user.userPrincipalName
    }
}

# --- Dataverse application user bootstrap ---

function Confirm-PPDataverseApplicationUser {
    # Creates a Dataverse application user + security role for an app if one doesn't already
    # exist. Uses the Caller's own Dataverse token, so the Caller's role governs whether this
    # can succeed.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$DataverseUrl,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$AppClientId,
        [Parameter(Mandatory)][string]$CallerDataverseToken,
        [string]$SecurityRoleName = 'System Administrator'
    )
    $headers = @{ Authorization = "Bearer $CallerDataverseToken"; 'Content-Type' = 'application/json'; 'OData-Version' = '4.0'; Accept = 'application/json' }

    $existing = Invoke-RestMethod -Uri "$DataverseUrl/api/data/v9.2/systemusers?`$filter=applicationid eq $AppClientId&`$select=systemuserid" -Headers $headers
    if ($existing.value.Count -gt 0) {
        Write-Host "Application user already exists for $AppClientId." -ForegroundColor DarkGray
        return $existing.value[0].systemuserid
    }
    if (-not $PSCmdlet.ShouldProcess("Dataverse application user for $AppClientId", 'Create + assign security role')) { return $null }

    $bu = Invoke-RestMethod -Uri "$DataverseUrl/api/data/v9.2/businessunits?`$filter=_parentbusinessunitid_value eq null&`$select=businessunitid" -Headers $headers
    $buId = $bu.value[0].businessunitid

    $body = @{ applicationid = $AppClientId; domainname = "$AppClientId@$TenantId"; "businessunitid@odata.bind" = "/businessunits($buId)" } | ConvertTo-Json
    $resp = Invoke-WebRequest -Uri "$DataverseUrl/api/data/v9.2/systemusers" -Headers $headers -Method Post -Body $body
    $userId = [regex]::Match((Get-PPFirstHeaderValue $resp.Headers['OData-EntityId']), 'systemusers\(([^)]+)\)').Groups[1].Value

    $role = Invoke-RestMethod -Uri "$DataverseUrl/api/data/v9.2/roles?`$filter=name eq '$SecurityRoleName' and _businessunitid_value eq $buId&`$select=roleid" -Headers $headers
    if ($role.value.Count -eq 0) { throw "Security role '$SecurityRoleName' not found in the root business unit." }
    $assoc = @{ "@odata.id" = "$DataverseUrl/api/data/v9.2/roles($($role.value[0].roleid))" } | ConvertTo-Json
    Invoke-WebRequest -Uri "$DataverseUrl/api/data/v9.2/systemusers($userId)/systemuserroles_association/`$ref" -Headers $headers -Method Post -Body $assoc | Out-Null

    Write-Host "Created Dataverse application user for $AppClientId." -ForegroundColor Green
    return $userId
}

# --- Connection parameter builders ---

# Add an entry here to support another CertOauth-style connector. ConnectorName is the "shared_xxx"
# connector id, TenantIdParam is the exact parameter key for the tenant id (casing varies by
# connector), IncludeGrantType controls whether token:grantType is sent, and RequiredExtraParams
# lists keys expected in -ExtraParameters.
$Script:PPConnectorRegistry = @{
    Dataverse = @{
        ConnectorName       = 'shared_commondataserviceforapps'
        TenantIdParam       = 'token:tenantId'
        IncludeGrantType    = $true
        RequiredExtraParams = @()
    }
    KeyVault  = @{
        ConnectorName       = 'shared_keyvault'
        TenantIdParam       = 'token:TenantId'
        IncludeGrantType    = $false
        RequiredExtraParams = @('vaultName')
    }
}

function Get-PPConnectorRegistry {
    return $Script:PPConnectorRegistry
}

function New-PPCertOauthConnectionParameterValues {
    param(
        [Parameter(Mandatory)][hashtable]$ConnectorInfo,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ConnectionClientId,
        [Parameter(Mandatory)][string]$PfxPassword,
        [Parameter(Mandatory)][string]$PfxBase64,
        [hashtable]$ExtraParameters = @{}
    )
    $redirectSuffix = $ConnectorInfo.ConnectorName -replace '^shared_', ''
    if ($ConnectorInfo.ContainsKey('RedirectSuffix') -and $ConnectorInfo.RedirectSuffix) { $redirectSuffix = $ConnectorInfo.RedirectSuffix }

    $values = [ordered]@{ token = @{ value = "https://global.consent.azure-apim.net/redirect/$redirectSuffix" } }
    foreach ($key in $ConnectorInfo.RequiredExtraParams) {
        if (-not $ExtraParameters.ContainsKey($key)) { throw "Connector '$($ConnectorInfo.ConnectorName)' requires an ExtraParameters value for '$key'." }
        $values[$key] = @{ value = $ExtraParameters[$key] }
    }
    $values[$ConnectorInfo.TenantIdParam] = @{ value = $TenantId }
    $values['token:clientId'] = @{ value = $ConnectionClientId }
    $values['token:clientCertificateSecret'] = @{ value = @{ password = $PfxPassword; pfx = $PfxBase64 } }
    if ($ConnectorInfo.IncludeGrantType) { $values['token:grantType'] = @{ value = 'client_credentials' } }
    return $values
}

function New-PPRunOwnerConnectionParameterValues {
    # Builds the "azureRelayRunOwner" values block for a PAD run-owner connection, per
    # learn.microsoft.com/power-automate/desktop-flows/how-to/set-runowner-desktopflowconnection
    #
    # -CredentialMode KeyVaultPassword: username and password both come from environment
    #    variables. KeyVaultCertificate/CyberArk: username comes from an environment variable,
    #    password is the literal "none" - Microsoft documents these two as the exact same body;
    #    the CyberArk-vs-KeyVault difference is in how the Dataverse Credential record itself is
    #    backed, not in this payload. Direct: literal username/password, no Credential record.
    param(
        [Parameter(Mandatory)][ValidateSet('KeyVaultPassword', 'KeyVaultCertificate', 'CyberArk', 'Direct')][string]$CredentialMode,
        [Parameter(Mandatory)][string]$MachineGroupId,
        [Parameter(Mandatory)][string]$RunOwnerAppId,
        [Parameter(Mandatory)][string]$RunOwnerPfxBase64,
        [Parameter(Mandatory)][string]$RunOwnerPfxPassword,
        [string]$UsernameEnvironmentVariable,
        [string]$PasswordEnvironmentVariable,
        [string]$DirectUsername,
        [string]$DirectPassword
    )
    switch ($CredentialMode) {
        'KeyVaultPassword' {
            if (-not $UsernameEnvironmentVariable -or -not $PasswordEnvironmentVariable) {
                throw "CredentialMode 'KeyVaultPassword' requires -UsernameEnvironmentVariable and -PasswordEnvironmentVariable."
            }
            $usernameValue = '@environmentVariables("{0}")' -f $UsernameEnvironmentVariable
            $passwordValue = '@environmentVariables("{0}")' -f $PasswordEnvironmentVariable
        }
        { $_ -in 'KeyVaultCertificate', 'CyberArk' } {
            if (-not $UsernameEnvironmentVariable) { throw "CredentialMode '$CredentialMode' requires -UsernameEnvironmentVariable." }
            $usernameValue = '@environmentVariables("{0}")' -f $UsernameEnvironmentVariable
            $passwordValue = 'none'
        }
        'Direct' {
            if (-not $DirectUsername -or -not $DirectPassword) { throw "CredentialMode 'Direct' requires -DirectUsername and -DirectPassword." }
            $usernameValue = $DirectUsername
            $passwordValue = $DirectPassword
        }
    }

    return [ordered]@{
        username                                    = @{ value = $usernameValue }
        password                                    = @{ value = $passwordValue }
        targetId                                    = @{ value = $MachineGroupId }
        'tokenRunOwnerCert:clientId'                = @{ value = $RunOwnerAppId }
        'tokenRunOwnerCert:clientCertificateSecret' = @{ value = @{ pfx = $RunOwnerPfxBase64; password = $RunOwnerPfxPassword } }
    }
}

# --- Create, share, and list connections ---

function Invoke-PPCreateConnection {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$EnvironmentApiHost,
        [Parameter(Mandatory)][string]$Connector,
        [Parameter(Mandatory)][string]$ConnectionId,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$Body,
        [string]$ApiVersion = '1',
        [int]$TimeoutSec = 100
    )
    $uri = "https://$EnvironmentApiHost/connectivity/connectors/$Connector/connections/$ConnectionId`?api-version=$ApiVersion"
    if (-not $PSCmdlet.ShouldProcess("connection '$ConnectionId' via $Connector", 'PUT (create/update)')) { return $null }
    try {
        return Invoke-RestMethod -Uri $uri -Headers @{ Authorization = "Bearer $AccessToken"; Accept = 'application/json' } -Method Put -Body $Body -ContentType 'application/json' -TimeoutSec $TimeoutSec
    }
    catch {
        $details = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        throw "Connection creation failed: $details"
    }
}

function Grant-PPConnectionAccess {
    # Shares a connection at one of the 3 access levels: CanUse -> CanView, CanUseAndShare ->
    # CanViewWithShare, CanEdit -> CanEdit. The body shape (capabilities/notifyShareTargetOption/
    # inviteGuestToTenant) matches what the maker portal itself sends, confirmed from a HAR
    # capture covering all three levels.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$EnvironmentApiHost,
        [Parameter(Mandatory)][string]$Connector,
        [Parameter(Mandatory)][string]$ConnectionId,
        [Parameter(Mandatory)][string]$EnvironmentId,
        [Parameter(Mandatory)]$Principal,
        [Parameter(Mandatory)][ValidateSet('CanUse', 'CanUseAndShare', 'CanEdit')][string]$AccessLevel,
        [ValidateSet('Notify', 'DoNotNotify', 'NotSpecified')][string]$NotifyShareTargetOption = 'Notify',
        [switch]$InviteGuestToTenant,
        [Parameter(Mandatory)][string]$AccessToken,
        [string]$ApiVersion = '1',
        [int]$TimeoutSec = 100
    )
    $roleName = switch ($AccessLevel) {
        'CanUse' { 'CanView' }
        'CanUseAndShare' { 'CanViewWithShare' }
        'CanEdit' { 'CanEdit' }
    }
    $envFilter = [Uri]::EscapeDataString("environment eq '$EnvironmentId'")
    $body = @{
        put    = @(
            @{
                properties = @{
                    roleName                = $roleName
                    principal                = $Principal
                    notifyShareTargetOption = $NotifyShareTargetOption
                    inviteGuestToTenant      = [bool]$InviteGuestToTenant
                    capabilities             = @()
                }
            }
        )
        delete = @()
    } | ConvertTo-Json -Depth 10
    $uri = "https://$EnvironmentApiHost/connectivity/connectors/$Connector/connections/$ConnectionId/modifyPermissions?api-version=$ApiVersion&`$filter=$envFilter"

    if (-not $PSCmdlet.ShouldProcess("connection '$ConnectionId'", "Share as $roleName with $($Principal.id)")) { return $null }
    try {
        Invoke-RestMethod -Uri $uri -Headers @{ Authorization = "Bearer $AccessToken" } -Method Post -Body $body -ContentType 'application/json' -TimeoutSec $TimeoutSec | Out-Null
    }
    catch {
        $details = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        throw "Sharing failed (roleName=$roleName): $details"
    }
    # The API returns 200 with an empty body on success, so we can't use the response itself to
    # tell a real share apart from the -WhatIf no-op above - return a plain marker instead.
    return $true
}

function Get-PPConnectionPermissions {
    # The read side of Grant-PPConnectionAccess - lists who currently has access to a connection.
    param(
        [Parameter(Mandatory)][string]$EnvironmentApiHost,
        [Parameter(Mandatory)][string]$Connector,
        [Parameter(Mandatory)][string]$ConnectionId,
        [Parameter(Mandatory)][string]$EnvironmentId,
        [Parameter(Mandatory)][string]$AccessToken,
        [string]$ApiVersion = '1',
        [int]$TimeoutSec = 100
    )
    $envFilter = [Uri]::EscapeDataString("environment eq '$EnvironmentId'")
    $uri = "https://$EnvironmentApiHost/connectivity/connectors/$Connector/connections/$ConnectionId/permissions?api-version=$ApiVersion&`$filter=$envFilter"
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers @{ Authorization = "Bearer $AccessToken" } -Method Get -TimeoutSec $TimeoutSec
    }
    catch {
        $details = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        throw "Listing permissions failed (the Caller identity usually needs to own the connection): $details"
    }
    return $response.value
}

function ConvertTo-PPFriendlyAccessLevel {
    param([Parameter(Mandatory)][string]$RoleName)
    switch ($RoleName) {
        'CanView' { 'CanUse' }
        'CanViewWithShare' { 'CanUseAndShare' }
        'CanEdit' { 'CanEdit' }
        'Owner' { 'Owner' }
        default { $RoleName }
    }
}

function Add-PPConnectionLogEntry {
    # Appends one line per created connection to a text log, so there's a durable history across runs.
    param(
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][string]$ConnectionType,
        [Parameter(Mandatory)][string]$ConnectionId,
        [string]$DisplayName,
        [string]$EnvironmentId,
        [string]$Connector,
        [string]$Status,
        [string]$CreatedByType
    )
    $timestamp = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = "$timestamp | ConnectionType=$ConnectionType | ConnectionId=$ConnectionId | DisplayName=$DisplayName | EnvironmentId=$EnvironmentId | Connector=$Connector | Status=$Status | CreatedByType=$CreatedByType"
    $logDir = Split-Path -Parent $LogPath
    if ($logDir -and -not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }
    Add-Content -LiteralPath $LogPath -Value $line
    return $line
}

Export-ModuleMember -Function *-PP*
