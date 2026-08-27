# PowerPlatform-CertConnections

Three PowerShell scripts + one shared module for creating and sharing certificate-authenticated
Power Platform connections (Dataverse, Key Vault, and Power Automate Desktop "run-owner"
connections) with **zero delegated/interactive user auth** for any Dataverse, Power Platform, or
Microsoft Graph call. Every call is made by a Service Principal authenticating with
`client_credentials` + a certificate assertion (RFC 7523).

Works on **both Windows PowerShell 5.1 and PowerShell 7+**.

This replaces two earlier, separate scripts (`New-DataverseCertConnection.ps1` and
`New-PADRunOwnerConnection.ps1`) - all of their logic now lives here, unified and shared.

## Layout

| File | Purpose |
|---|---|
| `Modules\PowerPlatformCertConnection.Common.psm1` | Shared logic: certificate loading (3 sources), cert-based token acquisition, connection-parameter builders, the create/share/list-permissions API calls. |
| `New-PowerPlatformCertConnection.ps1` | **Creates** a connection. `-ConnectionType Dataverse\|KeyVault\|PadRunOwner`. Prints the new connection id and appends it to a persistent log. |
| `Grant-PowerPlatformConnectionAccess.ps1` | **Shares** an existing connection with one or more principals, at any of the 3 access levels. |
| `Get-PowerPlatformConnectionPermissions.ps1` | **Lists** who an existing connection is currently shared with, and at what level. |

## The one deliberate exception to "no delegated auth"

Every call to Dataverse, the Power Platform connectivity API, and Microsoft Graph is app-only.
The **only** delegated (interactive user) auth anywhere in this toolkit is opt-in: if you choose
a Key Vault certificate source (`-*KeyVaultName` / `-*KeyVaultSecretName`), the script uses the
`az` CLI's own session (`az login` if you're not already signed in) purely to read the secret's
private key material. That session is never used to call Dataverse/Power Platform/Graph.

## Certificate sources (used for every identity - Caller, Connection, Run Owner)

Specify exactly **one** of these three per identity. If more than one is supplied, precedence is
Key Vault > PFX file > store thumbprint.

| Source | Parameters |
|---|---|
| Local certificate store | `-<Identity>CertThumbprint` (+ `-<Identity>CertStoreLocation`, default `CurrentUser`) |
| Local PFX file | `-<Identity>PfxPath` + `-<Identity>PfxPassword` (SecureString) |
| Azure Key Vault (az cli delegated auth) | `-<Identity>KeyVaultName` + `-<Identity>KeyVaultSecretName` (+ optional `-<Identity>KeyVaultSecretVersion` / `-<Identity>KeyVaultPfxPassword`) |

`<Identity>` is `Caller`, `Connection` (Dataverse/KeyVault types), or `RunOwner` (PadRunOwner
type). The Key Vault source works for both a Key Vault **Certificate** object (its private key is
exposed via the twin Secret of the same name) and a plain **Secret** holding a manually-uploaded
base64 PFX. Requires the [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) to
be installed; if not already signed in (or signed into a different tenant), an interactive
`az login` is triggered.

## Prerequisites (not created by either script)

- Both app registrations (Caller, and Connection/RunOwner) and their certificates already exist.
- The Connection/RunOwner app already has whatever access the target service requires:
  - **Dataverse**: this script *will* create a Dataverse application user + security role for it
    if one doesn't already exist (using the Caller's own Dataverse token).
  - **KeyVault**: you must grant it Key Vault access yourself (e.g. the "Key Vault Secrets User"
    RBAC role) - not automated here.
  - **PadRunOwner**: it must be a Dataverse application user with at least "Environment Maker",
    and shared (at least Read) on the Machine/Machine Group, Credential record, Desktop Flow, and
    any Work Queues used. See
    [Set a run owner on a desktop flow connection](https://learn.microsoft.com/power-automate/desktop-flows/how-to/set-runowner-desktopflowconnection).
- **PadRunOwner** additionally needs a pre-existing Dataverse `Credential` record (unless
  `-RunOwnerCredentialMode Direct`) and a properly-provisioned Machine Group (registered via the
  portal/machine runtime app - a Dataverse row inserted directly is not sufficient).

## `New-PowerPlatformCertConnection.ps1` - creating connections

### `-ConnectionType Dataverse`

Builds the `CertOauth` connectionParametersSet. Also runs a `WhoAmI` check with the Caller's own
Dataverse token to confirm cert auth works, and ensures the Connection app has a Dataverse
application user (creating one only if missing).

```powershell
.\New-PowerPlatformCertConnection.ps1 -ConnectionType Dataverse `
    -TenantId $tenantId -EnvironmentId $envId `
    -DataverseUrl 'https://contoso.crm.dynamics.com' `
    -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
    -ConnectionClientId $connectionAppId -ConnectionCertThumbprint $connectionThumbprint `
    -ShareWithUpns 'admin@contoso.onmicrosoft.com' -ShareAccessLevel CanEdit
```

### `-ConnectionType KeyVault`

Builds the same `CertOauth` shape with Key-Vault-specific parameter casing/keys. Requires
`-VaultName` (or `-ExtraParameters @{ vaultName = '...' }`). The Connection cert here is sourced
live from a *different* Key Vault via `az` CLI delegated auth, to demonstrate that source:

```powershell
.\New-PowerPlatformCertConnection.ps1 -ConnectionType KeyVault `
    -TenantId $tenantId -EnvironmentId $envId `
    -VaultName 'ContosoKeyVault' `
    -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
    -ConnectionClientId $connectionAppId `
    -ConnectionKeyVaultName 'CertsVault' -ConnectionKeyVaultSecretName 'connection-cert'
```

### `-ConnectionType PadRunOwner`

Builds the `azureRelayRunOwner` connectionParametersSet used by Power Automate Desktop run-owner
connections. Requires `-RunOwnerAppId` (+ a cert source), `-MachineGroupId`, and one of the four
`-RunOwnerCredentialMode` values below.

| `-RunOwnerCredentialMode` | Required params | `username` value | `password` value |
|---|---|---|---|
| `KeyVaultPassword` (default) | `-CredentialId`, `-UsernameEnvironmentVariable`, `-PasswordEnvironmentVariable` | `@environmentVariables("...")` | `@environmentVariables("...")` |
| `KeyVaultCertificate` | `-CredentialId`, `-UsernameEnvironmentVariable` | `@environmentVariables("...")` | literal `"none"` |
| `CyberArk` | `-CredentialId`, `-UsernameEnvironmentVariable` | `@environmentVariables("...")` | literal `"none"` |
| `Direct` | `-DirectUsername`, `-DirectPassword` | literal | literal |

**Important finding**: per Microsoft's own documented request bodies, `KeyVaultCertificate` and
`CyberArk` produce the **exact same JSON payload** - the distinction between "backed by Key Vault"
vs. "backed by CyberArk" lives entirely in how the referenced Dataverse `Credential` record itself
was configured (out of scope for this script, a prerequisite), not in this API call. Both modes
are kept as separate, clearly-named options purely so the script's intent is honest/self-documenting.
`Direct` sends no `credentialId` at all (matches Microsoft's "Connection without credentials" shape).

```powershell
# Key Vault password-based
.\New-PowerPlatformCertConnection.ps1 -ConnectionType PadRunOwner `
    -TenantId $tenantId -EnvironmentId $envId `
    -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
    -RunOwnerAppId $runOwnerAppId -RunOwnerCertPfxPath .\runowner.pfx -RunOwnerCertPfxPassword (Read-Host -AsSecureString) `
    -RunOwnerCredentialMode KeyVaultPassword `
    -CredentialId $credentialId -UsernameEnvironmentVariable 'new_UserName1' -PasswordEnvironmentVariable 'new_Password1' `
    -MachineGroupId $machineGroupId -ConnectionDisplayName 'Prod RunOwner Connection'

# CyberArk-backed (identical wire shape to KeyVaultCertificate)
.\New-PowerPlatformCertConnection.ps1 -ConnectionType PadRunOwner `
    -TenantId $tenantId -EnvironmentId $envId `
    -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
    -RunOwnerAppId $runOwnerAppId -RunOwnerCertPfxPath .\runowner.pfx -RunOwnerCertPfxPassword (Read-Host -AsSecureString) `
    -RunOwnerCredentialMode CyberArk `
    -CredentialId $credentialId -UsernameEnvironmentVariable 'new_UserName1' `
    -MachineGroupId $machineGroupId

# Direct credentials, no Dataverse Credential record
.\New-PowerPlatformCertConnection.ps1 -ConnectionType PadRunOwner `
    -TenantId $tenantId -EnvironmentId $envId `
    -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
    -RunOwnerAppId $runOwnerAppId -RunOwnerCertPfxPath .\runowner.pfx -RunOwnerCertPfxPassword (Read-Host -AsSecureString) `
    -RunOwnerCredentialMode Direct -DirectUsername 'CONTOSO\svc-pad' -DirectPassword (Read-Host -AsSecureString) `
    -MachineGroupId $machineGroupId
```

Per Microsoft's docs, PadRunOwner connections can only be shared with **other Service
Principals**, never human users - pass `-SharePrincipalType ServicePrincipal` if you use the
inline `-ShareWithUpns` option for this type.

### Connection ID logging

Every successful (non-`-WhatIf`) creation prints the new `ConnectionId` prominently to the
screen and appends a line to a persistent, append-only text log so you have a durable history of
everything ever created:

```
2026-08-27T15:57:48Z | ConnectionType=Dataverse | ConnectionId=11111111-1111-1111-1111-111111111111 | DisplayName=DataverseCertAuth | EnvironmentId=22222222-2222-2222-2222-222222222222 | Connector=shared_commondataserviceforapps | Status=Connected | CreatedByType=ServicePrincipal
```

Defaults to `<OutputDirectory>\CreatedConnections.log.txt`; override with `-ConnectionLogPath`.
Nothing is appended during a `-WhatIf` run (no connection actually existed to log).

### `-WhatIf`

Both scripts support `-WhatIf`/`-Confirm`. Certificate loading and token acquisition still happen
(they're read-only/diagnostic), but no connection is created/updated, no Dataverse application
user is created, and no sharing call is made.

## `Grant-PowerPlatformConnectionAccess.ps1` - sharing existing connections

Standalone script for granting/re-granting access to a connection that already exists, without
re-running creation. Supports all three access levels:

| `-AccessLevel` | Portal label | roleName sent |
|---|---|---|
| `CanUse` (default) | "Can use" | `CanView` |
| `CanUseAndShare` | "Can use and share" | `CanViewWithShare` |
| `CanEdit` | "Can edit" | `CanEdit` |

All three levels have been confirmed against a HAR capture of the maker portal sharing all three
in turn - only `roleName` changes between them; `capabilities` always stays an empty array. The
body also carries `notifyShareTargetOption` (`-NotifyShareTargetOption`, default `Notify` -
whether the recipient gets an email; set `DoNotNotify` to skip it) and `inviteGuestToTenant`
(`-InviteGuestToTenant` switch, default off), and a richer `principal` object (display name,
email, UPN) when the recipient is resolved from a UPN/email via Graph - all matching what the
portal itself sends.

```powershell
.\Grant-PowerPlatformConnectionAccess.ps1 `
    -TenantId $tenantId -EnvironmentId $envId `
    -Connector 'shared_commondataserviceforapps' -ConnectionId $connectionId `
    -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
    -PrincipalUpnsOrIds 'janedoe@contoso.onmicrosoft.com', 'admin@contoso.onmicrosoft.com' -AccessLevel CanUse
```

`-PrincipalUpnsOrIds` accepts UPNs/emails (resolved via an app-only Graph call - requires the
Caller app to have Microsoft Graph `User.Read.All` application permission, admin-consented) or
raw Entra object IDs directly (no extra Graph permission needed - though the principal object
sent for the share will then only have `id`/`type`/`tenantId`, since there's no Graph lookup to
enrich it from).

## `Get-PowerPlatformConnectionPermissions.ps1` - checking who a connection is shared with

Read-only companion script: lists everyone currently granted access to an existing connection,
with a friendly access-level label alongside the raw `roleName`. Confirmed via the same HAR
capture - `GET .../connections/{id}/permissions` on the same connectivity host used everywhere
else in this toolkit.

```powershell
.\Get-PowerPlatformConnectionPermissions.ps1 `
    -TenantId $tenantId -EnvironmentId $envId `
    -Connector 'shared_commondataserviceforapps' -ConnectionId $connectionId `
    -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint
```

```
PrincipalDisplayName PrincipalEmail       PrincipalId                          PrincipalType AccessLevel RoleName
-------------------- -------------------- ------------------------------------ ------------- ----------- --------
Portal Admin         admin@contoso.com    11111111-1111-1111-1111-111111111111 User          Owner       Owner
Jane Doe             janedoe@contoso.com  33333333-3333-3333-3333-333333333333 User          CanEdit     CanEdit
```

Add `-AsRawJson` to also save the unmodified API response to
`<OutputDirectory>\permissions_<ConnectionId>.json`. Listing permissions requires the Caller
identity to own the connection (or otherwise be entitled on it) - a non-owner call returns 403.

## Sovereign clouds

All three scripts expose `-LoginAuthorityBaseUrl`, `-PowerPlatformApiResource`,
`-EnvironmentApiDomainSuffix`, `-ApiVersion`, and `-TimeoutSec` overrides. Defaults are the public
commercial cloud; this toolkit has only been validated against it - verify the correct values for
your cloud before relying on the overrides.

## Compatibility notes (PowerShell 5.1 vs. 7+)

The shared module is written to behave identically on Windows PowerShell 5.1 (.NET Framework) and
PowerShell 7+ (.NET):
- Random password generation uses `RandomNumberGenerator.Create()+GetBytes()` rather than the
  .NET-only `Fill()` static method.
- The OAuth token request body is built manually with `[Uri]::EscapeDataString`, rather than
  relying on `Invoke-RestMethod`'s implicit Hashtable-to-form-encoded conversion.
- `Invoke-WebRequest` response headers are plain strings on 5.1 but `string[]` on 7+ - a small
  helper normalizes both shapes.
- TLS 1.2 is explicitly enabled via `ServicePointManager` when running under Windows PowerShell
  (a no-op on 7+, which negotiates modern TLS automatically).

## What changed vs. the original two scripts

- Third certificate source (Azure Key Vault via `az` cli delegated auth) added for every identity
  (Caller, Connection, Run Owner) - previously only store-thumbprint and PFX-file were supported.
- Run Owner cert source relaxed to accept a store thumbprint or Key Vault secret too (previously
  only a PFX file was accepted) - it's re-exported to a fresh PFX with a random password before
  embedding, exactly like the Connection cert already did.
- PAD run-owner connections are now a third `-ConnectionType` in the same creation script, instead
  of a separate script.
- `-RunOwnerCredentialMode` adds `KeyVaultCertificate`, `CyberArk`, and `Direct` alongside the
  original `KeyVaultPassword`-only behavior.
- Sharing extracted into its own script + shared module function, supporting all 3 access levels
  (previously only `CanEdit` was implemented).
- Cloud-sovereignty overrides and `-WhatIf`/`-Confirm` support (previously only in the PAD script)
  now apply to all scripts.
- Certificate-store location (`CurrentUser`/`LocalMachine`) is selectable for every identity, not
  just the Caller.
- Every created connection id is printed prominently and appended to a persistent text log
  (`CreatedConnections.log.txt`) - neither original script kept any record beyond a single
  overwritten `connection_result.json`.
- New `Get-PowerPlatformConnectionPermissions.ps1` - neither original script could check who a
  connection was already shared with.
- Sharing now sends `notifyShareTargetOption` and `inviteGuestToTenant`, and a fuller `principal`
  object (display name, email, UPN) when resolved from a UPN/email - matching a HAR capture of
  the maker portal sharing all three access levels. That same capture confirmed the
  `permissions` GET endpoint and fixed a bug where a real (non-`-WhatIf`) share could be
  mistaken for a `-WhatIf` no-op, because the API returns 200 with an empty body on success.

The original `New-DataverseCertConnection.ps1` and `New-PADRunOwnerConnection.ps1` (in
`OneDrive - Microsoft\Scripts\`) are left untouched.
